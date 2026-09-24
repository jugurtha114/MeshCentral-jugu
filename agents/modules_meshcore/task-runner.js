/*
Copyright 2026 Jugurtha-Green

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//
// task-runner: runs one attempt of a scheduled/queued task ("My Tasks") and reports what happened.
//
// All scheduling intelligence -- when to run, retries and backoff, waiting for a user to log in,
// expiry, not running twice across reconnects -- lives on the server (taskmanager.js). This module
// only ever answers "try it once, right now". It keeps just enough state to make delivery reliable:
//   _inflight  the attempts executing right now
//   _outbox    finished attempts whose result the server has not acknowledged yet (taskack); they are
//              re-sent whenever the server asks what we are up to (taskquery), so a result is not
//              lost because the connection happened to be down at the moment the script finished.
//
// Several tasks may run at once (unlike the older single-slot "Run Commands" console feature); only
// the total is capped so a burst cannot swamp a small device.
//

const MAX_CONCURRENT = 3;
const MAX_SCRIPT_BYTES = 512 * 1024;
const MAX_OUTBOX = 50;
const MAX_OUTBOX_BYTES = 1024 * 1024;
const DISPATCH_CONNECT_DEADLINE_MS = 60 * 1000;
var _inflight = {}; // taskrunid -> { child, dispatcher, scriptPath, timer, connectTimer }
var _outbox = {};   // taskrunid -> the taskresult message, kept until acknowledged

function nowMs() { return (new Date()).getTime(); }
// Two behaviours of this runtime's timers matter here: clearTimeout() throws ("Invalid Parameter") when the timer has already fired,
// so never call it bare; and a timer is cancelled if its handle is garbage collected, so every handle must be kept referenced
// until it fires (all of them below are stored on _inflight or in a closure that lives as long as the run).
function clearT(t) { if (t != null) { try { clearTimeout(t); } catch (ex) { } } }
function isWin() { return (process.platform == 'win32'); }

// The folder scripts are written to lives inside the agent's own directory rather than /tmp, which
// can be mounted noexec or be world-writable (symlink tricks). It is traversable but not listable
// by other users, and script names are unguessable.
function taskDir() {
    var dir = process.cwd() + (isWin() ? '\\mesh_tasks' : '/mesh_tasks');
    try { require('fs').mkdirSync(dir); } catch (ex) { } // Already exists
    try { if (!isWin()) { require('fs').chmodSync(dir, 457); } } catch (ex) { } // 0711
    return (dir);
}

// Leftovers from a crash or a killed agent. Nothing can be running yet when this module first loads.
try {
    var _leftovers = require('fs').readdirSync(taskDir());
    for (var _li in _leftovers) { try { require('fs').unlinkSync(taskDir() + (isWin() ? '\\' : '/') + _leftovers[_li]); } catch (ex) { } }
} catch (ex) { }

function scriptExtension(type) { if (isWin()) { return ((type == 2) ? '.ps1' : '.bat'); } return ((type == 3) ? '.py' : '.sh'); }

// Writes the script to a private file and returns its path. Running a real file (rather than typing
// the script into an interactive shell's stdin, as the older Run Commands feature does) gives the
// script its own exit code, avoids echo/quoting problems, keeps commands that read stdin from
// swallowing the rest of the script, and gives the run-as-user paths a stable path to hand over.
function writeScriptFile(taskrunid, type, body) {
    var fs = require('fs'), win = isWin();
    var path = taskDir() + (win ? '\\' : '/') + 't' + taskrunid.replace(/[^A-Za-z0-9]/g, '').substring(0, 24) + '_' + Math.floor(Math.random() * 1000000000) + scriptExtension(type);
    var text = win ? body.split('\r').join('').split('\n').join('\r\n') : body.split('\r').join('');
    if (win && (type == 2)) { // Windows PowerShell reads a BOM-less file as ANSI, so mark it as UTF-8
        try { fs.writeFileSync(path, Buffer.concat([Buffer.from([0xEF, 0xBB, 0xBF]), Buffer.from(text, 'utf8')])); return (path); } catch (ex) { }
    }
    fs.writeFileSync(path, text);
    try { if (!win) { fs.chmodSync(path, 420); } } catch (ex) { } // 0644: the user we may switch to has to be able to read it
    return (path);
}
function unlinkQuiet(path) { if (path) { try { require('fs').unlinkSync(path); } catch (ex) { } } }

// Output is bounded so a script that prints without end cannot exhaust the agent's memory: the start
// and the end are kept (the end is usually where the error is) and the middle is dropped.
function makeCollector(cap) {
    var half = Math.max(256, Math.floor((cap - 40) / 2)), head = '', tail = '', dropped = false; // 40 leaves room for the marker, so the total stays within cap
    return {
        add: function (s) {
            if (head.length < half) { var room = half - head.length; head += s.substring(0, room); s = s.substring(room); }
            if (s.length == 0) return;
            tail += s;
            if (tail.length > half) { tail = tail.substring(tail.length - half); dropped = true; }
        },
        get: function () { return (dropped ? { text: head + '\n... [output truncated] ...\n' + tail, truncated: true } : { text: head + tail, truncated: false }); }
    };
}

// Reports an attempt's outcome. It is also remembered in the outbox until the server acknowledges it.
function sendResult(data, patch) {
    var msg = { action: 'taskresult', taskrunid: data.taskrunid, responseid: data.responseid, attempt: data.attempt, ok: false, exitCode: null, output: '', outputTruncated: false, runAsResolved: null, durationMs: 0, error: null };
    for (var k in patch) { msg[k] = patch[k]; }
    _outbox[msg.taskrunid] = msg;
    var ids = Object.keys(_outbox), bytes = 0, i;
    for (i in ids) { bytes += (_outbox[ids[i]].output ? _outbox[ids[i]].output.length : 0) + 200; }
    for (i = 0; (i < ids.length) && ((ids.length - i > MAX_OUTBOX) || (bytes > MAX_OUTBOX_BYTES)); i++) { if (ids[i] != msg.taskrunid) { bytes -= (_outbox[ids[i]].output ? _outbox[ids[i]].output.length : 0) + 200; delete _outbox[ids[i]]; } }
    try { mesh.SendCommand(msg); } catch (ex) { }
}

function finishRun(id) {
    var st = _inflight[id];
    if (st == null) return (null);
    delete _inflight[id];
    clearT(st.timer); clearT(st.connectTimer);
    unlinkQuiet(st.scriptPath);
    return (st);
}

// Best-effort kill of a script and whatever it started. child.kill() alone ends only the one process.
// The helper runs synchronously (waitExit): a child object nobody references any more is garbage collected
// -- and killed -- by this runtime before it has done anything, and the helper is over in milliseconds.
function killTree(child) {
    var pid = null;
    try { pid = child.pid; } catch (ex) { }
    try {
        if ((pid != null) && (pid > 0)) {
            var helper;
            if (isWin()) {
                helper = require('child_process').execFile(process.env['windir'] + '\\system32\\taskkill.exe', ['taskkill', '/F', '/T', '/PID', pid.toString()]);
            } else {
                // The script was started in its own session, so its process group id is its pid. Some su implementations put the
                // real command in yet another session, so also take down the direct children of the process we started.
                helper = require('child_process').execFile('/bin/sh', ['sh', '-c', 'for c in $(ps -o pid= --ppid ' + pid + ' 2>/dev/null); do kill -KILL -- -$c 2>/dev/null; kill -KILL $c 2>/dev/null; done; kill -KILL -- -' + pid + ' 2>/dev/null; exit 0']);
            }
            helper.stdout.on('data', function () { }); helper.stderr.on('data', function () { });
            helper.waitExit();
        }
    } catch (ex) { }
    try { child.kill(); } catch (ex) { }
}

function defaultTimeoutMs(data) { return ((typeof data.timeoutSec == 'number') && (data.timeoutSec > 0)) ? (data.timeoutSec * 1000) : (10 * 60 * 1000); }
function computeOk(data, exitCode) { return (exitCode != null) && ((Array.isArray(data.successCodes) && (data.successCodes.length > 0)) ? (data.successCodes.indexOf(exitCode) >= 0) : (exitCode === 0)); }

// Everything the agent has open -- its server socket, its identity database, internal pipes -- is inherited by the
// processes it starts. A script must not get those: run as another user it could write into the agent's connection or
// database, and a dead agent's connection is kept alive by any script that outlives it. So POSIX scripts are started
// through this wrapper (/bin/sh -c WRAPPER sh program args...), which closes every descriptor above stderr and then
// replaces itself with the program (same pid, so timeouts and cancels still find the right process group).
// bash is preferred where installed. dash cannot redirect descriptors above 9 (and a failed "exec 10>&-" would end
// the shell), so without bash that is only attempted when the shell proves it can, else just 3-9 are closed.
// (No "2>/dev/null" on those evals: an exec inside eval makes such a redirection permanent, and stderr would be lost.)
var FD_CLOSE_BODY = 'for f in /proc/self/fd/* /dev/fd/*; do n=${f##*/}; case "$n" in ""|*[!0-9]*|0|1|2) ;; *) eval "exec $n>&-" ;; esac; done';
var FD_WRAPPER =
    'if command -v bash >/dev/null 2>&1; then exec bash -c \'' + FD_CLOSE_BODY + '; exec "$@"\' bash "$@"; fi; ' +
    'if ( eval "exec 99>&-" ) 2>/dev/null; then ' + FD_CLOSE_BODY + '; else for n in 3 4 5 6 7 8 9; do eval "exec $n>&-"; done; fi; exec "$@"';

// --- Run on this machine, as the agent's own identity (SYSTEM on Windows, the service account elsewhere) or through su ---
function runProcess(data, target, args, scriptPath, runAsLabel) {
    var startTime = nowMs(), id = data.taskrunid, collector = makeCollector(data.maxOutputBytes || 65536), child;
    if (!isWin()) { args = ['sh', '-c', FD_WRAPPER, 'sh', target].concat(args.slice(1)); target = '/bin/sh'; } // See FD_WRAPPER
    try {
        child = require('child_process').execFile(target, args, isWin() ? undefined : { detached: true }); // detached = own session/process group, so a timeout can take the whole tree down
    } catch (ex) {
        unlinkQuiet(scriptPath);
        sendResult(data, { error: 'spawn-failed: ' + ex, runAsResolved: runAsLabel });
        return;
    }
    _inflight[id] = { child: child, scriptPath: scriptPath };
    try { child.stdin.end(); } catch (ex) { } // Scripts that read stdin get end-of-file instead of waiting for a person

    // The exit event can arrive before the last of the output has been read from the pipes (stdout first, then
    // exit, then stderr, was seen in practice), and these pipes never signal end-of-stream. So after the exit the
    // output is drained until it has been quiet for a moment, with an upper limit for a script that leaves a
    // background process writing to the pipe.
    var exited = false, exitCode = null, exitTime = 0, reported = false, quiet = null, hardStop = null;
    var report = function () {
        if (reported || !exited) return;
        reported = true;
        clearT(quiet); clearT(hardStop);
        if (finishRun(id) == null) return; // A timeout or cancel got there first
        var o = collector.get();
        sendResult(data, { ok: computeOk(data, exitCode), exitCode: exitCode, output: o.text, outputTruncated: o.truncated, runAsResolved: runAsLabel, durationMs: exitTime - startTime });
    };
    var onData = function (c) {
        collector.add(c.toString());
        if (exited && !reported) { clearT(quiet); quiet = setTimeout(report, 250); }
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('exit', function (code) {
        exited = true; exitCode = code; exitTime = nowMs();
        quiet = setTimeout(report, 250);
        hardStop = setTimeout(report, 5000);
    });
    _inflight[id].timer = setTimeout(function () {
        var st = _inflight[id];
        if (st == null) return;
        killTree(st.child);
        finishRun(id);
        reported = true;
        var o = collector.get();
        sendResult(data, { error: 'timeout', output: o.text, outputTruncated: o.truncated, runAsResolved: runAsLabel, durationMs: nowMs() - startTime });
    }, defaultTimeoutMs(data));
}

// The name of the account this agent itself runs as (null if it cannot be determined).
function posixSelfName() {
    try { return (require('user-sessions').getUsername(require('user-sessions').Self())); } catch (ex) { }
    return (null);
}

// Runs a script directly, as the account the agent runs as.
function runPosixDirect(data, type, scriptPath, label) {
    if (type == 3) { runProcess(data, '/usr/bin/env', ['env', 'python3', scriptPath], scriptPath, label); }
    else if (type == 2) { runProcess(data, '/usr/bin/env', ['env', 'bash', scriptPath], scriptPath, label); }
    else { runProcess(data, '/bin/sh', ['sh', scriptPath], scriptPath, label); }
}

// POSIX "run as another user". Root re-launches the script through su, which -- unlike a bare setuid() --
// picks up that user's groups, HOME and environment the way a login for them would. The script's own text
// never touches a command line: only the validated user name and the path of the file we just wrote do.
function runAsPosixUser(data, username, scriptPath, interpreter) {
    var fail = function (msg) { unlinkQuiet(scriptPath); sendResult(data, { error: msg }); };
    if (require('user-sessions').isRoot() !== true) { fail('insufficient-privilege: the agent is not root, so it cannot switch users'); return; }
    if (!/^[A-Za-z0-9_.@][A-Za-z0-9_.@\-]*$/.test(username)) { fail('invalid-username'); return; }
    if (!/^[A-Za-z0-9_.\/\- ]+$/.test(scriptPath)) { fail('unsafe-script-path'); return; }
    var suPath = null, candidates = ['/usr/bin/su', '/bin/su'];
    for (var i in candidates) { if (require('fs').existsSync(candidates[i])) { suPath = candidates[i]; break; } }
    if (suPath == null) { fail('su-not-found'); return; }
    // "su - user -c cmd" is the one spelling that works with util-linux, BusyBox and BSD/macOS su alike.
    runProcess(data, suPath, ['su', '-', username, '-c', interpreter + ' "' + scriptPath + '"'], scriptPath, username);
}

// --- Windows "run as the interactively logged-in user" ---
// A service-context spawn with a session id only changes which desktop the process is attached to; it keeps
// the *service's* token. To get the user's real token, profile and environment we go through the same
// win-dispatcher (Task Scheduler, interactive-token logon) helper "Terminal as user" and clipboard sync use.
// Windows only allows that for a user who is already logged on, so the caller has confirmed a session exists.
function runAsWindowsUser(data, domainUser, target, args, scriptPath, runAsLabel) {
    var id = data.taskrunid, startTime = nowMs(), collector = makeCollector(data.maxOutputBytes || 65536), out = '';
    var timeoutSec = ((typeof data.timeoutSec == 'number') && (data.timeoutSec > 0)) ? data.timeoutSec : 600;

    // Module that runs inside the child process once it is executing with the user's own token. It runs the
    // interpreter, streams its output back over the win-dispatcher IPC pipe and ends with a sentinel line that
    // carries the real exit code. It also has its own timeout so the interpreter is killed even if the
    // parent's teardown signal is lost (an orphaned child is not killed just because its parent exits).
    var script =
        "module.exports = { run: function run(target, args, timeoutSec) {" +
        "var duplex = require('stream').Duplex; var done = false;" +
        "var ds = new duplex({ write: function (c, f) { f(); }, final: function (f) { f(); } });" +
        "var child; try { child = require('child_process').execFile(target, args); } catch (ex) { ds.push('###TASKEXIT:-1###'); ds.push(null); return (ds); }" +
        "try { child.stdin.end(); } catch (ex) { }" +
        "child.stdout.on('data', function (c) { ds.push(c); });" +
        "child.stderr.on('data', function (c) { ds.push(c); });" +
        "child.on('exit', function (code) { done = true; ds.push('###TASKEXIT:' + code + '###'); ds.push(null); });" +
        "ds._t = setTimeout(function () { if (!done) { try { var k = require('child_process').execFile(process.env['windir'] + '\\\\system32\\\\taskkill.exe', ['taskkill', '/F', '/T', '/PID', child.pid.toString()]); k.stdout.on('data', function () { }); k.stderr.on('data', function () { }); k.waitExit(); } catch (ex) { } try { child.kill(); } catch (ex) { } ds.push('###TASKEXIT:-2###'); ds.push(null); } }, (timeoutSec + 5) * 1000);" +
        "return (ds); } };";

    var dispatcher;
    try {
        dispatcher = require('win-dispatcher').dispatch({ user: domainUser, modules: [{ name: 'task-exec-user', script: script }], launch: { module: 'task-exec-user', method: 'run', args: [target, args, timeoutSec] } });
    } catch (ex) {
        unlinkQuiet(scriptPath);
        sendResult(data, { error: 'dispatch-failed: ' + ex, runAsResolved: runAsLabel });
        return;
    }

    _inflight[id] = { dispatcher: dispatcher, scriptPath: scriptPath };
    var settled = false, connected = false;
    dispatcher.on('connection', function (c) {
        connected = true;
        var st0 = _inflight[id]; if (st0 && st0.connectTimer) { clearT(st0.connectTimer); st0.connectTimer = null; }
        c.on('data', function (chunk) { out += chunk.toString(); if (out.length > 65536) { collector.add(out.substring(0, out.length - 64)); out = out.substring(out.length - 64); } }); // Keep a small tail so the exit sentinel is still found
        c.on('end', function () {
            if (settled) return; settled = true;
            if (finishRun(id) == null) return;
            var exitCode = null, m = /###TASKEXIT:(-?\d+)###/.exec(out);
            if (m) { exitCode = parseInt(m[1]); out = out.substring(0, m.index) + out.substring(m.index + m[0].length); }
            collector.add(out);
            var o = collector.get(), err = null;
            if (exitCode === -2) { err = 'timeout'; exitCode = null; } else if (exitCode === -1) { err = 'spawn-failed'; exitCode = null; } else if (exitCode == null) { err = 'no-exit-code'; }
            sendResult(data, { ok: (err == null) && computeOk(data, exitCode), exitCode: exitCode, output: o.text, outputTruncated: o.truncated, runAsResolved: runAsLabel, durationMs: nowMs() - startTime, error: err });
        });
    });
    var st = _inflight[id];
    st.connectTimer = setTimeout(function () { // The scheduled task never started, e.g. the session went away
        if (connected || settled) return; settled = true;
        try { dispatcher.close(); } catch (ex) { }
        if (finishRun(id) == null) return;
        sendResult(data, { error: 'dispatch-timeout: could not start the script in the user session', runAsResolved: runAsLabel, durationMs: nowMs() - startTime });
    }, DISPATCH_CONNECT_DEADLINE_MS);
    st.timer = setTimeout(function () {
        if (settled) return; settled = true;
        try { dispatcher.close(); } catch (ex) { }
        if (finishRun(id) == null) return;
        collector.add(out);
        var o = collector.get();
        sendResult(data, { error: 'timeout', output: o.text, outputTruncated: o.truncated, runAsResolved: runAsLabel, durationMs: nowMs() - startTime });
    }, (timeoutSec + 15) * 1000); // A little after the inline script's own timeout, so that one normally fires first
}

// The interactive session to run in: the console session if it has a user, otherwise the first active one.
// With a requested user name (optionally DOMAIN\name) only that user's session qualifies.
function findWindowsSession(requestedUser) {
    var users = null;
    try { require('user-sessions').Current(function (c) { users = c; }); } catch (ex) { }
    if ((users == null) || (users.Active == null) || (users.Active.length == 0)) return (null);
    var wantName = null, wantDomain = null;
    if (requestedUser != null) {
        if (requestedUser.indexOf('\\') >= 0) { wantDomain = requestedUser.split('\\')[0].toLowerCase(); wantName = requestedUser.split('\\').pop().toLowerCase(); }
        else { wantName = requestedUser.toLowerCase(); }
    }
    var consoleId = null;
    try { consoleId = require('user-sessions').consoleUid(); } catch (ex) { }
    var best = null;
    for (var i = 0; i < users.Active.length; i++) {
        var s = users.Active[i];
        if ((wantName != null) && ((s.Username == null) || (s.Username.toLowerCase() != wantName))) continue;
        if ((wantDomain != null) && (wantDomain != '.') && ((s.Domain == null) || (s.Domain.toLowerCase() != wantDomain))) continue;
        if (best == null) { best = s; }
        if (s.SessionId === consoleId) { best = s; break; }
    }
    return (best);
}

function run(data) {
    if ((data == null) || (typeof data.taskrunid != 'string')) return;
    if (_inflight[data.taskrunid] != null) return; // The same attempt dispatched twice, ignore
    var runningCount = 0; for (var k in _inflight) { runningCount++; }
    if (runningCount >= MAX_CONCURRENT) { sendResult(data, { error: 'busy', requeue: true }); return; }

    var win = isWin();
    var type = win ? data.winType : data.nixType;
    var body = win ? data.winScript : data.nixScript;
    if (!type || (typeof body != 'string') || (body.length == 0)) { sendResult(data, { error: 'no-script-for-platform' }); return; }
    if (body.length > MAX_SCRIPT_BYTES) { sendResult(data, { error: 'script-too-large' }); return; }

    var runAs = data.runAs || 0, scriptPath = null;
    var windir = process.env['windir'];
    var winTarget = function () { return (type == 2) ? (windir + '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe') : (windir + '\\system32\\cmd.exe'); };
    // On Windows the arguments are joined into one command line without any quoting, so the script path is quoted here.
    var winArgs = function (p) { return (type == 2) ? ['powershell', '-noprofile', '-nologo', '-noninteractive', '-executionpolicy', 'bypass', '-file', '"' + p + '"'] : ['cmd', '/d', '/c', '"' + p + '"']; };

    try {
        if (runAs === 0) { // The agent's own identity: always available
            scriptPath = writeScriptFile(data.taskrunid, type, body);
            if (win) { runProcess(data, winTarget(), winArgs(scriptPath), scriptPath, 'SYSTEM'); }
            else { runPosixDirect(data, type, scriptPath, posixSelfName() || 'root'); }
            return;
        }

        // runAs 1 = the logged-in user, or the agent's identity if nobody is; 2 = a logged-in user only; 3 = one specific user
        if (win) {
            var session = findWindowsSession((runAs === 3) ? data.runAsUser : null);
            if (session == null) {
                if (runAs === 1) { data.runAs = 0; run(data); return; }
                sendResult(data, { error: 'no-session' });
                return;
            }
            scriptPath = writeScriptFile(data.taskrunid, type, body);
            runAsWindowsUser(data, '"' + (session.Domain ? session.Domain : '.') + '\\' + session.Username + '"', winTarget(), winArgs(scriptPath), scriptPath, session.Username);
            return;
        }

        // Linux/macOS/BSD: su does not need the user to be "logged in" in any way
        var targetUser = null;
        if (runAs === 3) { targetUser = data.runAsUser; }
        else {
            try { targetUser = require('user-sessions').getUsername(require('user-sessions').consoleUid()); } catch (ex) { }
            if (targetUser == null) {
                if (runAs === 1) { data.runAs = 0; run(data); return; }
                sendResult(data, { error: 'no-session' });
                return;
            }
        }
        scriptPath = writeScriptFile(data.taskrunid, type, body);
        var selfName = posixSelfName();
        if ((selfName != null) && (targetUser === selfName)) { runPosixDirect(data, type, scriptPath, selfName); return; } // Already that user, nothing to switch
        if ((runAs === 1) && (require('user-sessions').isRoot() !== true)) { runPosixDirect(data, type, scriptPath, selfName || 'agent'); return; } // "User if possible": we can't switch, so run as ourselves
        runAsPosixUser(data, targetUser, scriptPath, (type == 3) ? 'python3' : ((type == 2) ? 'bash' : 'sh'));
    } catch (ex) {
        unlinkQuiet(scriptPath);
        sendResult(data, { error: 'spawn-failed: ' + ex });
    }
}

function cancel(data) {
    if ((data == null) || (data.taskrunid == null)) return;
    var st = _inflight[data.taskrunid];
    if (st == null) return;
    if (st.child) { killTree(st.child); }
    try { if (st.dispatcher) { st.dispatcher.close(); } } catch (ex) { }
    if (finishRun(data.taskrunid) == null) return;
    sendResult(data, { error: 'cancelled' });
}

// The server asks (taskquery) what this agent is still doing after a reconnect. It answers with every attempt it knows
// about -- running or finished-but-unacknowledged -- plus the unacknowledged results themselves.
function query() {
    var ids = Object.keys(_inflight), results = [];
    for (var k in _outbox) { if (ids.indexOf(k) < 0) { ids.push(k); } results.push(_outbox[k]); }
    try { mesh.SendCommand({ action: 'taskinflight', ids: ids, results: results }); } catch (ex) { }
}

// The server has stored a result; no need to keep it.
function ack(data) {
    if ((data == null) || (data.taskrunid == null)) return;
    var m = _outbox[data.taskrunid];
    if ((m != null) && ((data.responseid == null) || (m.responseid === data.responseid))) { delete _outbox[data.taskrunid]; }
}

module.exports = { run: run, cancel: cancel, query: query, ack: ack };

/**
* @description MeshCentral scheduled/queued device task manager ("My Tasks")
* @author Ylian Saint-Hilaire & Jugurtha-Green
* @copyright Intel Corporation 2018-2022, Jugurtha-Green 2026
* @license Apache-2.0
* @version v1.0.0
*/

/*jslint node: true */
/*jshint node: true */
/*jshint strict:false */
/*jshint -W097 */
/*jshint esversion: 6 */
'use strict';

//
// "My Tasks": prepare a Windows and/or Linux/macOS script once, aim it at devices and/or whole
// device groups (including devices that join a group later), and have it run as soon as a
// qualifying agent connects -- once per device, or on every connection -- as the system account,
// as whoever is logged in, or as a specific named user. Enabled with "settings": { "taskmanager": true }.
//
// Design notes
//  * The server owns all scheduling state, kept in two kinds of database records:
//      'task'    -> the definition (what to run, where, as whom, when, retry policy)
//      'taskrun' -> one small record per (task, device) with the current state of that pair
//      'taskrunout' -> the captured output of the last attempt, kept apart so listing tasks stays cheap
//  * The agent only ever answers "try this once, right now, and report back"
//    (agents/modules_meshcore/task-runner.js). It keeps nothing across restarts, so a lost
//    connection, an agent crash or a server restart can never strand a task: every attempt is
//    leased, results are re-sent until acknowledged, and a reconnecting agent is asked what it is
//    still running (taskquery/taskinflight) before anything new is dispatched to it.
//  * Delivery is at-least-once. A script that was interrupted (e.g. it rebooted the machine) is
//    counted as a failed attempt and follows the task's normal retry policy.
//  * Every dispatch re-checks that the task's owner still holds the "run commands" right on the
//    device, so revoking a permission takes effect on the next run without touching the task.
//

module.exports.createTaskManager = function (parent) {
    var obj = {};
    obj.parent = parent;
    var db = parent.db;
    var common = require('./common.js');
    var crypto = require('crypto');

    const MESHRIGHT_REMOTECOMMAND = 0x00020000;
    const SITERIGHT_ADMIN = 0xFFFFFFFF;
    const MAX_TARGETS = 500;
    const MAX_TASKS_PER_DOMAIN = 200;
    const MAX_SUCCESS_CODES = 20;
    const MAX_SCRIPT_LEN = 512 * 1024;
    const MAX_OUTPUT_BYTES = 256 * 1024;
    const MIN_RETRY_BACKOFF_SEC = 15;
    const MAX_TIMER_MS = 0x7FFFFFFF;
    const SETTLE_MS = 3000;                  // Let a freshly connected agent finish starting its core before the first dispatch
    const LEASE_SLACK_MS = 120 * 1000;       // An attempt must report within its timeout plus this, or it is counted as lost
    const BUSY_RETRY_MS = 30 * 1000;
    const QUERY_TIMEOUT_MS = 8000;
    const WAITING_USER_FALLBACK_MS = 5 * 60 * 1000;
    const JANITOR_MS = 6 * 60 * 60 * 1000;
    const DB_CONCURRENCY = 10;
    const NO_ACCESS = 'No such task, or you do not have access to it'; // The same answer either way, so task ids cannot be probed

    // The only fields a client may set on a task. Everything else on the record is server-managed.
    const TASK_FIELDS = ['name', 'desc', 'targets', 'winType', 'winScript', 'nixType', 'nixScript', 'runAs', 'runAsUser', 'waitForUser', 'trigger', 'minIntervalSec', 'connectDelaySec', 'startTime', 'expireTime', 'timeoutSec', 'maxRetries', 'retryBackoffSec', 'successCodes', 'maxOutputBytes'];

    // In-memory state only. None of it needs to survive a restart: the database records plus
    // reconcileOnStartup() and each agent's reconnect are enough to rebuild everything.
    var _startTimers = {};    // taskid -> Timeout: a future task.startTime arrives
    var _expireTimers = {};   // taskid -> Timeout: task.expireTime arrives
    var _runTimers = {};      // taskrunid -> Timeout: the attempt's lease runs out, or its retry backoff elapses
    var _waitingUser = {};    // nodeid -> { taskrunid: true }: runs parked until somebody logs in
    var _dispatching = {};    // taskrunid -> true while a dispatch decision is in progress (prevents double dispatch)
    var _busyRuns = {};       // nodeid -> { taskrunid: true }: runs the agent turned away because it was already running as many scripts as it allows
    var _queries = {};        // nodeid -> { start, stale, proceed, timer, done }: a taskquery awaiting the agent's answer

    function nowMs() { return (new Date()).getTime(); }
    function randHex(n) { return crypto.randomBytes(n).toString('hex'); }
    function newTaskId(domainid) { return ('task/' + domainid + '/' + randHex(16)); }
    function taskRunId(domainid, taskid, nodeid) { return ('taskrun/' + domainid + '/' + crypto.createHash('md5').update(taskid + '|' + nodeid).digest('hex')); }
    function runOutId(runid) { return ('taskrunout/' + runid.substring(8)); }
    function web() { return parent.webserver; } // Not created yet when this module is constructed, so never cache it
    function isAdmin(user) { return (user != null) && (user.siteadmin === SITERIGHT_ADMIN); }
    function unref(t) { try { if (t && t.unref) { t.unref(); } } catch (ex) { } return t; }
    function clearTimer(map, key) { if (map[key] != null) { try { clearTimeout(map[key]); } catch (ex) { } delete map[key]; } }
    function fixType(docs, type) { for (var i in docs) { docs[i].type = type; } return docs; } // GetAllTypeNoTypeField strips 'type', and saving a doc without it would orphan the record
    function dbg() { try { parent.debug.apply(parent, ['taskmanager'].concat(Array.prototype.slice.call(arguments))); } catch (ex) { } } // Shown with --debug taskmanager
    function clip(s, n) { return (typeof s == 'string') ? s.substring(0, n) : null; }
    // Keeps the start and the end of over-long output (the end is usually where the error is) and drops the middle.
    function boundOutput(s, max) {
        if (s.length <= max) { return { text: s, cut: false }; }
        var marker = '\n... [output truncated] ...\n', half = Math.max(256, Math.floor((max - marker.length) / 2));
        return { text: s.substring(0, half) + marker + s.substring(s.length - half), cut: true };
    }

    // Runs fn(item, next) over items with at most `limit` in flight, then calls done().
    // (Each item gets its own `called`/`next`: function-scoped vars declared in the loop would be shared by all items.)
    function eachLimit(items, limit, fn, done) {
        var i = 0, active = 0, finished = false;
        function launch(item) {
            active++;
            var called = false;
            var next = function () { if (called) return; called = true; active--; pump(); };
            try { fn(item, next); } catch (ex) { next(); }
        }
        function pump() {
            while ((active < limit) && (i < items.length)) { launch(items[i++]); }
            if ((active == 0) && (i >= items.length) && !finished) { finished = true; if (done) { done(); } }
        }
        pump();
    }

    // ---------------------------------------------------------------- validation

    // A list of device / device group ids, each "<prefix><name>" where the name is only the characters real ids are made of.
    function idList(arr, prefix) {
        if (arr == null) return [];
        if (!Array.isArray(arr)) return null;
        var out = [];
        for (var i in arr) {
            var v = arr[i];
            if ((typeof v != 'string') || (v.length > 256) || !v.startsWith(prefix) || !/^[A-Za-z0-9@$_\-]{1,128}$/.test(v.substring(prefix.length))) return null;
            if (out.indexOf(v) < 0) { out.push(v); }
        }
        return out;
    }
    function intIn(v, min, max) { return (typeof v == 'number') && isFinite(v) && (Math.floor(v) >= min) && (Math.floor(v) <= max); }

    // Validates a client-supplied task and returns { task } holding ONLY whitelisted, normalized fields, or { error }.
    function sanitizeTask(input, domain) {
        if ((input == null) || (typeof input != 'object')) return { error: 'Invalid task' };
        var t = {};
        if (!common.validateString(input.name, 1, 256) || (input.name.trim().length == 0)) return { error: 'Please give the task a name' };
        t.name = input.name.trim();
        t.desc = (typeof input.desc == 'string') ? input.desc.substring(0, 2048) : '';

        var tg = input.targets;
        if ((tg == null) || (typeof tg != 'object')) return { error: 'Select at least one device or device group' };
        var nodes = idList(tg.nodes, 'node/' + domain.id + '/'), meshes = idList(tg.meshes, 'mesh/' + domain.id + '/');
        if ((nodes == null) || (meshes == null)) return { error: 'Invalid target' };
        if ((nodes.length + meshes.length) == 0) return { error: 'Select at least one device or device group' };
        if ((nodes.length + meshes.length) > MAX_TARGETS) return { error: 'Too many targets' };
        t.targets = { nodes: nodes, meshes: meshes };

        if ([0, 1, 2].indexOf(input.winType) < 0) return { error: 'Invalid Windows script type' };
        if ([0, 1, 2, 3].indexOf(input.nixType) < 0) return { error: 'Invalid Linux/macOS script type' };
        if ((input.winType === 0) && (input.nixType === 0)) return { error: 'Provide a script for at least one platform' };
        t.winType = input.winType; t.nixType = input.nixType;
        t.winScript = ''; t.nixScript = '';
        if (t.winType !== 0) {
            if (!common.validateString(input.winScript, 1, MAX_SCRIPT_LEN) || (input.winScript.trim().length == 0) || (input.winScript.indexOf('\u0000') >= 0)) return { error: 'Invalid Windows script' };
            t.winScript = input.winScript;
        }
        if (t.nixType !== 0) {
            if (!common.validateString(input.nixScript, 1, MAX_SCRIPT_LEN) || (input.nixScript.trim().length == 0) || (input.nixScript.indexOf('\u0000') >= 0)) return { error: 'Invalid Linux/macOS script' };
            t.nixScript = input.nixScript;
        }

        if ([0, 1, 2, 3].indexOf(input.runAs) < 0) return { error: 'Invalid run-as setting' };
        t.runAs = input.runAs;
        t.runAsUser = null;
        if (t.runAs === 3) {
            if (!common.validateUsername(input.runAsUser, 1, 256)) return { error: 'Specify which user to run as' };
            t.runAsUser = input.runAsUser.trim();
        }
        t.waitForUser = (input.waitForUser !== false);

        if ([1, 2].indexOf(input.trigger) < 0) return { error: 'Invalid trigger' };
        t.trigger = input.trigger;
        if (!intIn(input.minIntervalSec, 0, 31536000)) return { error: 'Invalid minimum interval' };
        if (!intIn(input.connectDelaySec, 0, 86400)) return { error: 'Invalid connect delay' };
        if (!intIn(input.timeoutSec, 5, 86400)) return { error: 'Invalid timeout' };
        if (!intIn(input.maxRetries, 0, 50)) return { error: 'Invalid retry count' };
        if (!intIn(input.retryBackoffSec, MIN_RETRY_BACKOFF_SEC, 86400)) return { error: 'Invalid retry backoff' };
        if (!intIn(input.maxOutputBytes, 1024, MAX_OUTPUT_BYTES)) return { error: 'Invalid output limit' };
        t.minIntervalSec = Math.floor(input.minIntervalSec); t.connectDelaySec = Math.floor(input.connectDelaySec);
        t.timeoutSec = Math.floor(input.timeoutSec); t.maxRetries = Math.floor(input.maxRetries);
        t.retryBackoffSec = Math.floor(input.retryBackoffSec); t.maxOutputBytes = Math.floor(input.maxOutputBytes);

        t.successCodes = [0];
        if (input.successCodes != null) {
            if (!common.validateArray(input.successCodes, 1, MAX_SUCCESS_CODES)) return { error: 'Invalid success codes' };
            t.successCodes = [];
            for (var i in input.successCodes) {
                if (!intIn(input.successCodes[i], -2147483648, 2147483647)) return { error: 'Invalid success codes' };
                var c = Math.floor(input.successCodes[i]);
                if (t.successCodes.indexOf(c) < 0) { t.successCodes.push(c); }
            }
        }

        t.startTime = null; t.expireTime = null;
        if ((input.startTime != null) && (input.startTime !== 0)) { if (!intIn(input.startTime, 1, 4102444800000)) return { error: 'Invalid start time' }; t.startTime = Math.floor(input.startTime); }
        if ((input.expireTime != null) && (input.expireTime !== 0)) { if (!intIn(input.expireTime, 1, 4102444800000)) return { error: 'Invalid expiry time' }; t.expireTime = Math.floor(input.expireTime); }
        if ((t.startTime != null) && (t.expireTime != null) && (t.expireTime <= t.startTime)) return { error: 'The expiry must be after the start time' };
        return { task: t };
    }

    // ---------------------------------------------------------------- rights

    // True if `user` holds the run-commands right on every listed target, checked right now.
    function checkAllTargetRights(user, domain, targets, cb) {
        if (user == null) { cb(false, 'The task owner no longer exists'); return; }
        var meshes = targets.meshes || [], nodes = targets.nodes || [];
        for (var m in meshes) {
            if ((web().GetMeshRights(user, meshes[m]) & MESHRIGHT_REMOTECOMMAND) == 0) { cb(false, 'You do not have the "run commands" right on a targeted device group'); return; }
        }
        var i = 0;
        (function next() {
            if (i >= nodes.length) { cb(true, null); return; }
            web().GetNodeWithRights(domain, user, nodes[i++], function (node, rights) {
                if ((node == null) || ((rights & MESHRIGHT_REMOTECOMMAND) == 0)) { cb(false, 'You do not have the "run commands" right on a targeted device'); return; }
                next();
            });
        })();
    }

    // A task's execution authority (owner) is its creator, or whoever last edited it. Only the owner,
    // the creator or a site administrator may change or run it.
    function mayManage(user, task) { return isAdmin(user) || (task.owner === user._id) || (task.createdBy === user._id); }

    // Viewing needs the run-commands right somewhere on the task's targets (so users who could not
    // run commands there anyway cannot see what a task does).
    function mayView(user, domain, task, cb) {
        if (mayManage(user, task)) { cb(true); return; }
        var meshes = task.targets.meshes || [], nodes = task.targets.nodes || [];
        for (var m in meshes) { if ((web().GetMeshRights(user, meshes[m]) & MESHRIGHT_REMOTECOMMAND) != 0) { cb(true); return; } }
        var i = 0;
        (function next() {
            if ((i >= nodes.length) || (i >= 5)) { cb(false); return; }
            web().GetNodeWithRights(domain, user, nodes[i++], function (node, rights) { if ((node != null) && ((rights & MESHRIGHT_REMOTECOMMAND) != 0)) { cb(true); } else { next(); } });
        })();
    }

    // What a browser gets to see. Scripts can hold secrets, so only those who may manage the task see them.
    function publicTask(task, user) {
        var t = {};
        for (var k in task) { t[k] = task[k]; }
        if (!mayManage(user, task)) { t.winScript = ''; t.nixScript = ''; t.scriptsHidden = true; }
        return t;
    }

    // ---------------------------------------------------------------- database helpers

    function getTask(taskid, cb) { db.Get(taskid, function (err, docs) { cb(((docs != null) && (docs.length == 1) && (docs[0].type === 'task')) ? docs[0] : null); }); }
    function getRun(id, cb) { db.Get(id, function (err, docs) { cb(((docs != null) && (docs.length == 1) && (docs[0].type === 'taskrun')) ? docs[0] : null); }); }
    function saveRun(run, cb) { run.modifiedTime = nowMs(); db.Set(run, function () { if (cb) { cb(); } }); }
    function getTasksForDomain(domainid, cb) { db.GetAllTypeNoTypeField('task', domainid, function (err, docs) { cb((err == null) ? fixType(docs, 'task') : []); }); }
    function getRunsForDomain(domainid, cb) { db.GetAllTypeNoTypeField('taskrun', domainid, function (err, docs) { cb((err == null) ? fixType(docs, 'taskrun') : []); }); }
    function getRunsForTask(domainid, taskid, cb) { getRunsForDomain(domainid, function (runs) { cb(runs.filter(function (r) { return r.taskid === taskid; })); }); }

    function getOrCreateRun(domainid, taskid, nodeid, meshid, cb) {
        var id = taskRunId(domainid, taskid, nodeid);
        getRun(id, function (run) {
            if (run != null) { cb(run); return; }
            cb({ _id: id, type: 'taskrun', domain: domainid, taskid: taskid, nodeid: nodeid, meshid: meshid, state: 'pending', attempts: 0, noRetry: false, lastAttemptTime: null, nextAttemptTime: null, leaseUntil: null, lastError: null, exitCode: null, hasOutput: false, runAsResolved: null, durationMs: null, responseid: null, createdTime: nowMs() });
        });
    }

    function removeRunAndOutput(run, cb) {
        clearTimer(_runTimers, run._id);
        if (_waitingUser[run.nodeid] != null) { delete _waitingUser[run.nodeid][run._id]; }
        db.Remove(run._id, function () { db.Remove(runOutId(run._id), function () { if (cb) { cb(); } }); });
    }

    // ---------------------------------------------------------------- CRUD

    obj.createTask = function (user, domain, input, cb) {
        var s = sanitizeTask(input, domain);
        if (s.error) { cb(s.error); return; }
        checkAllTargetRights(user, domain, s.task.targets, function (ok, rerr) {
            if (!ok) { cb(rerr); return; }
            getTasksForDomain(domain.id, function (existing) {
                if (existing.length >= MAX_TASKS_PER_DOMAIN) { cb('Too many tasks, delete some first'); return; }
                var t = nowMs(), task = s.task;
                task._id = newTaskId(domain.id); task.type = 'task'; task.domain = domain.id;
                task.createdBy = user._id; task.createdByName = user.name; task.owner = user._id; task.ownerName = user.name;
                task.createdTime = t; task.modifiedTime = t; task.paused = false;
                db.Set(task, function () {
                    armTaskTimers(task);
                    seedRuns(task, function () { dispatchToConnected(task); });
                    logTaskEvent(user, domain, task, 'Created task "' + task.name + '"');
                    cb(null, publicTask(task, user));
                });
            });
        });
    };

    obj.editTask = function (user, domain, taskid, input, cb) {
        getTask(taskid, function (task) {
            if ((task == null) || (task.domain !== domain.id) || !mayManage(user, task)) { cb(NO_ACCESS); return; }
            var candidate = {};
            for (var i in TASK_FIELDS) { var f = TASK_FIELDS[i]; candidate[f] = (input && (input[f] !== undefined)) ? input[f] : task[f]; }
            var s = sanitizeTask(candidate, domain);
            if (s.error) { cb(s.error); return; }
            checkAllTargetRights(user, domain, s.task.targets, function (ok, rerr) {
                if (!ok) { cb(rerr); return; }
                clearTimer(_startTimers, taskid); clearTimer(_expireTimers, taskid);
                for (var j in TASK_FIELDS) { task[TASK_FIELDS[j]] = s.task[TASK_FIELDS[j]]; }
                task.modifiedTime = nowMs();
                if (task.owner !== user._id) { task.owner = user._id; task.ownerName = user.name; } // The last editor holds the execution authority now
                db.Set(task, function () {
                    armTaskTimers(task);
                    reconcileRunsAfterEdit(task, function () {
                        seedRuns(task, function () { if (!task.paused) { dispatchToConnected(task); } });
                    });
                    logTaskEvent(user, domain, task, 'Edited task "' + task.name + '"');
                    cb(null, publicTask(task, user));
                });
            });
        });
    };

    obj.deleteTask = function (user, domain, taskid, cb) {
        getTask(taskid, function (task) {
            if ((task == null) || (task.domain !== domain.id) || !mayManage(user, task)) { cb(NO_ACCESS); return; }
            clearTimer(_startTimers, taskid); clearTimer(_expireTimers, taskid);
            db.Remove(taskid, function () { // Remove the definition first so nothing new can be dispatched while the runs are cleaned up
                getRunsForTask(domain.id, taskid, function (runs) {
                    eachLimit(runs, DB_CONCURRENCY, function (run, next) { cancelAgentSide(run); removeRunAndOutput(run, next); }, function () {
                        logTaskEvent(user, domain, task, 'Deleted task "' + task.name + '"');
                        cb(null);
                    });
                });
            });
        });
    };

    obj.listTasks = function (user, domain, cb) {
        getTasksForDomain(domain.id, function (tasks) {
            var visible = [], i = 0;
            (function check() {
                if (i < tasks.length) { var task = tasks[i++]; mayView(user, domain, task, function (may) { if (may) { visible.push(task); } check(); }); return; }
                if (visible.length == 0) { cb([]); return; }
                getRunsForDomain(domain.id, function (runs) {
                    var buckets = {};
                    for (var r in runs) { (buckets[runs[r].taskid] = buckets[runs[r].taskid] || []).push(runs[r]); }
                    visible.sort(function (a, b) { return b.createdTime - a.createdTime; });
                    cb(visible.map(function (task) { var pt = publicTask(task, user); pt.summary = summarize(buckets[task._id] || []); return pt; }));
                });
            })();
        });
    };

    function summarize(runs) {
        var s = { total: runs.length, pending: 0, waitingUser: 0, queued: 0, success: 0, failed: 0, timeout: 0, cancelled: 0, expired: 0 };
        for (var i in runs) {
            var st = runs[i].state;
            if (st === 'waiting-user') { s.waitingUser++; } else if (st === 'running') { s.queued++; } else if (s[st] != null) { s[st]++; }
        }
        return s;
    }

    // Per-device state of one task. Output is fetched separately (getRunOutput) so this stays small.
    obj.getTaskRuns = function (user, domain, taskid, cb) {
        getTask(taskid, function (task) {
            if ((task == null) || (task.domain !== domain.id)) { cb([]); return; }
            mayView(user, domain, task, function (may) {
                if (!may) { cb([]); return; }
                getRunsForTask(domain.id, taskid, function (runs) {
                    cb(runs.map(function (r) { return { taskid: r.taskid, nodeid: r.nodeid, meshid: r.meshid, state: r.state, attempts: r.attempts, lastAttemptTime: r.lastAttemptTime, nextAttemptTime: r.nextAttemptTime, lastError: r.lastError, exitCode: r.exitCode, runAsResolved: r.runAsResolved, durationMs: r.durationMs, hasOutput: (r.hasOutput === true) }; }));
                });
            });
        });
    };

    obj.getRunOutput = function (user, domain, taskid, nodeid, cb) {
        getTask(taskid, function (task) {
            if ((task == null) || (task.domain !== domain.id)) { cb(null); return; }
            mayView(user, domain, task, function (may) {
                if (!may) { cb(null); return; }
                db.Get(runOutId(taskRunId(domain.id, taskid, nodeid)), function (err, docs) { cb(((docs != null) && (docs.length == 1)) ? { output: docs[0].output, outputTruncated: (docs[0].outputTruncated === true) } : null); });
            });
        });
    };

    // ---------------------------------------------------------------- action verbs

    obj.runNow = function (user, domain, taskid, nodeids, cb) { forceAction(user, domain, taskid, nodeids, 'run', cb); };
    obj.retryRuns = function (user, domain, taskid, nodeids, cb) { forceAction(user, domain, taskid, nodeids, 'retry', cb); };
    obj.cancelRuns = function (user, domain, taskid, nodeids, cb) { forceAction(user, domain, taskid, nodeids, 'cancel', cb); };

    obj.setPaused = function (user, domain, taskid, paused, cb) {
        getTask(taskid, function (task) {
            if ((task == null) || (task.domain !== domain.id) || !mayManage(user, task)) { cb(NO_ACCESS); return; }
            task.paused = (paused === true); task.modifiedTime = nowMs();
            db.Set(task, function () {
                if (!task.paused) { dispatchToConnected(task); }
                logTaskEvent(user, domain, task, (task.paused ? 'Paused' : 'Resumed') + ' task "' + task.name + '"');
                cb(null, publicTask(task, user));
            });
        });
    };

    function forceAction(user, domain, taskid, nodeids, verb, cb) {
        getTask(taskid, function (task) {
            if ((task == null) || (task.domain !== domain.id) || !mayManage(user, task)) { cb(NO_ACCESS); return; }
            if (nodeids != null) { if (!common.validateArray(nodeids, 1, MAX_TARGETS)) { cb('Invalid device list'); return; } for (var n in nodeids) { if (typeof nodeids[n] != 'string') { cb('Invalid device list'); return; } } }
            getRunsForTask(domain.id, taskid, function (runs) {
                var byNode = {}; for (var r in runs) { byNode[runs[r].nodeid] = runs[r]; }
                var wanted = [];
                if (nodeids != null) { wanted = nodeids; }
                else { for (var nid in byNode) { var st = byNode[nid].state; if ((verb === 'retry') ? (['failed', 'timeout'].indexOf(st) >= 0) : true) { wanted.push(nid); } } }
                eachLimit(wanted, DB_CONCURRENCY, function (nodeid, next) {
                    var apply = function (run) {
                        if (run == null) { next(); return; }
                        if (verb === 'cancel') { if (['success', 'cancelled', 'expired'].indexOf(run.state) < 0) { cancelOneRun(run, next); } else { next(); } return; }
                        if ((['queued', 'running'].indexOf(run.state) >= 0) && (run.leaseUntil != null) && (nowMs() < run.leaseUntil)) { next(); return; } // Already executing, don't run it twice at once
                        run.state = 'pending'; run.attempts = 0; run.noRetry = false; run.nextAttemptTime = null; run.lastError = null;
                        clearTimer(_runTimers, run._id);
                        saveRun(run, function () { dispatchNode(task, nodeid, null, next); });
                    };
                    if (byNode[nodeid] != null) { apply(byNode[nodeid]); return; }
                    // No run record yet: only create one for a device that really is a target of this task
                    db.Get(nodeid, function (err, docs) {
                        var node = ((docs != null) && (docs.length == 1) && (docs[0].type === 'node') && (docs[0].domain === domain.id)) ? docs[0] : null;
                        if ((node == null) || ((task.targets.nodes.indexOf(nodeid) < 0) && (task.targets.meshes.indexOf(node.meshid) < 0))) { next(); return; }
                        getOrCreateRun(domain.id, task._id, nodeid, node.meshid, apply);
                    });
                }, function () { cb(null); });
            });
        });
    }

    // ---------------------------------------------------------------- run records for a task's targets

    // Creates a 'pending' run record up front for every currently known target so the UI shows the
    // whole device list (honestly marked pending) right away instead of devices only appearing once
    // they connect. Devices that join a targeted group later get theirs when they first connect.
    function seedRuns(task, done) {
        var pairs = [];
        eachLimit(task.targets.nodes, DB_CONCURRENCY, function (nodeid, next) {
            db.Get(nodeid, function (err, docs) { if ((docs != null) && (docs.length == 1) && (docs[0].type === 'node')) { pairs.push({ nodeid: nodeid, meshid: docs[0].meshid }); } next(); });
        }, function () {
            var finish = function () {
                eachLimit(pairs, DB_CONCURRENCY, function (p, next) {
                    getOrCreateRun(task.domain, task._id, p.nodeid, p.meshid, function (run) { if (run.modifiedTime == null) { saveRun(run, next); } else { next(); } });
                }, done);
            };
            if (task.targets.meshes.length == 0) { finish(); return; }
            db.GetAllTypeNoTypeField('node', task.domain, function (err, allNodes) {
                if (err == null) { for (var n in allNodes) { if (task.targets.meshes.indexOf(allNodes[n].meshid) >= 0) { pairs.push({ nodeid: allNodes[n]._id, meshid: allNodes[n].meshid }); } } }
                finish();
            });
        });
    }

    // After an edit: runs for devices that are no longer targeted stop, and runs an expiry had ended come back if the window was extended.
    function reconcileRunsAfterEdit(task, done) {
        getRunsForTask(task.domain, task._id, function (runs) {
            eachLimit(runs, DB_CONCURRENCY, function (run, next) {
                var targeted = (task.targets.nodes.indexOf(run.nodeid) >= 0) || ((run.meshid != null) && (task.targets.meshes.indexOf(run.meshid) >= 0));
                if (!targeted) { if (['success', 'cancelled', 'expired'].indexOf(run.state) < 0) { cancelOneRun(run, next); } else { next(); } return; }
                if ((run.state === 'expired') && ((task.expireTime == null) || (task.expireTime > nowMs()))) { run.state = 'pending'; run.attempts = 0; run.noRetry = false; saveRun(run, next); return; }
                next();
            }, done);
        });
    }

    // ---------------------------------------------------------------- timers for start/expiry

    // Timers can fire a hair early relative to the wall clock (and are capped at ~24 days), so a fired timer re-reads the task and,
    // if the moment has not really arrived, simply waits again instead of giving up on the dispatch.
    function armTaskTimers(task) {
        var t = nowMs();
        if ((task.startTime != null) && (task.startTime > t)) {
            _startTimers[task._id] = unref(setTimeout(function () {
                delete _startTimers[task._id];
                getTask(task._id, function (fresh) {
                    if (fresh == null) return;
                    if ((fresh.startTime != null) && (fresh.startTime > nowMs())) { armTaskTimers(fresh); return; } // Early, or the start time was moved
                    dispatchToConnected(fresh);
                });
            }, Math.min(task.startTime - t + 20, MAX_TIMER_MS)));
        }
        if (task.expireTime != null) {
            var delay = task.expireTime - t;
            if (delay > 0) {
                _expireTimers[task._id] = unref(setTimeout(function () {
                    delete _expireTimers[task._id];
                    getTask(task._id, function (fresh) {
                        if (fresh == null) return;
                        if ((fresh.expireTime != null) && (fresh.expireTime > nowMs())) { armTaskTimers(fresh); } else if (fresh.expireTime != null) { expireTask(fresh); }
                    });
                }, Math.min(delay + 20, MAX_TIMER_MS)));
            } else { expireTask(task); }
        }
    }

    // Work that has not started stops being offered. An attempt that is executing right now is left to finish.
    function expireTask(task) {
        getRunsForTask(task.domain, task._id, function (runs) {
            eachLimit(runs, DB_CONCURRENCY, function (run, next) {
                if (['pending', 'waiting-user', 'failed', 'timeout'].indexOf(run.state) >= 0) { clearTimer(_runTimers, run._id); if (_waitingUser[run.nodeid] != null) { delete _waitingUser[run.nodeid][run._id]; } run.state = 'expired'; saveRun(run, next); } else { next(); }
            });
        });
    }

    // ---------------------------------------------------------------- dispatching

    // Sends a message to an agent, locally if it is connected to this server, otherwise through the peer servers.
    function sendToAgent(nodeid, agentObj, msg) {
        var a = agentObj || (web() ? web().wsagents[nodeid] : null);
        if (a != null) { try { a.send(JSON.stringify(msg)); return true; } catch (ex) { return false; } }
        if (parent.multiServer != null) { try { parent.multiServer.DispatchMessage({ action: 'agentCommand', nodeid: nodeid, command: msg }); return true; } catch (ex) { } }
        return false;
    }

    function isTargeted(task, nodeid, meshid) { return (task.targets.nodes.indexOf(nodeid) >= 0) || ((meshid != null) && (task.targets.meshes.indexOf(meshid) >= 0)); }

    // The "as soon as it's connected" entry point (see meshagent.js agentCoreIsStable()).
    obj.onAgentConnected = function (agentObj) {
        if ((agentObj.connectTime != null) && (agentObj._taskInit === agentObj.connectTime)) { dbg('onAgentConnected: already handled for this connection', agentObj.dbNodeKey); return; } // Once per connection
        agentObj._taskInit = agentObj.connectTime;
        var domainid = agentObj.domain.id, nodeid = agentObj.dbNodeKey, meshid = agentObj.dbMeshKey;
        getTasksForDomain(domainid, function (tasks) {
            var applicable = tasks.filter(function (t) { return !t.paused && isTargeted(t, nodeid, meshid); });
            dbg('onAgentConnected', nodeid, 'tasks in domain:', tasks.length, 'applicable:', applicable.length);
            if (applicable.length == 0) return;
            var pairs = [];
            eachLimit(applicable, DB_CONCURRENCY, function (task, next) {
                getOrCreateRun(domainid, task._id, nodeid, meshid, function (run) { pairs.push({ task: task, run: run }); next(); });
            }, function () {
                var proceed = function () {
                    for (var i in pairs) {
                        (function (task) {
                            unref(setTimeout(function () {
                                if (web().wsagents[nodeid] !== agentObj) return; // Dropped or reconnected in the meantime
                                getTask(task._id, function (fresh) { if (fresh != null) { dispatchNode(fresh, nodeid, agentObj); } }); // Fresh copy so edits made during the delay apply
                            }, SETTLE_MS + (task.connectDelaySec * 1000)));
                        })(pairs[i].task);
                    }
                };
                var stale = pairs.filter(function (p) { return (p.run.state === 'queued') || (p.run.state === 'running'); });
                if (stale.length == 0) { proceed(); return; }
                // Attempts were in flight on an earlier connection. Ask the agent what it still has before dispatching anything.
                var q = _queries[nodeid] = { start: nowMs(), stale: stale.map(function (p) { return p.run._id; }), done: false };
                q.proceed = function () { if (q.done) return; q.done = true; clearTimeout(q.timer); if (_queries[nodeid] === q) { delete _queries[nodeid]; } proceed(); };
                q.timer = unref(setTimeout(q.proceed, QUERY_TIMEOUT_MS));
                if (!sendToAgent(nodeid, agentObj, { action: 'taskquery' })) { q.proceed(); }
            });
        });
    };

    // Give one task a chance on every device that is connected right now (task created, edited, resumed, or its start time arrived):
    // those connected to this server, and -- with peer servers -- those connected to any other server of the cluster.
    function dispatchToConnected(task) {
        if ((web() == null) || task.paused) return;
        var ids = {};
        var consider = function (nodeid, meshid) { if (isTargeted(task, nodeid, meshid)) { ids[nodeid] = true; } };
        for (var nodeid in web().wsagents) { var a = web().wsagents[nodeid]; if (a != null) { consider(nodeid, a.dbMeshKey); } }
        if ((parent.multiServer != null) && (parent.connectivityByNode != null)) {
            for (var n in parent.connectivityByNode) { var st = parent.connectivityByNode[n]; if ((st != null) && ((st.connectivity & 1) != 0)) { consider(n, st.meshid); } }
        }
        eachLimit(Object.keys(ids), DB_CONCURRENCY, function (nodeid, next) { dispatchNode(task, nodeid, null, next); });
    }

    function computeEligibility(task, run, t) {
        if (task.paused) return { eligible: false };
        if ((task.startTime != null) && (t < task.startTime)) return { eligible: false };
        if ((task.expireTime != null) && (t > task.expireTime)) return { eligible: false };
        var sinceLast = (run.lastAttemptTime != null) ? (t - run.lastAttemptTime) : Infinity;
        switch (run.state) {
            case 'pending': case 'waiting-user': return { eligible: true };
            case 'success': // Once per device is done for good; every-connection tasks run again after the minimum interval
                if (task.trigger === 1) return { eligible: false };
                return { eligible: (sinceLast >= (task.minIntervalSec * 1000)), newCycle: true };
            case 'failed': case 'timeout':
                if (!run.noRetry && (run.attempts <= task.maxRetries)) { return { eligible: !((run.nextAttemptTime != null) && (t < run.nextAttemptTime)) }; } // Still inside the retry budget
                // Out of retries. An every-connection task starts a fresh cycle the next time round; a once-per-device task waits for a manual retry.
                return { eligible: (task.trigger === 2) && (sinceLast >= (task.minIntervalSec * 1000)), newCycle: true };
            default: return { eligible: false }; // queued/running (handled by the lease), cancelled, expired
        }
    }

    // Considers one (task, device) pair and, if it is due and allowed, dispatches it. done() is always called.
    function dispatchNode(task, nodeid, agentObj, done) {
        var finish = function () { if (done) { done(); } };
        var a = agentObj || (web() ? web().wsagents[nodeid] : null);
        var remote = false;
        if (a == null) {
            var cs = parent.GetConnectivityState ? parent.GetConnectivityState(nodeid) : null;
            remote = (parent.multiServer != null) && (cs != null) && ((cs.connectivity & 1) != 0);
            if (!remote) { finish(); return; } // Offline: it stays pending and is picked up when the device next connects
        }
        var runid = taskRunId(task.domain, task._id, nodeid);
        if (_dispatching[runid]) { finish(); return; }
        _dispatching[runid] = true;
        var release = function () { delete _dispatching[runid]; finish(); };

        var proceed = function (meshid, caps) {
            getOrCreateRun(task.domain, task._id, nodeid, meshid, function (run) {
                if (run.meshid !== meshid) { run.meshid = meshid; }
                var t = nowMs();
                // An attempt that never reported and whose lease ran out is counted as a failed attempt
                if ((['queued', 'running'].indexOf(run.state) >= 0) && (run.leaseUntil != null) && (t > run.leaseUntil)) { recordAttemptResult(task, run, { error: 'no-response' }, release); return; }
                var elig = computeEligibility(task, run, t);
                dbg('dispatchNode', task.name, nodeid, 'state:', run.state, 'attempts:', run.attempts, 'eligible:', elig.eligible);
                if (!elig.eligible) { release(); return; }
                if ((caps != null) && (((caps & 16) == 0) || ((caps & 0x40) != 0))) { run.lastAttemptTime = t; recordAttemptResult(task, run, { error: 'unsupported: this agent cannot run tasks' }, release); return; }
                var owner = web().users[task.owner], domain = parent.config.domains[task.domain];
                checkAllTargetRights(owner, domain, { nodes: [nodeid], meshes: [] }, function (ok, rerr) {
                    if (!ok) { run.lastAttemptTime = t; recordAttemptResult(task, run, { error: 'forbidden: ' + rerr }, release); return; } // Refused before reaching the device: not a try, but it still counts for the every-connection throttle
                    sendRunTask(task, run, nodeid, a, elig.newCycle === true, release);
                });
            });
        };
        if (a != null) { proceed(a.dbMeshKey, (a.agentInfo != null) ? a.agentInfo.capabilities : null); }
        else { db.Get(nodeid, function (err, docs) { if ((docs != null) && (docs.length == 1)) { proceed(docs[0].meshid, null); } else { release(); } }); }
    }

    function sendRunTask(task, run, nodeid, agentObj, newCycle, done) {
        var t = nowMs(), responseid = 't' + randHex(8);
        if (newCycle) { run.attempts = 0; run.noRetry = false; }
        run.state = 'queued'; run.responseid = responseid; run.attempts = (run.attempts || 0) + 1;
        run.lastAttemptTime = t; run.leaseUntil = t + (task.timeoutSec * 1000) + LEASE_SLACK_MS; run.nextAttemptTime = null; run.lastError = null;
        saveRun(run, function () {
            var msg = {
                action: 'runtask', taskrunid: run._id, responseid: responseid, attempt: run.attempts,
                winType: task.winType, winScript: task.winScript, nixType: task.nixType, nixScript: task.nixScript,
                runAs: task.runAs, runAsUser: task.runAsUser, timeoutSec: task.timeoutSec,
                successCodes: task.successCodes, maxOutputBytes: task.maxOutputBytes
            };
            var sent = sendToAgent(nodeid, agentObj, msg);
            dbg('sendRunTask', run._id, 'attempt', run.attempts, sent ? 'sent' : 'NOT sent');
            if (sent) {
                clearTimer(_runTimers, run._id);
                _runTimers[run._id] = unref(setTimeout(function () { delete _runTimers[run._id]; onLeaseExpired(run._id); }, Math.min(run.leaseUntil - nowMs() + 1000, MAX_TIMER_MS)));
                done();
            } else { // Could not be sent at all: this was not really an attempt
                run.state = 'pending'; run.attempts = Math.max(0, run.attempts - 1); run.leaseUntil = null; saveRun(run, done);
            }
        });
    }

    function onLeaseExpired(runid) {
        getRun(runid, function (run) {
            if ((run == null) || (['queued', 'running'].indexOf(run.state) < 0)) return;
            if ((run.leaseUntil != null) && (nowMs() < run.leaseUntil)) { _runTimers[runid] = unref(setTimeout(function () { delete _runTimers[runid]; onLeaseExpired(runid); }, Math.min(run.leaseUntil - nowMs() + 1000, MAX_TIMER_MS))); return; }
            getTask(run.taskid, function (task) { if (task != null) { recordAttemptResult(task, run, { error: 'no-response' }); } });
        });
    }

    // Agent -> server: one attempt finished (or could not start). An agent may only report on its own runs.
    obj.onTaskResult = function (agentObj, command, done) {
        var finish = function () { if (done) { done(); } };
        if ((command == null) || (typeof command.taskrunid != 'string') || (command.taskrunid.length > 256)) { finish(); return; }
        var nodeid = agentObj.dbNodeKey;
        dbg('onTaskResult', command.taskrunid, 'error:', command.error, 'exit:', command.exitCode);
        var ack = function () { sendToAgent(nodeid, agentObj, { action: 'taskack', taskrunid: command.taskrunid, responseid: command.responseid }); };
        getRun(command.taskrunid, function (run) {
            if ((run == null) || (run.nodeid !== nodeid)) { if (run == null) { ack(); } finish(); return; }
            if ((run.responseid !== command.responseid) || (['queued', 'running'].indexOf(run.state) < 0)) { ack(); finish(); return; } // Stale, cancelled or already handled
            getTask(run.taskid, function (task) {
                if (task == null) { ack(); finish(); return; }
                ack();
                if (command.requeue === true) { // The agent was busy with other tasks: that was not an attempt
                    run.state = 'pending'; run.attempts = Math.max(0, run.attempts - 1); run.leaseUntil = null;
                    (_busyRuns[nodeid] = _busyRuns[nodeid] || {})[run._id] = true;
                    saveRun(run, function () { scheduleDispatch(task, run, BUSY_RETRY_MS); finish(); }); // Fallback; normally kickBusy() gets there first, as soon as a script on this device finishes
                    return;
                }
                if ((command.error === 'no-session') && task.waitForUser && ((task.runAs === 2) || (task.runAs === 3))) { // Park it until somebody logs in
                    run.state = 'waiting-user'; run.attempts = Math.max(0, run.attempts - 1); run.leaseUntil = null; run.lastError = 'Waiting for a user to log in';
                    clearTimer(_runTimers, run._id);
                    (_waitingUser[nodeid] = _waitingUser[nodeid] || {})[run._id] = true;
                    saveRun(run, finish);
                    return;
                }
                recordAttemptResult(task, run, command, finish);
            });
        });
    };

    // Agent -> server: the answer to a taskquery. Anything we thought was running that the agent has never
    // heard of died with the previous connection (crash, reboot, ...) and counts as a failed attempt.
    obj.onTaskInflight = function (agentObj, command) {
        var nodeid = agentObj.dbNodeKey, q = _queries[nodeid];
        dbg('onTaskInflight', nodeid, 'ids:', Array.isArray(command.ids) ? command.ids.length : 0, 'results:', Array.isArray(command.results) ? command.results.length : 0, 'query pending:', q != null);
        var known = {};
        if (Array.isArray(command.ids)) { for (var i in command.ids) { if (typeof command.ids[i] == 'string') { known[command.ids[i]] = true; } } }
        var results = Array.isArray(command.results) ? command.results.slice(0, 50) : [];
        eachLimit(results, 1, function (res, next) { obj.onTaskResult(agentObj, res, next); }, function () {
            if (q == null) return; // Not asked (or already timed out): the results above are still valid, but there is nothing to reconcile
            eachLimit(q.stale, DB_CONCURRENCY, function (runid, next) {
                if (known[runid]) { next(); return; }
                getRun(runid, function (run) {
                    if ((run == null) || (['queued', 'running'].indexOf(run.state) < 0) || (run.lastAttemptTime >= q.start)) { next(); return; } // Handled meanwhile, or dispatched after we asked
                    getTask(run.taskid, function (task) { if (task != null) { recordAttemptResult(task, run, { error: 'interrupted' }, next); } else { next(); } });
                });
            }, function () { q.proceed(); });
        });
    };

    // A user logged in or out on a device: runs parked waiting for a user get another go straight away.
    obj.onAgentUsersChanged = function (agentObj, users) {
        var nodeid = agentObj.dbNodeKey;
        if ((_waitingUser[nodeid] == null) || !Array.isArray(users) || (users.length == 0)) return;
        probeWaiting(nodeid);
    };

    function probeWaiting(nodeid) {
        var runids = Object.keys(_waitingUser[nodeid] || {});
        if (runids.length == 0) { delete _waitingUser[nodeid]; return; }
        unref(setTimeout(function () {
            eachLimit(runids, DB_CONCURRENCY, function (runid, next) {
                getRun(runid, function (run) {
                    if ((run == null) || (run.state !== 'waiting-user')) { if (_waitingUser[nodeid]) { delete _waitingUser[nodeid][runid]; } next(); return; }
                    getTask(run.taskid, function (task) { if (task != null) { dispatchNode(task, nodeid, null, next); } else { next(); } });
                });
            });
        }, SETTLE_MS));
    }

    // Records the outcome of one attempt, decides between success / retry / giving up, and tells the world.
    function recordAttemptResult(task, run, res, done) {
        var finish = function () { if (done) { done(); } };
        clearTimer(_runTimers, run._id);
        if (_waitingUser[run.nodeid] != null) { delete _waitingUser[run.nodeid][run._id]; }
        var err = clip(res.error, 256);
        var exitCode = (typeof res.exitCode == 'number') ? Math.floor(res.exitCode) : null;
        var bounded = boundOutput((typeof res.output == 'string') ? res.output : '', Math.min(MAX_OUTPUT_BYTES, task.maxOutputBytes));
        var output = bounded.text;
        // Never trust the agent's own verdict: success is an exit code the task lists, with no error.
        var ok = (err == null) && (exitCode != null) && (task.successCodes.indexOf(exitCode) >= 0);
        run.exitCode = exitCode; run.lastError = ok ? null : (err || ((exitCode != null) ? ('exit code ' + exitCode) : 'failed'));
        run.runAsResolved = clip(res.runAsResolved, 256); run.durationMs = (typeof res.durationMs == 'number') ? Math.floor(res.durationMs) : null;
        run.leaseUntil = null; run.nextAttemptTime = null;
        var retryInMs = null;
        dbg('recordAttemptResult', run._id, ok ? 'ok' : ('failed: ' + run.lastError), 'attempts:', run.attempts);
        if (ok) { run.state = 'success'; }
        else {
            run.state = (err === 'timeout') ? 'timeout' : 'failed';
            var hopeless = (err != null) && /^(forbidden|unsupported|script-too-large|no-script-for-platform|insufficient-privilege|invalid-username)/.test(err); // Retrying cannot change these
            if (hopeless) { run.noRetry = true; }
            else if (run.attempts <= task.maxRetries) {
                var backoff = Math.min(task.retryBackoffSec * Math.pow(2, Math.max(0, run.attempts - 1)), 86400);
                retryInMs = backoff * 1000; run.nextAttemptTime = nowMs() + retryInMs;
            }
        }
        var hasOutput = (output.length > 0);
        run.hasOutput = hasOutput;
        var saveOut = function (cb2) {
            if (hasOutput) { db.Set({ _id: runOutId(run._id), type: 'taskrunout', domain: run.domain, taskid: run.taskid, nodeid: run.nodeid, output: output, outputTruncated: (res.outputTruncated === true) || bounded.cut, time: nowMs() }, function () { cb2(); }); }
            else { db.Remove(runOutId(run._id), function () { cb2(); }); }
        };
        saveOut(function () {
            saveRun(run, function () {
                if (retryInMs != null) { scheduleDispatch(task, run, retryInMs + 250); }
                kickBusy(run.nodeid); // A script just finished, so this device has a free slot for anything it had to turn away
                var domain = parent.config.domains[task.domain];
                if (domain) {
                    var who = run.runAsResolved ? (' as ' + run.runAsResolved) : '';
                    var msg = 'Task "' + task.name + '" ' + (ok ? ('succeeded' + ((run.exitCode != null) ? (' (exit code ' + run.exitCode + ')') : '') + who) : ('failed: ' + run.lastError + who)) + ((retryInMs != null) ? (', retrying in ' + Math.round(retryInMs / 1000) + 's') : '');
                    logRunEvent(task, domain, run, msg);
                }
                finish();
            });
        });
    }

    function kickBusy(nodeid) {
        var runids = Object.keys(_busyRuns[nodeid] || {});
        if (runids.length == 0) return;
        delete _busyRuns[nodeid];
        runids.forEach(function (runid) {
            getRun(runid, function (run) {
                if ((run == null) || (run.state !== 'pending')) return;
                getTask(run.taskid, function (task) { if (task != null) { scheduleDispatch(task, run, 1000); } });
            });
        });
    }

    // Re-examine one device for a task after a delay. The task is re-read when the timer fires so edits, pauses and deletions made meanwhile are honoured.
    function scheduleDispatch(task, run, delayMs) {
        clearTimer(_runTimers, run._id);
        var taskid = task._id, nodeid = run.nodeid, runid = run._id;
        _runTimers[runid] = unref(setTimeout(function () {
            delete _runTimers[runid];
            getTask(taskid, function (fresh) { if (fresh != null) { dispatchNode(fresh, nodeid, null); } });
        }, Math.min(Math.max(delayMs, 1000), MAX_TIMER_MS)));
    }

    function cancelAgentSide(run) {
        if (['queued', 'running'].indexOf(run.state) >= 0) { sendToAgent(run.nodeid, null, { action: 'canceltask', taskrunid: run._id, responseid: run.responseid }); }
    }

    function cancelOneRun(run, cb) {
        clearTimer(_runTimers, run._id);
        if (_waitingUser[run.nodeid] != null) { delete _waitingUser[run.nodeid][run._id]; }
        cancelAgentSide(run);
        run.state = 'cancelled'; run.leaseUntil = null; run.nextAttemptTime = null;
        saveRun(run, cb);
    }

    // ---------------------------------------------------------------- events

    function logTaskEvent(user, domain, task, msg) {
        try {
            var targets = [user._id];
            for (var i = 0; (i < task.targets.meshes.length) && (i < 50); i++) { targets.push(task.targets.meshes[i]); }
            parent.DispatchEvent(targets, obj, { etype: 'user', userid: user._id, username: user.name, action: 'agenttask', taskid: task._id, msg: msg, domain: domain.id });
        } catch (ex) { }
    }
    function logRunEvent(task, domain, run, msg) {
        try {
            var targets = web().CreateNodeDispatchTargets(run.meshid, run.nodeid, [task.owner]);
            parent.DispatchEvent(targets, obj, { etype: 'node', userid: task.owner, username: task.ownerName, nodeid: run.nodeid, action: 'agenttask', taskid: task._id, state: run.state, msg: msg, domain: domain.id });
        } catch (ex) { }
    }

    // ---------------------------------------------------------------- background work

    // Backstop for runs parked waiting for a user: not every platform reports logins promptly, so look again now and then.
    unref(setInterval(function () { for (var nodeid in _waitingUser) { if ((web() != null) && (web().wsagents[nodeid] != null)) { probeWaiting(nodeid); } } }, WAITING_USER_FALLBACK_MS));

    // Housekeeping: drop run records whose task or device no longer exists.
    function janitor() {
        if ((web() == null) || (parent.config == null) || (parent.config.domains == null)) return;
        Object.keys(parent.config.domains).forEach(function (domainid) {
            getTasksForDomain(domainid, function (tasks) {
                var taskIds = {}; for (var t in tasks) { taskIds[tasks[t]._id] = true; }
                db.GetAllTypeNoTypeField('node', domainid, function (err, nodes) {
                    if (err != null) return;
                    var nodeIds = {}; for (var n in nodes) { nodeIds[nodes[n]._id] = true; }
                    getRunsForDomain(domainid, function (runs) {
                        var dead = runs.filter(function (r) { return !taskIds[r.taskid] || !nodeIds[r.nodeid]; });
                        eachLimit(dead, DB_CONCURRENCY, function (run, next) { removeRunAndOutput(run, next); });
                    });
                });
            });
        });
    }
    unref(setInterval(janitor, JANITOR_MS));
    unref(setTimeout(janitor, 5 * 60 * 1000));

    // Runs once when the server starts. The web server does not exist yet at this point, so this only re-arms
    // the start/expiry timers; devices are dealt with as each agent reconnects (onAgentConnected).
    obj.reconcileOnStartup = function () {
        db.GetAllType('task', function (err, tasks) { if (err == null) { for (var i in tasks) { armTaskTimers(tasks[i]); } } });
    };

    // Compatibility no-op: an older, never-completed upstream attempt at this idea left a single hook in
    // meshagent.js (action 'script-task' -> taskManager.agentAction()). Nothing sends that action today.
    obj.agentAction = function (command, agentObj) { };

    return obj;
};

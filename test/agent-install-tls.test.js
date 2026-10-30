'use strict';
// The Linux/BSD one-line install must survive a system that cannot verify the server's TLS certificate (out-of-date
// CA store, a firewall that inspects TLS): that is what "curl: (60) SSL certificate problem: self-signed certificate
// in certificate chain" looked like on a fresh machine. These tests run the real installer script and the command the
// web UI generates against a local HTTPS server whose certificate is self-signed, so curl and wget refuse it for real.
// Nothing here installs anything: the "agent" it downloads is a shell script that only records its arguments.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const { execFileSync, spawn, spawnSync } = require('child_process');

const root = path.join(__dirname, '..');
const template = fs.readFileSync(path.join(root, 'agents', 'meshinstall-linux-oneline.sh'), 'utf8');
const have = tool => { try { execFileSync('sh', ['-c', 'command -v ' + tool], { stdio: 'ignore' }); return true; } catch (ex) { return false; } };
const which = tool => { try { return execFileSync('sh', ['-c', 'command -v ' + tool], { encoding: 'utf8' }).trim(); } catch (ex) { return null; } };
const shells = ['sh', 'dash', 'busybox sh'].filter(sh => have(sh.split(' ')[0]));

// What sendAgentInstallScript() in webserver.js does to the template
function render(options) {
    let data = template;
    for (const key in options) { data = data.split('{{{' + key + '}}}').join(options[key]); }
    return data;
}

// A directory of stand-ins that stays first on PATH: sudo just runs the command (the tests do not need root).
function makeStubs(dir, extra) {
    const bin = path.join(dir, 'bin');
    fs.mkdirSync(bin);
    const put = (name, body) => { fs.writeFileSync(path.join(bin, name), '#!/bin/sh\n' + body); fs.chmodSync(path.join(bin, name), 0o755); };
    for (const util of ['id', 'uname', 'getconf', 'mktemp', 'chmod', 'rm', 'cat', 'mkdir']) { const real = which(util); if (real) { fs.symlinkSync(real, path.join(bin, util)); } }
    put('sudo', 'exec "$@"\n');
    for (const name in (extra || {})) { put(name, extra[name]); }
    return bin;
}

// An HTTP client stand-in that behaves like curl/wget on a failing certificate: exit 60 (curl) / 5 (wget) unless the
// certificate check is skipped, exit $failcode for everything else. Records every call in $LOG.
function clientStub(kind, failcode) {
    const skip = kind == 'curl' ? '-k' : '--no-check-certificate';
    const outflag = kind == 'curl' ? '-o' : '-O';
    return 'skipped=0; out=; url=\n' +
        'for a in "$@"; do\n' +
        '  if [ "$prev" = ' + outflag + ' ]; then out="$a"; fi\n' +
        '  case "$a" in ' + (kind == 'curl' ? '-fsSLk|-k' : '--no-check-certificate') + ') skipped=1 ;; esac\n' +
        '  prev="$a"; url="$a"\n' +
        'done\n' +
        'echo "' + kind + ' skipped=$skipped $url" >> "$LOG"\n' +
        'if [ "$skipped" = 0 ]; then exit ' + failcode + '; fi\n' +
        'case "$url" in\n' +
        '  *meshsettings*) printf "MeshID=0x01\\n" > "$out" ;;\n' +
        '  *) printf \'#!/bin/sh\\necho "$@" > "$MARK"\\n\' > "$out" ;;\n' +
        'esac\n';
}

function runScript(shell, scriptText, dir, binDir, extraEnv) {
    const scriptPath = path.join(dir, 'install.sh');
    fs.writeFileSync(scriptPath, scriptText);
    const [name, ...args] = shell.split(' ');
    const env = Object.assign({}, process.env, { PATH: binDir, TMPDIR: dir, LOG: path.join(dir, 'calls.log'), MARK: path.join(dir, 'installed.txt'), HOME: dir }, extraEnv);
    const r = spawnSync(which(name), args.concat(scriptPath), { env, encoding: 'utf8' });
    const read = f => { try { return fs.readFileSync(path.join(dir, f), 'utf8'); } catch (ex) { return ''; } };
    return { code: r.status, out: (r.stdout || '') + (r.stderr || ''), calls: read('calls.log').split('\n').filter(Boolean), installed: read('installed.txt').trim() };
}

function scratch() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'install-tls-'));
    return { dir, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

const baseOptions = { agenturl: 'https://example.test/meshagents?id=', mshurl: 'https://example.test/meshsettings?id=G', action: 'install', curloptions: '', wgetoptions: '', fetchoptions: '', tlsfallback: '1' };

for (const shell of shells) {
    for (const [kind, failcode] of [['curl', 60], ['wget', 5]].filter(([kind]) => !(shell.startsWith('busybox') && kind == 'wget'))) { // busybox sh runs its own wget applet before any PATH stub
        test(shell + ' / ' + kind + ': a certificate failure is retried once without the check, with a warning, and the install goes through', () => {
            const t = scratch();
            try {
                const bin = makeStubs(t.dir, { [kind]: clientStub(kind, failcode) });
                const r = runScript(shell, render(baseOptions), t.dir, bin);
                assert.strictEqual(r.code, 0, r.out);
                assert.match(r.out, /Warning: this system could not verify the TLS certificate/);
                assert.strictEqual(r.installed, '-fullinstall --copy-msh=1');
                // settings: verified try + unverified retry; agent: straight to unverified (the first failure is remembered)
                assert.deepStrictEqual(r.calls.map(c => c.split(' ')[1]), ['skipped=0', 'skipped=1', 'skipped=1']);
            } finally { t.cleanup(); }
        });

        test(shell + ' / ' + kind + ': strict servers never retry, and say why', () => {
            const t = scratch();
            try {
                const bin = makeStubs(t.dir, { [kind]: clientStub(kind, failcode) });
                const r = runScript(shell, render(Object.assign({}, baseOptions, { tlsfallback: '0' })), t.dir, bin);
                assert.notStrictEqual(r.code, 0);
                assert.match(r.out, /could not verify the TLS certificate/);
                assert.match(r.out, /could not download the device group settings/);
                assert.strictEqual(r.installed, '');
                assert.strictEqual(r.calls.length, 1);
            } finally { t.cleanup(); }
        });

        test(shell + ' / ' + kind + ': other failures (not the certificate) are not retried without checks', () => {
            const t = scratch();
            try {
                const bin = makeStubs(t.dir, { [kind]: clientStub(kind, kind == 'curl' ? 22 : 8) });
                const r = runScript(shell, render(baseOptions), t.dir, bin);
                assert.notStrictEqual(r.code, 0);
                assert.doesNotMatch(r.out, /TLS certificate/);
                assert.strictEqual(r.calls.length, 1);
                assert.ok(r.calls[0].includes('skipped=0'));
            } finally { t.cleanup(); }
        });
    }

    test(shell + ' / wget exiting 1 (BusyBox, fetch): retried too, with a hedged warning', { skip: shell.startsWith('busybox') }, () => {
        const t = scratch();
        try {
            const bin = makeStubs(t.dir, { wget: clientStub('wget', 1) });
            const r = runScript(shell, render(baseOptions), t.dir, bin);
            assert.strictEqual(r.code, 0, r.out);
            assert.match(r.out, /Warning: the download failed, possibly because this system could not verify the TLS certificate/);
            assert.strictEqual(r.installed, '-fullinstall --copy-msh=1');
        } finally { t.cleanup(); }
    });

    test(shell + ': when the certificate is fine nothing changes (no warning, never skipped)', () => {
        const t = scratch();
        try {
            const ok = clientStub('curl', 60).replace('if [ "$skipped" = 0 ]; then exit 60; fi', ':');
            const bin = makeStubs(t.dir, { curl: ok });
            const r = runScript(shell, render(baseOptions), t.dir, bin);
            assert.strictEqual(r.code, 0, r.out);
            assert.doesNotMatch(r.out, /Warning/);
            assert.ok(r.calls.every(c => c.includes('skipped=0')), r.calls.join('\n'));
            assert.strictEqual(r.installed, '-fullinstall --copy-msh=1');
        } finally { t.cleanup(); }
    });
}

// ---- The command the web UI generates, taken from the templates themselves ----

function loadGenerator(file, strict) {
    const src = fs.readFileSync(path.join(root, 'views', file), 'utf8');
    const start = src.indexOf('var agentInstallScriptUrl = null;');
    const fn = src.indexOf('function agentInstallCommand(', start);
    const end = fn < 0 ? -1 : src.indexOf('\n        }\n', fn) + '\n        }\n'.length; // the function's closing brace
    assert.ok(start > 0 && fn > start && end > fn, 'generator not found in ' + file);
    const body = src.substring(start, end).replace("'{{{agentinstallstricttls}}}'", strict ? "'1'" : "''");
    return function (tool, features, url, uninstall) {
        const Q = () => ({ value: tool });
        return new Function('Q', 'features', 'url', 'uninstall', body + '\nagentInstallScriptUrl = url;\nreturn agentInstallCommand(uninstall);')(Q, features, url, uninstall);
    };
}

const SCRIPT_URL = 'https://srv.example/meshagents?script=1&meshid=A%40b%24c';

test('the UI command is identical in the classic and the modern template', () => {
    for (const strict of [false, true]) {
        const a = loadGenerator('default.handlebars', strict), b = loadGenerator('default3.handlebars', strict);
        for (const tool of ['wget', 'curl', 'fetch']) {
            for (const features of [0, 0x80000000, 0x2000, 0x80002000]) {
                for (const un of [false, true]) { assert.strictEqual(a(tool, features, SCRIPT_URL, un), b(tool, features, SCRIPT_URL, un)); }
            }
        }
    }
});

test('the UI command keeps the plain pipe where the retry makes no sense, and retries only otherwise', () => {
    const gen = loadGenerator('default.handlebars', false), strict = loadGenerator('default.handlebars', true);
    assert.strictEqual(strict('curl', 0, SCRIPT_URL), "curl -fsSL '" + SCRIPT_URL + "' | sh");
    assert.strictEqual(strict('wget', 0, SCRIPT_URL, true), "wget -qO- '" + SCRIPT_URL + "&uninstall=1' | sh");
    assert.strictEqual(gen('curl', 0x80000000, SCRIPT_URL), "curl -fsSL -k '" + SCRIPT_URL + "' | sh"); // known self-signed: skip at once, as before
    assert.strictEqual(gen('fetch', 0x80002000, SCRIPT_URL), "fetch -qo- --no-verify-peer -d '" + SCRIPT_URL + "' | sh");
    const retry = gen('curl', 0x2000, SCRIPT_URL);
    assert.strictEqual(retry, "sh -c 'ms=$(curl -fsSL --noproxy '*' \"$0\" || curl -fsSL -k --noproxy '*' \"$0\") && printf \"%s\\n\" \"$ms\" | sh' '" + SCRIPT_URL + "'");
});

// ---- Everything together against a real self-signed HTTPS server ----

function startServer(dir, strictScript) {
    const certDir = path.join(dir, 'cert');
    fs.mkdirSync(certDir);
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(certDir, 'k.pem'), '-out', path.join(certDir, 'c.pem'), '-days', '2', '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore' });
    const hits = [];
    const server = https.createServer({ key: fs.readFileSync(path.join(certDir, 'k.pem')), cert: fs.readFileSync(path.join(certDir, 'c.pem')) }, (req, res) => {
        hits.push(req.url);
        const base = 'https://127.0.0.1:' + server.address().port;
        if (req.url.startsWith('/meshagents?script=1')) {
            res.end(render({ agenturl: base + '/meshagents?id=', mshurl: base + '/meshsettings?id=G', action: 'install', curloptions: '', wgetoptions: '', fetchoptions: '', tlsfallback: strictScript ? '0' : '1' }));
        } else if (req.url.startsWith('/meshsettings')) { res.end('MeshID=0x01\n'); }
        else if (req.url.startsWith('/meshagents?id=')) { res.end('#!/bin/sh\necho "$@" > "$MARK"\n'); }
        else { res.statusCode = 404; res.end(); }
    });
    return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve({ server, hits, base: 'https://127.0.0.1:' + server.address().port })));
}

function runCommand(command, dir, bin) {
    return new Promise(resolve => {
        const env = Object.assign({}, process.env, { PATH: bin + ':' + process.env.PATH, TMPDIR: dir, MARK: path.join(dir, 'installed.txt'), HOME: dir });
        const child = spawn('sh', ['-c', command], { env, stdio: ['ignore', 'pipe', 'pipe'] });
        let out = '';
        child.stdout.on('data', d => out += d); child.stderr.on('data', d => out += d);
        child.on('close', code => resolve({ code, out, installed: fs.existsSync(path.join(dir, 'installed.txt')) ? fs.readFileSync(path.join(dir, 'installed.txt'), 'utf8').trim() : '' }));
    });
}

for (const tool of ['curl', 'wget']) {
    test('end to end with real ' + tool + ' against a self-signed server: the generated command installs', { skip: !have(tool) || !have('openssl') }, async () => {
        const t = scratch();
        const s = await startServer(t.dir, false);
        try {
            const command = loadGenerator('default.handlebars', false)(tool, 0, s.base + '/meshagents?script=1&meshid=G', false);
            const r = await runCommand(command, t.dir, makeStubs(t.dir));
            assert.strictEqual(r.code, 0, r.out);
            assert.strictEqual(r.installed, '-fullinstall --copy-msh=1', r.out);
            assert.match(r.out, /Warning: this system could not verify the TLS certificate/);
        } finally { s.server.close(); t.cleanup(); }
    });

    test('end to end with real ' + tool + ': a strict server installs nothing from a system that distrusts its certificate', { skip: !have(tool) || !have('openssl') }, async () => {
        const t = scratch();
        const s = await startServer(t.dir, true);
        try {
            const command = loadGenerator('default.handlebars', true)(tool, 0, s.base + '/meshagents?script=1&meshid=G', false);
            const r = await runCommand(command, t.dir, makeStubs(t.dir));
            assert.strictEqual(r.installed, '', 'nothing may be installed over an unverified connection');
            assert.strictEqual(s.hits.length, 0, 'the server must not even have been reached');
        } finally { s.server.close(); t.cleanup(); }
    });
}

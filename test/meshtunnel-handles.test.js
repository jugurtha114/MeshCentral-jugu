/*
The "<handle>.mesh" names of devices must be the same everywhere: in the web UI (views/default.handlebars), which shows
the commands, and in the three clients that resolve them (meshtunnel.js, meshtunnel/meshtunnel.py, meshtunnel/meshtunnel.ps1).
Run with: node --test test/meshtunnel-handles.test.js (the Python and PowerShell parts run when python3 / pwsh exist).
*/
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const childProcess = require('child_process');

const root = path.join(__dirname, '..');
const NAMES = [
    'web01', 'Web01', 'WEB01', 'db-01', 'Café Élysée #1', 'ÅÄÖ box', '---a..b---', '', '   ', '日本語', 'emoji 😀 host',
    'a/b\\c', 'İstanbul', 'Straße', 'mañana.local', 'x'.repeat(80), 'node_7', '.hidden.', 'ﬁle ligature', 'Ⅻ roman',
    'tab\tname', 'ｗｉｄｅ', 'Ω-omega', '日本語'
];
// Node ids shaped like MeshCentral's: "node//" + base64 of 48 bytes, with "@" and "$" for "+" and "/".
function nodeId(i) { return 'node//' + crypto.createHash('sha384').update('device ' + i).digest('base64').replace(/\+/g, '@').replace(/\//g, '$'); }
const DEVICES = NAMES.map(function (name, i) { return { id: nodeId(i), name: name }; });

function reference() {
    const mt = require('../meshtunnel.js');
    const list = DEVICES.map(function (d) { return { id: d.id, name: d.name }; });
    mt.assignHandles(list);
    return list.map(function (d) { return d.handle; });
}

function has(cmd) { const r = childProcess.spawnSync(cmd, ['--version'], { encoding: 'utf8' }); return (r.error == null) && (r.status === 0); }

test('the reference names are what users expect', function () {
    const h = reference();
    assert.equal(h[0], 'web01-' + h[0].slice(6), 'three devices named web01 in any case get an id suffix');
    assert.match(h[0], /^web01-[0-9a-f]{6}$/);
    assert.equal(h[3], 'db-01');
    assert.equal(h[4], 'cafe-elysee-1');
    assert.match(h[7], /^device-[0-9a-f]{6}$/, 'nameless devices (empty, blank, no latin letters) are "device", with an id suffix when several');
    assert.equal(new Set(h).size, h.length, 'handles are unique');
    for (const x of h) { assert.match(x, /^[a-z0-9._-]+$/); }
});

test('the web UI names devices like the clients', function () {
    const tpl = fs.readFileSync(path.join(root, 'views', 'default.handlebars'), 'utf8');
    const m = /function meshTunnelSlug\(name\) \{[\s\S]*?\n        \}\n        function meshTunnelHandle\(node\) \{[\s\S]*?\n        \}\n/.exec(tpl);
    assert.ok(m, 'meshTunnelSlug() and meshTunnelHandle() not found in views/default.handlebars');
    const make = new Function('nodes', 'atob', m[0] + '\nreturn meshTunnelHandle;');
    const nodes = DEVICES.map(function (d) { return { _id: d.id, name: d.name }; });
    const handle = make(nodes, globalThis.atob);
    assert.deepEqual(nodes.map(handle), reference());
});

test('meshtunnel.py names devices like meshtunnel.js', { skip: has('python3') ? false : 'python3 is not installed' }, function () {
    const code = [
        'import importlib.util, json, sys',
        'spec = importlib.util.spec_from_file_location("meshtunnel", sys.argv[1])',
        'mt = importlib.util.module_from_spec(spec)',
        'spec.loader.exec_module(mt)',
        'devices = json.loads(sys.stdin.buffer.read().decode("utf-8"))',
        'mt.assign_handles(devices)',
        'print(json.dumps([d["handle"] for d in devices]))'
    ].join('\n');
    const r = childProcess.spawnSync('python3', ['-c', code, path.join(root, 'meshtunnel', 'meshtunnel.py')], { input: JSON.stringify(DEVICES), encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(JSON.parse(r.stdout), reference());
});

test('meshtunnel.ps1 names devices like meshtunnel.js', { skip: has('pwsh') ? false : 'pwsh is not installed' }, function () {
    const ps1 = path.join(root, 'meshtunnel', 'meshtunnel.ps1').replace(/'/g, "''");
    const script = path.join(fs.mkdtempSync(path.join(require('os').tmpdir(), 'mt-handles-')), 'handles.ps1');
    fs.writeFileSync(script, ". '" + ps1 + "'\n" + // Dot-sourced: defines the functions without running a command
        '$in = [Console]::In.ReadToEnd() | ConvertFrom-Json\n' +
        '$list = @($in | ForEach-Object { @{ id = $_.id; name = [string]$_.name } })\n' +
        'Set-Handles $list\n' +
        '[Console]::Out.WriteLine((ConvertTo-Json -Compress -InputObject @($list | ForEach-Object { $_.handle })))\n');
    try {
        const r = childProcess.spawnSync('pwsh', ['-NoProfile', '-NonInteractive', '-File', script], { input: JSON.stringify(DEVICES), encoding: 'utf8' });
        assert.equal(r.status, 0, r.stderr);
        assert.deepEqual(JSON.parse(r.stdout.trim().split('\n').pop()), reference());
    } finally { fs.rmSync(path.dirname(script), { recursive: true, force: true }); }
});

'use strict';
// This fork ships its own CI-built agents in agents/ (microphone, camera, tasks runtime). Upstream's pinned
// "default agent" downloads must never replace them with the stock release assets, and must still fill in the
// platforms the fork does not build. If a future upstream sync changes agentbuilds.js, these tests say whether
// the fork guard survived it.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { CreateAgentDefaults } = require('../agentbuilds');
const agentTypes = require('../agenttypes');

const sha384 = buffer => crypto.createHash('sha384').update(buffer).digest('hex');
const FORK = Buffer.from('FORK build with microphone and camera support');
const STOCK_WIN = Buffer.from('STOCK upstream MeshService64');
const STOCK_OSX = Buffer.from('STOCK upstream macOS universal agent');

function setup(clientBehaviour) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agentbuilds-test-'));
    const bundled = path.join(root, 'agents'), data = path.join(root, 'data');
    fs.mkdirSync(bundled); fs.mkdirSync(data);
    fs.writeFileSync(path.join(bundled, 'MeshService64.exe'), FORK); // shipped by the fork
    const manifest = {
        schemaVersion: 1,
        releases: [{
            repository: 'Ylianst/MeshAgent', tag: 'legacy-1.2.6',
            files: [
                { filename: 'MeshService64.exe', asset: 'MeshService64.exe', size: STOCK_WIN.length, sha384: sha384(STOCK_WIN) },
                { filename: 'meshagent_osx-universal-64', asset: 'meshagent_osx-universal-64', size: STOCK_OSX.length, sha384: sha384(STOCK_OSX) }
            ]
        }]
    };
    const manifestPath = path.join(bundled, 'agent-defaults.json');
    fs.writeFileSync(manifestPath, JSON.stringify(manifest));
    const downloads = [];
    const client = {
        download: async function (url, temp) {
            downloads.push(url);
            if (clientBehaviour === 'offline') { const e = new Error('offline'); e.unreachable = true; throw e; }
            fs.writeFileSync(temp, url.endsWith('MeshService64.exe') ? STOCK_WIN : STOCK_OSX);
        }
    };
    const parent = { datapath: data, config: { settings: { agentdownloads: { fetchreleases: false } } }, meshAgentsArchitectureNumbers: agentTypes() };
    return { root, bundled, data, manifestPath, downloads, client, parent, cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}

test('a fork-built agent in agents/ is served, never replaced by the stock release asset', async () => {
    const t = setup();
    try {
        const defaults = CreateAgentDefaults(t.parent, { bundledDirectory: t.bundled, client: t.client, log() { } });
        await defaults.prepare();
        defaults.start();
        const served = defaults.sourcePath('MeshService64.exe');
        assert.strictEqual(served, path.join(t.bundled, 'MeshService64.exe'));
        assert.deepStrictEqual(fs.readFileSync(served), FORK);
        assert.strictEqual(defaults.info('MeshService64.exe'), null, 'a fork build is not a pinned release');
        assert.ok(!t.downloads.some(url => url.endsWith('MeshService64.exe')), 'the stock asset must not even be downloaded');
    } finally { t.cleanup(); }
});

test('platforms the fork does not build are still filled in from the pinned releases', async () => {
    const t = setup();
    try {
        const defaults = CreateAgentDefaults(t.parent, { bundledDirectory: t.bundled, client: t.client, log() { } });
        await defaults.prepare();
        defaults.start();
        const served = defaults.sourcePath('meshagent_osx-universal-64');
        assert.ok(served && served.startsWith(path.join(t.data, 'agentbuilds')), 'served from the verified download cache');
        assert.deepStrictEqual(fs.readFileSync(served), STOCK_OSX);
        assert.deepStrictEqual(defaults.status().files.map(file => file.filename), ['meshagent_osx-universal-64']);
        assert.strictEqual(t.downloads.length, 1);
    } finally { t.cleanup(); }
});

test('the fork agent keeps being served when GitHub is unreachable, and nothing stock stands in for the rest', async () => {
    const t = setup('offline');
    try {
        const defaults = CreateAgentDefaults(t.parent, { bundledDirectory: t.bundled, client: t.client, log() { } });
        await defaults.prepare();
        defaults.start();
        assert.strictEqual(defaults.sourcePath('MeshService64.exe'), path.join(t.bundled, 'MeshService64.exe'));
        assert.strictEqual(defaults.sourcePath('meshagent_osx-universal-64'), null);
    } finally { t.cleanup(); }
});

test('check-releases mode (an explicit folder) still pins the whole manifest', async () => {
    const t = setup();
    try {
        t.parent.config.settings.agentdownloads.manifest = t.manifestPath;
        const defaults = CreateAgentDefaults(t.parent, { directory: t.bundled, client: t.client, log() { } });
        await defaults.prepare();
        assert.deepStrictEqual(defaults.status().files.map(file => file.filename).sort(), ['MeshService64.exe', 'meshagent_osx-universal-64']);
        assert.strictEqual(t.downloads.length, 2, 'the fork file does not match the pin, so the stock one is fetched for verification');
    } finally { t.cleanup(); }
});

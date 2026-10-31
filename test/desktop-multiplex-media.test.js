/*
Unit tests for the audio / microphone / camera messages in meshdesktopmultiplex.js. Run with:
    node --test test/desktop-multiplex-media.test.js   (or just: node --test)

With "desktopMultiplex": true every desktop-type session (Desktop, Mic and Camera panels) goes through the multiplexor. It used to drop
every media message in both directions, so the Mic and Camera panels stayed on "Checking what camera this device has...". These tests
drive the real processViewerData / processAgentData with fake sockets: no server, agent or network is needed.
*/
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { CreateDesktopMultiplexor } = require('../meshdesktopmultiplex.js');

// Wire ids, as in MeshAgent's meshcore/meshdefines.h.
const AUDIO_DATA = 90, AUDIO_CAPS = 91, AUDIO_START = 92, AUDIO_STOP = 93, AUDIO_QUERY = 94;
const MIC_QUERY = 95, MIC_CAPS = 96, MIC_START = 97, MIC_STOP = 98, MIC_DATA = 99, MIC_CONSENT = 100, MIC_DEVICE_QUERY = 103, MIC_DEVICE_LIST = 104;
const CAM_QUERY = 105, CAM_CAPS = 106, CAM_START = 107, CAM_STOP = 108, CAM_DATA = 109, CAM_CONSENT = 110, CAM_DEVICE_QUERY = 113, CAM_DEVICE_LIST = 114;
const CAM_SNAPSHOT = 115, CAM_SNAPSHOT_DATA = 116;

const quietConsole = () => { const logs = []; const orig = console.log; console.log = (...a) => { logs.push(a.join(' ')); }; return { logs, restore() { console.log = orig; } }; };

// A wire message: 2-byte command, 2-byte total length, then the payload.
function msg(command, payloadLength = 4) {
    const b = Buffer.alloc(4 + payloadLength);
    b.writeUInt16BE(command, 0); b.writeUInt16BE(b.length, 2);
    for (let i = 4; i < b.length; i++) { b[i] = i & 0xff; }
    return b;
}
// What the agent does for frames too big for the 16-bit length: a 27 wrapper (8-byte header) around a 32-bit-length message.
function jumbo(command, payloadLength) {
    const inner = Buffer.alloc(4 + payloadLength);
    inner.writeUInt16BE(command, 0);
    const b = Buffer.alloc(8 + inner.length);
    b.writeUInt16BE(27, 0); b.writeUInt16BE(8, 2); b.writeUInt32BE(inner.length, 4);
    inner.copy(b, 8);
    return b;
}

function makeSession() {
    // The constructor looks the device up once; answering "not found" makes it call back with null and touch nothing else.
    const parent = { trafficStats: { desktopMultiplex: { sessions: 0 } }, parent: { debug() { } }, db: { Get(id, cb) { cb(null, []); } } };
    const session = CreateDesktopMultiplexor(parent, {}, 'node//test', 'session1', () => { });
    const toAgent = [];
    session.agent = { sending: false, sendQueue: [], paused: false, ws: { send(d, cb) { toAgent.push(d); if (cb) { cb(); } }, _socket: { pause() { }, resume() { } } } };
    const addViewer = (name, viewOnly) => {
        const received = [];
        const viewer = {
            name, viewOnly, received, sending: false, sendQueue: [], overflow: false, dataPtr: null, desktopPaused: true, paused: false,
            imageType: 1, imageCompression: 30, imageScaling: 1024, imageFrameRate: 100,
            ws: { send(d, cb) { received.push(d); if (cb) { cb(); } }, _socket: { pause() { }, resume() { } } }
        };
        session.viewers.push(viewer);
        return viewer;
    };
    return { session, toAgent, addViewer };
}
const commandsOf = (list) => list.map((b) => b.readUInt16BE(0));

test('viewer status queries (audio, mic, camera, device lists) reach the device, from any viewer', () => {
    for (const viewOnly of [false, true]) {
        const { session, toAgent, addViewer } = makeSession();
        const v = addViewer('v', viewOnly);
        const q = [AUDIO_QUERY, MIC_QUERY, MIC_DEVICE_QUERY, CAM_QUERY, CAM_DEVICE_QUERY];
        const con = quietConsole();
        try { for (const c of q) { session.processViewerData(v, msg(c)); } } finally { con.restore(); }
        assert.deepEqual(commandsOf(toAgent), q, 'viewOnly=' + viewOnly);
        assert.deepEqual(con.logs, [], 'nothing may be reported as unhandled');
    }
});

test('viewer capture controls reach the device only from viewers that may control it', () => {
    const controls = [AUDIO_START, AUDIO_STOP, MIC_START, MIC_STOP, MIC_CONSENT, CAM_START, CAM_STOP, CAM_CONSENT, CAM_SNAPSHOT];
    const full = makeSession(), ro = makeSession();
    const vf = full.addViewer('full', false), vr = ro.addViewer('readonly', true);
    const con = quietConsole();
    try { for (const c of controls) { full.session.processViewerData(vf, msg(c)); ro.session.processViewerData(vr, msg(c)); } } finally { con.restore(); }
    assert.deepEqual(commandsOf(full.toAgent), controls);
    assert.deepEqual(ro.toAgent, [], 'a view-only viewer must not be able to start the microphone or camera');
});

test('the payload of a forwarded viewer command is passed through untouched (start flags, settings)', () => {
    const { session, toAgent, addViewer } = makeSession();
    const v = addViewer('v', false);
    const start = msg(CAM_START, 12);
    session.processViewerData(v, start);
    assert.equal(toAgent.length, 1);
    assert.ok(toAgent[0].equals(start));
});

test('device status (capabilities, device lists) is delivered to every viewer, view-only ones included', () => {
    const { session, addViewer } = makeSession();
    const a = addViewer('a', false), b = addViewer('b', true);
    const status = [AUDIO_CAPS, MIC_CAPS, MIC_DEVICE_LIST, CAM_CAPS, CAM_DEVICE_LIST];
    const con = quietConsole();
    try { for (const c of status) { session.processAgentData(msg(c, 8)); } } finally { con.restore(); }
    assert.deepEqual(commandsOf(a.received), status);
    assert.deepEqual(commandsOf(b.received), status);
    assert.deepEqual(con.logs, [], 'nothing may be reported as unhandled');
});

test('captured audio / microphone / camera content is delivered to controlling viewers only, never to view-only ones', () => {
    const { session, addViewer } = makeSession();
    const full = addViewer('full', false), ro = addViewer('readonly', true);
    const content = [AUDIO_DATA, MIC_DATA, CAM_DATA, CAM_SNAPSHOT_DATA];
    for (const c of content) { session.processAgentData(msg(c, 64)); }
    assert.deepEqual(commandsOf(full.received), content);
    assert.deepEqual(ro.received, []);
});

test('a jumbo-wrapped camera frame is relayed exactly as the agent sent it, so the browser can unwrap it', () => {
    const { session, addViewer } = makeSession();
    const v = addViewer('v', false);
    const frame = jumbo(CAM_DATA, 70000); // larger than the 16-bit length field can describe
    session.processAgentData(frame);
    assert.equal(v.received.length, 1);
    assert.ok(v.received[0].equals(frame), 'the wrapper must be kept');
    assert.equal(v.received[0].readUInt16BE(0), 27);
});

test('a jumbo-wrapped status message follows the status rule, not the content rule', () => {
    const { session, addViewer } = makeSession();
    const ro = addViewer('readonly', true);
    session.processAgentData(jumbo(CAM_DEVICE_LIST, 70000));
    assert.equal(ro.received.length, 1);
});

test('commands that are neither classic desktop nor media are still reported and dropped', () => {
    const { session, toAgent, addViewer } = makeSession();
    const v = addViewer('v', false);
    const con = quietConsole();
    try {
        session.processViewerData(v, msg(200));
        session.processAgentData(msg(201, 4));
        // Internal agent-side messages must never leak to browsers (consent handshakes between the native code and the agent core).
        for (const c of [101, 102, 111, 112]) { session.processAgentData(msg(c, 4)); }
    } finally { con.restore(); }
    assert.deepEqual(toAgent, []);
    assert.deepEqual(v.received, []);
    assert.equal(con.logs.filter((l) => /Un-handled/.test(l)).length, 6);
});

test('the classic desktop path is unchanged: keys from a view-only viewer are still refused, other viewers still forwarded', () => {
    const { session, toAgent, addViewer } = makeSession();
    const full = addViewer('full', false), ro = addViewer('readonly', true);
    session.processViewerData(ro, msg(1, 4));  // key event, view-only: dropped
    session.processViewerData(full, msg(1, 4)); // key event, full: forwarded
    assert.deepEqual(commandsOf(toAgent), [1]);
});

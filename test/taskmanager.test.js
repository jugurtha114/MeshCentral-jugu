/*
Unit tests for taskmanager.js ("My Tasks"). Run with:   node --test test/taskmanager.test.js   (or just: node --test)

They use a fake in-memory database, fake agents and Node's mock timers, so time-dependent behaviour (leases,
retry backoff, settle delays) is deterministic and no server, agent or network is needed. Requires Node 20+.
*/
'use strict';
const { test, mock, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const { createTaskManager } = require('../taskmanager.js');

const NOW = 1_800_000_000_000;
const SETTLE = 3000, BUSY_RETRY = 30000, QUERY_TIMEOUT = 8000, LEASE_SLACK = 120000;
const flush = async () => { for (let i = 0; i < 40; i++) { await new Promise(r => setImmediate(r)); } };
const tick = async (ms) => { mock.timers.tick(ms); await flush(); };

// A tiny in-memory stand-in for db.js that, like the real thing, stores copies (never shared references).
function fakeDb() {
    const docs = new Map();
    const clone = (o) => JSON.parse(JSON.stringify(o));
    const db = {
        docs,
        Get(id, cb) { setImmediate(() => cb(null, docs.has(id) ? [clone(docs.get(id))] : [])); },
        Set(doc, cb) { docs.set(doc._id, clone(doc)); setImmediate(() => cb && cb()); },
        Remove(id, cb) { docs.delete(id); setImmediate(() => cb && cb()); },
        GetAllType(type, cb) { setImmediate(() => cb(null, [...docs.values()].filter(d => d.type === type).map(clone))); },
        GetAllTypeNoTypeField(type, domain, cb) { setImmediate(() => cb(null, [...docs.values()].filter(d => d.type === type && d.domain === domain).map(d => { const c = clone(d); delete c.type; return c; }))); }
    };
    return db;
}

function fakeAgent(nodeid, meshid, caps) {
    return { dbNodeKey: nodeid, dbMeshKey: meshid, domain: { id: '' }, agentInfo: { capabilities: (caps === undefined) ? 31 : caps }, connectTime: 1, sent: [], send(s) { this.sent.push(JSON.parse(s)); }, last(action) { return [...this.sent].reverse().find(m => m.action === action); }, all(action) { return this.sent.filter(m => m.action === action); } };
}

const ADMIN = { _id: 'user//admin', name: 'admin', siteadmin: 0xFFFFFFFF };
const BOB = { _id: 'user//bob', name: 'bob', siteadmin: 0 };
const DOMAIN = { id: '' };
const MESH = 'mesh//M1', N1 = 'node//N1', N2 = 'node//N2';

function mkEnv() {
    const db = fakeDb(), events = [], agents = {}, multi = { sent: [] };
    const rights = { 'user//admin': { [MESH]: 0xFFFFFFFF }, 'user//bob': { [MESH]: 8 | 131072 } };
    for (const n of [N1, N2]) { db.docs.set(n, { _id: n, type: 'node', domain: '', meshid: MESH, name: n }); }
    const web = {
        wsagents: agents, users: { 'user//admin': ADMIN, 'user//bob': BOB },
        GetMeshRights: (user, meshid) => (rights[user._id] && rights[user._id][meshid]) || 0,
        GetNodeWithRights: (domain, user, nodeid, cb) => { const n = db.docs.get(nodeid); const r = n ? ((rights[user._id] && rights[user._id][n.meshid]) || 0) : 0; setImmediate(() => cb(n ? clone(n) : null, r, r != 0)); },
        CreateNodeDispatchTargets: (mesh, nodeid, added) => (added || []).concat([nodeid, '*'])
    };
    const clone = (o) => JSON.parse(JSON.stringify(o));
    const parent = { db, config: { domains: { '': DOMAIN } }, webserver: web, DispatchEvent: (t, s, e) => events.push(e), debug() { }, multiServer: null, connectivityByNode: {}, GetConnectivityState: (id) => parent.connectivityByNode[id] };
    const tm = createTaskManager(parent);
    return { db, events, agents, rights, web, parent, tm, multi };
}

function fields(o) {
    return Object.assign({ name: 'task', desc: '', targets: { nodes: [], meshes: [MESH] }, winType: 0, winScript: '', nixType: 1, nixScript: 'echo hi', runAs: 0, runAsUser: '', waitForUser: true, trigger: 1, minIntervalSec: 0, connectDelaySec: 0, timeoutSec: 60, maxRetries: 2, retryBackoffSec: 15, successCodes: [0], maxOutputBytes: 65536, startTime: null, expireTime: null }, o);
}
const create = (env, o, user) => new Promise(res => env.tm.createTask(user || ADMIN, DOMAIN, fields(o), (err, task) => res({ err, task })));
const runsOf = (env, taskid, user) => new Promise(res => env.tm.getTaskRuns(user || ADMIN, DOMAIN, taskid, res));
const runOf = async (env, taskid, nodeid) => (await runsOf(env, taskid)).find(r => r.nodeid === (nodeid || N1));
const connect = (env, agent) => { env.agents[agent.dbNodeKey] = agent; };

beforeEach(() => { mock.timers.enable({ apis: ['setTimeout', 'setInterval', 'Date'], now: NOW }); });
afterEach(() => { mock.timers.reset(); });

test('a task created while the device is online is dispatched immediately, with the right settings', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH); connect(env, a);
    const { err, task } = await create(env, { runAs: 3, runAsUser: 'alice', timeoutSec: 90, successCodes: [0, 3010], maxOutputBytes: 4096 });
    assert.equal(err, null);
    await flush();
    const m = a.last('runtask');
    assert.ok(m, 'runtask sent');
    assert.equal(m.nixScript, 'echo hi'); assert.equal(m.runAs, 3); assert.equal(m.runAsUser, 'alice');
    assert.equal(m.timeoutSec, 90); assert.deepEqual(m.successCodes, [0, 3010]); assert.equal(m.maxOutputBytes, 4096);
    assert.equal((await runOf(env, task._id)).state, 'queued');
});

test('a result is stored, the task succeeds, output is kept separately, the agent gets an acknowledgement', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH); connect(env, a);
    const { task } = await create(env, {}); await flush();
    const m = a.last('runtask');
    env.tm.onTaskResult(a, { taskrunid: m.taskrunid, responseid: m.responseid, exitCode: 0, output: 'hello\n', runAsResolved: 'root', durationMs: 12 });
    await flush();
    const r = await runOf(env, task._id);
    assert.equal(r.state, 'success'); assert.equal(r.exitCode, 0); assert.equal(r.runAsResolved, 'root'); assert.equal(r.hasOutput, true);
    assert.equal(r.output, undefined, 'the run list does not carry the output');
    const out = await new Promise(res => env.tm.getRunOutput(ADMIN, DOMAIN, task._id, N1, res));
    assert.equal(out.output, 'hello\n');
    assert.ok(a.last('taskack'), 'acknowledged');
    assert.ok(env.events.some(e => e.action === 'agenttask' && /succeeded/.test(e.msg)), 'event logged');
});

test('the server never trusts the agent\'s own verdict or field types', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH); connect(env, a);
    const { task } = await create(env, { maxRetries: 0 }); await flush();
    const m = a.last('runtask');
    env.tm.onTaskResult(a, { taskrunid: m.taskrunid, responseid: m.responseid, ok: true, exitCode: 5, output: 'x' });
    await flush();
    assert.equal((await runOf(env, task._id)).state, 'failed', 'ok:true with an exit code that is not listed is a failure');
    // hostile types
    const t2 = await create(env, { name: 't2', maxRetries: 0 }); await flush();
    const m2 = a.all('runtask').find(x => x.taskrunid !== m.taskrunid);
    env.tm.onTaskResult(a, { taskrunid: m2.taskrunid, responseid: m2.responseid, ok: true, exitCode: '0', output: { evil: 1 }, error: 'e'.repeat(5000), runAsResolved: 12345 });
    await flush();
    const r2 = await runOf(env, t2.task._id);
    assert.equal(r2.state, 'failed');
    assert.ok(r2.lastError.length <= 256, 'error text is clipped');
    assert.equal(r2.runAsResolved, null);
});

test('an agent can only report on its own runs, and stale or unknown reports are ignored', async () => {
    const env = mkEnv(), a1 = fakeAgent(N1, MESH), a2 = fakeAgent(N2, MESH); connect(env, a1); connect(env, a2);
    const { task } = await create(env, { targets: { nodes: [N1], meshes: [] } }); await flush();
    const m = a1.last('runtask');
    env.tm.onTaskResult(a2, { taskrunid: m.taskrunid, responseid: m.responseid, exitCode: 0, output: 'forged' }); // another device
    await flush();
    assert.equal((await runOf(env, task._id)).state, 'queued', 'a different device cannot complete the run');
    env.tm.onTaskResult(a1, { taskrunid: m.taskrunid, responseid: 'wrong-attempt', exitCode: 0 }); // stale attempt
    await flush();
    assert.equal((await runOf(env, task._id)).state, 'queued', 'a report for another attempt is ignored');
    env.tm.onTaskResult(a1, { taskrunid: 'taskrun//does-not-exist', responseid: 'x', exitCode: 0 });
    await flush(); // must not throw
    assert.ok(a1.last('taskack'), 'a report for an unknown run is still acknowledged so the agent stops resending it');
});

test('failure -> retry with exponential backoff -> gives up after maxRetries', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH); connect(env, a);
    const { task } = await create(env, { maxRetries: 2, retryBackoffSec: 15 }); await flush();
    let m = a.last('runtask');
    env.tm.onTaskResult(a, { taskrunid: m.taskrunid, responseid: m.responseid, exitCode: 1 }); await flush();
    let r = await runOf(env, task._id);
    assert.equal(r.state, 'failed'); assert.equal(r.attempts, 1); assert.equal(r.nextAttemptTime, NOW + 15000);
    assert.equal(a.all('runtask').length, 1);
    await tick(15000 + 300);
    assert.equal(a.all('runtask').length, 2, 'retry 1 after 15s');
    m = a.last('runtask'); assert.equal(m.attempt, 2);
    env.tm.onTaskResult(a, { taskrunid: m.taskrunid, responseid: m.responseid, exitCode: 1 }); await flush();
    r = await runOf(env, task._id); assert.equal(r.attempts, 2);
    assert.equal(r.nextAttemptTime, NOW + 15000 + 300 + 30000, 'the backoff doubles');
    await tick(30000 + 300);
    assert.equal(a.all('runtask').length, 3, 'retry 2 after 30s');
    m = a.last('runtask');
    env.tm.onTaskResult(a, { taskrunid: m.taskrunid, responseid: m.responseid, exitCode: 1 }); await flush();
    r = await runOf(env, task._id);
    assert.equal(r.state, 'failed'); assert.equal(r.attempts, 3); assert.equal(r.nextAttemptTime, null, 'no more retries');
    await tick(24 * 3600 * 1000);
    assert.equal(a.all('runtask').length, 3, 'nothing more is ever dispatched');
});

test('an attempt that never reports is counted as lost when its lease runs out, then retried', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH); connect(env, a);
    const { task } = await create(env, { timeoutSec: 30, maxRetries: 1, retryBackoffSec: 15 }); await flush();
    assert.equal(a.all('runtask').length, 1);
    await tick(30000 + LEASE_SLACK - 1000);
    assert.equal((await runOf(env, task._id)).state, 'queued', 'still within the lease');
    await tick(3000);
    const r = await runOf(env, task._id);
    assert.equal(r.state, 'failed'); assert.equal(r.lastError, 'no-response'); assert.equal(r.attempts, 1);
    await tick(15300);
    assert.equal(a.all('runtask').length, 2, 'retried');
});

test('"wait for a user to log in": parked without using an attempt, and started when a user appears', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH); connect(env, a);
    const { task } = await create(env, { runAs: 2, waitForUser: true, maxRetries: 0 }); await flush();
    let m = a.last('runtask');
    env.tm.onTaskResult(a, { taskrunid: m.taskrunid, responseid: m.responseid, error: 'no-session' }); await flush();
    let r = await runOf(env, task._id);
    assert.equal(r.state, 'waiting-user'); assert.equal(r.attempts, 0, 'no attempt was used'); assert.match(r.lastError, /log in/);
    env.tm.onAgentUsersChanged(a, []); await tick(SETTLE + 100);
    assert.equal(a.all('runtask').length, 1, 'nobody logged in yet: nothing happens');
    env.tm.onAgentUsersChanged(a, ['bob']); await tick(SETTLE + 100);
    assert.equal(a.all('runtask').length, 2, 'a user logged in: dispatched again');
    m = a.last('runtask');
    env.tm.onTaskResult(a, { taskrunid: m.taskrunid, responseid: m.responseid, exitCode: 0, runAsResolved: 'bob' }); await flush();
    assert.equal((await runOf(env, task._id)).state, 'success');
});

test('without "wait for a user", no session is an ordinary failed attempt that follows the retry policy', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH); connect(env, a);
    const { task } = await create(env, { runAs: 2, waitForUser: false, maxRetries: 1 }); await flush();
    const m = a.last('runtask');
    env.tm.onTaskResult(a, { taskrunid: m.taskrunid, responseid: m.responseid, error: 'no-session' }); await flush();
    const r = await runOf(env, task._id);
    assert.equal(r.state, 'failed'); assert.equal(r.attempts, 1); assert.ok(r.nextAttemptTime);
});

test('a busy agent defers the attempt without consuming it', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH); connect(env, a);
    const { task } = await create(env, {}); await flush();
    const m = a.last('runtask');
    env.tm.onTaskResult(a, { taskrunid: m.taskrunid, responseid: m.responseid, error: 'busy', requeue: true }); await flush();
    let r = await runOf(env, task._id);
    assert.equal(r.state, 'pending'); assert.equal(r.attempts, 0);
    await tick(BUSY_RETRY + 100);
    assert.equal(a.all('runtask').length, 2, 'tried again after 30s');
});

test('a script finishing on a busy device immediately re-tries what the device had to turn away', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH); connect(env, a);
    const first = await create(env, { name: 'first' }); await flush();
    const second = await create(env, { name: 'second' }); await flush();
    const m1 = a.all('runtask')[0], m2 = a.all('runtask')[1];
    env.tm.onTaskResult(a, { taskrunid: m2.taskrunid, responseid: m2.responseid, error: 'busy', requeue: true }); await flush(); // the device turned the second one away
    assert.equal((await runOf(env, second.task._id)).state, 'pending');
    env.tm.onTaskResult(a, { taskrunid: m1.taskrunid, responseid: m1.responseid, exitCode: 0 }); await flush(); // the first finishes
    await tick(1200); // well before the 30s fallback
    assert.equal(a.all('runtask').length, 3, 'the deferred one was sent again straight away');
});

test('the task owner\'s rights are checked at every dispatch: revoked rights refuse the run', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH); connect(env, a);
    env.rights['user//bob'][MESH] = 8 | 131072;
    const { task } = await create(env, { maxRetries: 3 }, BOB); await flush();
    assert.equal(a.all('runtask').length, 1, 'allowed while bob holds the right');
    const m = a.last('runtask');
    env.tm.onTaskResult(a, { taskrunid: m.taskrunid, responseid: m.responseid, exitCode: 0 }); await flush();
    env.rights['user//bob'][MESH] = 8; // revoked
    await new Promise(res => env.tm.runNow(BOB, DOMAIN, task._id, undefined, res)); await flush();
    const r = await runOf(env, task._id);
    assert.equal(r.state, 'failed'); assert.match(r.lastError, /^forbidden/);
    assert.equal(a.all('runtask').length, 1, 'nothing was sent to the device');
    await tick(24 * 3600 * 1000);
    assert.equal(a.all('runtask').length, 1, 'and it is not retried on its own');
});

test('agents that cannot run tasks (no JavaScript core, or a recovery agent) are refused cleanly', async () => {
    for (const caps of [0, 15, 31 | 0x40]) {
        const env = mkEnv(), a = fakeAgent(N1, MESH, caps); connect(env, a);
        const { task } = await create(env, {}); await flush();
        const r = await runOf(env, task._id);
        assert.equal(r.state, 'failed', 'caps ' + caps); assert.match(r.lastError, /^unsupported/);
        assert.equal(a.all('runtask').length, 0);
    }
});

test('a paused task is not dispatched on connect, and resuming dispatches it', async () => {
    const env = mkEnv();
    const { task } = await create(env, {}); await flush();
    await new Promise(res => env.tm.setPaused(ADMIN, DOMAIN, task._id, true, res));
    const a = fakeAgent(N1, MESH); connect(env, a);
    env.tm.onAgentConnected(a); await tick(SETTLE + 100);
    assert.equal(a.all('runtask').length, 0);
    await new Promise(res => env.tm.setPaused(ADMIN, DOMAIN, task._id, false, res)); await flush();
    assert.equal(a.all('runtask').length, 1);
});

test('offline device: pending until it connects, then dispatched after the settle delay (plus the task\'s own delay)', async () => {
    const env = mkEnv();
    const { task } = await create(env, { connectDelaySec: 5 }); await flush();
    assert.equal((await runOf(env, task._id)).state, 'pending');
    const a = fakeAgent(N1, MESH); connect(env, a);
    env.tm.onAgentConnected(a); await flush();
    await tick(SETTLE + 4000);
    assert.equal(a.all('runtask').length, 0, 'still waiting out the delay');
    await tick(1500);
    assert.equal(a.all('runtask').length, 1);
});

test('every-connection tasks start a fresh cycle after a final failure, respecting the minimum interval', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH); connect(env, a);
    const { task } = await create(env, { trigger: 2, minIntervalSec: 600, maxRetries: 0 }); await flush();
    let m = a.last('runtask');
    env.tm.onTaskResult(a, { taskrunid: m.taskrunid, responseid: m.responseid, exitCode: 1 }); await flush();
    assert.equal((await runOf(env, task._id)).state, 'failed');
    a.connectTime = 2; env.tm.onAgentConnected(a); await tick(SETTLE + 100);
    assert.equal(a.all('runtask').length, 1, 'reconnected too soon');
    await tick(600 * 1000);
    a.connectTime = 3; env.tm.onAgentConnected(a); await tick(SETTLE + 100);
    assert.equal(a.all('runtask').length, 2, 'after the interval it runs again');
    assert.equal(a.last('runtask').attempt, 1, 'as a fresh cycle');
});

test('once-per-device tasks never run again after success, even on reconnect', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH); connect(env, a);
    const { task } = await create(env, { trigger: 1 }); await flush();
    const m = a.last('runtask');
    env.tm.onTaskResult(a, { taskrunid: m.taskrunid, responseid: m.responseid, exitCode: 0 }); await flush();
    a.connectTime = 2; env.tm.onAgentConnected(a); await tick(SETTLE + 100);
    assert.equal(a.all('runtask').length, 1);
});

test('reconnect with an attempt still recorded as running: the agent is asked, and a lost attempt is recorded as interrupted', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH); connect(env, a);
    const { task } = await create(env, { maxRetries: 1, retryBackoffSec: 15 }); await flush();
    assert.equal(a.all('runtask').length, 1);
    await tick(2000); // time passes: the attempt was dispatched clearly before the new connection asks
    // the agent process dies and comes back as a new connection that knows nothing
    const b = fakeAgent(N1, MESH); b.connectTime = 2; connect(env, b);
    env.tm.onAgentConnected(b); await flush();
    assert.ok(b.last('taskquery'), 'asks what the agent is still running');
    assert.equal(b.all('runtask').length, 0, 'and dispatches nothing before it knows');
    env.tm.onTaskInflight(b, { ids: [], results: [] }); await flush();
    const r = await runOf(env, task._id);
    assert.equal(r.lastError, 'interrupted'); assert.equal(r.state, 'failed'); assert.equal(r.attempts, 1);
    await tick(15400);
    assert.equal(b.all('runtask').length, 1, 'retried after the backoff');
});

test('reconnect: a result the agent kept while disconnected is accepted (not turned into "interrupted")', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH); connect(env, a);
    const { task } = await create(env, {}); await flush();
    const m = a.last('runtask');
    const b = fakeAgent(N1, MESH); b.connectTime = 2; connect(env, b);
    env.tm.onAgentConnected(b); await flush();
    env.tm.onTaskInflight(b, { ids: [m.taskrunid], results: [{ action: 'taskresult', taskrunid: m.taskrunid, responseid: m.responseid, exitCode: 0, output: 'done while offline' }] }); await flush();
    const r = await runOf(env, task._id);
    assert.equal(r.state, 'success'); assert.equal(r.lastError, null);
    assert.ok(b.last('taskack'), 'and acknowledged so the agent can forget it');
});

test('reconnect: an attempt the agent says it is still running is left alone', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH); connect(env, a);
    const { task } = await create(env, {}); await flush();
    const m = a.last('runtask');
    const b = fakeAgent(N1, MESH); b.connectTime = 2; connect(env, b);
    env.tm.onAgentConnected(b); await flush();
    env.tm.onTaskInflight(b, { ids: [m.taskrunid], results: [] }); await tick(SETTLE + 100);
    assert.equal((await runOf(env, task._id)).state, 'queued');
    assert.equal(b.all('runtask').length, 0, 'not dispatched a second time');
});

test('reconnect: if the agent never answers the query, dispatching carries on after a timeout', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH); connect(env, a);
    const { task } = await create(env, { timeoutSec: 5, maxRetries: 1, retryBackoffSec: 15 }); await flush();
    const b = fakeAgent(N1, MESH); b.connectTime = 2; connect(env, b);
    env.tm.onAgentConnected(b); await flush();
    await tick(QUERY_TIMEOUT + 100);
    assert.equal((await runOf(env, task._id)).state, 'queued', 'still leased, so it is left alone');
    await tick(5000 + LEASE_SLACK);
    assert.equal((await runOf(env, task._id)).lastError, 'no-response', 'the lease still catches it');
});

test('cancel tells the agent, and a late result for the cancelled attempt is ignored', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH); connect(env, a);
    const { task } = await create(env, {}); await flush();
    const m = a.last('runtask');
    await new Promise(res => env.tm.cancelRuns(ADMIN, DOMAIN, task._id, [N1], res)); await flush();
    assert.ok(a.last('canceltask'), 'agent told to stop');
    assert.equal((await runOf(env, task._id)).state, 'cancelled');
    env.tm.onTaskResult(a, { taskrunid: m.taskrunid, responseid: m.responseid, exitCode: 0 }); await flush();
    assert.equal((await runOf(env, task._id)).state, 'cancelled');
    a.connectTime = 2; env.tm.onAgentConnected(a); await tick(SETTLE + 100);
    assert.equal(a.all('runtask').length, 1, 'a cancelled run does not come back by itself');
});

test('expiry drops work that has not started, but not an attempt that is running', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH), b = fakeAgent(N2, MESH); connect(env, a);
    const { task } = await create(env, { expireTime: NOW + 60000, maxRetries: 3 }); await flush(); // N1 running, N2 offline (pending)
    assert.equal((await runOf(env, task._id, N1)).state, 'queued');
    assert.equal((await runOf(env, task._id, N2)).state, 'pending');
    await tick(61000);
    assert.equal((await runOf(env, task._id, N1)).state, 'queued', 'the running attempt is left to finish');
    assert.equal((await runOf(env, task._id, N2)).state, 'expired');
    connect(env, b); env.tm.onAgentConnected(b); await tick(SETTLE + 100);
    assert.equal(b.all('runtask').length, 0, 'an expired task is no longer offered');
});

test('start time in the future: nothing before it, dispatched when it arrives', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH); connect(env, a);
    await create(env, { startTime: NOW + 20000 }); await flush();
    assert.equal(a.all('runtask').length, 0);
    await tick(20100);
    assert.equal(a.all('runtask').length, 1);
});

test('a start timer that fires early (relative to the wall clock) waits again instead of dropping the dispatch', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH); connect(env, a);
    await create(env, { startTime: NOW + 20000 }); await flush();
    mock.timers.setTime(NOW - 500); // the wall clock is half a second behind the timers
    await tick(20100);
    assert.equal(a.all('runtask').length, 0, 'not yet: the start time has not really arrived');
    await tick(600);
    assert.equal(a.all('runtask').length, 1, 'dispatched once it has');
});

test('startup: constructing and reconciling before the web server exists must not throw, and timers are re-armed', async () => {
    const env = mkEnv();
    const t = await create(env, { startTime: NOW + 30000 }); await flush();
    const parent2 = { db: env.db, config: env.parent.config, webserver: null, DispatchEvent() { }, debug() { }, multiServer: null };
    const tm2 = createTaskManager(parent2);
    assert.doesNotThrow(() => tm2.reconcileOnStartup());
    await flush();
    const a = fakeAgent(N1, MESH); parent2.webserver = Object.assign({}, env.web, { wsagents: { [N1]: a } }); // the web server appears later, as in the real server
    await tick(30100);
    assert.equal(a.all('runtask').length, 1, 'the restarted manager dispatches when the start time arrives');
});

test('editing: only whitelisted fields are applied; ids, creator, domain and type cannot be smuggled in', async () => {
    const env = mkEnv();
    const { task } = await create(env, {});
    const r = await new Promise(res => env.tm.editTask(ADMIN, DOMAIN, task._id, { name: 'renamed', _id: 'user//admin', type: 'user', createdBy: 'user//evil', owner: 'user//evil', domain: 'x', paused: true }, (e, t) => res({ e, t })));
    assert.equal(r.e, null); assert.equal(r.t.name, 'renamed');
    const stored = env.db.docs.get(task._id);
    assert.equal(stored._id, task._id); assert.equal(stored.type, 'task'); assert.equal(stored.createdBy, 'user//admin');
    assert.equal(stored.owner, 'user//admin'); assert.equal(stored.domain, ''); assert.equal(stored.paused, false);
    assert.ok(env.db.docs.get('user//admin') === undefined, 'no other record was created or overwritten');
});

test('permissions: another user with the run-commands right can see status but not scripts, and cannot change anything', async () => {
    const env = mkEnv();
    const { task } = await create(env, { nixScript: 'echo secret' }); await flush();
    const list = await new Promise(res => env.tm.listTasks(BOB, DOMAIN, res));
    assert.equal(list.length, 1); assert.equal(list[0].scriptsHidden, true); assert.equal(list[0].nixScript, '');
    for (const verb of ['editTask', 'deleteTask', 'setPaused', 'runNow', 'retryRuns', 'cancelRuns']) {
        const args = { editTask: [{ name: 'x' }], deleteTask: [], setPaused: [true], runNow: [undefined], retryRuns: [undefined], cancelRuns: [undefined] }[verb];
        const err = await new Promise(res => env.tm[verb](BOB, DOMAIN, task._id, ...args, res));
        assert.match(String(err), /No such task, or you do not have access/, verb);
    }
    env.rights['user//bob'][MESH] = 8; // no run-commands right at all
    assert.equal((await new Promise(res => env.tm.listTasks(BOB, DOMAIN, res))).length, 0, 'invisible without the right');
    assert.equal((await runsOf(env, task._id, BOB)).length, 0);
    assert.equal(await new Promise(res => env.tm.getRunOutput(BOB, DOMAIN, task._id, N1, res)), null);
});

test('permissions: creating a task needs the run-commands right on every target', async () => {
    const env = mkEnv();
    env.rights['user//bob'][MESH] = 8; // remote control only
    const { err } = await create(env, {}, BOB);
    assert.match(err, /run commands/);
    const r2 = await create(env, { targets: { nodes: [N1], meshes: [] } }, BOB);
    assert.match(r2.err, /run commands/);
});

test('an admin who edits someone else\'s task takes over its execution authority', async () => {
    const env = mkEnv();
    const { task } = await create(env, {}, BOB);
    const r = await new Promise(res => env.tm.editTask(ADMIN, DOMAIN, task._id, { name: 'fixed' }, (e, t) => res({ e, t })));
    assert.equal(r.e, null); assert.equal(r.t.owner, 'user//admin'); assert.equal(r.t.createdBy, 'user//bob');
});

test('editing the targets cancels work for devices no longer targeted; extending the expiry revives expired runs', async () => {
    const env = mkEnv();
    const { task } = await create(env, { targets: { nodes: [N1, N2], meshes: [] }, expireTime: NOW + 5000 }); await flush(); // both offline: pending
    await tick(6000);
    assert.equal((await runOf(env, task._id, N1)).state, 'expired');
    await new Promise(res => env.tm.editTask(ADMIN, DOMAIN, task._id, { expireTime: null, targets: { nodes: [N1], meshes: [] } }, res)); await flush();
    assert.equal((await runOf(env, task._id, N1)).state, 'pending', 'revived');
    assert.equal((await runOf(env, task._id, N2)).state, 'expired', 'no longer a target, left as it was');
});

test('delete removes the task, its runs and their stored output, and tells running agents to stop', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH); connect(env, a);
    const { task } = await create(env, {}); await flush();
    const m = a.last('runtask');
    await new Promise(res => env.tm.deleteTask(ADMIN, DOMAIN, task._id, res)); await flush();
    assert.ok(a.last('canceltask'));
    assert.ok(![...env.db.docs.values()].some(d => d.type === 'task' || d.type === 'taskrun' || d.type === 'taskrunout'), 'nothing left behind');
    env.tm.onTaskResult(a, { taskrunid: m.taskrunid, responseid: m.responseid, exitCode: 0 }); await flush(); // must not throw or resurrect anything
    assert.ok(![...env.db.docs.values()].some(d => d.type === 'taskrun'));
});

test('output longer than the limit keeps both its start and its end', async () => {
    const env = mkEnv(), a = fakeAgent(N1, MESH); connect(env, a);
    const { task } = await create(env, { maxOutputBytes: 1024 }); await flush();
    const m = a.last('runtask');
    env.tm.onTaskResult(a, { taskrunid: m.taskrunid, responseid: m.responseid, exitCode: 0, output: 'START' + 'x'.repeat(50000) + 'THE-END' }); await flush();
    const out = await new Promise(res => env.tm.getRunOutput(ADMIN, DOMAIN, task._id, N1, res));
    assert.ok(out.output.length <= 1024); assert.ok(out.output.startsWith('START')); assert.ok(out.output.endsWith('THE-END')); assert.equal(out.outputTruncated, true);
});

test('unrelated types are never returned as tasks, and records survive the type-stripping query helpers', async () => {
    const env = mkEnv();
    const { task } = await create(env, {}); await flush();
    env.db.docs.set('user//admin', { _id: 'user//admin', type: 'user', domain: '' });
    assert.equal((await new Promise(res => env.tm.listTasks(ADMIN, DOMAIN, res))).length, 1);
    await new Promise(res => env.tm.setPaused(ADMIN, DOMAIN, task._id, true, res));
    assert.equal(env.db.docs.get(task._id).type, 'task');
    await tick(5 * 60 * 1000 + 100); // the housekeeping pass rewrites nothing it should not
    for (const d of env.db.docs.values()) { assert.ok(d.type, 'every record still has its type: ' + d._id); }
});

test('housekeeping removes run records whose device no longer exists', async () => {
    const env = mkEnv();
    const { task } = await create(env, { targets: { nodes: [N1, N2], meshes: [] } }); await flush();
    assert.equal((await runsOf(env, task._id)).length, 2);
    env.db.docs.delete(N2);
    await tick(5 * 60 * 1000 + 100);
    assert.deepEqual((await runsOf(env, task._id)).map(r => r.nodeid), [N1]);
});

test('with peer servers, a device connected to another server is reached through them', async () => {
    const env = mkEnv();
    env.parent.multiServer = { DispatchMessage: (m) => env.multi.sent.push(m) };
    env.parent.connectivityByNode[N1] = { connectivity: 1, meshid: MESH }; // connected to another server of the cluster
    await create(env, {}); await flush();
    const m = env.multi.sent.find(x => x.command && x.command.action === 'runtask');
    assert.ok(m, 'sent through the peers'); assert.equal(m.action, 'agentCommand');
});

test('validation rejects malformed tasks without touching the database', async () => {
    const env = mkEnv();
    const bad = [
        { name: '' }, { targets: { nodes: [], meshes: [] } }, { targets: { nodes: ['node//../../etc'], meshes: [] } }, { targets: { nodes: ['node/other/abc'], meshes: [] } },
        { nixType: 0, winType: 0 }, { winType: 1, winScript: '' }, { timeoutSec: 1 }, { maxRetries: 999 }, { retryBackoffSec: 1 }, { trigger: 9 }, { runAs: 3, runAsUser: '' },
        { successCodes: [] }, { successCodes: ['0'] }, { startTime: NOW + 10, expireTime: NOW + 5 }, { nixScript: 'a\u0000b' }, { maxOutputBytes: 1e12 }
    ];
    for (const o of bad) { const { err } = await create(env, o); assert.ok(err, 'should reject ' + JSON.stringify(o)); }
    assert.equal([...env.db.docs.values()].filter(d => d.type === 'task').length, 0);
});

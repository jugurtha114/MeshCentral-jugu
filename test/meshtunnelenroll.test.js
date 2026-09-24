/*
Unit tests for meshtunnelenroll.js (setup codes for the meshtunnel tool). Run with: node --test test/meshtunnelenroll.test.js
*/
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createEnrollmentStore, isValidCode } = require('../meshtunnelenroll.js');

function clock(start) { const c = { t: start || 1000000 }; c.now = function () { return c.t; }; return c; }

test('codes are 20 letters/digits, unique, and never start with a dash', function () {
    const s = createEnrollmentStore({ maxPerUser: 100000, maxTotal: 100000 });
    const seen = new Set();
    for (let i = 0; i < 2000; i++) {
        const r = s.create('user//u' + i, '', {});
        assert.match(r.code, /^[A-Za-z0-9]{20}$/);
        assert.ok(!seen.has(r.code));
        seen.add(r.code);
    }
});

test('the alphabet is used evenly (no modulo bias)', function () {
    const s = createEnrollmentStore({ maxPerUser: 100000, maxTotal: 100000 });
    const counts = {};
    for (let i = 0; i < 3000; i++) { for (const ch of s.create('user//u' + i, '', {}).code) { counts[ch] = (counts[ch] || 0) + 1; } }
    const values = Object.values(counts);
    assert.equal(values.length, 62);
    const expected = (3000 * 20) / 62;
    for (const v of values) { assert.ok(Math.abs(v - expected) < expected * 0.25, 'character frequency ' + v + ' too far from ' + expected); }
});

test('a code is single use', function () {
    const s = createEnrollmentStore();
    const r = s.create('user//alice', '', { expireDays: 30 });
    const e = s.redeem(r.code);
    assert.equal(e.userid, 'user//alice');
    assert.equal(e.domainid, '');
    assert.equal(e.enrollId, r.enrollId);
    assert.equal(e.expireDays, 30);
    assert.equal(s.redeem(r.code), null);
});

test('a code expires after the TTL', function () {
    const c = clock();
    const s = createEnrollmentStore({ now: c.now, ttlMs: 60000 });
    const r = s.create('user//alice', '', {});
    assert.equal(r.expiresIn, 60);
    assert.equal(r.expire, c.t + 60000);
    c.t += 59999;
    const r2 = s.create('user//bob', '', {});
    c.t += 1;
    assert.equal(s.redeem(r.code), null, 'expired exactly at the TTL');
    assert.ok(s.redeem(r2.code), 'the younger code still works');
});

test('malformed, unknown and look-alike codes are rejected', function () {
    const s = createEnrollmentStore();
    const r = s.create('user//alice', '', {});
    for (const bad of [null, undefined, 42, {}, '', 'x', r.code + 'A', r.code.slice(1), ' ' + r.code, r.code.toLowerCase() == r.code ? r.code.toUpperCase() : r.code.toLowerCase(), '-' + r.code.slice(1), r.code.slice(0, 19) + '/']) {
        assert.equal(s.redeem(bad), null, 'accepted ' + JSON.stringify(bad));
    }
    assert.ok(s.redeem(r.code), 'the real code was not consumed by the bad attempts');
    assert.equal(isValidCode(r.code), true);
    assert.equal(isValidCode('a'.repeat(21)), false);
});

test('at most maxPerUser pending codes per user: the oldest is dropped', function () {
    const c = clock();
    const s = createEnrollmentStore({ now: c.now, maxPerUser: 3 });
    const codes = [];
    for (let i = 0; i < 5; i++) { codes.push(s.create('user//alice', '', {}).code); c.t += 10; }
    const other = s.create('user//bob', '', {}).code;
    assert.equal(s.redeem(codes[0]), null);
    assert.equal(s.redeem(codes[1]), null);
    assert.ok(s.redeem(codes[2])); assert.ok(s.redeem(codes[3])); assert.ok(s.redeem(codes[4]));
    assert.ok(s.redeem(other), 'another user is not affected');
});

test('the same user id in two domains counts separately', function () {
    const s = createEnrollmentStore({ maxPerUser: 1 });
    const a = s.create('user//alice', '', {}).code;
    const b = s.create('user//alice', 'other', {}).code;
    assert.ok(s.redeem(a)); assert.ok(s.redeem(b));
});

test('the global cap refuses new codes instead of growing without bound', function () {
    const c = clock();
    const s = createEnrollmentStore({ now: c.now, maxTotal: 3, ttlMs: 1000 });
    assert.ok(s.create('user//a', '', {})); assert.ok(s.create('user//b', '', {})); assert.ok(s.create('user//c', '', {}));
    assert.equal(s.create('user//d', '', {}), null);
    c.t += 1000; // all expired: purged on the next call
    assert.ok(s.create('user//d', '', {}));
    assert.equal(s.size(), 1);
});

test('expireDays is only accepted as a sane whole number of days', function () {
    const s = createEnrollmentStore({ maxPerUser: 100 });
    const cases = [[7, 7], [90, 90], [0, 0], [-1, 0], [1.5, 0], ['30', 0], [99999, 0], [undefined, 0]];
    for (const [input, expected] of cases) {
        const r = s.create('user//alice', '', { expireDays: input });
        assert.equal(s.redeem(r.code).expireDays, expected, 'expireDays ' + JSON.stringify(input));
    }
});

test('the plain code is not kept in memory', function () {
    const s = createEnrollmentStore();
    const r = s.create('user//alice', '', {});
    const dump = require('util').inspect(s, { showHidden: true, depth: 10 });
    assert.ok(dump.indexOf(r.code) < 0);
});

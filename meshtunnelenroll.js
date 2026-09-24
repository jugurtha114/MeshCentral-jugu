/**
* @description Setup codes for the meshtunnel command line tool: the web UI, where the user is already signed in, creates
*              a single-use code that expires quickly; the setup command pasted on another computer trades it for a
*              normal login token. So setting up a computer needs no password, and works the same for accounts that
*              sign in with SSO, two-factor authentication or hardware keys.
* @author Jugurtha-Green
* @license Apache-2.0
* @version v1.0.0
*/

/*jslint node: true */
/*jshint node: true */
/*jshint strict:false */
/*jshint -W097 */
/*jshint esversion: 6 */
'use strict';

const crypto = require('crypto');

const CODE_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const CODE_LENGTH = 20;   // About 119 bits. Letters and digits only: safe in a URL, a shell and PowerShell, never starts with "-"
const CODE_PATTERN = /^[A-Za-z0-9]{20}$/;

// A code of CODE_LENGTH characters drawn uniformly from CODE_ALPHABET (rejection sampling, no modulo bias).
function randomCode() {
    let code = '';
    while (code.length < CODE_LENGTH) {
        const bytes = crypto.randomBytes(32);
        for (let i = 0; (i < bytes.length) && (code.length < CODE_LENGTH); i++) {
            if (bytes[i] < 248) { code += CODE_ALPHABET[bytes[i] % 62]; } // 248 = 4 * 62
        }
    }
    return code;
}

function hashCode(code) { return crypto.createHash('sha256').update(code, 'utf8').digest('hex'); }

module.exports.isValidCode = function (code) { return (typeof code == 'string') && CODE_PATTERN.test(code); };

// options: now (function returning milliseconds, for tests), ttlMs, maxPerUser, maxTotal
module.exports.createEnrollmentStore = function (options) {
    options = options || {};
    const now = options.now || Date.now;
    const ttlMs = options.ttlMs || (15 * 60 * 1000);
    const maxPerUser = options.maxPerUser || 5;
    const maxTotal = options.maxTotal || 10000;
    const entries = new Map(); // SHA-256 of the code (hex) -> enrollment. The code itself is never kept.

    function purge() {
        const t = now();
        for (const [key, e] of entries) { if (e.expire <= t) { entries.delete(key); } }
    }

    return {
        // Returns { code, enrollId, expire, expiresIn } or null when too many codes are pending on the server.
        // Creating a code while the user already has maxPerUser pending ones drops their oldest.
        create: function (userid, domainid, opts) {
            purge();
            const mine = [];
            for (const [key, e] of entries) { if ((e.userid === userid) && (e.domainid === domainid)) { mine.push([key, e]); } }
            mine.sort(function (a, b) { return a[1].created - b[1].created; });
            while (mine.length >= maxPerUser) { entries.delete(mine.shift()[0]); }
            if (entries.size >= maxTotal) { return null; }
            let code = randomCode(), key = hashCode(code);
            while (entries.has(key)) { code = randomCode(); key = hashCode(code); }
            const t = now();
            const expireDays = ((opts != null) && Number.isInteger(opts.expireDays) && (opts.expireDays > 0) && (opts.expireDays <= 3650)) ? opts.expireDays : 0;
            const e = { userid: userid, domainid: domainid, enrollId: crypto.randomBytes(8).toString('hex'), created: t, expire: t + ttlMs, expireDays: expireDays };
            entries.set(key, e);
            return { code: code, enrollId: e.enrollId, expire: e.expire, expiresIn: Math.round(ttlMs / 1000) };
        },

        // Single use: a valid code is removed as it is redeemed. Returns the enrollment, or null if the code is
        // malformed, unknown, already used or expired.
        redeem: function (code) {
            if (module.exports.isValidCode(code) == false) { return null; }
            purge();
            const key = hashCode(code);
            const e = entries.get(key);
            if (e == null) { return null; }
            entries.delete(key);
            return { userid: e.userid, domainid: e.domainid, enrollId: e.enrollId, created: e.created, expireDays: e.expireDays };
        },

        size: function () { purge(); return entries.size; }
    };
};

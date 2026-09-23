#!/usr/bin/env node
/**
* @description meshtunnel: reach MeshCentral devices from your own terminal. It is an ssh ProxyCommand (so ssh, scp,
*              rsync, sftp and VS Code work as usual), a local port forwarder and a client for the agent's own shell.
*              Everything goes through the server's relay on its HTTPS port, so devices behind NAT or a firewall work
*              without opening anything. Single file, Node.js 16 or newer, no dependencies.
* @author Jugurtha-Green
* @license Apache-2.0
* @version v1.0.0
*/

/*jslint node: true */
/*jshint node: true */
/*jshint strict:false */
/*jshint -W097 */
/*jshint esversion: 11 */
'use strict';

const VERSION = '1.0.0';
if (parseInt(process.versions.node.split('.')[0]) < 16) { process.stderr.write('meshtunnel needs Node.js 16 or newer, this is ' + process.version + '\n'); process.exit(1); }

const fs = require('fs');
const os = require('os');
const net = require('net');
const tls = require('tls');
const path = require('path');
const crypto = require('crypto');
const childProcess = require('child_process');
const EventEmitter = require('events');

const EXIT = { OK: 0, USAGE: 1, AUTH: 2, NOTFOUND: 3, REFUSED: 4, TLS: 5 };
const CTRL = '102938';                  // Control channel id of MeshCentral relay sessions
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MAX_MESSAGE = 64 * 1024 * 1024;   // Largest WebSocket message accepted from the server
const RELAY_TIMEOUT = 20000;            // The server itself gives the agent 15 seconds to join a relay
const TERMINAL_PROTOCOLS = [1, 6, 8, 9]; // Admin shell, admin PowerShell, user shell, user PowerShell

class MtError extends Error {
    constructor(message, code, extra) { super(message); this.code = (code == null) ? EXIT.USAGE : code; if (extra != null) { Object.assign(this, extra); } }
}
function fail(message, code, extra) { throw new MtError(message, code, extra); }
function note(message) { process.stderr.write('meshtunnel: ' + message + '\n'); }

//
// Files
//

function configFile() {
    if (process.env.MESHTUNNEL_CONFIG) { return path.resolve(process.env.MESHTUNNEL_CONFIG); }
    const base = (process.platform == 'win32') ? (process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming')) : (process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'));
    return path.join(base, 'meshtunnel', 'config.json');
}

function cacheDir() {
    const base = (process.platform == 'win32') ? (process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local')) : (process.env.XDG_CACHE_HOME || path.join(os.homedir(), '.cache'));
    return path.join(base, 'meshtunnel');
}

function scriptPath() { try { return fs.realpathSync(process.argv[1]); } catch (ex) { return path.resolve(process.argv[1]); } }
function mkdirp(dir, mode) { fs.mkdirSync(dir, { recursive: true, mode: mode }); }

// Write through a temporary file and a rename, so concurrent readers (parallel ssh sessions) never see a partial file.
function writeFileAtomic(file, data, mode) {
    const tmp = file + '.' + process.pid + '.' + crypto.randomBytes(4).toString('hex') + '.tmp';
    try { fs.writeFileSync(tmp, data, { mode: mode }); fs.chmodSync(tmp, mode); fs.renameSync(tmp, file); }
    catch (ex) { try { fs.unlinkSync(tmp); } catch (ex2) { } throw ex; }
}

function loadConfig(required) {
    const file = configFile();
    let text = null;
    try { text = fs.readFileSync(file, 'utf8'); } catch (ex) { }
    if (text == null) { if (required) { fail('not logged in yet, run: meshtunnel login <server-url>', EXIT.AUTH); } return null; }
    if (process.platform != 'win32') {
        try { if ((fs.statSync(file).mode & 0o077) != 0) { note('warning: ' + file + ' holds a login token but other users can read it, run: chmod 600 \'' + file + '\''); } } catch (ex) { }
    }
    let cfg = null;
    try { cfg = JSON.parse(text); } catch (ex) { fail('cannot read ' + file + ': ' + ex.message); }
    if (required && ((typeof cfg.url != 'string') || (typeof cfg.user != 'string') || (typeof cfg.pass != 'string'))) { fail(file + ' is incomplete, run meshtunnel login again', EXIT.AUTH); }
    return cfg;
}

function saveConfig(cfg) {
    const file = configFile();
    mkdirp(path.dirname(file), 0o700);
    writeFileAtomic(file, JSON.stringify(cfg, null, 2) + '\n', 0o600);
    return file;
}

//
// Server address and certificate pinning
//

// Accepts "host", "host:port" or a pasted https://, wss:// or page URL. Returns the server base URL (ending with the
// domain path and a slash) plus the optional 3FA login key from "?key=".
function parseServerUrl(input) {
    let s = String(input || '').trim();
    if (s == '') { fail('missing server URL, e.g. https://mesh.example.com'); }
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s) == false) { s = 'https://' + s; }
    let u = null;
    try { u = new URL(s); } catch (ex) { fail('invalid server URL: ' + input); }
    if (u.protocol == 'wss:') { u.protocol = 'https:'; }
    if (u.protocol != 'https:') { fail('the server URL must use https://, got ' + u.protocol + '//'); }
    let p = u.pathname.replace(/[^/]*\.(ashx|html?|js)$/i, '');
    if (p.endsWith('/') == false) { p += '/'; }
    const key = u.searchParams.get('key');
    return { url: 'https://' + u.host + p, loginkey: key ? key : undefined };
}

function serverParts(url) {
    const u = new URL(url);
    return { host: u.hostname.replace(/^\[|\]$/g, ''), port: parseInt(u.port || '443'), hostHeader: u.host, basePath: u.pathname };
}

// Pins are curl's --pinnedpubkey format: "sha256//" + base64 of the SHA-256 of the certificate's public key (SPKI).
function normalizePin(pin) {
    const m = /^sha256\/\/([A-Za-z0-9+/]{43}=)$/.exec(String(pin || '').trim());
    if (m == null) { fail('invalid --pin, expected sha256//<44 base64 characters> as shown in the web UI'); }
    return 'sha256//' + m[1];
}
function certPin(cert) { return 'sha256//' + crypto.createHash('sha256').update(new crypto.X509Certificate(cert.raw).publicKey.export({ type: 'spki', format: 'der' })).digest('base64'); }

//
// Network: TLS with optional HTTP CONNECT proxy
//

function proxyFor(host) {
    const p = process.env.HTTPS_PROXY || process.env.https_proxy;
    if (!p) { return null; }
    const h = host.toLowerCase();
    if ((h == 'localhost') || (h == '127.0.0.1') || (h == '::1')) { return null; }
    for (const entry of (process.env.NO_PROXY || process.env.no_proxy || '').split(',')) {
        const n = entry.trim().toLowerCase().replace(/:\d+$/, '');
        if (n == '') { continue; }
        if (n == '*') { return null; }
        const d = n.replace(/^\*?\./, '');
        if ((h == d) || h.endsWith('.' + d)) { return null; }
    }
    let u = null;
    try { u = new URL(/^[a-z]+:\/\//i.test(p) ? p : ('http://' + p)); } catch (ex) { note('ignoring HTTPS_PROXY, it is not a valid URL'); return null; }
    if (u.protocol != 'http:') { note('ignoring HTTPS_PROXY ' + u.protocol + '//' + u.host + ', only http:// proxies are supported'); return null; }
    return u;
}

function connectViaProxy(proxy, host, port) {
    return new Promise(function (resolve, reject) {
        const target = (net.isIPv6(host) ? ('[' + host + ']') : host) + ':' + port;
        const sock = net.connect(parseInt(proxy.port || '80'), proxy.hostname.replace(/^\[|\]$/g, ''));
        let buf = Buffer.alloc(0);
        const onError = function (e) { sock.destroy(); reject(new MtError('cannot reach proxy ' + proxy.host + ': ' + e.message, EXIT.NOTFOUND)); };
        sock.once('error', onError);
        sock.setTimeout(20000, function () { sock.destroy(new Error('timed out')); });
        sock.once('connect', function () {
            let req = 'CONNECT ' + target + ' HTTP/1.1\r\nHost: ' + target + '\r\n';
            if (proxy.username) { req += 'Proxy-Authorization: Basic ' + Buffer.from(decodeURIComponent(proxy.username) + ':' + decodeURIComponent(proxy.password)).toString('base64') + '\r\n'; }
            sock.write(req + '\r\n');
        });
        const onData = function (chunk) {
            buf = Buffer.concat([buf, chunk]);
            const end = buf.indexOf('\r\n\r\n');
            if (end < 0) { if (buf.length > 16384) { sock.destroy(); reject(new MtError('the proxy sent an oversized reply', EXIT.NOTFOUND)); } return; }
            sock.removeListener('data', onData); sock.removeListener('error', onError); sock.setTimeout(0); sock.pause();
            const status = buf.slice(0, buf.indexOf('\r\n')).toString();
            if (/^HTTP\/1\.[01] 200/.test(status) == false) { sock.destroy(); reject(new MtError('the proxy refused the connection: ' + status, EXIT.NOTFOUND)); return; }
            if (buf.length > (end + 4)) { sock.unshift(buf.slice(end + 4)); }
            resolve(sock);
        };
        sock.on('data', onData);
    });
}

// Open a TLS connection and decide trust BEFORE anything is written, so credentials never reach an unverified peer.
// Trusted means: a valid CA chain for this host name, or the public key matches the pinned one.
async function connectTls(url, pin, allowUntrusted) {
    const sp = serverParts(url);
    const proxy = proxyFor(sp.host);
    const raw = (proxy != null) ? await connectViaProxy(proxy, sp.host, sp.port) : null;
    return new Promise(function (resolve, reject) {
        const opts = { host: sp.host, port: sp.port, rejectUnauthorized: false, ALPNProtocols: ['http/1.1'] };
        if (net.isIP(sp.host) == 0) { opts.servername = sp.host; }
        if (raw != null) { opts.socket = raw; }
        const sock = tls.connect(opts);
        const onError = function (e) { sock.destroy(); reject(new MtError('cannot connect to ' + sp.hostHeader + ': ' + e.message, EXIT.NOTFOUND)); };
        sock.once('error', onError);
        sock.setTimeout(20000, function () { sock.destroy(new Error('timed out')); });
        sock.once('secureConnect', function () {
            sock.removeListener('error', onError);
            sock.setTimeout(0);
            let fingerprint = null;
            try { fingerprint = certPin(sock.getPeerCertificate()); } catch (ex) { }
            const info = { sock: sock, fingerprint: fingerprint, authorized: (sock.authorized === true), reason: (sock.authorizationError ? String(sock.authorizationError) : null) };
            if (info.authorized || ((pin != null) && (fingerprint === pin)) || allowUntrusted) { sock.setNoDelay(true); resolve(info); return; }
            sock.destroy();
            if (pin != null) {
                reject(new MtError('the server certificate does NOT match the pinned key!\n  pinned: ' + pin + '\n  server: ' + fingerprint + '\nIt was replaced, or someone is intercepting the connection. If the change is expected, run: meshtunnel login ' + url, EXIT.TLS));
            } else {
                reject(new MtError('the server certificate is not trusted (' + info.reason + ') and no key is pinned, run: meshtunnel login ' + url, EXIT.TLS));
            }
        });
    });
}

// Read an HTTP response head. The socket is left paused with any extra bytes returned in "rest".
function readHttpHead(sock, timeoutMs) {
    return new Promise(function (resolve, reject) {
        let buf = Buffer.alloc(0);
        const timer = setTimeout(function () { cleanup(); sock.destroy(); reject(new MtError('the server did not answer', EXIT.NOTFOUND)); }, timeoutMs);
        function cleanup() { clearTimeout(timer); sock.removeListener('data', onData); sock.removeListener('end', onEnd); sock.removeListener('error', onError); sock.pause(); }
        function onEnd() { cleanup(); reject(new MtError('the server closed the connection', EXIT.NOTFOUND)); }
        function onError(e) { cleanup(); reject(new MtError('connection error: ' + e.message, EXIT.NOTFOUND)); }
        function onData(chunk) {
            buf = Buffer.concat([buf, chunk]);
            const end = buf.indexOf('\r\n\r\n');
            if (end < 0) { if (buf.length > 65536) { cleanup(); sock.destroy(); reject(new MtError('the server sent an oversized HTTP header', EXIT.NOTFOUND)); } return; }
            cleanup();
            const lines = buf.slice(0, end).toString('latin1').split('\r\n');
            const statusLine = lines.shift();
            const headers = {};
            for (const l of lines) { const i = l.indexOf(':'); if (i > 0) { headers[l.slice(0, i).trim().toLowerCase()] = l.slice(i + 1).trim(); } }
            resolve({ statusLine: statusLine, status: parseInt(statusLine.split(' ')[1]), headers: headers, rest: buf.slice(end + 4) });
        }
        sock.on('data', onData); sock.once('end', onEnd); sock.once('error', onError);
        sock.resume();
    });
}

async function httpsGet(cfg, pathAndQuery) {
    const sp = serverParts(cfg.url);
    const sock = (await connectTls(cfg.url, cfg.pin)).sock;
    sock.write('GET ' + pathAndQuery + ' HTTP/1.1\r\nHost: ' + sp.hostHeader + '\r\nUser-Agent: meshtunnel/' + VERSION + '\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n');
    const head = await readHttpHead(sock, 20000);
    if (head.status != 200) { sock.destroy(); fail('the server answered ' + head.statusLine + ' for ' + pathAndQuery, EXIT.NOTFOUND); }
    const chunks = [head.rest];
    await new Promise(function (resolve, reject) { sock.on('data', function (d) { chunks.push(d); }); sock.once('end', resolve); sock.once('close', resolve); sock.once('error', reject); sock.resume(); });
    let body = Buffer.concat(chunks);
    if (/chunked/i.test(head.headers['transfer-encoding'] || '')) {
        const parts = []; let i = 0;
        while (i < body.length) {
            const eol = body.indexOf('\r\n', i); if (eol < 0) { break; }
            const size = parseInt(body.slice(i, eol).toString(), 16); if (!(size > 0)) { break; }
            parts.push(body.slice(eol + 2, eol + 2 + size)); i = eol + 2 + size + 2;
        }
        body = Buffer.concat(parts);
    } else if (head.headers['content-length'] != null) {
        const len = parseInt(head.headers['content-length']);
        if (body.length < len) { fail('the download was cut short', EXIT.NOTFOUND); }
        body = body.slice(0, len);
    }
    return body;
}

//
// WebSocket client (RFC 6455). Only what MeshCentral needs, with explicit flow control:
// pause()/resume() stop and restart message delivery, sends return false when the socket buffer is full ('drain' follows).
// Events: 'text'(string), 'binary'(Buffer), 'drain', 'close'(code, reason, error). There is never an 'error' event.
//

class WsConn extends EventEmitter {
    constructor(sock, head) {
        super();
        this.sock = sock; this.chunks = []; this.buffered = 0;
        this.paused = true; this.closed = false; this.closeSent = false; this.closeTimer = null;
        this.fragments = null; this.fragOpcode = 0; this.fragSize = 0;
        this.lastSeen = Date.now(); this.keepalive = null;
        if ((head != null) && (head.length > 0)) { this.chunks.push(head); this.buffered = head.length; }
        const self = this;
        sock.on('data', function (d) { self.lastSeen = Date.now(); self.chunks.push(d); self.buffered += d.length; self._parse(); });
        sock.on('drain', function () { self.emit('drain'); });
        sock.on('error', function (e) { self._finish(1006, e.message, new MtError('connection lost: ' + e.message, EXIT.NOTFOUND)); });
        sock.on('end', function () { self._finish(1006, 'end', null); });
        sock.on('close', function () { self._finish(1006, 'closed', null); });
        sock.pause();
    }

    pause() { this.paused = true; if (this.closed == false) { this.sock.pause(); } }
    resume() { if (this.closed) { return; } this.paused = false; this.sock.resume(); this._parse(); }

    sendBinary(buf) { return this._send(0x2, buf); }
    sendText(str) { return this._send(0x1, Buffer.from(str, 'utf8')); }

    close(code) {
        if (this.closed) { return; }
        if (this.closeSent == false) { this.closeSent = true; const p = Buffer.alloc(2); p.writeUInt16BE(code || 1000, 0); this._send(0x8, p); }
        // Wait for the server's answer, but not forever: MeshCentral holds a relay socket paused until both sides join.
        if (this.closeTimer == null) { const self = this; this.closeTimer = setTimeout(function () { self._finish(1000, 'closed', null); }, 1500); this.closeTimer.unref(); }
    }

    destroy() { this._finish(1006, 'destroyed', null); }

    startKeepalive() {
        const self = this;
        if (this.keepalive != null) { return; }
        this.keepalive = setInterval(function () {
            if (self.paused) { self.lastSeen = Date.now(); return; } // Not reading on purpose (flow control), nothing to judge
            if ((Date.now() - self.lastSeen) > 90000) { self._finish(1006, 'timeout', new MtError('the server stopped responding', EXIT.NOTFOUND)); return; }
            self._send(0x9, Buffer.alloc(0));
        }, 30000);
        this.keepalive.unref();
    }

    _finish(code, reason, error) {
        if (this.closed) { return; }
        this.closed = true;
        if (this.keepalive != null) { clearInterval(this.keepalive); this.keepalive = null; }
        if (this.closeTimer != null) { clearTimeout(this.closeTimer); this.closeTimer = null; }
        const sock = this.sock;
        sock.end();
        setTimeout(function () { sock.destroy(); }, 1000).unref();
        this.emit('close', code, reason, error);
    }

    _send(opcode, payload) {
        if (this.closed || this.sock.destroyed) { return false; }
        const len = payload.length;
        const hl = (len < 126) ? 2 : ((len < 65536) ? 4 : 10);
        const frame = Buffer.allocUnsafe(hl + 4 + len);
        frame[0] = 0x80 | opcode;
        if (len < 126) { frame[1] = 0x80 | len; }
        else if (len < 65536) { frame[1] = 0x80 | 126; frame.writeUInt16BE(len, 2); }
        else { frame[1] = 0x80 | 127; frame.writeUInt32BE(0, 2); frame.writeUInt32BE(len, 6); }
        crypto.randomFillSync(frame, hl, 4);
        const m0 = frame[hl], m1 = frame[hl + 1], m2 = frame[hl + 2], m3 = frame[hl + 3], o = hl + 4;
        let i = 0;
        for (; (i + 3) < len; i += 4) { frame[o + i] = payload[i] ^ m0; frame[o + i + 1] = payload[i + 1] ^ m1; frame[o + i + 2] = payload[i + 2] ^ m2; frame[o + i + 3] = payload[i + 3] ^ m3; }
        for (; i < len; i++) { frame[o + i] = payload[i] ^ frame[hl + (i & 3)]; }
        return this.sock.write(frame);
    }

    _peek(n) {
        const first = this.chunks[0];
        if (first.length >= n) { return first.subarray(0, n); }
        const out = Buffer.allocUnsafe(n); let o = 0;
        for (const c of this.chunks) { const k = Math.min(c.length, n - o); c.copy(out, o, 0, k); o += k; if (o == n) { break; } }
        return out;
    }

    _take(n) {
        if (n == 0) { return Buffer.alloc(0); }
        const first = this.chunks[0];
        if (first.length >= n) {
            this.buffered -= n;
            if (first.length == n) { this.chunks.shift(); } else { this.chunks[0] = first.subarray(n); }
            return first.subarray(0, n);
        }
        const out = Buffer.allocUnsafe(n); let o = 0;
        while (o < n) {
            const c = this.chunks[0], k = Math.min(c.length, n - o);
            c.copy(out, o, 0, k); o += k;
            if (k == c.length) { this.chunks.shift(); } else { this.chunks[0] = c.subarray(k); }
        }
        this.buffered -= n;
        return out;
    }

    _protocolError(message) { this._finish(1002, message, new MtError('WebSocket protocol error: ' + message, EXIT.NOTFOUND)); }

    _parse() {
        while ((this.paused == false) && (this.closed == false) && (this.buffered >= 2)) {
            const h = this._peek(2), b0 = h[0], b1 = h[1];
            const opcode = b0 & 0x0f, fin = ((b0 & 0x80) != 0), masked = ((b1 & 0x80) != 0);
            let len = b1 & 0x7f, hl = 2;
            if ((b0 & 0x70) != 0) { this._protocolError('unexpected extension bits'); return; }
            if (len == 126) { if (this.buffered < 4) { return; } len = this._peek(4).readUInt16BE(2); hl = 4; }
            else if (len == 127) {
                if (this.buffered < 10) { return; }
                const b = this._peek(10);
                if (b.readUInt32BE(2) != 0) { this._protocolError('frame too large'); return; }
                len = b.readUInt32BE(6); hl = 10;
            }
            if (len > MAX_MESSAGE) { this._protocolError('frame too large'); return; }
            const mhl = hl + (masked ? 4 : 0);
            if (this.buffered < (mhl + len)) { return; }
            const header = this._take(mhl);
            let payload = this._take(len);
            if (masked) { payload = Buffer.from(payload); for (let i = 0; i < payload.length; i++) { payload[i] ^= header[hl + (i & 3)]; } }
            this._frame(opcode, fin, payload);
        }
    }

    _frame(opcode, fin, payload) {
        if (opcode >= 8) {
            if ((fin == false) || (payload.length > 125)) { this._protocolError('bad control frame'); return; }
            if (opcode == 0x8) {
                const code = (payload.length >= 2) ? payload.readUInt16BE(0) : 1005;
                const reason = (payload.length > 2) ? payload.slice(2).toString('utf8') : '';
                if (this.closeSent == false) { this.closeSent = true; this._send(0x8, (payload.length >= 2) ? payload.slice(0, 2) : Buffer.alloc(0)); }
                this._finish(code, reason, null);
            } else if (opcode == 0x9) {
                this._send(0xA, payload);
            }
            return;
        }
        if (opcode == 0) {
            if (this.fragments == null) { this._protocolError('unexpected continuation frame'); return; }
            this.fragments.push(payload); this.fragSize += payload.length;
            if (this.fragSize > MAX_MESSAGE) { this._protocolError('message too large'); return; }
            if (fin) { const msg = Buffer.concat(this.fragments), op = this.fragOpcode; this.fragments = null; this._deliver(op, msg); }
            return;
        }
        if ((opcode != 1) && (opcode != 2)) { this._protocolError('unknown opcode ' + opcode); return; }
        if (this.fragments != null) { this._protocolError('interleaved messages'); return; }
        if (fin) { this._deliver(opcode, payload); } else { this.fragments = [payload]; this.fragOpcode = opcode; this.fragSize = payload.length; }
    }

    _deliver(opcode, payload) { if (opcode == 1) { this.emit('text', payload.toString('utf8')); } else { this.emit('binary', payload); } }
}

function meshAuth(user, pass, token) {
    const b64 = function (s) { return Buffer.from(String(s), 'utf8').toString('base64'); };
    return b64(user) + ',' + b64(pass) + ((token != null) ? (',' + b64(token)) : '');
}

async function wsConnect(cfg, pathAndQuery, headers) {
    const sp = serverParts(cfg.url);
    const sock = (await connectTls(cfg.url, cfg.pin)).sock;
    const key = crypto.randomBytes(16).toString('base64');
    let req = 'GET ' + pathAndQuery + ' HTTP/1.1\r\nHost: ' + sp.hostHeader + '\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ' + key + '\r\nSec-WebSocket-Version: 13\r\nUser-Agent: meshtunnel/' + VERSION + '\r\n';
    for (const name in headers) { req += name + ': ' + headers[name] + '\r\n'; }
    sock.write(req + '\r\n');
    const res = await readHttpHead(sock, 20000);
    if (res.status != 101) {
        sock.destroy();
        if (res.status == 404) { fail('the server answered "404 Not Found" for ' + pathAndQuery.split('?')[0] + ', check the server URL (and the domain path, if any)', EXIT.NOTFOUND); }
        fail('the server refused the WebSocket: ' + res.statusLine, ((res.status == 401) || (res.status == 403)) ? EXIT.AUTH : EXIT.NOTFOUND);
    }
    if (res.headers['sec-websocket-accept'] != crypto.createHash('sha1').update(key + WS_GUID).digest('base64')) { sock.destroy(); fail('the server sent an invalid WebSocket handshake', EXIT.NOTFOUND); }
    return new WsConn(sock, res.rest);
}

//
// MeshCentral control channel (control.ashx)
//

function authError(m) {
    if (m.cause == 'banned') { return new MtError('the server is refusing logins from this IP address for a while, after too many failures', EXIT.AUTH); }
    if (m.cause == 'notools') { return new MtError('this account is not allowed to use MeshCentral tools, ask the administrator', EXIT.AUTH); }
    if (m.cause == 'emailvalidation') { return new MtError('this account must verify its email address first, log in to the web UI once', EXIT.AUTH); }
    if (m.cause == 'expired') { return new MtError('the session expired, run: meshtunnel login', EXIT.AUTH); }
    if (m.msg == 'tokenrequired') { return new MtError('a two-factor code is required', EXIT.AUTH, { twoFactor: true, email2fa: (m.email2fa === true), sms2fa: (m.sms2fa === true), msg2fa: (m.msg2fa === true) }); }
    return new MtError('authentication failed (' + (m.msg || m.cause) + '): wrong credentials, or the login token was revoked or has expired; run: meshtunnel login', EXIT.AUTH);
}

class Control {
    constructor(ws) {
        const self = this;
        this.ws = ws; this.waiters = []; this.listeners = []; this.closed = false; this.closeInfo = null; this.serverinfo = null; this.userinfo = null;
        ws.on('text', function (t) { let m = null; try { m = JSON.parse(t); } catch (ex) { return; } self._message(m); });
        ws.on('close', function (code, reason, err) {
            self.closed = true;
            const e = self._closedError(err);
            for (const w of self.waiters.splice(0)) { w.reject(e); }
        });
    }
    _message(m) {
        if (m.action == 'close') { this.closeInfo = m; }
        else if (m.action == 'serverinfo') { this.serverinfo = m.serverinfo; }
        else if (m.action == 'userinfo') { this.userinfo = m.userinfo; }
        for (const w of this.waiters.slice()) { if (w.match(m)) { this.waiters.splice(this.waiters.indexOf(w), 1); w.resolve(m); } }
        for (const f of this.listeners) { f(m); }
    }
    _closedError(err) { if (this.closeInfo != null) { return authError(this.closeInfo); } return err || new MtError('the server closed the connection', EXIT.NOTFOUND); }
    wait(match, timeoutMs) {
        if (this.closed) { return Promise.reject(this._closedError()); }
        const self = this;
        return new Promise(function (resolve, reject) {
            const w = { match: match };
            w.timer = setTimeout(function () { const i = self.waiters.indexOf(w); if (i >= 0) { self.waiters.splice(i, 1); } reject(new MtError('the server did not answer in time', EXIT.NOTFOUND)); }, timeoutMs || 20000);
            w.resolve = function (m) { clearTimeout(w.timer); resolve(m); };
            w.reject = function (e) { clearTimeout(w.timer); reject(e); };
            self.waiters.push(w);
        });
    }
    onMessage(f) { this.listeners.push(f); }
    send(obj) { this.ws.sendText(JSON.stringify(obj)); }
    request(obj, match, timeoutMs) { const p = this.wait(match, timeoutMs); this.send(obj); return p; }
    close() { this.ws.close(1000); }
}

async function controlConnect(cfg, creds) {
    const q = cfg.loginkey ? ('?key=' + encodeURIComponent(cfg.loginkey)) : '';
    const ws = await wsConnect(cfg, serverParts(cfg.url).basePath + 'control.ashx' + q, { 'x-meshauth': meshAuth(creds.user, creds.pass, creds.token) });
    const ctl = new Control(ws);
    const ready = ctl.wait(function (m) { return m.action == 'userinfo'; }, 20000); // Sent right after "serverinfo" once logged in
    ws.resume();
    try { await ready; } catch (e) { ws.destroy(); throw e; }
    return ctl;
}

//
// Devices
//

function isWindowsAgent(agent) { return (agent != null) && ([1, 2, 3, 4, 21, 22, 34, 42, 43].indexOf(agent.id) >= 0); }

// Same rule as the Terminal tab dialog in the web UI (default.handlebars), keep the two in sync.
function slugify(name) {
    const s = String(name || '').normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^[-.]+|[-.]+$/g, '');
    return (s == '') ? 'device' : s;
}
function idHex(id) { return Buffer.from(String(id).split('/').pop().replace(/@/g, '+').replace(/\$/g, '/'), 'base64').toString('hex'); }
function assignHandles(list) {
    const count = {};
    for (const d of list) { d.slug = slugify(d.name); count[d.slug] = (count[d.slug] || 0) + 1; }
    for (const d of list) { d.handle = (count[d.slug] > 1) ? (d.slug + '-' + idHex(d.id).slice(0, 6)) : d.slug; }
}

function deviceCacheFile() { return path.join(cacheDir(), 'devices.json'); }
function cacheKey(cfg) { return crypto.createHash('sha256').update(cfg.url + '\n' + cfg.user).digest('hex'); }
function loadDeviceCache(cfg) {
    try { const c = JSON.parse(fs.readFileSync(deviceCacheFile(), 'utf8')); if ((c.key == cacheKey(cfg)) && Array.isArray(c.devices)) { return c.devices; } } catch (ex) { }
    return null;
}
function saveDeviceCache(cfg, list) {
    try { mkdirp(cacheDir(), 0o700); writeFileAtomic(deviceCacheFile(), JSON.stringify({ key: cacheKey(cfg), time: Date.now(), devices: list }), 0o600); } catch (ex) { }
}

async function fetchDevices(cfg) {
    const ctl = await controlConnect(cfg, { user: cfg.user, pass: cfg.pass });
    try {
        const meshes = await ctl.request({ action: 'meshes' }, function (m) { return m.action == 'meshes'; }, 30000);
        const nodes = await ctl.request({ action: 'nodes', responseid: 'meshtunnel' }, function (m) { return (m.action == 'nodes') && (m.responseid == 'meshtunnel'); }, 30000);
        if ((nodes.result != null) && (nodes.result != 'ok')) { fail('the server refused the device list: ' + nodes.result, EXIT.AUTH); }
        const groups = {};
        for (const m of (meshes.meshes || [])) { groups[m._id] = m.name; }
        const list = [];
        for (const meshid in (nodes.nodes || {})) {
            for (const n of nodes.nodes[meshid]) {
                if ((n == null) || (typeof n._id != 'string')) { continue; }
                list.push({ id: n._id, name: String((n.name != null) ? n.name : n._id), group: groups[meshid] || '', os: n.osdesc || '', conn: n.conn || 0, windows: isWindowsAgent(n.agent) });
            }
        }
        assignHandles(list);
        list.sort(function (a, b) { return (a.group.localeCompare(b.group) || a.name.localeCompare(b.name)); });
        saveDeviceCache(cfg, list);
        return list;
    } finally { ctl.close(); }
}

function matchDevice(list, query) {
    const q = String(query).trim().replace(/\.mesh$/i, '').toLowerCase();
    const ambiguous = function (m) { fail('"' + query + '" matches ' + m.length + ' devices, use one of: ' + m.map(function (d) { return d.handle + ((d.group != '') ? (' (' + d.group + ')') : ''); }).join(', '), EXIT.NOTFOUND); };
    let m = list.filter(function (d) { return d.handle == q; });
    if (m.length == 1) { return m[0]; }
    m = list.filter(function (d) { return d.name.toLowerCase() == q; });
    if (m.length == 1) { return m[0]; }
    if (m.length > 1) { ambiguous(m); }
    m = list.filter(function (d) { return d.slug == q; });
    if (m.length == 1) { return m[0]; }
    if (m.length > 1) { ambiguous(m); }
    return null;
}

async function getDevice(cfg, query) {
    if (!query) { fail('missing device: a handle from "meshtunnel ls", a device name or a node id'); }
    if (/^node\//.test(query)) {
        const d = (loadDeviceCache(cfg) || []).find(function (x) { return x.id == query; });
        return d || { id: query, name: query, handle: query, group: '', conn: 1, windows: false };
    }
    const cached = loadDeviceCache(cfg);
    let found = (cached != null) ? matchDevice(cached, query) : null;
    if (found == null) { found = matchDevice(await fetchDevices(cfg), query); }
    if (found == null) { fail('no device matches "' + query + '", see: meshtunnel ls', EXIT.NOTFOUND); }
    return found;
}

//
// Relay sessions
//

// Resolves once the server says both sides are joined ("c", or "cr" when the session is recorded). The connection is left
// paused so no data frame can slip past before the caller attaches its handlers.
function waitRelayStart(ws, timeoutMs, onAbort) {
    return new Promise(function (resolve, reject) {
        let settled = false, closeInfo = null;
        const timer = setTimeout(function () { settle(new MtError('timed out waiting for the device', EXIT.NOTFOUND, { relayEarly: true, timedOut: true })); }, timeoutMs);
        function settle(err) {
            if (settled) { return; }
            settled = true; clearTimeout(timer);
            ws.removeListener('text', onText); ws.removeListener('close', onClose);
            if (err != null) { ws.destroy(); reject(err); } else { resolve(); }
        }
        function onText(t) {
            if ((t == 'c') || (t == 'cr')) { ws.pause(); settle(null); return; }
            if (t.charAt(0) == '{') { try { const m = JSON.parse(t); if (m.action == 'close') { closeInfo = m; } } catch (ex) { } }
        }
        function onClose(code, reason, err) { settle((closeInfo != null) ? authError(closeInfo) : (err || new MtError('the relay closed before the device answered', EXIT.NOTFOUND, { relayEarly: true }))); }
        ws.on('text', onText); ws.on('close', onClose);
        if (onAbort) { onAbort(function (err) { settle(err); }); }
        ws.resume();
    });
}

// The server closes a relay it will not route without saying why: find the reason from the device list.
async function explainTunnelFailure(cfg, dev, err, forShell) {
    if ((err == null) || (err.relayEarly !== true)) { return err; }
    let list = null;
    try { list = await fetchDevices(cfg); } catch (e) { return e; }
    const d = list.find(function (x) { return x.id == dev.id; });
    if (d == null) { return new MtError(dev.name + ' is not visible to this account anymore (removed, or access was revoked)', EXIT.NOTFOUND); }
    if ((d.conn & 1) == 0) { return new MtError(d.name + ' is offline: its agent is not connected to the server', EXIT.NOTFOUND); }
    if (err.timedOut) { return new MtError(d.name + ' did not answer the tunnel request in time, try again', EXIT.NOTFOUND); }
    if (forShell) { return new MtError('the server refused the terminal on ' + d.name + ': this account needs "Remote Control" without the "No Terminal" restriction', EXIT.AUTH); }
    return new MtError('the server refused the tunnel to ' + d.name + ': this account needs "Remote Control" or "Relay" rights on it', EXIT.AUTH);
}

function parsePort(value, what) {
    const p = parseInt(value);
    if ((String(p) != String(value).trim()) || (p < 1) || (p > 65535)) { fail('invalid ' + (what || 'port') + ': ' + value); }
    return p;
}
function parseTargetHost(value) {
    if (value == null) { return null; }
    if (/^[A-Za-z0-9.:_-]{1,253}$/.test(value) == false) { fail('invalid --to host: ' + value); }
    return value;
}

// A relay to a TCP port on the device (or on another host of its network), in its data phase and paused.
async function openPortTunnel(cfg, dev, port, toHost) {
    let q = 'nodeid=' + encodeURIComponent(dev.id) + '&tcpport=' + port;
    if (toHost != null) { q += '&tcpaddr=' + encodeURIComponent(toHost); }
    let ws = null;
    try {
        ws = await wsConnect(cfg, serverParts(cfg.url).basePath + 'meshrelay.ashx?' + q, { 'x-meshauth': meshAuth(cfg.user, cfg.pass) });
        await waitRelayStart(ws, RELAY_TIMEOUT);
    } catch (e) { throw await explainTunnelFailure(cfg, dev, e, false); }
    return ws;
}

function refusedMessage(dev, port, toHost) {
    return 'nothing answered on ' + ((toHost != null) ? toHost : '127.0.0.1') + ':' + port + ' of ' + dev.name + ' (refused, or closed at once). Is the ' + ((port == 22) ? 'SSH server (sshd)' : 'service') + ' running there?';
}

//
// Prompts
//

let stdinText = null, stdinEnded = false;
const stdinWaiters = [];
function pumpStdinLines() {
    while (stdinWaiters.length > 0) {
        const i = stdinText.indexOf('\n');
        if (i >= 0) { const line = stdinText.slice(0, i).replace(/\r$/, ''); stdinText = stdinText.slice(i + 1); stdinWaiters.shift()(line); }
        else if (stdinEnded) { const line = stdinText; stdinText = ''; stdinWaiters.shift()(line); }
        else { break; }
    }
}
function readStdinLine() {
    return new Promise(function (resolve) {
        if (stdinText == null) {
            stdinText = '';
            process.stdin.setEncoding('utf8');
            process.stdin.on('data', function (d) { stdinText += d; pumpStdinLines(); });
            process.stdin.on('end', function () { stdinEnded = true; pumpStdinLines(); });
        }
        stdinWaiters.push(resolve);
        process.stdin.resume();
        pumpStdinLines();
    }).then(function (line) { process.stdin.pause(); return line; });
}

function prompt(question, secret) {
    const stdin = process.stdin;
    if (stdin.isTTY !== true) { return readStdinLine(); }
    return new Promise(function (resolve, reject) {
        let value = '';
        process.stderr.write(question);
        stdin.setRawMode(true); stdin.resume();
        function done(err) { stdin.removeListener('data', onData); stdin.setRawMode(false); stdin.pause(); process.stderr.write('\n'); if (err) { reject(err); } else { resolve(value); } }
        function onData(d) {
            for (const ch of d.toString('utf8')) {
                if ((ch == '\r') || (ch == '\n')) { done(null); return; }
                if ((ch == '\u0003') || ((ch == '\u0004') && (value == ''))) { done(new MtError('aborted', EXIT.USAGE)); return; }
                if ((ch == '\u007f') || (ch == '\b')) { if (value.length > 0) { value = Array.from(value).slice(0, -1).join(''); if (!secret) { process.stderr.write('\b \b'); } } continue; }
                if (ch < ' ') { continue; }
                value += ch;
                if (!secret) { process.stderr.write(ch); }
            }
        }
        stdin.on('data', onData);
    });
}

function isInteractive() { return (process.stdin.isTTY === true) && (process.stderr.isTTY === true); }

//
// Commands
//

async function cmdLogin(a) {
    if (a._.length != 1) { fail('usage: meshtunnel login <server-url> [--pin sha256//...] [--user name] [--expire-days N]'); }
    const server = parseServerUrl(a._[0]);
    let pin = (a.flags.pin != null) ? normalizePin(a.flags.pin) : null;
    let expireDays = 0;
    if (a.flags['expire-days'] != null) { expireDays = parseInt(a.flags['expire-days']); if (!(expireDays >= 0)) { fail('invalid --expire-days'); } }

    // Decide whether to trust the server before sending anything to it.
    const probe = await connectTls(server.url, null, true);
    probe.sock.destroy();
    if (probe.authorized == false) {
        if (pin != null) {
            if (pin !== probe.fingerprint) { fail('the server certificate does not match --pin\n  --pin:  ' + pin + '\n  server: ' + probe.fingerprint, EXIT.TLS); }
        } else {
            note('the certificate of ' + serverParts(server.url).hostHeader + ' is not signed by a trusted authority (' + probe.reason + ')');
            note('its public key fingerprint is ' + probe.fingerprint);
            if (isInteractive() == false) { fail('not trusting it without confirmation; if that fingerprint is right, run again with --pin ' + probe.fingerprint, EXIT.TLS); }
            const answer = await prompt('Check it against the fingerprint shown in the web UI (Terminal tab > Local Terminal). Trust it (yes/no)? ', false);
            if (/^y(es)?$/i.test(answer.trim()) == false) { fail('aborted', EXIT.TLS); }
            pin = probe.fingerprint;
        }
    }

    const cfg = { url: server.url, loginkey: server.loginkey, pin: (pin || undefined) };
    const user = (a.flags.user != null) ? String(a.flags.user) : (await prompt('Username (or a ~t: login token): ', false)).trim();
    if (user == '') { fail('no username given'); }
    const pass = await prompt(user.startsWith('~t:') ? 'Token password: ' : 'Password: ', true);

    let saved = null;
    if (user.startsWith('~t:')) {
        // A login token made in the web UI (My Account > Login Tokens), for accounts that use SSO or hardware keys.
        const ctl = await controlConnect(cfg, { user: user, pass: pass });
        const account = (ctl.userinfo && ctl.userinfo.name) ? ctl.userinfo.name : null;
        ctl.close();
        saved = Object.assign({}, cfg, { user: user, pass: pass, account: account });
    } else {
        let token = null, ctl = null;
        for (let attempt = 0; ; attempt++) {
            try { ctl = await controlConnect(cfg, { user: user, pass: pass, token: token }); break; }
            catch (e) {
                if ((e.twoFactor !== true) || (attempt >= 5)) { throw e; }
                if (isInteractive() == false) { fail('this account uses two-factor authentication: log in from a terminal, or use a login token made in the web UI (My Account > Login Tokens)', EXIT.AUTH); }
                const ways = []; if (e.email2fa) { ways.push('"email"'); } if (e.sms2fa) { ways.push('"sms"'); } if (e.msg2fa) { ways.push('"msg"'); }
                const code = (await prompt('Two-factor code' + ((ways.length > 0) ? (' (or ' + ways.join(', ') + ' to receive one)') : '') + ': ', false)).trim();
                token = ({ email: '**email**', sms: '**sms**', msg: '**msg**' })[code.toLowerCase()] || code;
            }
        }
        const account = (ctl.userinfo && ctl.userinfo.name) ? ctl.userinfo.name : user;
        const tokenName = ('meshtunnel@' + os.hostname()).slice(0, 100);
        let r = null;
        try { r = await ctl.request({ action: 'createLoginToken', name: tokenName, expire: expireDays * 1440, responseid: 'meshtunnel' }, function (m) { return m.action == 'createLoginToken'; }, 20000); }
        finally { ctl.close(); }
        if (!r.tokenUser || !r.tokenPass) { fail('the server refused to create a login token (' + (r.result || 'no reason given') + '). An administrator can allow them (domains > passwordRequirements > loginTokens); an existing token from My Account > Login Tokens also works as the username here.', EXIT.AUTH); }
        saved = Object.assign({}, cfg, { user: r.tokenUser, pass: r.tokenPass, tokenName: tokenName, createdToken: true, account: account });
    }

    const file = saveConfig(saved);
    const devices = await fetchDevices(saved);
    const online = devices.filter(function (d) { return (d.conn & 1) != 0; }).length;
    process.stderr.write('Logged in to ' + saved.url + ' as ' + (saved.account || 'token user') + ', ' + devices.length + ' device(s), ' + online + ' online.\n');
    process.stderr.write('The ' + (saved.createdToken ? ('login token "' + saved.tokenName + '"') : 'login token') + ' is stored in ' + file + ', revoke it any time in My Account > Login Tokens' + (saved.createdToken ? ' or with: meshtunnel logout' : '') + '.\n');
    process.stderr.write('Next: meshtunnel ssh-config --install   (then: ssh <user>@<device>.mesh)\n');
    return EXIT.OK;
}

async function cmdLogout() {
    const cfg = loadConfig(false);
    if (cfg == null) { note('not logged in'); return EXIT.OK; }
    let revoked = false;
    if (cfg.createdToken === true) {
        try {
            const ctl = await controlConnect(cfg, { user: cfg.user, pass: cfg.pass });
            try {
                const r = await ctl.request({ action: 'loginTokens', remove: [cfg.user] }, function (m) { return m.action == 'loginTokens'; }, 15000);
                revoked = !(r.loginTokens || []).some(function (t) { return t.tokenUser == cfg.user; });
            } finally { ctl.close(); }
        } catch (e) { note('could not revoke the login token on the server: ' + e.message); }
    }
    try { fs.unlinkSync(configFile()); } catch (ex) { }
    try { fs.unlinkSync(deviceCacheFile()); } catch (ex) { }
    if (revoked) { note('logged out, login token "' + cfg.tokenName + '" revoked'); }
    else { note('logged out on this computer' + (cfg.tokenName ? (', revoke login token "' + cfg.tokenName + '" in My Account > Login Tokens') : '')); }
    return EXIT.OK;
}

async function cmdLs(a) {
    const cfg = loadConfig(true);
    let list = await fetchDevices(cfg);
    if (a._.length > 0) {
        const f = a._.join(' ').toLowerCase();
        list = list.filter(function (d) { return (d.handle.indexOf(f) >= 0) || (d.name.toLowerCase().indexOf(f) >= 0) || (d.group.toLowerCase().indexOf(f) >= 0); });
    }
    if (a.flags.json) { process.stdout.write(JSON.stringify(list.map(function (d) { return { handle: d.handle, name: d.name, group: d.group, os: d.os, online: ((d.conn & 1) != 0), id: d.id }; }), null, 2) + '\n'); return EXIT.OK; }
    const rows = [['HANDLE', 'NAME', 'GROUP', 'OS', 'STATE']];
    for (const d of list) { rows.push([d.handle, d.name, d.group, d.os, ((d.conn & 1) != 0) ? 'online' : 'offline']); }
    const widths = [0, 0, 0, 0];
    for (const r of rows) { for (let i = 0; i < 4; i++) { widths[i] = Math.min(Math.max(widths[i], r[i].length), 40); } }
    for (const r of rows) {
        let line = '';
        for (let i = 0; i < 4; i++) { let c = r[i]; if (c.length > 40) { c = c.slice(0, 39) + '~'; } line += c + ' '.repeat(widths[i] - c.length + 2); }
        process.stdout.write(line + r[4] + '\n');
    }
    if (list.length == 0) { note('no devices'); }
    return EXIT.OK;
}

async function cmdProxy(a) {
    if ((a._.length < 1) || (a._.length > 2)) { fail('usage: meshtunnel proxy <device> [port] [--to host]'); }
    const cfg = loadConfig(true);
    const port = parsePort((a._.length > 1) ? a._[1] : '22');
    const toHost = parseTargetHost(a.flags.to);
    const dev = await getDevice(cfg, a._[0]);
    const ws = await openPortTunnel(cfg, dev, port, toHost);
    return new Promise(function (resolve) {
        const stdin = process.stdin, stdout = process.stdout, started = Date.now();
        let received = 0, inputEnded = false, done = false;
        ws.on('binary', function (d) {
            received += d.length;
            if (stdout.write(d) == false) { ws.pause(); stdout.once('drain', function () { ws.resume(); }); }
        });
        ws.on('close', function (code, reason, err) {
            if (done) { return; }
            done = true;
            let exitCode = EXIT.OK;
            if (err != null) { note(err.message); exitCode = err.code; }
            else if ((received == 0) && (inputEnded == false) && ((Date.now() - started) < 15000)) { note(refusedMessage(dev, port, toHost)); exitCode = EXIT.REFUSED; }
            stdin.pause();
            stdout.write('', function () { resolve(exitCode); });
        });
        stdin.on('data', function (d) { if (ws.sendBinary(d) == false) { stdin.pause(); ws.once('drain', function () { stdin.resume(); }); } });
        stdin.on('end', function () { inputEnded = true; ws.close(1000); });
        stdin.on('error', function () { inputEnded = true; ws.close(1000); });
        stdout.on('error', function () { ws.destroy(); }); // EPIPE: the ssh client went away
        ws.startKeepalive();
        ws.resume();
    });
}

async function cmdForward(a) {
    if (a._.length != 3) { fail('usage: meshtunnel forward <local-port> <device> <remote-port> [--bind address] [--to host]'); }
    const cfg = loadConfig(true);
    const lport = (a._[0] == '0') ? 0 : parsePort(a._[0], 'local port');
    const rport = parsePort(a._[2], 'remote port');
    const bind = (a.flags.bind != null) ? String(a.flags.bind) : '127.0.0.1';
    const toHost = parseTargetHost(a.flags.to);
    const list = await fetchDevices(cfg); // Also proves the login still works before listening
    const dev = matchDevice(list, a._[1]) || (/^node\//.test(a._[1]) ? { id: a._[1], name: a._[1], conn: 1 } : null);
    if (dev == null) { fail('no device matches "' + a._[1] + '", see: meshtunnel ls', EXIT.NOTFOUND); }
    if ((dev.conn & 1) == 0) { note('warning: ' + dev.name + ' is offline right now, connections will fail until its agent is back'); }
    const target = dev.name + ':' + ((toHost != null) ? (toHost + ':') : '') + rport;
    return new Promise(function (resolve) {
        const tunnels = new Set();
        let stopping = false;
        function stop(code) {
            if (stopping) { return; }
            stopping = true;
            server.close();
            for (const ws of tunnels) { ws.close(1000); }
            setTimeout(function () { resolve(code); }, 300);
        }
        const server = net.createServer(function (client) {
            const label = client.remoteAddress + ':' + client.remotePort;
            client.pause();
            client.on('error', function () { });
            openPortTunnel(cfg, dev, rport, toHost).then(function (ws) {
                if (client.destroyed) { ws.close(1000); return; }
                tunnels.add(ws);
                let received = 0;
                ws.on('binary', function (d) { received += d.length; if (client.write(d) == false) { ws.pause(); client.once('drain', function () { ws.resume(); }); } });
                ws.on('close', function (code, reason, err) {
                    tunnels.delete(ws);
                    if (err != null) { note(label + ': ' + err.message); }
                    else if (received == 0) { note(label + ': ' + refusedMessage(dev, rport, toHost)); }
                    client.end();
                });
                client.on('data', function (d) { if (ws.sendBinary(d) == false) { client.pause(); ws.once('drain', function () { client.resume(); }); } });
                client.on('end', function () { ws.close(1000); });
                client.on('close', function () { ws.close(1000); });
                ws.startKeepalive();
                ws.resume();
                client.resume();
            }, function (err) {
                note(label + ': ' + err.message);
                client.destroy();
                if (err.code == EXIT.AUTH) { note('stopping, the server no longer accepts this login'); stop(EXIT.AUTH); }
            });
        });
        server.on('error', function (e) { note('cannot listen on ' + bind + ':' + lport + ': ' + e.message); stop(EXIT.USAGE); });
        server.listen(lport, bind, function () { note('forwarding ' + bind + ':' + server.address().port + ' -> ' + target + ', press Ctrl-C to stop'); });
        process.on('SIGINT', function () { stop(EXIT.OK); });
        process.on('SIGTERM', function () { stop(EXIT.OK); });
    });
}

async function cmdShell(a) {
    const hold = (a.flags['hold-on-error'] === true);
    let code = EXIT.USAGE;
    try { code = await runShell(a); }
    catch (e) {
        if ((hold == false) || (isInteractive() == false)) { throw e; }
        // Opened from a meshtunnel:// link: keep the error on screen instead of closing the window at once.
        note(e.message);
        await holdWindow();
        return (e instanceof MtError) ? e.code : EXIT.USAGE;
    }
    if (hold && (code != EXIT.OK) && isInteractive()) { await holdWindow(); }
    return code;
}

function holdWindow() {
    process.stderr.write('Press Enter to close this window.');
    return prompt('', true).catch(function () { });
}

async function runShell(a) {
    if (a._.length != 1) { fail('usage: meshtunnel shell <device> [--user] [--powershell] [--login]'); }
    const cfg = loadConfig(true);
    const dev = await getDevice(cfg, a._[0]);
    let protocol = 1;
    if (a.flags.powershell) { protocol = a.flags.user ? 9 : 6; } else if (a.flags.user) { protocol = 8; }
    const base = serverParts(cfg.url).basePath;
    const ctl = await controlConnect(cfg, { user: cfg.user, pass: cfg.pass });
    let ws = null;
    try {
        const cookie = await ctl.request({ action: 'authcookie' }, function (m) { return m.action == 'authcookie'; }, 20000);
        const rid = crypto.randomBytes(8).toString('hex');
        // The server answers "OK" right away and "Unable to route" once its rights check fails, so only the failure counts.
        let routeError = null, routeAbort = null;
        ctl.onMessage(function (m) {
            if ((m.action != 'msg') || (m.responseid != 'meshtunnel') || (m.result == 'OK')) { return; }
            routeError = new MtError('the server would not route the terminal request to ' + dev.name, EXIT.NOTFOUND, { relayEarly: true }); // Offline or no rights, see explainTunnelFailure()
            if (routeAbort != null) { routeAbort(routeError); }
        });
        ctl.send({ action: 'msg', type: 'tunnel', nodeid: dev.id, usage: protocol, responseid: 'meshtunnel', value: '*' + base + 'meshrelay.ashx?p=' + protocol + '&nodeid=' + encodeURIComponent(dev.id) + '&id=' + rid + '&rauth=' + encodeURIComponent(cookie.rcookie) });
        ws = await wsConnect(cfg, base + 'meshrelay.ashx?browser=1&p=' + protocol + '&nodeid=' + encodeURIComponent(dev.id) + '&id=' + rid, { 'x-meshauth': meshAuth(cfg.user, cfg.pass) });
        try { await waitRelayStart(ws, RELAY_TIMEOUT, function (abort) { if (routeError != null) { abort(routeError); } else { routeAbort = abort; } }); }
        catch (e) { throw await explainTunnelFailure(cfg, dev, e, true); }
    } catch (e) { ctl.close(); throw e; }
    return terminalSession(ws, ctl, dev, protocol, (a.flags.login === true));
}

function terminalSession(ws, ctl, dev, protocol, requireLogin) {
    return new Promise(function (resolve) {
        const stdin = process.stdin, stdout = process.stdout, tty = (stdin.isTTY === true) && (stdout.isTTY === true);
        let raw = false, ended = false, atLineStart = true, tilde = false;
        function restoreTty() { if (raw) { raw = false; try { stdin.setRawMode(false); } catch (ex) { } } }
        function finish(code, message) {
            if (ended) { return; }
            ended = true;
            restoreTty();
            if (message) { process.stderr.write((tty ? '\r\n' : '') + message + '\n'); }
            ctl.close();
            stdin.pause();
            stdout.write('', function () { resolve(code); });
        }
        function disconnect() { ws.sendText(JSON.stringify({ ctrlChannel: CTRL, type: 'close' })); ws.close(1000); }
        function send(buf) { if ((buf.length > 0) && (ws.sendBinary(buf) == false)) { stdin.pause(); ws.once('drain', function () { stdin.resume(); }); } }
        process.on('exit', restoreTty);
        for (const sig of ['SIGHUP', 'SIGTERM']) { process.on(sig, function () { restoreTty(); disconnect(); finish(128 + os.constants.signals[sig], null); }); }

        // Terminal options first, then the protocol number: the same order the web UI and meshctrl use.
        const opts = { ctrlChannel: CTRL, type: 'options', cols: (stdout.columns || 80), rows: (stdout.rows || 24) };
        if (requireLogin) { opts.requireLogin = true; }
        ws.sendText(JSON.stringify(opts));
        ws.sendText(String(protocol));

        let lastOutput = Date.now();
        ws.on('binary', function (d) { lastOutput = Date.now(); if (stdout.write(d) == false) { ws.pause(); stdout.once('drain', function () { ws.resume(); }); } });
        ws.on('text', function (t) {
            if ((t == 'c') || (t == 'cr')) { return; }
            lastOutput = Date.now();
            if (t.charAt(0) == '{') {
                let m = null;
                try { m = JSON.parse(t); } catch (ex) { }
                if ((m != null) && (m.ctrlChannel == CTRL)) {
                    if (m.type == 'ping') { ws.sendText(JSON.stringify({ ctrlChannel: CTRL, type: 'pong' })); }
                    else if ((m.type == 'console') && m.msg) { process.stderr.write((tty ? '\r\n' : '') + '[' + m.msg + ']' + (tty ? '\r\n' : '\n')); }
                    return;
                }
            }
            stdout.write(t);
        });
        ws.on('close', function (code, reason, err) { finish((err != null) ? err.code : EXIT.OK, (err != null) ? ('meshtunnel: ' + err.message) : ('Connection to ' + dev.name + ' closed.')); });

        if (tty) {
            stdin.setRawMode(true);
            raw = true;
            stdout.on('resize', function () { ws.sendText(JSON.stringify({ ctrlChannel: CTRL, type: 'termsize', cols: stdout.columns, rows: stdout.rows })); });
        }
        stdin.on('data', function (d) {
            if (tty == false) { send(d); return; }
            // ssh-style escapes, only right after a newline: "~." disconnects, "~~" sends a single "~", "~?" lists them.
            if ((tilde == false) && (d.indexOf(0x7e) < 0)) { send(d); const last = d[d.length - 1]; atLineStart = ((last == 0x0d) || (last == 0x0a)); return; }
            const out = [];
            for (const b of d) {
                if (tilde) {
                    tilde = false;
                    if (b == 0x2e) { send(Buffer.from(out)); disconnect(); return; }
                    if (b == 0x3f) { process.stderr.write('\r\nSupported escape sequences:\r\n ~.  - disconnect\r\n ~~  - send the escape character\r\n ~?  - this message\r\n(They are only recognized right after a newline.)\r\n'); continue; }
                    if (b == 0x7e) { out.push(0x7e); atLineStart = false; continue; }
                    out.push(0x7e);
                } else if (atLineStart && (b == 0x7e)) { tilde = true; continue; }
                out.push(b);
                atLineStart = ((b == 0x0d) || (b == 0x0a));
            }
            send(Buffer.from(out));
        });
        // End of piped input: send ^D so the remote shell ends, like it would over ssh. Bash drops typeahead while it starts
        // and when it redraws its prompt, so a ^D sent during a running command is lost: send another one each time the
        // remote side printed something since the last ^D (typically the next prompt) and then went quiet.
        stdin.on('end', function () {
            if (tty) { return; }
            let tries = 0, lastEot = 0;
            const timer = setInterval(function () {
                if (ended || (tries >= 50)) { clearInterval(timer); return; }
                const now = Date.now();
                if ((now - lastOutput) < 500) { return; }
                if ((lastOutput <= lastEot) && ((now - lastEot) < 5000)) { return; }
                tries++;
                lastEot = now;
                ws.sendBinary(Buffer.from([4]));
            }, 250);
            timer.unref();
        });
        ws.startKeepalive();
        ws.resume();
        stdin.resume();
    });
}

function sshConfigText(cfg) {
    const quote = function (p) { if (p.indexOf('"') >= 0) { fail('cannot write an ssh config for a path containing a double quote: ' + p); } return '"' + p.split('%').join('%%') + '"'; };
    const lines = [
        '# meshtunnel: reach MeshCentral devices as <device>.mesh (ssh, scp, rsync, sftp)',
        '# Server: ' + ((cfg != null) ? cfg.url : '(not logged in yet)'),
        '# Written by "meshtunnel ssh-config"; run it again if node or meshtunnel moves.',
        'Host *.mesh',
        '    ProxyCommand ' + quote(process.execPath) + ' ' + quote(scriptPath()) + ' proxy %n %p',
        '    ServerAliveInterval 30',
        '    ServerAliveCountMax 3'
    ];
    if (process.platform != 'win32') {
        // Reuse one tunnel for later ssh/scp/rsync to the same device: they start instantly, and so does shell completion of remote paths.
        lines.push('    ControlMaster auto', '    ControlPath ~/.ssh/meshtunnel-%C', '    ControlPersist 10m');
    }
    return lines.join('\n') + '\n';
}

async function cmdSshConfig(a) {
    const text = sshConfigText(loadConfig(false));
    if (a.flags.install !== true) { process.stdout.write(text); return EXIT.OK; }
    const sshDir = path.join(os.homedir(), '.ssh');
    mkdirp(sshDir, 0o700);
    const confFile = path.join(sshDir, 'meshtunnel.conf');
    writeFileAtomic(confFile, text, 0o600);
    // Include it from the TOP of ~/.ssh/config: an Include placed after a Host line would only apply to that host.
    let main = path.join(sshDir, 'config'), current = '', mode = 0o600;
    try { main = fs.realpathSync(main); current = fs.readFileSync(main, 'utf8'); mode = fs.statSync(main).mode & 0o777; } catch (ex) { }
    if (/^\s*Include\s+("?)(~\/\.ssh\/)?meshtunnel\.conf\1\s*$/mi.test(current) == false) {
        writeFileAtomic(main, 'Include meshtunnel.conf\n' + ((current.length > 0) ? ('\n' + current) : ''), mode);
        note('added "Include meshtunnel.conf" at the top of ' + main);
    }
    note('wrote ' + confFile);
    process.stderr.write('Now use devices as <handle>.mesh, the handles are listed by "meshtunnel ls":\n  ssh root@web01.mesh\n  scp ./file root@web01.mesh:/tmp/\n  rsync -avP ./dir/ root@web01.mesh:/tmp/dir/\n');
    return EXIT.OK;
}

//
// meshtunnel:// links from the web UI ("Open in my terminal")
//

const DESKTOP_FILE = 'meshtunnel-url.desktop';

function findExecutable(name) {
    const ok = function (p) { try { fs.accessSync(p, fs.constants.X_OK); return fs.statSync(p).isFile(); } catch (ex) { return false; } };
    if (name.indexOf(path.sep) >= 0) { return ok(name) ? name : null; }
    for (const dir of (process.env.PATH || '').split(path.delimiter)) { if (dir == '') { continue; } const p = path.join(dir, name); if (ok(p)) { return p; } }
    return null;
}

// Quote one argument of a desktop entry Exec key (the general string escaping applies on top of the quoting rules).
function desktopExecArg(s) {
    const map = { '\\': '\\\\\\\\', '"': '\\\\"', '`': '\\\\`', '$': '\\\\$' };
    return '"' + s.replace(/[\\"`$]/g, function (c) { return map[c]; }).split('%').join('%%') + '"';
}

async function cmdInstallHandler() {
    if (process.platform == 'win32') {
        const key = 'HKCU\\Software\\Classes\\meshtunnel';
        const reg = function (args) { childProcess.execFileSync('reg', args, { stdio: 'ignore', windowsHide: true }); };
        reg(['add', key, '/ve', '/d', 'URL:meshtunnel', '/f']);
        reg(['add', key, '/v', 'URL Protocol', '/d', '', '/f']);
        reg(['add', key + '\\shell\\open\\command', '/ve', '/d', '"' + process.execPath + '" "' + scriptPath() + '" open "%1"', '/f']);
        note('meshtunnel:// links now open in a console window');
        return EXIT.OK;
    }
    if (process.platform == 'darwin') { fail('opening meshtunnel:// links is not supported on macOS yet, use the commands from the Local Terminal dialog'); }
    const appsDir = path.join(process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share'), 'applications');
    mkdirp(appsDir, 0o755);
    const entry = ['[Desktop Entry]', 'Type=Application', 'Name=meshtunnel', 'Comment=Open MeshCentral devices in your own terminal',
        'Exec=' + desktopExecArg(process.execPath) + ' ' + desktopExecArg(scriptPath()) + ' open %u',
        'MimeType=x-scheme-handler/meshtunnel;', 'NoDisplay=true', 'Terminal=false'].join('\n') + '\n';
    writeFileAtomic(path.join(appsDir, DESKTOP_FILE), entry, 0o644);
    const xdgMime = findExecutable('xdg-mime');
    if (xdgMime == null) { fail('xdg-mime was not found (package xdg-utils): wrote ' + path.join(appsDir, DESKTOP_FILE) + ' but could not register it'); }
    childProcess.execFileSync(xdgMime, ['default', DESKTOP_FILE, 'x-scheme-handler/meshtunnel'], { stdio: 'ignore' });
    const udd = findExecutable('update-desktop-database');
    if (udd != null) { try { childProcess.execFileSync(udd, [appsDir], { stdio: 'ignore' }); } catch (ex) { } }
    let terminal = null;
    try { terminal = terminalCommand(loadConfig(false) || {}, 'test', ['true'])[0]; } catch (ex) { }
    note('meshtunnel:// links will open ' + ((terminal != null) ? terminal : 'a terminal (none found yet: set $TERMINAL)'));
    return EXIT.OK;
}

async function cmdUninstallHandler() {
    if (process.platform == 'win32') {
        try { childProcess.execFileSync('reg', ['delete', 'HKCU\\Software\\Classes\\meshtunnel', '/f'], { stdio: 'ignore', windowsHide: true }); } catch (ex) { }
        note('meshtunnel:// handler removed');
        return EXIT.OK;
    }
    const appsDir = path.join(process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share'), 'applications');
    try { fs.unlinkSync(path.join(appsDir, DESKTOP_FILE)); } catch (ex) { }
    // Drop the default-handler line that "xdg-mime default" wrote.
    for (const f of [path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'mimeapps.list'), path.join(appsDir, 'mimeapps.list')]) {
        try {
            const text = fs.readFileSync(f, 'utf8');
            const kept = text.split('\n').filter(function (l) { return /^x-scheme-handler\/meshtunnel=/.test(l) == false; }).join('\n');
            if (kept != text) { writeFileAtomic(f, kept, fs.statSync(f).mode & 0o777); }
        } catch (ex) { }
    }
    const udd = findExecutable('update-desktop-database');
    if (udd != null) { try { childProcess.execFileSync(udd, [appsDir], { stdio: 'ignore' }); } catch (ex) { } }
    note('meshtunnel:// handler removed');
    return EXIT.OK;
}

// The terminal emulator command line, as an argv array (never a shell string).
function terminalCommand(cfg, title, cmd) {
    if (Array.isArray(cfg.terminal) && (cfg.terminal.length > 0)) {
        const out = [];
        for (const a of cfg.terminal) { if (a == '{cmd}') { out.push.apply(out, cmd); } else { out.push(String(a).split('{title}').join(title)); } }
        if (cfg.terminal.indexOf('{cmd}') < 0) { out.push.apply(out, cmd); }
        return out;
    }
    const candidates = process.env.TERMINAL ? [process.env.TERMINAL] : ['x-terminal-emulator', 'kitty', 'alacritty', 'wezterm', 'foot', 'gnome-terminal', 'konsole', 'xfce4-terminal', 'xterm'];
    for (const c of candidates) {
        const bin = findExecutable(c);
        if (bin == null) { continue; }
        let real = bin;
        try { real = fs.realpathSync(bin); } catch (ex) { }
        const base = path.basename(real).toLowerCase();
        if (base == 'gnome-terminal') { return [bin, '--'].concat(cmd); }
        if (base == 'kitty') { return [bin, '--title', title].concat(cmd); }
        if (base == 'alacritty') { return [bin, '--title', title, '-e'].concat(cmd); }
        if (base.startsWith('wezterm')) { return [bin, 'start', '--'].concat(cmd); }
        if ((base == 'foot') || (base == 'footclient')) { return [bin, '--title=' + title].concat(cmd); }
        if (base == 'konsole') { return [bin, '-e'].concat(cmd); }
        if (base == 'xfce4-terminal') { return [bin, '--title', title, '-x'].concat(cmd); }
        return [bin, '-T', title, '-e'].concat(cmd); // xterm, and x-terminal-emulator wrappers (Debian policy: -e takes the rest)
    }
    fail('no terminal emulator found, set $TERMINAL or a "terminal" array in ' + configFile());
}

function handlerFailure(message) {
    note(message);
    try { mkdirp(cacheDir(), 0o700); fs.appendFileSync(path.join(cacheDir(), 'handler.log'), new Date().toISOString() + ' ' + message + '\n'); } catch (ex) { }
    const notify = (process.platform == 'linux') ? findExecutable('notify-send') : null;
    if (notify != null) { try { childProcess.spawn(notify, ['meshtunnel', message], { detached: true, stdio: 'ignore' }).unref(); } catch (ex) { } }
}

async function cmdOpen(a) {
    try {
        if (a._.length != 1) { fail('usage: meshtunnel open <meshtunnel://...>'); }
        let u = null;
        try { u = new URL(a._[0]); } catch (ex) { }
        if ((u == null) || (u.protocol != 'meshtunnel:')) { fail('not a meshtunnel:// link'); }
        const cfg = loadConfig(false);
        const server = u.searchParams.get('s') || '';
        if (cfg == null) { fail('meshtunnel is not logged in on this computer, run: meshtunnel login ' + server); }
        // The link comes from a web page: never let it point the stored credentials at another server.
        let target = null;
        try { target = parseServerUrl(server).url; } catch (ex) { }
        if (target !== cfg.url) { fail('refusing a link for ' + server + ': meshtunnel is logged in to ' + cfg.url); }
        const nodeid = u.searchParams.get('n') || '';
        if (/^node\/[^/]*\/[A-Za-z0-9@$]+$/.test(nodeid) == false) { fail('the link has an invalid device id'); }
        const protocol = parseInt(u.searchParams.get('p') || '1');
        if (TERMINAL_PROTOCOLS.indexOf(protocol) < 0) { fail('the link asks for an unknown shell type'); }
        const login = (u.searchParams.get('l') == '1');
        const title = (u.searchParams.get('t') || 'meshtunnel').replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 60);
        const args = ['shell', nodeid];
        if ((protocol == 8) || (protocol == 9)) { args.push('--user'); }
        if ((protocol == 6) || (protocol == 9)) { args.push('--powershell'); }
        if (login) { args.push('--login'); }
        args.push('--hold-on-error');
        let argv = null;
        if (process.platform == 'win32') {
            // "start" opens a new console window; every argument is validated above, so none needs quoting beyond the paths.
            const line = '/d /c start "' + title.replace(/[^A-Za-z0-9 ._-]/g, '') + '" "' + process.execPath + '" "' + scriptPath() + '" ' + args.join(' ');
            argv = [process.env.ComSpec || 'cmd.exe', line];
            await spawnDetached(argv, { windowsVerbatimArguments: true });
        } else {
            argv = terminalCommand(cfg, title, [process.execPath, scriptPath()].concat(args));
            await spawnDetached(argv, {});
        }
        return EXIT.OK;
    } catch (e) {
        handlerFailure(e.message);
        return (e instanceof MtError) ? e.code : EXIT.USAGE;
    }
}

function spawnDetached(argv, extra) {
    return new Promise(function (resolve, reject) {
        const child = childProcess.spawn(argv[0], argv.slice(1), Object.assign({ detached: true, stdio: 'ignore' }, extra));
        child.once('error', function (e) { reject(new MtError('cannot start ' + argv[0] + ': ' + e.message)); });
        child.once('spawn', function () { child.unref(); resolve(); });
    });
}

async function cmdUpdate() {
    const cfg = loadConfig(true);
    const body = await httpsGet(cfg, serverParts(cfg.url).basePath + 'meshtunnel.js' + (cfg.loginkey ? ('?key=' + encodeURIComponent(cfg.loginkey)) : ''));
    const text = body.toString('utf8');
    const m = /const VERSION = '([^']+)'/.exec(text);
    if ((m == null) || (text.startsWith('#!/usr/bin/env node') == false)) { fail('the server did not send a meshtunnel script', EXIT.NOTFOUND); }
    const target = scriptPath(), tmp = target + '.' + process.pid + '.new.js'; // "node --check" refuses unknown extensions
    fs.writeFileSync(tmp, body, { mode: fs.statSync(target).mode & 0o777 });
    try { childProcess.execFileSync(process.execPath, ['--check', tmp], { stdio: 'ignore' }); }
    catch (ex) { try { fs.unlinkSync(tmp); } catch (ex2) { } fail('the downloaded script does not parse, keeping the current one'); }
    fs.renameSync(tmp, target);
    note((m[1] == VERSION) ? ('already up to date (' + VERSION + ')') : ('updated from ' + VERSION + ' to ' + m[1]));
    return EXIT.OK;
}

//
// Command line
//

const HELP = [
    'meshtunnel ' + VERSION + ': your own terminal, ssh, scp and rsync for MeshCentral devices',
    '',
    'Setup (once per computer)',
    '  login <server-url> [--pin sha256//...] [--user NAME] [--expire-days N]',
    '                      Sign in; stores a revocable login token, never your password',
    '  ssh-config [--install]',
    '                      Print, or install into ~/.ssh, the config that makes <device>.mesh hosts work',
    '  install-handler     Let the web UI\'s "Open in my terminal" button open your terminal (Linux, Windows)',
    '  uninstall-handler   Remove that link handler',
    '  logout              Revoke the stored login token and forget the server',
    '  update              Replace this script with the version served by the server',
    '',
    'Devices',
    '  ls [filter] [--json]',
    '                      List devices with the handle to use in commands',
    '  shell <device> [--user] [--powershell] [--login]',
    '                      The agent\'s own shell in this terminal, no SSH server needed; ~. disconnects',
    '  forward <local-port> <device> <remote-port> [--bind ADDRESS] [--to HOST]',
    '                      Forward a local port to a port of the device, or of HOST in its network',
    '  proxy <device> [port] [--to HOST]',
    '                      Relay stdin/stdout to a port of the device (the ssh ProxyCommand)',
    '',
    'Examples',
    '  ssh root@web01.mesh',
    '  scp backup.tar.gz root@web01.mesh:/tmp/',
    '  rsync -avP ./site/ root@web01.mesh:/var/www/site/',
    '  meshtunnel forward 8080 web01 80',
    '',
    'A device is a handle from "meshtunnel ls", its exact name, or its node id.',
    'Exit codes: 0 ok, 1 usage, 2 login or rights, 3 device not found or offline, 4 nothing listening on the device port, 5 certificate problem.',
    ''
].join('\n');

const COMMANDS = {
    'login': { spec: { 'pin': 'value', 'user': 'value', 'expire-days': 'value' }, run: cmdLogin },
    'logout': { spec: {}, run: cmdLogout },
    'ls': { spec: { 'json': 'bool' }, run: cmdLs },
    'proxy': { spec: { 'to': 'value' }, run: cmdProxy },
    'forward': { spec: { 'bind': 'value', 'to': 'value' }, run: cmdForward },
    'shell': { spec: { 'user': 'bool', 'powershell': 'bool', 'login': 'bool', 'hold-on-error': 'bool' }, run: cmdShell },
    'ssh-config': { spec: { 'install': 'bool' }, run: cmdSshConfig },
    'install-handler': { spec: {}, run: cmdInstallHandler },
    'uninstall-handler': { spec: {}, run: cmdUninstallHandler },
    'open': { spec: {}, run: cmdOpen },
    'update': { spec: {}, run: cmdUpdate }
};

function parseArgs(argv, spec) {
    const out = { _: [], flags: {} };
    for (let i = 0; i < argv.length; i++) {
        const arg = argv[i];
        if (arg == '--') { out._.push.apply(out._, argv.slice(i + 1)); break; }
        if (arg.startsWith('--')) {
            let name = arg.slice(2), value = null;
            const eq = name.indexOf('=');
            if (eq >= 0) { value = name.slice(eq + 1); name = name.slice(0, eq); }
            if (Object.prototype.hasOwnProperty.call(spec, name) == false) { fail('unknown option --' + name + ', see: meshtunnel help'); }
            if (spec[name] == 'bool') { if (value != null) { fail('--' + name + ' takes no value'); } out.flags[name] = true; }
            else { if (value == null) { if ((i + 1) >= argv.length) { fail('--' + name + ' needs a value'); } value = argv[++i]; } out.flags[name] = value; }
        } else if ((arg.length > 1) && (arg.charAt(0) == '-')) {
            fail('unknown option ' + arg + ', see: meshtunnel help');
        } else {
            out._.push(arg);
        }
    }
    return out;
}

async function main(argv) {
    const cmd = argv[0];
    if ((cmd == null) || (cmd == 'help') || (cmd == '--help') || (cmd == '-h')) { process.stdout.write(HELP); return EXIT.OK; }
    if ((cmd == 'version') || (cmd == '--version')) { process.stdout.write('meshtunnel ' + VERSION + '\n'); return EXIT.OK; }
    const c = COMMANDS[cmd];
    if (c == null) { fail('unknown command "' + cmd + '", see: meshtunnel help'); }
    const args = parseArgs(argv.slice(1), Object.assign({ 'help': 'bool' }, c.spec));
    if (args.flags.help) { process.stdout.write(HELP); return EXIT.OK; }
    return c.run(args);
}

main(process.argv.slice(2)).then(function (code) {
    process.exit((typeof code == 'number') ? code : EXIT.OK);
}, function (err) {
    if (err instanceof MtError) { note(err.message); process.exit(err.code); }
    note('unexpected error: ' + ((err && err.stack) ? err.stack : err));
    process.exit(EXIT.USAGE);
});

#!/usr/bin/env python3
"""meshtunnel: reach MeshCentral devices from your own terminal (Python edition).

An ssh ProxyCommand (so ssh, scp, rsync, sftp and VS Code work as usual), a local port forwarder and a client for the
agent's own shell. Everything goes through the server's relay on its HTTPS port, so devices behind NAT or a firewall
work without opening anything. Single file, Python 3.6 or newer, standard library only. Same commands, settings file,
certificate pins and device names as meshtunnel.js (Node.js) and meshtunnel.ps1 (PowerShell): use whichever runtime
the computer has.

Author: Jugurtha-Green. License: Apache-2.0.
"""

import base64
import hashlib
import json
import os
import re
import select
import signal
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import unicodedata
import urllib.parse

VERSION = '1.1.0'

EXIT_OK, EXIT_USAGE, EXIT_AUTH, EXIT_NOTFOUND, EXIT_REFUSED, EXIT_TLS = 0, 1, 2, 3, 4, 5
CTRL = '102938'                     # Control channel id of MeshCentral relay sessions
WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
MAX_MESSAGE = 64 * 1024 * 1024      # Largest WebSocket message accepted from the server
RELAY_TIMEOUT = 20.0                # The server itself gives the agent 15 seconds to join a relay
TERMINAL_PROTOCOLS = (1, 6, 8, 9)   # Admin shell, admin PowerShell, user shell, user PowerShell
PATH_MARK = '# added by meshtunnel'
IS_WINDOWS = (os.name == 'nt')
# Forward compatible names: socket.timeout is only an alias of TimeoutError since 3.10, and ssl.CertificateError of
# SSLCertVerificationError since 3.7, so new Pythons may drop the old names.
SOCKET_TIMEOUT = (socket.timeout, TimeoutError) if hasattr(socket, 'timeout') else (TimeoutError,)
CERT_VERIFY_ERRORS = tuple(c for c in (getattr(ssl, 'SSLCertVerificationError', None), getattr(ssl, 'CertificateError', None)) if c is not None)


class MtError(Exception):
    def __init__(self, message, code=EXIT_USAGE, **extra):
        Exception.__init__(self, message)
        self.message = message
        self.code = code
        self.__dict__.update(extra)


def fail(message, code=EXIT_USAGE, **extra):
    raise MtError(message, code, **extra)


def note(message):
    try:
        sys.stderr.write('meshtunnel: ' + message + '\n')
        sys.stderr.flush()
    except (OSError, ValueError):
        pass


def err_write(text):
    try:
        sys.stderr.write(text)
        sys.stderr.flush()
    except (OSError, ValueError):
        pass


#
# Files
#

def home():
    return os.path.expanduser('~')


def config_file():
    if os.environ.get('MESHTUNNEL_CONFIG'):
        return os.path.abspath(os.environ['MESHTUNNEL_CONFIG'])
    if IS_WINDOWS:
        base = os.environ.get('APPDATA') or os.path.join(home(), 'AppData', 'Roaming')
    else:
        base = os.environ.get('XDG_CONFIG_HOME') or os.path.join(home(), '.config')
    return os.path.join(base, 'meshtunnel', 'config.json')


def cache_dir():
    if IS_WINDOWS:
        base = os.environ.get('LOCALAPPDATA') or os.path.join(home(), 'AppData', 'Local')
    else:
        base = os.environ.get('XDG_CACHE_HOME') or os.path.join(home(), '.cache')
    return os.path.join(base, 'meshtunnel')


def script_path():
    return os.path.realpath(os.path.abspath(sys.argv[0]))


def mkdirp(path, mode):
    os.makedirs(path, mode=mode, exist_ok=True)


def write_file_atomic(path, data, mode):
    """Write through a temporary file and a rename, so concurrent readers (parallel ssh sessions) never see a partial file."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    tmp = '%s.%d.%s.tmp' % (path, os.getpid(), os.urandom(4).hex())
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_config(required):
    path = config_file()
    try:
        with open(path, 'r', encoding='utf-8') as f:
            text = f.read()
    except OSError:
        if required:
            fail('not logged in yet, run: meshtunnel login <server-url>', EXIT_AUTH)
        return None
    if not IS_WINDOWS:
        try:
            if os.stat(path).st_mode & 0o077:
                note('warning: %s holds a login token but other users can read it, run: chmod 600 \'%s\'' % (path, path))
        except OSError:
            pass
    try:
        cfg = json.loads(text)
    except ValueError as e:
        fail('cannot read %s: %s' % (path, e))
    if required and not all(isinstance(cfg.get(k), str) for k in ('url', 'user', 'pass')):
        fail(path + ' is incomplete, run meshtunnel login again', EXIT_AUTH)
    return cfg


def save_config(cfg):
    path = config_file()
    mkdirp(os.path.dirname(path), 0o700)
    clean = dict((k, v) for k, v in cfg.items() if v is not None)
    write_file_atomic(path, json.dumps(clean, indent=2) + '\n', 0o600)
    return path


#
# Server address and certificate pinning
#

def parse_server_url(value):
    """Accepts "host", "host:port" or a pasted https://, wss:// or page URL. Returns the server base URL (ending with the
    domain path and a slash) and the optional 3FA login key from "?key="."""
    s = str(value or '').strip()
    if s == '':
        fail('missing server URL, e.g. https://mesh.example.com')
    if not re.match(r'^[a-z][a-z0-9+.-]*://', s, re.I):
        s = 'https://' + s
    try:
        u = urllib.parse.urlsplit(s)
        u.port  # Raises on an invalid port
    except ValueError:
        fail('invalid server URL: %s' % value)
    scheme = u.scheme.lower()
    if scheme == 'wss':
        scheme = 'https'
    if scheme != 'https':
        fail('the server URL must use https://, got %s://' % scheme)
    if not u.netloc or '@' in u.netloc:
        fail('invalid server URL: %s' % value)
    p = re.sub(r'[^/]*\.(ashx|html?|js)$', '', u.path, flags=re.I)
    if not p.endswith('/'):
        p += '/'
    key = urllib.parse.parse_qs(u.query).get('key', [None])[0]
    return {'url': 'https://' + u.netloc.lower() + p, 'loginkey': key or None}


def server_parts(url):
    u = urllib.parse.urlsplit(url)
    return {'host': u.hostname, 'port': u.port or 443, 'hostHeader': u.netloc, 'basePath': u.path}


def normalize_pin(pin):
    m = re.match(r'^sha256//([A-Za-z0-9+/]{43}=)$', str(pin or '').strip())
    if not m:
        fail('invalid --pin, expected sha256//<44 base64 characters> as shown in the web UI')
    return 'sha256//' + m.group(1)


def _der_tlv(buf, pos):
    tag = buf[pos]
    length = buf[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7f
        if n == 0 or n > 4:
            raise ValueError('unsupported DER length')
        length = int.from_bytes(buf[pos:pos + n], 'big')
        pos += n
    if pos + length > len(buf):
        raise ValueError('truncated DER')
    return tag, pos, length


def cert_pin(der):
    """curl's --pinnedpubkey format: "sha256//" + base64 of the SHA-256 of the certificate's SubjectPublicKeyInfo."""
    _, p, _ = _der_tlv(der, 0)              # Certificate
    _, p, _ = _der_tlv(der, p)              # tbsCertificate
    tag, vp, vl = _der_tlv(der, p)
    if tag == 0xA0:                         # [0] version, optional
        p = vp + vl
    for _ in range(5):                      # serialNumber, signature, issuer, validity, subject
        _, vp, vl = _der_tlv(der, p)
        p = vp + vl
    _, vp, vl = _der_tlv(der, p)            # subjectPublicKeyInfo
    return 'sha256//' + base64.b64encode(hashlib.sha256(der[p:vp + vl]).digest()).decode('ascii')


#
# Network: TLS with an optional HTTP CONNECT proxy
#

def proxy_for(host):
    p = os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy')
    if not p:
        return None
    h = host.lower()
    if h in ('localhost', '127.0.0.1', '::1'):
        return None
    for entry in (os.environ.get('NO_PROXY') or os.environ.get('no_proxy') or '').split(','):
        n = re.sub(r':\d+$', '', entry.strip().lower())
        if n == '':
            continue
        if n == '*':
            return None
        d = re.sub(r'^\*?\.', '', n)
        if h == d or h.endswith('.' + d):
            return None
    u = urllib.parse.urlsplit(p if re.match(r'^[a-z]+://', p, re.I) else 'http://' + p)
    if u.scheme != 'http' or not u.hostname:
        note('ignoring HTTPS_PROXY %s, only http:// proxies are supported' % p)
        return None
    return u


def _tcp_connect(host, port):
    proxy = proxy_for(host)
    if proxy is None:
        try:
            return socket.create_connection((host, port), timeout=20)
        except OSError as e:
            fail('cannot connect to %s:%d: %s' % (host, port, e.strerror or e), EXIT_NOTFOUND)
    target = ('[%s]' % host if ':' in host else host) + ':%d' % port
    try:
        sock = socket.create_connection((proxy.hostname, proxy.port or 80), timeout=20)
    except OSError as e:
        fail('cannot reach proxy %s: %s' % (proxy.netloc, e.strerror or e), EXIT_NOTFOUND)
    req = 'CONNECT %s HTTP/1.1\r\nHost: %s\r\n' % (target, target)
    if proxy.username:
        cred = urllib.parse.unquote(proxy.username) + ':' + urllib.parse.unquote(proxy.password or '')
        req += 'Proxy-Authorization: Basic ' + base64.b64encode(cred.encode('utf-8')).decode('ascii') + '\r\n'
    sock.sendall((req + '\r\n').encode('latin-1'))
    buf = b''
    while b'\r\n\r\n' not in buf:
        chunk = sock.recv(4096)
        if not chunk or len(buf) > 16384:
            sock.close()
            fail('the proxy closed the connection or sent an oversized reply', EXIT_NOTFOUND)
        buf += chunk
    status = buf.split(b'\r\n', 1)[0].decode('latin-1')
    if not re.match(r'^HTTP/1\.[01] 200', status):
        sock.close()
        fail('the proxy refused the connection: ' + status, EXIT_NOTFOUND)
    if len(buf) > buf.index(b'\r\n\r\n') + 4:
        sock.close()
        fail('the proxy sent data before the TLS handshake', EXIT_NOTFOUND)
    return sock


_contexts = {}


def _ssl_context(verify):
    """One TLS context per mode, built once: loading the system trust store is not free."""
    ctx = _contexts.get(verify)
    if ctx is not None:
        return ctx
    if verify:
        ctx = ssl.create_default_context()
        try:
            # python.org builds on macOS ship without a trust store until "Install Certificates" is run: fall back to
            # certifi when installed, and to the system bundle.
            if ctx.cert_store_stats().get('x509_ca', 0) == 0:
                extra = []
                try:
                    import certifi
                    extra.append(certifi.where())
                except ImportError:
                    pass
                extra += [f for f in ('/etc/ssl/cert.pem',) if os.path.isfile(f)]
                for f in extra:
                    ctx.load_verify_locations(cafile=f)
        except (ssl.SSLError, OSError, ValueError):
            pass
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_alpn_protocols(['http/1.1'])
    except (NotImplementedError, AttributeError):
        pass
    _contexts[verify] = ctx
    return ctx


def _handshake(host, port, verify):
    raw = _tcp_connect(host, port)
    try:
        sock = _ssl_context(verify).wrap_socket(raw, server_hostname=host)
    except BaseException:
        raw.close()
        raise
    der = sock.getpeercert(binary_form=True)
    try:
        fp = cert_pin(der)
    except (ValueError, IndexError, TypeError):
        fp = None
    return sock, fp


def _is_verify_error(e):
    return isinstance(e, CERT_VERIFY_ERRORS) or (isinstance(e, ssl.SSLError) and 'CERTIFICATE_VERIFY_FAILED' in str(e))


class TlsInfo(object):
    def __init__(self, sock, fingerprint, authorized, reason):
        self.sock, self.fingerprint, self.authorized, self.reason = sock, fingerprint, authorized, reason


def connect_tls(url, pin, allow_untrusted=False):
    """Open a TLS connection and decide trust BEFORE anything is written, so credentials never reach an unverified peer.
    Trusted means: a valid CA chain for this host name, or the public key matches the pinned one."""
    sp = server_parts(url)
    host, port = sp['host'], sp['port']
    try:
        seen = None
        if pin:  # The usual case for a self-signed server: one handshake, checked against the stored pin
            sock, fp = _handshake(host, port, False)
            if fp == pin:
                sock.settimeout(None)
                return TlsInfo(sock, fp, False, None)
            sock.close()
            seen = fp
        try:
            sock, fp = _handshake(host, port, True)
            sock.settimeout(None)
            return TlsInfo(sock, fp, True, None)
        except (ssl.SSLError, ValueError) as e:
            if not _is_verify_error(e):
                raise
            reason = getattr(e, 'verify_message', None) or str(e)
        if allow_untrusted:
            sock, fp = _handshake(host, port, False)
            sock.settimeout(None)
            return TlsInfo(sock, fp, False, reason)
        if pin:
            fail('the server certificate does NOT match the pinned key!\n  pinned: %s\n  server: %s\nIt was replaced, or someone is intercepting the connection. If the change is expected, run: meshtunnel login %s' % (pin, seen, url), EXIT_TLS)
        fail('the server certificate is not trusted (%s) and no key is pinned, run: meshtunnel login %s' % (reason, url), EXIT_TLS)
    except MtError:
        raise
    except (OSError, ssl.SSLError) as e:
        fail('cannot connect to %s: %s' % (sp['hostHeader'], getattr(e, 'strerror', None) or e), EXIT_NOTFOUND)


def read_http_head(sock, timeout=20.0):
    """Read an HTTP response head. Returns (status, status_line, headers, rest)."""
    sock.settimeout(timeout)
    buf = b''
    try:
        while b'\r\n\r\n' not in buf:
            chunk = sock.recv(16384)
            if not chunk:
                fail('the server closed the connection', EXIT_NOTFOUND)
            buf += chunk
            if len(buf) > 65536 and b'\r\n\r\n' not in buf:
                fail('the server sent an oversized HTTP header', EXIT_NOTFOUND)
    except SOCKET_TIMEOUT:
        fail('the server did not answer', EXIT_NOTFOUND)
    finally:
        sock.settimeout(None)
    end = buf.index(b'\r\n\r\n')
    lines = buf[:end].decode('latin-1').split('\r\n')
    status_line = lines[0]
    headers = {}
    for line in lines[1:]:
        i = line.find(':')
        if i > 0:
            headers[line[:i].strip().lower()] = line[i + 1:].strip()
    try:
        status = int(status_line.split(' ')[1])
    except (IndexError, ValueError):
        status = 0
    return status, status_line, headers, buf[end + 4:]


def https_request(cfg, method, path_and_query, form=None):
    """A small HTTPS request: (status, status_line, body bytes). Handles Content-Length and chunked bodies."""
    sp = server_parts(cfg['url'])
    sock = connect_tls(cfg['url'], cfg.get('pin')).sock
    try:
        body = urllib.parse.urlencode(form).encode('utf-8') if form is not None else None
        req = '%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: meshtunnel/%s (python)\r\nAccept-Encoding: identity\r\nConnection: close\r\n' % (method, path_and_query, sp['hostHeader'], VERSION)
        if body is not None:
            req += 'Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n' % len(body)
        sock.sendall((req + '\r\n').encode('latin-1') + (body or b''))
        status, status_line, headers, rest = read_http_head(sock)
        chunks = [rest]
        sock.settimeout(30)
        while True:
            try:
                d = sock.recv(65536)
            except OSError:  # Timeouts and TLS errors included
                break
            if not d:
                break
            chunks.append(d)
        data = b''.join(chunks)
        if 'chunked' in headers.get('transfer-encoding', '').lower():
            out, i = [], 0
            while i < len(data):
                eol = data.find(b'\r\n', i)
                if eol < 0:
                    break
                size = int(data[i:eol].split(b';')[0] or b'0', 16)
                if size <= 0:
                    break
                out.append(data[eol + 2:eol + 2 + size])
                i = eol + 2 + size + 2
            data = b''.join(out)
        elif headers.get('content-length') is not None:
            n = int(headers['content-length'])
            if len(data) < n:
                fail('the download was cut short', EXIT_NOTFOUND)
            data = data[:n]
        return status, status_line, data
    finally:
        try:
            sock.close()
        except OSError:
            pass


#
# WebSocket client (RFC 6455). Only what MeshCentral needs. All reads and writes of one connection happen on one thread:
# an OpenSSL connection must not be used from two threads at once.
#

def _mask(data, key):
    n = len(data)
    if n == 0:
        return b''
    k = (key * ((n + 3) // 4))[:n]
    return (int.from_bytes(data, 'big') ^ int.from_bytes(k, 'big')).to_bytes(n, 'big')  # Whole-buffer XOR, in C


class WsConn(object):
    """One WebSocket connection. Once connected its socket is non-blocking: sends are queued in self.out and written as
    fast as the server takes them, so a peer that stops reading can never block this process or deadlock a tunnel."""

    def __init__(self, sock, initial=b''):
        self.sock = sock
        self.buf = bytearray(initial)
        self.out = bytearray()
        self.want = 0               # A TLS write to retry with at least this many bytes (an OpenSSL rule)
        self.closed = False
        self.close_sent = False
        self.close_code = None
        self.error = None           # Why the connection broke, when it did not end normally
        self.fragments = None
        self.frag_opcode = 0
        self.frag_size = 0
        self.last_seen = time.monotonic()
        sock.setblocking(False)

    def fileno(self):
        return self.sock.fileno()

    def has_buffered(self):
        """Decrypted bytes waiting inside the TLS layer: select() cannot see them."""
        try:
            return (not self.closed) and self.sock.pending() > 0
        except (OSError, ValueError, AttributeError):
            return False

    def _send(self, opcode, payload):
        if self.closed:
            return False
        n = len(payload)
        if n < 126:
            head = struct.pack('!BB', 0x80 | opcode, 0x80 | n)
        elif n < 65536:
            head = struct.pack('!BBH', 0x80 | opcode, 0x80 | 126, n)
        else:
            head = struct.pack('!BBQ', 0x80 | opcode, 0x80 | 127, n)
        key = os.urandom(4)
        self.out += head + key
        self.out += _mask(bytes(payload), key)
        self.flush()
        return not self.closed

    def flush(self):
        """Write whatever the socket accepts right now."""
        while self.out and not self.closed:
            n = max(self.want, min(len(self.out), 262144))
            try:
                sent = self.sock.send(self.out[:n])
            except (ssl.SSLWantWriteError, ssl.SSLWantReadError, BlockingIOError, InterruptedError):
                self.want = n
                return
            except (OSError, ValueError) as e:
                self.error = str(e)
                self._finish(1006)
                return
            self.want = 0
            self.last_seen = time.monotonic()  # The server takes data: it is alive even when it has nothing to say
            del self.out[:sent]

    def send_binary(self, data):
        return self._send(0x2, data)

    def send_text(self, text):
        return self._send(0x1, text.encode('utf-8'))

    def ping(self):
        return self._send(0x9, b'')

    def close(self, code=1000):
        if not self.closed and not self.close_sent:
            self.close_sent = True
            self._send(0x8, struct.pack('!H', code))

    def drain(self, timeout):
        """Wait up to timeout seconds for everything queued to be written."""
        deadline = time.monotonic() + timeout
        while self.out and not self.closed:
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            try:
                select.select([], [self.sock], [], left)
            except (OSError, ValueError):
                return False
            self.flush()
        return not self.out

    def _finish(self, code):
        if self.closed:
            return
        self.closed = True
        if self.close_code is None:
            self.close_code = code
        self.out = bytearray()
        try:
            self.sock.close()
        except (OSError, ValueError):
            pass

    def destroy(self):
        self._finish(1006)

    def _recv(self):
        """Take what arrived. Returns False once the connection has ended."""
        try:
            data = self.sock.recv(262144)
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError, InterruptedError):
            return True
        except (OSError, ValueError) as e:
            self.error = str(e)
            return False
        if not data:
            return False
        self.last_seen = time.monotonic()
        self.buf += data
        while True:  # Also take what TLS already decrypted: select() would not report it
            try:
                if self.sock.pending() <= 0:
                    break
                more = self.sock.recv(262144)
            except (OSError, ValueError):
                break
            if not more:
                break
            self.buf += more
        return True

    def read(self, timeout=None):
        """Wait up to timeout seconds (None: no limit) for complete messages and return them as tuples
        ('text', str) | ('binary', bytes) | ('close', code). A close is always the last one."""
        out = self._parse()
        if out or self.closed:
            return out
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            if not self.has_buffered():
                left = None if deadline is None else max(0.0, deadline - time.monotonic())
                try:
                    r, w, _ = select.select([self.sock], [self.sock] if self.out else [], [], left)
                except (OSError, ValueError):
                    r, w = [self.sock], []
                if w:
                    self.flush()
                    if self.closed:
                        return [('close', self.close_code)]
                if not r:
                    if deadline is not None and time.monotonic() >= deadline:
                        return []
                    continue
            if not self._recv():
                self._finish(1006)
                return [('close', 1006)]
            out = self._parse()
            if out or self.closed:
                return out
            if deadline is not None and time.monotonic() >= deadline:
                return []

    def _protocol_error(self, message):
        self._finish(1002)
        raise MtError('WebSocket protocol error: ' + message, EXIT_NOTFOUND)

    def _parse(self):
        out = []
        buf, pos, end = self.buf, 0, len(self.buf)
        try:
            while not self.closed and end - pos >= 2:
                b0, b1 = buf[pos], buf[pos + 1]
                opcode, fin, masked, n = b0 & 0x0f, bool(b0 & 0x80), bool(b1 & 0x80), b1 & 0x7f
                hl = 2
                if b0 & 0x70:
                    self._protocol_error('unexpected extension bits')
                if n == 126:
                    if end - pos < 4:
                        break
                    n = struct.unpack_from('!H', buf, pos + 2)[0]
                    hl = 4
                elif n == 127:
                    if end - pos < 10:
                        break
                    n = struct.unpack_from('!Q', buf, pos + 2)[0]
                    hl = 10
                if n > MAX_MESSAGE:
                    self._protocol_error('frame too large')
                mhl = hl + (4 if masked else 0)
                if end - pos < mhl + n:
                    break
                payload = bytes(buf[pos + mhl:pos + mhl + n])
                if masked:
                    payload = _mask(payload, bytes(buf[pos + hl:pos + hl + 4]))
                pos += mhl + n
                if opcode >= 8:
                    if not fin or n > 125:
                        self._protocol_error('bad control frame')
                    if opcode == 0x8:
                        code = struct.unpack('!H', payload[:2])[0] if len(payload) >= 2 else 1005
                        if not self.close_sent:
                            self.close_sent = True
                            self._send(0x8, payload[:2])
                        self.close_code = code
                        self._finish(code)
                        out.append(('close', code))
                        return out
                    if opcode == 0x9:
                        self._send(0xA, payload)
                    continue
                if opcode == 0:
                    if self.fragments is None:
                        self._protocol_error('unexpected continuation frame')
                    self.fragments.append(payload)
                    self.frag_size += len(payload)
                    if self.frag_size > MAX_MESSAGE:
                        self._protocol_error('message too large')
                    if fin:
                        msg, op = b''.join(self.fragments), self.frag_opcode
                        self.fragments = None
                        out.append(self._message(op, msg))
                    continue
                if opcode not in (1, 2):
                    self._protocol_error('unknown opcode %d' % opcode)
                if self.fragments is not None:
                    self._protocol_error('interleaved messages')
                if fin:
                    out.append(self._message(opcode, payload))
                else:
                    self.fragments = [payload]
                    self.frag_opcode = opcode
                    self.frag_size = len(payload)
        finally:
            if pos and not self.closed:
                del buf[:pos]
        return out

    @staticmethod
    def _message(opcode, payload):
        return ('text', payload.decode('utf-8', 'replace')) if opcode == 1 else ('binary', payload)


def mesh_auth(user, password, token=None):
    b64 = lambda s: base64.b64encode(str(s).encode('utf-8')).decode('ascii')
    return b64(user) + ',' + b64(password) + ((',' + b64(token)) if token is not None else '')


def ws_connect(cfg, path_and_query, headers):
    sp = server_parts(cfg['url'])
    sock = connect_tls(cfg['url'], cfg.get('pin')).sock
    key = base64.b64encode(os.urandom(16)).decode('ascii')
    req = 'GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nUser-Agent: meshtunnel/%s (python)\r\n' % (path_and_query, sp['hostHeader'], key, VERSION)
    for name, value in headers.items():
        req += '%s: %s\r\n' % (name, value)
    try:
        sock.sendall((req + '\r\n').encode('latin-1'))
        status, status_line, hdrs, rest = read_http_head(sock)
    except BaseException:
        sock.close()
        raise
    if status != 101:
        sock.close()
        if status == 404:
            fail('the server answered "404 Not Found" for %s, check the server URL (and the domain path, if any)' % path_and_query.split('?')[0], EXIT_NOTFOUND)
        fail('the server refused the WebSocket: ' + status_line, EXIT_AUTH if status in (401, 403) else EXIT_NOTFOUND)
    expected = base64.b64encode(hashlib.sha1((key + WS_GUID).encode('ascii')).digest()).decode('ascii')
    if hdrs.get('sec-websocket-accept') != expected:
        sock.close()
        fail('the server sent an invalid WebSocket handshake', EXIT_NOTFOUND)
    return WsConn(sock, rest)


#
# MeshCentral control channel (control.ashx)
#

def auth_error(m):
    cause, msg = m.get('cause'), m.get('msg')
    if cause == 'banned':
        return MtError('the server is refusing logins from this IP address for a while, after too many failures', EXIT_AUTH)
    if cause == 'notools':
        return MtError('this account is not allowed to use MeshCentral tools, ask the administrator', EXIT_AUTH)
    if cause == 'emailvalidation':
        return MtError('this account must verify its email address first, log in to the web UI once', EXIT_AUTH)
    if cause == 'expired':
        return MtError('the session expired, run: meshtunnel login', EXIT_AUTH)
    if msg == 'tokenrequired':
        return MtError('a two-factor code is required', EXIT_AUTH, twoFactor=True, email2fa=(m.get('email2fa') is True), sms2fa=(m.get('sms2fa') is True), msg2fa=(m.get('msg2fa') is True))
    return MtError('authentication failed (%s): wrong credentials, or the login token was revoked or has expired; run: meshtunnel login' % (msg or cause), EXIT_AUTH)


class Control(object):
    def __init__(self, ws):
        self.ws = ws
        self.close_info = None
        self.serverinfo = None
        self.userinfo = None
        self.backlog = []

    def _handle(self, m):
        a = m.get('action')
        if a == 'close':
            self.close_info = m
        elif a == 'serverinfo':
            self.serverinfo = m.get('serverinfo')
        elif a == 'userinfo':
            self.userinfo = m.get('userinfo')

    def _closed_error(self):
        if self.close_info is not None:
            return auth_error(self.close_info)
        return MtError('the server closed the connection', EXIT_NOTFOUND)

    def poll(self, timeout=0):
        """Read what is available (up to timeout seconds) and return the JSON messages."""
        out = []
        for kind, value in self.ws.read(timeout):
            if kind == 'close':
                break
            if kind != 'text':
                continue
            try:
                m = json.loads(value)
            except ValueError:
                continue
            if isinstance(m, dict):
                self._handle(m)
                out.append(m)
        return out

    def wait(self, match, timeout=20.0):
        deadline = time.monotonic() + timeout
        while True:
            for i, m in enumerate(self.backlog):
                if match(m):
                    del self.backlog[i]
                    return m
            if self.ws.closed:
                raise self._closed_error()
            left = deadline - time.monotonic()
            if left <= 0:
                fail('the server did not answer in time', EXIT_NOTFOUND)
            self.backlog.extend(self.poll(left))
            del self.backlog[:-200]

    def send(self, obj):
        self.ws.send_text(json.dumps(obj))

    def request(self, obj, match, timeout=20.0):
        self.send(obj)
        return self.wait(match, timeout)

    def close(self):
        self.ws.close(1000)
        self.ws.destroy()


def control_connect(cfg, user, password, token=None):
    q = ('?key=' + urllib.parse.quote(cfg['loginkey'], safe='')) if cfg.get('loginkey') else ''
    ws = ws_connect(cfg, server_parts(cfg['url'])['basePath'] + 'control.ashx' + q, {'x-meshauth': mesh_auth(user, password, token)})
    ctl = Control(ws)
    try:
        ctl.wait(lambda m: m.get('action') == 'userinfo', 20.0)  # Sent right after "serverinfo" once logged in
    except BaseException:
        ws.destroy()
        raise
    return ctl


#
# Setup codes and token revocation (see meshtunnelenroll.js on the server)
#

def key_query(cfg):
    return ('?key=' + urllib.parse.quote(cfg['loginkey'], safe='')) if cfg.get('loginkey') else ''


def _json_or_none(data):
    try:
        v = json.loads(data.decode('utf-8'))
        return v if isinstance(v, dict) else None
    except (ValueError, UnicodeDecodeError):
        return None


def redeem_setup_code(cfg, code, previous):
    form = {'code': code, 'name': ('meshtunnel@' + socket.gethostname())[:100]}
    if previous and previous.get('createdToken') is True and previous.get('url') == cfg['url'] and isinstance(previous.get('user'), str) and isinstance(previous.get('pass'), str):
        form['replaceuser'] = previous['user']
        form['replacepass'] = previous['pass']
    status, status_line, body = https_request(cfg, 'POST', server_parts(cfg['url'])['basePath'] + 'meshtunnel-redeem' + key_query(cfg), form)
    j = _json_or_none(body)
    if status == 200 and j and isinstance(j.get('user'), str) and isinstance(j.get('pass'), str):
        return j
    if status == 404:
        fail('this server does not accept setup codes (is it older than this tool?), sign in with your password instead: meshtunnel login ' + cfg['url'], EXIT_AUTH)
    fail(j['error'] if j and j.get('error') else 'the server refused the setup code: ' + status_line, EXIT_AUTH)


def revoke_token(cfg):
    """True when the server removed the stored token (or no longer knows it), None for an older server without the endpoint."""
    status, status_line, body = https_request(cfg, 'POST', server_parts(cfg['url'])['basePath'] + 'meshtunnel-revoke' + key_query(cfg), {'user': cfg['user'], 'pass': cfg['pass']})
    if status in (200, 403):
        return True
    if status == 404:
        return None
    j = _json_or_none(body)
    fail(j['error'] if j and j.get('error') else 'the server answered ' + status_line, EXIT_AUTH)


def revoke_stored_token(cfg):
    r = revoke_token(cfg)
    if r is not None:
        return r
    ctl = control_connect(cfg, cfg['user'], cfg['pass'])  # Older server: ask over the control channel
    try:
        lst = ctl.request({'action': 'loginTokens', 'remove': [cfg['user']]}, lambda m: m.get('action') == 'loginTokens', 15.0)
        return not any(t.get('tokenUser') == cfg['user'] for t in (lst.get('loginTokens') or []))
    finally:
        ctl.close()


#
# Devices
#

def is_windows_agent(agent):
    return isinstance(agent, dict) and agent.get('id') in (1, 2, 3, 4, 21, 22, 34, 42, 43)


def slugify(name):
    """Same rule as meshTunnelSlug() in the web UI and slugify() in meshtunnel.js: keep them in sync."""
    s = unicodedata.normalize('NFKD', str(name if name is not None else ''))
    s = re.sub('[\u0300-\u036f]', '', s).lower()
    s = re.sub(r'[^a-z0-9._-]+', '-', s)
    s = re.sub(r'^[-.]+|[-.]+$', '', s)
    return s or 'device'


def id_hex(node_id):
    b = str(node_id).split('/')[-1].replace('@', '+').replace('$', '/')
    try:
        return base64.b64decode(b + '=' * (-len(b) % 4)).hex()
    except (ValueError, TypeError):
        return ''


def assign_handles(devices):
    count = {}
    for d in devices:
        d['slug'] = slugify(d['name'])
        count[d['slug']] = count.get(d['slug'], 0) + 1
    for d in devices:
        d['handle'] = (d['slug'] + '-' + id_hex(d['id'])[:6]) if count[d['slug']] > 1 else d['slug']


def device_cache_file():
    return os.path.join(cache_dir(), 'devices.json')


def cache_key(cfg):
    return hashlib.sha256((cfg['url'] + '\n' + cfg['user']).encode('utf-8')).hexdigest()


def load_device_cache(cfg):
    try:
        with open(device_cache_file(), 'r', encoding='utf-8') as f:
            c = json.load(f)
        if c.get('key') == cache_key(cfg) and isinstance(c.get('devices'), list):
            return c['devices']
    except (OSError, ValueError, AttributeError):
        pass
    return None


def save_device_cache(cfg, devices):
    try:
        mkdirp(cache_dir(), 0o700)
        write_file_atomic(device_cache_file(), json.dumps({'key': cache_key(cfg), 'time': int(time.time() * 1000), 'devices': devices}), 0o600)
    except OSError:
        pass


def fetch_devices(cfg):
    ctl = control_connect(cfg, cfg['user'], cfg['pass'])
    try:
        meshes = ctl.request({'action': 'meshes'}, lambda m: m.get('action') == 'meshes', 30.0)
        nodes = ctl.request({'action': 'nodes', 'responseid': 'meshtunnel'}, lambda m: m.get('action') == 'nodes' and m.get('responseid') == 'meshtunnel', 30.0)
    finally:
        ctl.close()
    if nodes.get('result') not in (None, 'ok'):
        fail('the server refused the device list: %s' % nodes.get('result'), EXIT_AUTH)
    groups = dict((m.get('_id'), m.get('name') or '') for m in (meshes.get('meshes') or []) if isinstance(m, dict))
    devices = []
    for meshid, lst in (nodes.get('nodes') or {}).items():
        for n in lst or []:
            if not isinstance(n, dict) or not isinstance(n.get('_id'), str):
                continue
            devices.append({'id': n['_id'], 'name': str(n['name'] if n.get('name') is not None else n['_id']), 'group': groups.get(meshid, ''), 'os': n.get('osdesc') or '', 'conn': n.get('conn') or 0, 'windows': is_windows_agent(n.get('agent'))})
    assign_handles(devices)
    devices.sort(key=lambda d: (d['group'].casefold(), d['name'].casefold()))
    save_device_cache(cfg, devices)
    return devices


def match_device(devices, query):
    q = re.sub(r'\.mesh$', '', str(query).strip(), flags=re.I).lower()

    def ambiguous(m):
        fail('"%s" matches %d devices, use one of: %s' % (query, len(m), ', '.join(d['handle'] + (' (%s)' % d['group'] if d['group'] else '') for d in m)), EXIT_NOTFOUND)
    m = [d for d in devices if d.get('handle') == q]
    if len(m) == 1:
        return m[0]
    m = [d for d in devices if d['name'].lower() == q]
    if len(m) == 1:
        return m[0]
    if len(m) > 1:
        ambiguous(m)
    m = [d for d in devices if d.get('slug') == q]
    if len(m) == 1:
        return m[0]
    if len(m) > 1:
        ambiguous(m)
    return None


def get_device(cfg, query):
    if not query:
        fail('missing device: a handle from "meshtunnel ls", a device name or a node id')
    if query.startswith('node/'):
        for d in load_device_cache(cfg) or []:
            if d.get('id') == query:
                return d
        return {'id': query, 'name': query, 'handle': query, 'group': '', 'conn': 1, 'windows': False}
    cached = load_device_cache(cfg)
    found = match_device(cached, query) if cached is not None else None
    if found is None:
        found = match_device(fetch_devices(cfg), query)
    if found is None:
        fail('no device matches "%s", see: meshtunnel ls' % query, EXIT_NOTFOUND)
    return found


#
# Relay sessions
#

def wait_relay_start(ws, timeout, route_error=None):
    """Return once the server says both sides are joined ("c", or "cr" when the session is recorded). Anything that came
    after it is kept for the caller. route_error() may report that the server refused to route the request."""
    deadline = time.monotonic() + timeout
    close_info = None
    while True:
        if route_error is not None:
            e = route_error()
            if e is not None:
                ws.destroy()
                raise e
        left = deadline - time.monotonic()
        if left <= 0:
            ws.destroy()
            raise MtError('timed out waiting for the device', EXIT_NOTFOUND, relayEarly=True, timedOut=True)
        msgs = ws.read(min(left, 0.25) if route_error is not None else left)
        for i, (kind, value) in enumerate(msgs):
            if kind == 'text' and value in ('c', 'cr'):
                return msgs[i + 1:]
            if kind == 'text' and value.startswith('{'):
                try:
                    m = json.loads(value)
                    if isinstance(m, dict) and m.get('action') == 'close':
                        close_info = m
                except ValueError:
                    pass
            if kind == 'close':
                if close_info is not None:
                    raise auth_error(close_info)
                raise MtError('the relay closed before the device answered', EXIT_NOTFOUND, relayEarly=True)


def explain_tunnel_failure(cfg, dev, err, for_shell):
    """The server closes a relay it will not route without saying why: find the reason from the device list."""
    if not getattr(err, 'relayEarly', False):
        return err
    try:
        devices = fetch_devices(cfg)
    except MtError as e:
        return e
    d = next((x for x in devices if x['id'] == dev['id']), None)
    if d is None:
        return MtError('%s is not visible to this account anymore (removed, or access was revoked)' % dev['name'], EXIT_NOTFOUND)
    if not (d['conn'] & 1):
        return MtError('%s is offline: its agent is not connected to the server' % d['name'], EXIT_NOTFOUND)
    if getattr(err, 'timedOut', False):
        return MtError('%s did not answer the tunnel request in time, try again' % d['name'], EXIT_NOTFOUND)
    if for_shell:
        return MtError('the server refused the terminal on %s: this account needs "Remote Control" without the "No Terminal" restriction' % d['name'], EXIT_AUTH)
    return MtError('the server refused the tunnel to %s: this account needs "Remote Control" or "Relay" rights on it' % d['name'], EXIT_AUTH)


def parse_port(value, what='port'):
    try:
        p = int(str(value).strip())
    except ValueError:
        p = -1
    if str(p) != str(value).strip() or p < 1 or p > 65535:
        fail('invalid %s: %s' % (what, value))
    return p


def parse_target_host(value):
    if value is None:
        return None
    if not re.match(r'^[A-Za-z0-9.:_-]{1,253}$', value):
        fail('invalid --to host: %s' % value)
    return value


def open_port_tunnel(cfg, dev, port, to_host):
    """A relay to a TCP port on the device (or on another host of its network), in its data phase."""
    q = 'nodeid=' + urllib.parse.quote(dev['id'], safe='') + '&tcpport=%d' % port
    if to_host is not None:
        q += '&tcpaddr=' + urllib.parse.quote(to_host, safe='')
    try:
        ws = ws_connect(cfg, server_parts(cfg['url'])['basePath'] + 'meshrelay.ashx?' + q, {'x-meshauth': mesh_auth(cfg['user'], cfg['pass'])})
        early = wait_relay_start(ws, RELAY_TIMEOUT)
    except MtError as e:
        raise explain_tunnel_failure(cfg, dev, e, False)
    return ws, early


def refused_message(dev, port, to_host):
    return 'nothing answered on %s:%d of %s (refused, or closed at once). Is the %s running there?' % (to_host or '127.0.0.1', port, dev['name'], 'SSH server (sshd)' if port == 22 else 'service')


def write_all(fd, data):
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


HIGH_WATER = 4 * 1024 * 1024  # Stop reading a side while this much of its data waits for the other side


class StdioEnd(object):
    """stdin/stdout of the ssh ProxyCommand. Writes block: ssh always reads what its proxy prints."""

    def __init__(self):
        self.in_fd = sys.stdin.fileno()
        self.out_fd = sys.stdout.fileno()
        self.broken = False

    def read(self):
        try:
            return os.read(self.in_fd, 65536)
        except (BlockingIOError, InterruptedError):
            return None
        except OSError:
            return b''

    def write(self, data):
        if not self.broken:
            try:
                write_all(self.out_fd, data)
            except OSError:  # The ssh client went away
                self.broken = True

    def flush(self):
        pass

    def pending(self):
        return 0


class SocketEnd(object):
    """A local connection of "forward": non-blocking, with its own output queue."""

    def __init__(self, sock):
        sock.setblocking(False)
        self.sock = self.in_fd = self.out_fd = sock
        self.out = bytearray()
        self.broken = False

    def read(self):
        try:
            return self.sock.recv(65536)
        except (BlockingIOError, InterruptedError):
            return None
        except OSError:
            return b''

    def write(self, data):
        self.out += data
        self.flush()

    def flush(self):
        while self.out and not self.broken:
            try:
                n = self.sock.send(self.out)
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                self.broken = True
                self.out = bytearray()
                return
            del self.out[:n]

    def pending(self):
        return len(self.out)


def pump(ws, early, end):
    """Move data between a relay and a local end until either side is done, with back pressure both ways.
    Returns (bytes received from the device, whether the local input ended)."""
    received, input_open, drained_at = 0, True, None
    last_ping = time.monotonic()
    for kind, value in early:
        if kind == 'binary' and value:
            received += len(value)
            end.write(value)
    while not ws.closed and not end.broken:
        rl = [ws] if end.pending() < HIGH_WATER else []
        if input_open and len(ws.out) < HIGH_WATER:
            rl.append(end.in_fd)
        wl = ([ws] if ws.out else []) + ([end.out_fd] if end.pending() else [])
        busy = (ws in rl) and ws.has_buffered()
        try:
            r, w, _ = select.select(rl, wl, [], 0 if busy else 1.0)
        except (OSError, ValueError):
            break
        if ws in w:
            ws.flush()
        if end.out_fd in w:
            end.flush()
        if ws in r or busy:
            for kind, value in ws.read(0):
                if kind == 'binary' and value:
                    received += len(value)
                    end.write(value)
        if input_open and end.in_fd in r:
            data = end.read()
            if data:
                ws.send_binary(data)
            elif data is not None:
                input_open = False
                ws.close(1000)
        now = time.monotonic()
        if not input_open and not ws.out:
            # All sent: give the server a moment to answer the close, MeshCentral may hold a relay socket open.
            if drained_at is None:
                drained_at = now
            elif now - drained_at > 1.5:
                break
        if ws not in rl:
            ws.last_seen = now  # Not reading on purpose (the local side is slow): nothing to judge
        if now - last_ping >= 30:
            last_ping = now
            if now - ws.last_seen > 90:
                ws.destroy()
                raise MtError('the server stopped responding', EXIT_NOTFOUND)
            ws.ping()
    ws.destroy()
    # The relay can end right after its last data: hand what is still queued to the local side first.
    deadline = time.monotonic() + 30
    while end.pending() and not end.broken and time.monotonic() < deadline:
        try:
            select.select([], [end.out_fd], [], 1.0)
        except (OSError, ValueError):
            break
        end.flush()
    return received, not input_open


#
# Prompts
#

def is_interactive():
    try:
        return sys.stdin.isatty() and sys.stderr.isatty()
    except (AttributeError, ValueError):
        return False


def prompt(question, secret=False):
    if secret:
        import getpass
        try:
            return getpass.getpass(question, stream=sys.stderr)
        except (EOFError, KeyboardInterrupt):
            err_write('\n')
            fail('aborted')
    err_write(question)
    line = sys.stdin.readline()
    if line == '':
        fail('aborted')
    return line.rstrip('\r\n')


#
# Commands
#

def cmd_login(a):
    if len(a['_']) != 1:
        fail('usage: meshtunnel login <server-url> [--pin sha256//...] [--code CODE | --user name] [--expire-days N]')
    server = parse_server_url(a['_'][0])
    previous = load_config(False)
    pin = normalize_pin(a['flags']['pin']) if a['flags'].get('pin') is not None else None
    expire_days = 0
    if a['flags'].get('expire-days') is not None:
        try:
            expire_days = int(a['flags']['expire-days'])
        except ValueError:
            expire_days = -1
        if expire_days < 0:
            fail('invalid --expire-days')

    # Decide whether to trust the server before sending anything to it.
    probe = connect_tls(server['url'], None, True)
    probe.sock.close()
    if not probe.authorized:
        if pin is not None:
            if pin != probe.fingerprint:
                fail('the server certificate does not match --pin\n  --pin:  %s\n  server: %s' % (pin, probe.fingerprint), EXIT_TLS)
        else:
            note('the certificate of %s is not signed by a trusted authority (%s)' % (server_parts(server['url'])['hostHeader'], probe.reason))
            note('its public key fingerprint is ' + str(probe.fingerprint))
            if not is_interactive():
                fail('not trusting it without confirmation; if that fingerprint is right, run again with --pin ' + str(probe.fingerprint), EXIT_TLS)
            answer = prompt('Check it against the fingerprint shown in the web UI (Terminal tab > Local Terminal). Trust it (yes/no)? ')
            if not re.match(r'^y(es)?$', answer.strip(), re.I):
                fail('aborted', EXIT_TLS)
            pin = probe.fingerprint

    cfg = {'url': server['url'], 'loginkey': server['loginkey'], 'pin': pin}
    if a['flags'].get('code') is not None:
        r = redeem_setup_code(cfg, str(a['flags']['code']).strip(), previous)
        return finish_login(dict(cfg, user=r['user'], **{'pass': r['pass'], 'tokenName': r.get('name'), 'createdToken': True, 'account': r.get('account')}), True)

    user = str(a['flags']['user']) if a['flags'].get('user') is not None else prompt('Username (or a ~t: login token): ').strip()
    if user == '':
        fail('no username given')
    password = prompt('Token password: ' if user.startswith('~t:') else 'Password: ', True)

    if user.startswith('~t:'):
        # A login token made in the web UI (My Account > Login Tokens), for accounts that use SSO or hardware keys.
        ctl = control_connect(cfg, user, password)
        account = (ctl.userinfo or {}).get('name')
        ctl.close()
        return finish_login(dict(cfg, user=user, account=account, **{'pass': password}), False)

    token, ctl = None, None
    attempt = 0
    while True:
        try:
            ctl = control_connect(cfg, user, password, token)
            break
        except MtError as e:
            if not getattr(e, 'twoFactor', False) or attempt >= 5:
                raise
            attempt += 1
            if not is_interactive():
                fail('this account uses two-factor authentication: log in from a terminal, or use a setup code from the web UI (Terminal tab > Local Terminal)', EXIT_AUTH)
            ways = [w for w, on in (('"email"', getattr(e, 'email2fa', False)), ('"sms"', getattr(e, 'sms2fa', False)), ('"msg"', getattr(e, 'msg2fa', False))) if on]
            code = prompt('Two-factor code' + ((' (or %s to receive one)' % ', '.join(ways)) if ways else '') + ': ').strip()
            token = {'email': '**email**', 'sms': '**sms**', 'msg': '**msg**'}.get(code.lower(), code)
    account = (ctl.userinfo or {}).get('name') or user
    token_name = ('meshtunnel@' + socket.gethostname())[:100]
    try:
        r = ctl.request({'action': 'createLoginToken', 'name': token_name, 'expire': expire_days * 1440, 'responseid': 'meshtunnel'}, lambda m: m.get('action') == 'createLoginToken', 20.0)
        # Logging in again replaces the token this tool made before: revoke that one rather than leave it valid and forgotten.
        if r.get('tokenUser') and previous and previous.get('createdToken') is True and previous.get('url') == cfg['url'] and isinstance(previous.get('user'), str) and previous['user'] != r['tokenUser']:
            try:
                ctl.request({'action': 'loginTokens', 'remove': [previous['user']]}, lambda m: m.get('action') == 'loginTokens', 10.0)
            except MtError:
                pass
    finally:
        ctl.close()
    if not r.get('tokenUser') or not r.get('tokenPass'):
        fail('the server refused to create a login token (%s). An administrator can allow them (domains > passwordRequirements > loginTokens); a setup code from the web UI or an existing token from My Account > Login Tokens also works.' % (r.get('result') or 'no reason given'), EXIT_AUTH)
    return finish_login(dict(cfg, user=r['tokenUser'], tokenName=token_name, createdToken=True, account=account, **{'pass': r['tokenPass']}), False)


def finish_login(saved, quiet):
    path = save_config(saved)
    devices = fetch_devices(saved)
    online = len([d for d in devices if d['conn'] & 1])
    err_write('Logged in to %s as %s, %d device(s), %d online.\n' % (saved['url'], saved.get('account') or 'token user', len(devices), online))
    err_write('The %s is stored in %s, revoke it any time in My Account > Login Tokens%s.\n' % (('login token "%s"' % saved.get('tokenName')) if saved.get('createdToken') else 'login token', path, ' or with: meshtunnel logout' if saved.get('createdToken') else ''))
    if not quiet and not os.path.exists(os.path.join(home(), '.ssh', 'meshtunnel.conf')):
        err_write('Next: meshtunnel ssh-config --install   (then: ssh <user>@<device>.mesh)\n')
    return EXIT_OK


def cmd_logout(a):
    cfg = load_config(False)
    if cfg is None:
        note('not logged in')
        return EXIT_OK
    revoked = False
    if cfg.get('createdToken') is True:
        try:
            revoked = revoke_stored_token(cfg)
        except MtError as e:
            note('could not revoke the login token on the server: ' + e.message)
    for f in (config_file(), device_cache_file()):
        try:
            os.unlink(f)
        except OSError:
            pass
    if revoked:
        note('logged out, login token "%s" revoked' % cfg.get('tokenName'))
    else:
        note('logged out on this computer' + ((', revoke login token "%s" in My Account > Login Tokens' % cfg['tokenName']) if cfg.get('tokenName') else ''))
    return EXIT_OK


def safe_print(text):
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())  # e.g. "meshtunnel ls | head": exit quietly
        except OSError:
            pass


def cmd_ls(a):
    cfg = load_config(True)
    devices = fetch_devices(cfg)
    if a['_']:
        f = ' '.join(a['_']).lower()
        devices = [d for d in devices if f in d['handle'] or f in d['name'].lower() or f in d['group'].lower()]
    if a['flags'].get('json'):
        safe_print(json.dumps([{'handle': d['handle'], 'name': d['name'], 'group': d['group'], 'os': d['os'], 'online': bool(d['conn'] & 1), 'id': d['id']} for d in devices], indent=2) + '\n')
        return EXIT_OK
    rows = [['HANDLE', 'NAME', 'GROUP', 'OS', 'STATE']] + [[d['handle'], d['name'], d['group'], d['os'], 'online' if d['conn'] & 1 else 'offline'] for d in devices]
    widths = [min(max(len(r[i]) for r in rows), 40) for i in range(4)]
    lines = []
    for r in rows:
        line = ''
        for i in range(4):
            c = r[i] if len(r[i]) <= 40 else r[i][:39] + '~'
            line += c + ' ' * (widths[i] - len(c) + 2)
        lines.append(line + r[4])
    safe_print('\n'.join(lines) + '\n')
    if not devices:
        note('no devices')
    return EXIT_OK


def cmd_proxy(a):
    if len(a['_']) < 1 or len(a['_']) > 2:
        fail('usage: meshtunnel proxy <device> [port] [--to host]')
    cfg = load_config(True)
    port = parse_port(a['_'][1] if len(a['_']) > 1 else '22')
    to_host = parse_target_host(a['flags'].get('to'))
    dev = get_device(cfg, a['_'][0])
    ws, early = open_port_tunnel(cfg, dev, port, to_host)
    started = time.monotonic()
    try:
        received, input_ended = pump(ws, early, StdioEnd())
    except MtError as e:
        note(e.message)
        return e.code
    if received == 0 and not input_ended and time.monotonic() - started < 15:
        note(refused_message(dev, port, to_host))
        return EXIT_REFUSED
    return EXIT_OK


def cmd_forward(a):
    if len(a['_']) != 3:
        fail('usage: meshtunnel forward <local-port> <device> <remote-port> [--bind address] [--to host]')
    cfg = load_config(True)
    lport = 0 if a['_'][0] == '0' else parse_port(a['_'][0], 'local port')
    rport = parse_port(a['_'][2], 'remote port')
    bind = str(a['flags']['bind']) if a['flags'].get('bind') is not None else '127.0.0.1'
    to_host = parse_target_host(a['flags'].get('to'))
    devices = fetch_devices(cfg)  # Also proves the login still works before listening
    dev = match_device(devices, a['_'][1]) or ({'id': a['_'][1], 'name': a['_'][1], 'conn': 1} if a['_'][1].startswith('node/') else None)
    if dev is None:
        fail('no device matches "%s", see: meshtunnel ls' % a['_'][1], EXIT_NOTFOUND)
    if not (dev['conn'] & 1):
        note('warning: %s is offline right now, connections will fail until its agent is back' % dev['name'])
    target = dev['name'] + ':' + ((to_host + ':') if to_host else '') + str(rport)
    try:
        server = _listen(bind, lport)
    except OSError as e:
        fail('cannot listen on %s:%d: %s' % (bind, lport, e.strerror or e))
    stop = {'code': None}

    def serve(client, addr):
        label = '%s:%d' % (addr[0], addr[1])
        try:
            try:
                ws, early = open_port_tunnel(cfg, dev, rport, to_host)
            except MtError as e:
                note(label + ': ' + e.message)
                if e.code == EXIT_AUTH:
                    note('stopping, the server no longer accepts this login')
                    stop['code'] = EXIT_AUTH
                return
            try:
                received, _ = pump(ws, early, SocketEnd(client))
                if received == 0:
                    note(label + ': ' + refused_message(dev, rport, to_host))
            except MtError as e:
                note(label + ': ' + e.message)
        finally:
            try:
                client.close()
            except OSError:
                pass

    note('forwarding %s:%d -> %s, press Ctrl-C to stop' % (bind, server.getsockname()[1], target))
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, lambda signum, frame: stop.update(code=EXIT_OK))
    try:
        server.settimeout(0.5)
        while stop['code'] is None:
            try:
                client, addr = server.accept()
            except SOCKET_TIMEOUT:
                continue
            except InterruptedError:
                continue
            t = threading.Thread(target=serve, args=(client, addr))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
    return stop['code'] if stop['code'] is not None else EXIT_OK


def _listen(bind, port):
    info = socket.getaddrinfo(bind, port, 0, socket.SOCK_STREAM, 0, socket.AI_PASSIVE)[0]
    s = socket.socket(info[0], socket.SOCK_STREAM)
    try:
        if not IS_WINDOWS:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(info[4])
        s.listen(16)
    except BaseException:
        s.close()
        raise
    return s


def cmd_shell(a):
    hold = a['flags'].get('hold-on-error') is True
    try:
        code = run_shell(a)
    except MtError as e:
        if not hold or not is_interactive():
            raise
        note(e.message)  # Opened from a meshtunnel:// link: keep the error on screen instead of closing the window at once
        hold_window()
        return e.code
    if hold and code != EXIT_OK and is_interactive():
        hold_window()
    return code


def hold_window():
    try:
        prompt('Press Enter to close this window.', True)
    except MtError:
        pass


def run_shell(a):
    if len(a['_']) != 1:
        fail('usage: meshtunnel shell <device> [--user] [--powershell] [--login]')
    if IS_WINDOWS:
        fail('on Windows, use the PowerShell client (meshtunnel.ps1) or the Node.js client (meshtunnel.js) for the agent shell')
    cfg = load_config(True)
    dev = get_device(cfg, a['_'][0])
    protocol = 1
    if a['flags'].get('powershell'):
        protocol = 9 if a['flags'].get('user') else 6
    elif a['flags'].get('user'):
        protocol = 8
    base = server_parts(cfg['url'])['basePath']
    ctl = control_connect(cfg, cfg['user'], cfg['pass'])
    try:
        cookie = ctl.request({'action': 'authcookie'}, lambda m: m.get('action') == 'authcookie', 20.0)
        rid = os.urandom(8).hex()
        ctl.send({'action': 'msg', 'type': 'tunnel', 'nodeid': dev['id'], 'usage': protocol, 'responseid': 'meshtunnel', 'value': '*' + base + 'meshrelay.ashx?p=%d&nodeid=%s&id=%s&rauth=%s' % (protocol, urllib.parse.quote(dev['id'], safe=''), rid, urllib.parse.quote(str(cookie.get('rcookie')), safe=''))})
        ws = ws_connect(cfg, base + 'meshrelay.ashx?browser=1&p=%d&nodeid=%s&id=%s' % (protocol, urllib.parse.quote(dev['id'], safe=''), rid), {'x-meshauth': mesh_auth(cfg['user'], cfg['pass'])})

        # The server answers "OK" right away and "Unable to route" once its rights check fails, so only a failure counts.
        def route_error():
            for m in ctl.poll(0):
                if m.get('action') == 'msg' and m.get('responseid') == 'meshtunnel' and m.get('result') != 'OK':
                    return MtError('the server would not route the terminal request to %s' % dev['name'], EXIT_NOTFOUND, relayEarly=True)
            return None
        try:
            early = wait_relay_start(ws, RELAY_TIMEOUT, route_error)
        except MtError as e:
            raise explain_tunnel_failure(cfg, dev, e, True)
    except BaseException:
        ctl.close()
        raise
    try:
        return terminal_session(ws, early, ctl, dev, protocol, a['flags'].get('login') is True)
    finally:
        ctl.close()


def terminal_session(ws, early, ctl, dev, protocol, require_login):
    import termios
    import tty as ttymod
    stdin_fd, stdout_fd = sys.stdin.fileno(), sys.stdout.fileno()
    is_tty = os.isatty(stdin_fd) and os.isatty(stdout_fd)
    saved_attrs = None
    wake_r, wake_w = os.pipe()
    os.set_blocking(wake_r, False)
    os.set_blocking(wake_w, False)
    old_wakeup = signal.set_wakeup_fd(wake_w)
    events = {'resize': False, 'stop': None}

    def on_signal(signum, frame):
        if signum == getattr(signal, 'SIGWINCH', None):
            events['resize'] = True
        else:
            events['stop'] = signum
    old_handlers = {}
    for name in ('SIGWINCH', 'SIGHUP', 'SIGTERM'):
        sig = getattr(signal, name, None)
        if sig is not None:
            old_handlers[sig] = signal.signal(sig, on_signal)

    def size():
        try:
            s = os.get_terminal_size(stdout_fd)
            return s.columns, s.lines
        except OSError:
            return 80, 24

    closing = {'at': None}

    def disconnect():
        if closing['at'] is None:
            closing['at'] = time.monotonic()
            ws.send_text(json.dumps({'ctrlChannel': CTRL, 'type': 'close'}))
            ws.close(1000)

    def output(data):
        try:
            write_all(stdout_fd, data)
        except OSError:
            ws.destroy()

    code, message = EXIT_OK, 'Connection to %s closed.' % dev['name']
    try:
        cols, rows = size()
        opts = {'ctrlChannel': CTRL, 'type': 'options', 'cols': cols, 'rows': rows}
        if require_login:
            opts['requireLogin'] = True
        ws.send_text(json.dumps(opts))  # Terminal options first, then the protocol number: the order the web UI uses
        ws.send_text(str(protocol))
        if is_tty:
            saved_attrs = termios.tcgetattr(stdin_fd)
            ttymod.setraw(stdin_fd)
        at_line_start, tilde, input_open = True, False, True
        last_output = last_ping = time.monotonic()
        last_eot, eot_tries = 0.0, 0
        pending = list(early)
        while True:
            for kind, value in pending:
                if kind == 'binary':
                    last_output = time.monotonic()
                    output(value)
                elif kind == 'text':
                    if value in ('c', 'cr'):
                        continue
                    last_output = time.monotonic()
                    if value.startswith('{'):
                        try:
                            m = json.loads(value)
                        except ValueError:
                            m = None
                        if isinstance(m, dict) and str(m.get('ctrlChannel')) == CTRL:
                            if m.get('type') == 'ping':
                                ws.send_text(json.dumps({'ctrlChannel': CTRL, 'type': 'pong'}))
                            elif m.get('type') == 'console' and m.get('msg'):
                                err_write(('\r\n' if is_tty else '') + '[' + str(m['msg']) + ']' + ('\r\n' if is_tty else '\n'))
                            continue
                    output(value.encode('utf-8'))
            pending = []
            if ws.closed:
                if ws.error is not None and closing['at'] is None:
                    code, message = EXIT_NOTFOUND, 'meshtunnel: connection lost: ' + ws.error
                break
            now = time.monotonic()
            if closing['at'] is not None and now - closing['at'] > 1.5:
                break  # MeshCentral may never answer the close
            if events['stop'] is not None:
                disconnect()
                code, message = 128 + events['stop'], None
                break
            if events['resize']:
                events['resize'] = False
                cols, rows = size()
                ws.send_text(json.dumps({'ctrlChannel': CTRL, 'type': 'termsize', 'cols': cols, 'rows': rows}))
            rlist = [ws, wake_r] + ([] if ctl.ws.closed else [ctl.ws])
            if input_open and closing['at'] is None and len(ws.out) < HIGH_WATER:
                rlist.append(stdin_fd)
            wlist = [c for c in (ws, ctl.ws) if c.out and not c.closed]
            try:
                r, w, _ = select.select(rlist, wlist, [], 0 if ws.has_buffered() else 0.25)
            except (OSError, ValueError):
                break
            for c in w:
                c.flush()
            if wake_r in r:
                try:
                    os.read(wake_r, 512)
                except OSError:
                    pass
            if ctl.ws in r:
                ctl.poll(0)  # Keep the control channel drained; nothing in it matters here
            if ws in r or ws.has_buffered():
                pending = ws.read(0)
            if stdin_fd in r:
                data = os.read(stdin_fd, 65536)
                if not data:
                    input_open = False
                elif not is_tty:
                    ws.send_binary(data)
                else:
                    # ssh-style escapes, only right after a newline: "~." disconnects, "~~" sends a single "~", "~?" lists them.
                    out = bytearray()
                    quit_now = False
                    for b in data:
                        if tilde:
                            tilde = False
                            if b == 0x2e:
                                quit_now = True
                                break
                            if b == 0x3f:
                                err_write('\r\nSupported escape sequences:\r\n ~.  - disconnect\r\n ~~  - send the escape character\r\n ~?  - this message\r\n(They are only recognized right after a newline.)\r\n')
                                continue
                            if b == 0x7e:
                                out.append(0x7e)
                                at_line_start = False
                                continue
                            out.append(0x7e)
                        elif at_line_start and b == 0x7e:
                            tilde = True
                            continue
                        out.append(b)
                        at_line_start = b in (0x0d, 0x0a)
                    if out:
                        ws.send_binary(bytes(out))
                    if quit_now:
                        disconnect()
            now = time.monotonic()
            if not input_open and not is_tty and eot_tries < 50 and closing['at'] is None:
                # End of piped input: send ^D so the remote shell ends, like it would over ssh. Bash drops typeahead while it
                # starts and when it redraws its prompt, so resend it whenever output appeared since the last one and then went quiet.
                if now - last_output >= 0.5 and not (last_output <= last_eot and now - last_eot < 5):
                    eot_tries += 1
                    last_eot = now
                    ws.send_binary(b'\x04')
            if now - last_ping >= 30:
                last_ping = now
                if now - ws.last_seen > 90:
                    code, message = EXIT_NOTFOUND, 'meshtunnel: the server stopped responding'
                    break
                ws.ping()
    finally:
        if saved_attrs is not None:
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, saved_attrs)
        signal.set_wakeup_fd(old_wakeup)
        for sig, h in old_handlers.items():
            signal.signal(sig, h)
        os.close(wake_r)
        os.close(wake_w)
        ws.drain(1.0)
        ws.destroy()
    if message:
        err_write(('\r\n' if is_tty else '') + message + '\n')
    return code


def ssh_config_text():
    def quote(p):
        if '"' in p:
            fail('cannot write an ssh config for a path containing a double quote: ' + p)
        return '"' + p.replace('%', '%%') + '"'
    lines = [
        '# meshtunnel: reach MeshCentral devices as <device>.mesh (ssh, scp, rsync, sftp), through the server "meshtunnel login" chose.',
        '# Written by "meshtunnel ssh-config"; run it again if python or meshtunnel moves.',
        'Host *.mesh',
        '    ProxyCommand %s %s proxy %%n %%p' % (quote(sys.executable), quote(script_path())),
        '    ServerAliveInterval 30',
        '    ServerAliveCountMax 3',
    ]
    if not IS_WINDOWS:
        # Reuse one tunnel for later ssh/scp/rsync to the same device: they start instantly, and so does shell completion of remote paths.
        lines += ['    ControlMaster auto', '    ControlPath ~/.ssh/meshtunnel-%C', '    ControlPersist 10m']
    return '\n'.join(lines) + '\n'


INCLUDE_RE = re.compile(r'^\s*Include\s+("?)(~/\.ssh/)?meshtunnel\.conf\1\s*$', re.I | re.M)


def cmd_ssh_config(a):
    text = ssh_config_text()
    if a['flags'].get('install') is not True:
        safe_print(text)
        return EXIT_OK
    ssh_dir = os.path.join(home(), '.ssh')
    mkdirp(ssh_dir, 0o700)
    conf = os.path.join(ssh_dir, 'meshtunnel.conf')
    write_file_atomic(conf, text, 0o600)
    # Include it from the TOP of ~/.ssh/config: an Include placed after a Host line would only apply to that host.
    main = os.path.join(ssh_dir, 'config')
    current, mode = '', 0o600
    try:
        main = os.path.realpath(main)
        with open(main, 'r', encoding='utf-8') as f:
            current = f.read()
        mode = os.stat(main).st_mode & 0o777
    except OSError:
        pass
    if not INCLUDE_RE.search(current):
        write_file_atomic(main, 'Include meshtunnel.conf\n' + (('\n' + current) if current else ''), mode)
        note('added "Include meshtunnel.conf" at the top of ' + main)
    note('wrote ' + conf)
    err_write('Now use devices as <handle>.mesh (handles are listed by "meshtunnel ls"), e.g.:\n  ssh root@web01.mesh\n  scp ./file.txt root@web01.mesh:/tmp/\n  rsync -avz ./folder/ root@web01.mesh:/srv/folder/\n')
    return EXIT_OK


def remove_ssh_config():
    ssh_dir = os.path.join(home(), '.ssh')
    try:
        os.unlink(os.path.join(ssh_dir, 'meshtunnel.conf'))
        note('removed ' + os.path.join(ssh_dir, 'meshtunnel.conf'))
    except OSError:
        pass
    try:
        main = os.path.realpath(os.path.join(ssh_dir, 'config'))
        with open(main, 'r', encoding='utf-8') as f:
            lines = f.read().split('\n')
        is_include = lambda l: INCLUDE_RE.match(l) is not None
        if len(lines) > 1 and is_include(lines[0]) and lines[1] == '':
            kept = lines[2:]
        else:
            kept = [l for l in lines if not is_include(l)]
        if len(kept) != len(lines):
            write_file_atomic(main, '\n'.join(kept), os.stat(main).st_mode & 0o777)
            note('removed "Include meshtunnel.conf" from ' + main)
    except OSError:
        pass


#
# meshtunnel:// links from the web UI ("Open in my terminal")
#

DESKTOP_FILE = 'meshtunnel-url.desktop'


def find_executable(name):
    import shutil
    return shutil.which(name)


def desktop_exec_arg(s):
    """Quote one argument of a desktop entry Exec key (the general string escaping applies on top of the quoting rules)."""
    m = {'\\': '\\\\\\\\', '"': '\\\\"', '`': '\\\\`', '$': '\\\\$'}
    return '"' + re.sub(r'[\\"`$]', lambda x: m[x.group(0)], s).replace('%', '%%') + '"'


def apps_dir():
    return os.path.join(os.environ.get('XDG_DATA_HOME') or os.path.join(home(), '.local', 'share'), 'applications')


def cmd_install_handler(a):
    if IS_WINDOWS:
        fail('on Windows, use the PowerShell client (meshtunnel.ps1) or the Node.js client for "Open in my terminal"')
    if sys.platform == 'darwin':
        fail('opening meshtunnel:// links is not supported on macOS yet, use the commands from the Local Terminal dialog')
    d = apps_dir()
    mkdirp(d, 0o755)
    entry = '\n'.join(['[Desktop Entry]', 'Type=Application', 'Name=meshtunnel', 'Comment=Open MeshCentral devices in your own terminal',
                       'Exec=%s %s open %%u' % (desktop_exec_arg(sys.executable), desktop_exec_arg(script_path())),
                       'MimeType=x-scheme-handler/meshtunnel;', 'NoDisplay=true', 'Terminal=false']) + '\n'
    write_file_atomic(os.path.join(d, DESKTOP_FILE), entry, 0o644)
    xdg_mime = find_executable('xdg-mime')
    if xdg_mime is None:
        fail('xdg-mime was not found (package xdg-utils): wrote %s but could not register it' % os.path.join(d, DESKTOP_FILE))
    subprocess.check_call([xdg_mime, 'default', DESKTOP_FILE, 'x-scheme-handler/meshtunnel'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    udd = find_executable('update-desktop-database')
    if udd is not None:
        subprocess.call([udd, d], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    terminal = None
    try:
        terminal = terminal_command(load_config(False) or {}, 'test', ['true'])[0]
    except MtError:
        pass
    note('meshtunnel:// links will open ' + (terminal or 'a terminal (none found yet: set $TERMINAL)'))
    return EXIT_OK


def cmd_uninstall_handler(a):
    if IS_WINDOWS or sys.platform == 'darwin':
        return EXIT_OK
    d = apps_dir()
    try:
        os.unlink(os.path.join(d, DESKTOP_FILE))
    except OSError:
        pass
    for f in (os.path.join(os.environ.get('XDG_CONFIG_HOME') or os.path.join(home(), '.config'), 'mimeapps.list'), os.path.join(d, 'mimeapps.list')):
        try:
            with open(f, 'r', encoding='utf-8') as fh:
                text = fh.read()
            kept = '\n'.join(l for l in text.split('\n') if not l.startswith('x-scheme-handler/meshtunnel='))
            if kept != text:
                write_file_atomic(f, kept, os.stat(f).st_mode & 0o777)
        except OSError:
            pass
    udd = find_executable('update-desktop-database')
    if udd is not None:
        subprocess.call([udd, d], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    note('meshtunnel:// handler removed')
    return EXIT_OK


def terminal_command(cfg, title, cmd):
    """The terminal emulator command line, as an argv list (never a shell string)."""
    if isinstance(cfg.get('terminal'), list) and cfg['terminal']:
        out = []
        for x in cfg['terminal']:
            if x == '{cmd}':
                out += cmd
            else:
                out.append(str(x).replace('{title}', title))
        if '{cmd}' not in cfg['terminal']:
            out += cmd
        return out
    candidates = [os.environ['TERMINAL']] if os.environ.get('TERMINAL') else ['x-terminal-emulator', 'kitty', 'alacritty', 'wezterm', 'foot', 'gnome-terminal', 'konsole', 'xfce4-terminal', 'xterm']
    for c in candidates:
        path = find_executable(c)
        if path is None:
            continue
        base = os.path.basename(os.path.realpath(path)).lower()
        if base == 'gnome-terminal':
            return [path, '--'] + cmd
        if base == 'kitty':
            return [path, '--title', title] + cmd
        if base == 'alacritty':
            return [path, '--title', title, '-e'] + cmd
        if base.startswith('wezterm'):
            return [path, 'start', '--'] + cmd
        if base in ('foot', 'footclient'):
            return [path, '--title=' + title] + cmd
        if base == 'konsole':
            return [path, '-e'] + cmd
        if base == 'xfce4-terminal':
            return [path, '--title', title, '-x'] + cmd
        return [path, '-T', title, '-e'] + cmd  # xterm, and x-terminal-emulator wrappers (Debian policy: -e takes the rest)
    fail('no terminal emulator found, set $TERMINAL or a "terminal" list in ' + config_file())


def handler_failure(message):
    note(message)
    try:
        mkdirp(cache_dir(), 0o700)
        with open(os.path.join(cache_dir(), 'handler.log'), 'a', encoding='utf-8') as f:
            f.write(time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()) + ' ' + message + '\n')
    except OSError:
        pass
    notify = find_executable('notify-send') if sys.platform.startswith('linux') else None
    if notify:
        try:
            subprocess.Popen([notify, 'meshtunnel', message], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        except OSError:
            pass


def cmd_open(a):
    try:
        if len(a['_']) != 1:
            fail('usage: meshtunnel open <meshtunnel://...>')
        u = urllib.parse.urlsplit(a['_'][0])
        if u.scheme != 'meshtunnel':
            fail('not a meshtunnel:// link')
        q = urllib.parse.parse_qs(u.query)
        get = lambda k, default='': (q.get(k) or [default])[0]
        cfg = load_config(False)
        server = get('s')
        if cfg is None:
            fail('meshtunnel is not logged in on this computer, run: meshtunnel login ' + server)
        # The link comes from a web page: never let it point the stored credentials at another server.
        try:
            target = parse_server_url(server)['url']
        except MtError:
            target = None
        if target != cfg.get('url'):
            fail('refusing a link for %s: meshtunnel is logged in to %s' % (server, cfg.get('url')))
        nodeid = get('n')
        if not re.match(r'^node/[^/]*/[A-Za-z0-9@$]+$', nodeid):
            fail('the link has an invalid device id')
        try:
            protocol = int(get('p', '1'))
        except ValueError:
            protocol = -1
        if protocol not in TERMINAL_PROTOCOLS:
            fail('the link asks for an unknown shell type')
        title = re.sub(r'[\x00-\x1f\x7f]', '', get('t', 'meshtunnel'))[:60] or 'meshtunnel'
        args = ['shell', nodeid]
        if protocol in (8, 9):
            args.append('--user')
        if protocol in (6, 9):
            args.append('--powershell')
        if get('l') == '1':
            args.append('--login')
        args.append('--hold-on-error')
        argv = terminal_command(cfg, title, [sys.executable, script_path()] + args)
        try:
            subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        except OSError as e:
            fail('cannot start %s: %s' % (argv[0], e))
        return EXIT_OK
    except MtError as e:
        handler_failure(e.message)
        return e.code


def cmd_update(a):
    cfg = load_config(True)
    status, status_line, body = https_request(cfg, 'GET', server_parts(cfg['url'])['basePath'] + 'meshtunnel.py' + key_query(cfg))
    if status != 200:
        fail('the server answered %s for meshtunnel.py' % status_line, EXIT_NOTFOUND)
    text = body.decode('utf-8', 'replace')
    m = re.search(r"^VERSION = '([^']+)'", text, re.M)
    if m is None or not text.startswith('#!/usr/bin/env python3'):
        fail('the server did not send a meshtunnel script', EXIT_NOTFOUND)
    try:
        compile(text, 'meshtunnel.py', 'exec')
    except SyntaxError as e:
        fail('the downloaded script does not parse (%s), keeping the current one' % e)
    target = script_path()
    write_file_atomic(target, body, os.stat(target).st_mode & 0o777)
    note(('already up to date (%s)' % VERSION) if m.group(1) == VERSION else ('updated from %s to %s' % (VERSION, m.group(1))))
    return EXIT_OK


def remove_path_lines():
    for rc in ('.bashrc', '.zshrc'):
        f = os.path.join(home(), rc)
        try:
            with open(f, 'r', encoding='utf-8') as fh:
                text = fh.read()
            kept = '\n'.join(l for l in text.split('\n') if not l.rstrip().endswith(PATH_MARK))
            if kept != text:
                write_file_atomic(f, kept, os.stat(f).st_mode & 0o777)
                note('removed the meshtunnel PATH line from ' + f)
        except OSError:
            pass


def cmd_uninstall(a):
    """Undo the setup on this computer: revoke the login token, remove the ssh config, the link handler, the settings, and
    the copy of meshtunnel the installer put in place (a copy run from anywhere else is left alone)."""
    cfg = load_config(False)
    if cfg and cfg.get('createdToken') is True:
        try:
            note(('login token "%s" revoked' % cfg.get('tokenName')) if revoke_stored_token(cfg) else ('revoke login token "%s" in My Account > Login Tokens' % cfg.get('tokenName')))
        except MtError as e:
            note('could not revoke the login token on the server (%s), revoke "%s" in My Account > Login Tokens' % (e.message, cfg.get('tokenName')))
    cmd_uninstall_handler(a)
    remove_ssh_config()
    for f in (config_file(), device_cache_file(), os.path.join(cache_dir(), 'handler.log')):
        try:
            os.unlink(f)
        except OSError:
            pass
    for d in (os.path.dirname(config_file()), cache_dir()):
        try:
            os.rmdir(d)  # Only if empty
        except OSError:
            pass
    remove_path_lines()
    me = script_path()
    if me == os.path.join(home(), '.local', 'bin', 'meshtunnel'):
        try:
            os.unlink(me)
            note('removed ' + me)
        except OSError as e:
            note('could not remove %s: %s' % (me, e))
    else:
        note('left %s in place, it was not installed by the setup command' % me)
    note('meshtunnel is uninstalled from this computer')
    return EXIT_OK


#
# Command line
#

HELP = '\n'.join([
    'meshtunnel %s (Python): your own terminal and ssh for MeshCentral devices' % VERSION,
    '',
    'Setup (once per computer; the web UI gives a one-line setup command in the Terminal tab > Local Terminal)',
    '  login <server-url> [--pin sha256//...] [--code CODE | --user NAME] [--expire-days N]',
    '                      Sign in with a setup code from the web UI, or with your password.',
    '                      Stores a revocable login token, never your password',
    '  ssh-config [--install]',
    '                      Print, or install into ~/.ssh, the config that makes <device>.mesh hosts work',
    '  install-handler     Let the web UI\'s "Open in my terminal" button open your terminal (Linux)',
    '  uninstall-handler   Remove that link handler',
    '  logout              Revoke the stored login token and forget the server',
    '  uninstall           Undo the setup: revoke the token, remove the ssh config, the link handler and this tool',
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
    '  ssh root@web01.mesh                            SSH (VS Code Remote-SSH, sftp and git use web01.mesh too)',
    '  scp ./app.tar.gz root@web01.mesh:/tmp/         copy a file to the device',
    '  scp root@web01.mesh:/var/log/syslog .          copy a file from the device',
    '  rsync -avz ./site/ root@web01.mesh:/var/www/   sync a folder',
    '  ssh -D 1080 -N root@web01.mesh                 SOCKS proxy into the device\'s network',
    '  meshtunnel shell web01                         the agent\'s own shell, no SSH server needed',
    '  meshtunnel forward 8080 web01 80               then open http://localhost:8080',
    '',
    'A device is a handle from "meshtunnel ls", its exact name, or its node id.',
    'Exit codes: 0 ok, 1 usage, 2 login or rights, 3 device not found or offline, 4 nothing listening on the device port, 5 certificate problem.',
    ''])

COMMANDS = {
    'login': ({'pin': 'value', 'user': 'value', 'expire-days': 'value', 'code': 'value'}, cmd_login),
    'logout': ({}, cmd_logout),
    'uninstall': ({}, cmd_uninstall),
    'ls': ({'json': 'bool'}, cmd_ls),
    'proxy': ({'to': 'value'}, cmd_proxy),
    'forward': ({'bind': 'value', 'to': 'value'}, cmd_forward),
    'shell': ({'user': 'bool', 'powershell': 'bool', 'login': 'bool', 'hold-on-error': 'bool'}, cmd_shell),
    'ssh-config': ({'install': 'bool'}, cmd_ssh_config),
    'install-handler': ({}, cmd_install_handler),
    'uninstall-handler': ({}, cmd_uninstall_handler),
    'open': ({}, cmd_open),
    'update': ({}, cmd_update),
}


def parse_args(argv, spec):
    out = {'_': [], 'flags': {}}
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == '--':
            out['_'] += argv[i + 1:]
            break
        if arg.startswith('--'):
            name, value = arg[2:], None
            if '=' in name:
                name, value = name.split('=', 1)
            if name not in spec:
                fail('unknown option --%s, see: meshtunnel help' % name)
            if spec[name] == 'bool':
                if value is not None:
                    fail('--%s takes no value' % name)
                out['flags'][name] = True
            else:
                if value is None:
                    if i + 1 >= len(argv):
                        fail('--%s needs a value' % name)
                    i += 1
                    value = argv[i]
                out['flags'][name] = value
        elif len(arg) > 1 and arg.startswith('-'):
            fail('unknown option %s, see: meshtunnel help' % arg)
        else:
            out['_'].append(arg)
        i += 1
    return out


def main(argv):
    cmd = argv[0] if argv else None
    if cmd in (None, 'help', '--help', '-h'):
        safe_print(HELP)
        return EXIT_OK
    if cmd in ('version', '--version'):
        safe_print('meshtunnel %s\n' % VERSION)
        return EXIT_OK
    if IS_WINDOWS and cmd not in ('login', 'logout', 'ls', 'forward', 'update', 'uninstall'):
        fail('on Windows, use the PowerShell client (built in, no install needed) or the Node.js client: the Local Terminal dialog of the web UI gives the setup command')
    if cmd not in COMMANDS:
        fail('unknown command "%s", see: meshtunnel help' % cmd)
    spec, run = COMMANDS[cmd]
    spec = dict(spec, help='bool')
    a = parse_args(argv[1:], spec)
    if a['flags'].get('help'):
        safe_print(HELP)
        return EXIT_OK
    return run(a)


def entry():
    if sys.version_info < (3, 6):
        sys.stderr.write('meshtunnel needs Python 3.6 or newer, this is %s\n' % sys.version.split()[0])
        sys.exit(1)
    try:
        code = main(sys.argv[1:])
    except MtError as e:
        note(e.message)
        code = e.code
    except KeyboardInterrupt:
        code = 130
    except Exception as e:  # Keep the traceback: a bug should be reportable
        import traceback
        note('unexpected error: ' + ''.join(traceback.format_exception(type(e), e, e.__traceback__)))
        code = EXIT_USAGE
    try:
        sys.stdout.flush()
    except (OSError, ValueError):
        pass
    sys.exit(code if isinstance(code, int) else EXIT_OK)


if __name__ == '__main__':
    entry()

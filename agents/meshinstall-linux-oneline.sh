#!/bin/sh
# MeshCentral agent installer for Linux and BSD, served already set up for one
# device group so that adding a device takes a single command, for example:
#   wget -qO- 'https://server/meshagents?script=1&meshid=GROUP' | sh
# The same URL with "&uninstall=1" added removes the agent instead.
# Plain POSIX sh: it has to run on dash, busybox ash and the BSD shells too.
# Author: Jugurtha-Green

agenturl='{{{agenturl}}}'
mshurl='{{{mshurl}}}'
action='{{{action}}}'
tlsfallback='{{{tlsfallback}}}' # 1: a download may be retried without certificate checks when they fail, 0: never
insecure=

fail() {
  echo "Error: $*" >&2
  exit 1
}

# Download $1 into the file $2 with whichever HTTP client this system has; $3 = k skips the certificate checks.
# $tool is left set for is_cert_error().
download_once() {
  if command -v curl >/dev/null 2>&1; then
    tool=curl
    if [ "$3" = k ]; then curl -fsSLk {{{curloptions}}}-o "$2" "$1"; else curl -fsSL {{{curloptions}}}-o "$2" "$1"; fi
  elif command -v wget >/dev/null 2>&1; then
    tool=wget
    if [ "$3" = k ]; then wget -q --no-check-certificate {{{wgetoptions}}}-O "$2" "$1"; else wget -q {{{wgetoptions}}}-O "$2" "$1"; fi
  elif command -v fetch >/dev/null 2>&1; then
    tool=fetch
    if [ "$3" = k ]; then fetch -q --no-verify-peer {{{fetchoptions}}}-o "$2" "$1"; else fetch -q {{{fetchoptions}}}-o "$2" "$1"; fi
  else
    fail "curl, wget or fetch is needed to download the agent."
  fi
}

# True when exit status $1 of the last download tool means the server certificate may not have been accepted, and sets
# $certain when that is the only possible reason: curl 51 (peer certificate), 60 (not trusted: unknown or self-signed
# issuer), 77 (CA bundle missing), 83 (issuer check) and GNU wget 5. BusyBox wget and fetch exit 1 for everything,
# so for them any failure counts as a maybe.
is_cert_error() {
  certain=1
  case "$tool/$1" in
    curl/51|curl/60|curl/77|curl/83|wget/5) return 0 ;;
    wget/1|fetch/1) certain=; return 0 ;;
  esac
  return 1
}

# A system with an out-of-date CA store, or behind a firewall that inspects TLS, cannot verify a perfectly good
# certificate. The first such failure is reported and everything after it skips the checks, unless the server says no.
download() {
  if [ -z "$insecure" ]; then
    download_once "$1" "$2" && return 0
    rc=$?
    is_cert_error "$rc" || return "$rc"
    if [ -n "$certain" ]; then
      why="this system could not verify the TLS certificate of the server (out-of-date CA certificates, or a network that inspects TLS)"
    else
      why="the download failed, possibly because this system could not verify the TLS certificate of the server (out-of-date CA certificates, or a network that inspects TLS)"
    fi
    if [ "$tlsfallback" != 1 ]; then
      echo "Error: $why." >&2
      return "$rc"
    fi
    echo "Warning: $why. Continuing without certificate checks." >&2
    insecure=1
  fi
  download_once "$1" "$2" k
}

# Everything happens in main(), which is only called on the last line: if this
# script is cut off while it is being downloaded, nothing at all gets run.
main() {
  # Only the agent's own installer needs root, downloads run as the current user.
  if [ "$(id -u)" = 0 ]; then
    asroot=
  elif command -v sudo >/dev/null 2>&1; then
    asroot=sudo
  elif command -v doas >/dev/null 2>&1; then
    asroot=doas
  else
    fail "this needs to be run as root."
  fi

  # Pick the agent build for this system (IDs from meshAgentsArchitectureNumbers).
  # A 64-bit kernel can run a 32-bit userland, as Raspberry Pi OS does, and the
  # agent has to match the userland.
  os=$(uname -s)
  cpu=$(uname -m)
  bits=$(getconf LONG_BIT 2>/dev/null)
  case "$os/$cpu" in
    Linux/x86_64|Linux/amd64) if [ "$bits" = 32 ]; then id=5; else id=6; fi ;;
    Linux/i[3-6]86|Linux/x86) id=5 ;;
    Linux/aarch64|Linux/arm64) if [ "$bits" = 32 ]; then id=25; else id=26; fi ;;
    Linux/armv6l|Linux/armv7l) id=25 ;;
    Linux/riscv64) id=45 ;;
    OpenBSD/amd64) id=37 ;;
    *BSD/amd64|*BSD/x86_64) id=30 ;;
    *) fail "there is no agent for $os on $cpu here, use the binary installer from MeshCentral instead." ;;
  esac

  # Work in a private folder the agent can be run from: some systems mount /tmp noexec.
  dir=
  for base in "${TMPDIR:-/tmp}" /var/tmp "$HOME" "$PWD"; do
    [ -n "$base" ] || continue
    dir=$(mktemp -d "$base/meshagent.XXXXXX" 2>/dev/null) || continue
    printf '#!/bin/sh\n' > "$dir/meshagent" && chmod 700 "$dir/meshagent" && "$dir/meshagent" 2>/dev/null && break
    rm -rf "$dir"
    dir=
  done
  [ -n "$dir" ] || fail "found no folder to download the agent to."
  trap 'rm -rf "$dir"' EXIT
  trap 'exit 1' INT TERM

  # Settings first: they are small, and an invitation link only stays valid for a short while.
  download "$mshurl" "$dir/meshagent.msh" || fail "could not download the device group settings."
  echo "Downloading the agent for $os $cpu..."
  download "$agenturl$id" "$dir/meshagent" || fail "could not download the agent."
  chmod 755 "$dir/meshagent"

  if [ "$action" = uninstall ]; then
    $asroot "$dir/meshagent" -fulluninstall </dev/null
  else
    # The agent needs to know the init system when it updates itself.
    case "$os" in
      *BSD) startup=5 ;;
      *) case "$(cat /proc/1/comm 2>/dev/null)" in
           systemd) startup=1 ;;
           init) if [ -d /etc/init ]; then startup=2; else startup=3; fi ;;
           *) startup=0 ;;
         esac ;;
    esac
    echo "StartupType=$startup" >> "$dir/meshagent.msh"
    # A fresh FreeBSD may not have the folder the agent puts its service script in.
    if [ "$os" = FreeBSD ]; then $asroot mkdir -p /usr/local/etc/rc.d; fi
    $asroot "$dir/meshagent" -fullinstall --copy-msh=1 </dev/null
  fi
}

main

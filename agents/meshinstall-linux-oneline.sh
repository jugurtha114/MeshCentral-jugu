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

fail() {
  echo "Error: $*" >&2
  exit 1
}

# Download $1 into the file $2 with whichever HTTP client this system has.
download() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL {{{curloptions}}}-o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q {{{wgetoptions}}}-O "$2" "$1"
  elif command -v fetch >/dev/null 2>&1; then
    fetch -q {{{fetchoptions}}}-o "$2" "$1"
  else
    fail "curl, wget or fetch is needed to download the agent."
  fi
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

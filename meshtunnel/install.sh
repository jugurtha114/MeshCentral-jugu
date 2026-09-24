#!/bin/sh
# meshtunnel setup for Linux and macOS. MeshCentral serves this file with its own address filled in and both clients
# (Python and Node.js) inside, so nothing else is downloaded. Use the one-line setup command from the web UI
# (Terminal tab > Local Terminal), which looks like:
#     curl -fsSL https://<server>/meshtunnel-install.sh | sh -s <setup-code> [python|node]
# It installs meshtunnel for the current user in ~/.local/bin (no root needed), signs in with the one-time setup code
# and sets up ssh so that "ssh <user>@<device>.mesh" works. "meshtunnel uninstall" undoes all of it.
# Author: Jugurtha-Green. License: Apache-2.0.
#
# Everything runs from main(), called on the very last line: a download cut short runs nothing.

main() {
    SERVER='__MESHTUNNEL_SERVER__'
    PIN='__MESHTUNNEL_PIN__'
    LOGINKEY='__MESHTUNNEL_LOGINKEY__'
    code=${1-}
    runtime=${2-auto}

    case $SERVER in
        https://*) ;;
        *) die 'run the setup command from the web UI (Terminal tab > Local Terminal), not this file directly' ;;
    esac
    [ -n "${HOME-}" ] && [ -d "$HOME" ] || die 'HOME is not set to a directory'
    case $code in
        *[!A-Za-z0-9]*) die "\"$code\" is not a setup code, copy the command again from the web UI" ;;
    esac
    [ -z "$code" ] || [ ${#code} -eq 20 ] || die "a setup code has 20 letters and digits, \"$code\" has ${#code}: copy the command again from the web UI"
    case $runtime in
        auto | python | node) ;;
        *) die "unknown client \"$runtime\", use python or node (or nothing to pick one automatically)" ;;
    esac

    # Pick the runtime. Python first: it is part of most systems and its path does not move with version managers.
    interp=''
    if [ "$runtime" != node ]; then
        interp=$(find_python) && use=python
    fi
    if [ -z "$interp" ] && [ "$runtime" != python ]; then
        interp=$(find_node) && use=node
    fi
    if [ -z "$interp" ]; then
        case $runtime in
            python) need='Python 3.6 or newer' ;;
            node) need='Node.js 16 or newer' ;;
            *) need='Python 3.6 or newer, or Node.js 16 or newer,' ;;
        esac
        die "$need was not found. Install it (e.g. \"sudo apt install python3\", \"sudo dnf install python3\" or \"brew install python\"), then paste the same command again: the setup code stays valid for 15 minutes."
    fi
    if [ "$use" = python ]; then
        version=$("$interp" -c 'import sys; print("Python %d.%d" % sys.version_info[:2])' </dev/null 2>/dev/null)
    else
        version=$("$interp" -p '"Node.js " + process.versions.node' </dev/null 2>/dev/null)
    fi

    # Install: write next to the target, check it runs, then move it in place in one step.
    bindir=$HOME/.local/bin
    target=$bindir/meshtunnel
    mkdir -p "$bindir" || die "cannot create $bindir"
    tmp=$bindir/.meshtunnel-setup.$$
    trap 'rm -f "$tmp"' EXIT
    trap 'exit 130' INT TERM
    if [ "$use" = python ]; then write_python >"$tmp"; else write_node >"$tmp"; fi || die "cannot write $tmp"
    chmod 755 "$tmp" || die "cannot make $tmp executable"
    "$interp" "$tmp" version </dev/null >/dev/null 2>&1 || die "the $version client does not start, try the other one: sh -s $code $( [ "$use" = python ] && echo node || echo python )"
    mv -f "$tmp" "$target" || die "cannot write $target"
    say "meshtunnel setup: installed the $version client as $target"

    url=$SERVER
    [ -z "$LOGINKEY" ] || url="$SERVER?key=$LOGINKEY"
    if [ -z "$code" ]; then
        say "meshtunnel setup: no setup code given, sign in with: $target login '$url'${PIN:+ --pin '$PIN'}"
    else
        set -- login "$url" --code "$code"
        [ -z "$PIN" ] || set -- "$@" --pin "$PIN"
        "$interp" "$target" "$@" </dev/null || exit $?
    fi

    "$interp" "$target" ssh-config --install </dev/null || die "could not set up ssh, run later: meshtunnel ssh-config --install"
    command -v ssh >/dev/null 2>&1 || say "meshtunnel setup: note: no ssh client is installed here, \"meshtunnel shell <device>\" works without one"

    # "Open in my terminal" links from the web UI: on a Linux desktop with the freedesktop tools.
    if [ "$(uname -s)" = Linux ] && [ -n "${DISPLAY-}${WAYLAND_DISPLAY-}" ] && command -v xdg-mime >/dev/null 2>&1; then
        "$interp" "$target" install-handler </dev/null || say 'meshtunnel setup: "Open in my terminal" links are not set up, run later: meshtunnel install-handler'
    fi

    # Make the meshtunnel command available in new terminals.
    case ":${PATH-}:" in
        *":$bindir:"*) say 'meshtunnel setup: done. Try: meshtunnel ls' ;;
        *)
            case ${SHELL-} in
                */zsh) rc=$HOME/.zshrc ;;
                */bash) rc=$HOME/.bashrc ;;
                *) rc='' ;;
            esac
            if [ -n "$rc" ] && ! grep -qs '# added by meshtunnel' "$rc"; then
                printf '\nexport PATH="$HOME/.local/bin:$PATH" # added by meshtunnel\n' >>"$rc" && say "meshtunnel setup: added ~/.local/bin to PATH in $rc"
            fi
            if [ -n "$rc" ]; then
                say 'meshtunnel setup: done. Open a new terminal to use the meshtunnel command (ssh to <device>.mesh works right away).'
            else
                say "meshtunnel setup: done. Add $bindir to your PATH to use the meshtunnel command (ssh to <device>.mesh works right away)."
            fi
            ;;
    esac
}

say() { printf '%s\n' "$*" >&2; }
die() { printf 'meshtunnel setup: %s\n' "$*" >&2; exit 1; }

# The first python3/python that is Python 3.6+ with ssl, printed as the interpreter's real path.
find_python() {
    for name in python3 python; do
        bin=$(command -v "$name" 2>/dev/null) || continue
        case $bin in /*) ;; *) continue ;; esac
        # On a Mac without the developer tools, /usr/bin/python3 only opens an "install the tools" dialog.
        if [ "$bin" = /usr/bin/python3 ] && [ "$(uname -s)" = Darwin ] && ! xcode-select -p >/dev/null 2>&1; then continue; fi
        "$bin" -c 'import sys, ssl, select, json; sys.exit(0 if sys.version_info >= (3, 6) else 1)' </dev/null >/dev/null 2>&1 || continue
        "$bin" -c 'import sys; print(sys.executable)' </dev/null 2>/dev/null && return 0
    done
    return 1
}

# The first node/nodejs that is Node.js 16+, printed as the real path of the executable.
find_node() {
    for name in node nodejs; do
        bin=$(command -v "$name" 2>/dev/null) || continue
        case $bin in /*) ;; *) continue ;; esac
        "$bin" -e 'process.exit(parseInt(process.versions.node) >= 16 ? 0 : 1)' </dev/null >/dev/null 2>&1 || continue
        "$bin" -p 'process.execPath' </dev/null 2>/dev/null && return 0
    done
    return 1
}

write_python() {
    cat <<'MESHTUNNEL_PY_EOF'
__MESHTUNNEL_SOURCE_PY__
MESHTUNNEL_PY_EOF
}

write_node() {
    cat <<'MESHTUNNEL_JS_EOF'
__MESHTUNNEL_SOURCE_JS__
MESHTUNNEL_JS_EOF
}

main "$@"

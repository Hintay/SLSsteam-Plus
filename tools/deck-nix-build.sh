#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

find_nix_shell() {
	if command -v nix-shell >/dev/null 2>&1; then
		command -v nix-shell
		return 0
	fi
	for path in \
		"$HOME/.nix-profile/bin/nix-shell" \
		"$HOME/.local/state/nix/profiles/profile/bin/nix-shell" \
		"/nix/var/nix/profiles/default/bin/nix-shell"
	do
		if [ -x "$path" ]; then
			printf '%s\n' "$path"
			return 0
		fi
	done
	return 1
}

NIX_SHELL=${NIX_SHELL:-$(find_nix_shell)}
JOBS=${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || printf '1')}
case "$JOBS" in
	''|*[!0-9]*)
		echo "Invalid JOBS value: $JOBS" >&2
		exit 1
		;;
esac

echo "[deck-nix] building 32-bit SLSsteam libraries"
"$NIX_SHELL" shell.nix --run \
	"set -e; make deps; make -j$JOBS bin/SLSsteam.so bin/library-inject.so; test -s bin/SLSsteam.so; test -s bin/library-inject.so"

echo "[deck-nix] building 64-bit Proton injection helper"
"$NIX_SHELL" -E 'with import <nixpkgs> {}; mkShell { nativeBuildInputs = [ gcc gnumake pkg-config file ]; }' --run \
	"set -e; make bin/sls_proton_inject.so HOST_CC=gcc; test -s bin/sls_proton_inject.so"

if command -v file >/dev/null 2>&1; then
	file bin/SLSsteam.so bin/library-inject.so bin/sls_proton_inject.so
fi

#!/usr/bin/env bash
# Extract a struct field's byte offset (and, for a bitfield, its bit position)
# from a built, -g, UNSTRIPPED binary/object — using pahole (dwarves). This is
# how a technique-3 "state-mutation" patch gets the offset for bpf_probe_write_user;
# never hardcode/guess offsets — read them from the binary you built.
#
#   ./find_offsets.sh <binary-or-.o> <struct_name> [field_name]
#
# e.g. ./find_offsets.sh ../target/<path>/<binary> <struct_name> <field>
set -u
BIN="${1:?usage: find_offsets.sh <binary-or-.o> <struct> [field]}"
STRUCT="${2:?need a struct name}"
FIELD="${3:-}"

command -v pahole >/dev/null 2>&1 || { echo "ERROR: pahole not found (apt-get install dwarves)"; exit 3; }
[ -r "$BIN" ] || { echo "ERROR: cannot read $BIN"; exit 3; }

dump="$(pahole -C "$STRUCT" "$BIN" 2>/dev/null)"
[ -n "$dump" ] || { echo "ERROR: struct '$STRUCT' not found in $BIN — is it built with -g and NOT stripped?"; exit 1; }

if [ -z "$FIELD" ]; then
	printf '%s\n' "$dump"; exit 0
fi

# Show the field line verbatim (authoritative), then parse the trailing pahole
# comment. pahole prints a bitfield as  /* BYTE: BIT  SIZE */  (note the SPACE
# after the colon) and a regular field as  /* OFFSET  SIZE */.
# Trailing class accepts space/colon/semicolon AND '[' ']' (arrays) and '(' ')' (function
# pointers: `(*fn)(...)` follows the name with ')'), so those fields match too — not only scalars.
line="$(printf '%s\n' "$dump" | grep -E "[^a-zA-Z0-9_]${FIELD}[][ :;()]" | head -1)"
[ -n "$line" ] || { echo "ERROR: field '$FIELD' not found in struct '$STRUCT'"; exit 1; }
echo "field line:  $(printf '%s' "$line" | sed 's/^[[:space:]]*//')"
comment="$(printf '%s' "$line" | sed -n 's#.*/\*\(.*\)\*/.*#\1#p')"
uc="$(printf '%s' "$FIELD" | tr '[:lower:]' '[:upper:]')"

if printf '%s' "$comment" | grep -qE '[0-9]+[[:space:]]*:[[:space:]]*[0-9]+'; then
	# bitfield: "<storage-unit byte offset> : <bit within unit>  <size>"
	byte="$(printf '%s' "$comment" | sed -nE 's/^[^0-9]*([0-9]+)[[:space:]]*:[[:space:]]*([0-9]+).*/\1/p')"
	bit="$(printf '%s' "$comment"  | sed -nE 's/^[^0-9]*([0-9]+)[[:space:]]*:[[:space:]]*([0-9]+).*/\2/p')"
	# single-byte read-modify-write coords (little-endian: x86_64/aarch64):
	rmw_off=$(( byte + bit / 8 )); rmw_bit=$(( bit % 8 ))
	echo "bitfield: storage-unit byte offset $byte, bit $bit within unit"
	echo ""
	echo "# paste into patch.bpf.c (single-byte read-modify-write clears ONLY this bit):"
	echo "#define ${uc}_OFF $rmw_off"
	echo "#define ${uc}_BIT $rmw_bit"
else
	byte="$(printf '%s' "$comment" | grep -oE '[0-9]+' | head -1)"
	echo "whole field at byte offset ${byte:-?} — memcpy the value; do NOT bit-mask"
	echo ""
	echo "# paste into patch.bpf.c:"
	echo "#define ${uc}_OFF ${byte:-?}"
fi

#!/bin/bash
# Generate the v1.1 Recon-menu hooks from the user payload.
#   library/recon/client/CamHound/payload.sh  and  library/recon/access_point/CamHound/payload.sh
# are byte-identical: hook_header.sh + the user payload's PAYLOAD_REL..config block + its lib block +
# its watch-core block + hook_main.sh. cam_signatures.txt is copied beside each hook.
# Run after every change to library/user/reconnaissance/CamHound/payload.sh, then check_sync.sh.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
SRC="$ROOT/library/user/reconnaissance/CamHound/payload.sh"
SIGS="$ROOT/library/user/reconnaissance/CamHound/cam_signatures.txt"
OUT=$(mktemp)
{
  cat "$HERE/hook_header.sh"
  sed -n '/^PAYLOAD_REL=/,/end config block ---$/p' "$SRC"
  printf '\n'
  sed -n '/^# --- camhound lib begin ---$/,/^# --- camhound lib end ---$/p' "$SRC"
  sed -n '/^# --- watch core begin ---$/,/^# --- watch core end ---$/p' "$SRC"
  cat "$HERE/hook_main.sh"
} >"$OUT"
bash -n "$OUT"
for d in client access_point; do
  mkdir -p "$ROOT/library/recon/$d/CamHound"
  cp "$OUT" "$ROOT/library/recon/$d/CamHound/payload.sh"; chmod +x "$ROOT/library/recon/$d/CamHound/payload.sh"
  cp "$SIGS" "$ROOT/library/recon/$d/CamHound/cam_signatures.txt"
done
rm -f "$OUT"
printf 'hooks generated: %s lines each\n' "$(wc -l <"$ROOT/library/recon/client/CamHound/payload.sh")"

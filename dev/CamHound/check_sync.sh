#!/bin/bash
# Verify that the lib block, the watch-core block and the config block are identical in the user
# payload and both Recon hooks, and that both hooks and both signature copies are byte-identical.
set -u
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
U="$ROOT/library/user/reconnaissance/CamHound/payload.sh"
C="$ROOT/library/recon/client/CamHound/payload.sh"
A="$ROOT/library/recon/access_point/CamHound/payload.sh"
rc=0
blk() { sed -n "/^$2\$/,/^$3\$/p" "$1" | md5sum | cut -c1-32; }
for f in "$C" "$A"; do
  [ -f "$f" ] || { printf 'missing %s\n' "$f"; rc=1; continue; }
  for b in "# --- camhound lib begin ---|# --- camhound lib end ---" "# --- watch core begin ---|# --- watch core end ---" "PAYLOAD_REL=.*|# -*. end config block ---"; do
    s=${b%%|*}; e=${b##*|}
    if [ "$(blk "$U" "$s" "$e")" != "$(blk "$f" "$s" "$e")" ]; then printf 'DIFF %s in %s\n' "${s#\# --- }" "$f"; rc=1; fi
  done
done
cmp -s "$C" "$A" || { printf 'DIFF client vs access_point hook\n'; rc=1; }
cmp -s "$ROOT/library/user/reconnaissance/CamHound/cam_signatures.txt" "$ROOT/library/recon/client/CamHound/cam_signatures.txt" || { printf 'DIFF cam_signatures.txt (client)\n'; rc=1; }
cmp -s "$ROOT/library/user/reconnaissance/CamHound/cam_signatures.txt" "$ROOT/library/recon/access_point/CamHound/cam_signatures.txt" || { printf 'DIFF cam_signatures.txt (access_point)\n'; rc=1; }
[ $rc -eq 0 ] && printf 'in sync: lib %s watch %s\n' "$(blk "$U" '# --- camhound lib begin ---' '# --- camhound lib end ---')" "$(blk "$U" '# --- watch core begin ---' '# --- watch core end ---')"
exit $rc

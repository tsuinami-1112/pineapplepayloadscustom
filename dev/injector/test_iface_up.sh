#!/bin/sh
# test_iface_up.sh -- the fixture test for run_17a.sh. No radio, no device, no privileges.
#
# WHY THIS FILE EXISTS. On 2026-11-10 a rewrite of run_17a.sh's iface_up was justified by a
# "mutation test over a fixture tree" that lived only in a session scratchpad and was never
# committed, while dev/CamHound/AUDIT-2026-11-10.md asserted "the fixture tree above now exists, so
# the next change to it is cheap to attack". The audit caught that: the tree did not exist, the
# quoted pass count was unreproducible, and the one case that would have caught the regression
# shipped in the same commit (an ABSENT interface read as "recovered" in a loop whose job is to wait
# for recovery) was missing. The fixture that DID exist was synthetic and had been written from the
# hypothesis it was meant to test. So this is committed, and it is the thing to extend.
#
# It tests the SHIPPED text: the predicates are extracted from run_17a.sh by marker, not copied.
#
#   sh dev/injector/test_iface_up.sh        # must end "0 failed"
#
# To attack the predicates, add a row to PREDICATE CASES and run it. To attack the park/warn
# output, add an arm to the stub section: it drives the real script with a fake PATH and asserts on
# what the operator would actually read.

set -u
HERE=$(dirname "$0")
SCRIPT="$HERE/run_17a.sh"
[ -r "$SCRIPT" ] || { echo "cannot read $SCRIPT"; exit 1; }

T=$(mktemp -d) || exit 1
trap 'rm -rf "$T"' EXIT
PASS=0; FAIL=0

ok() {   # ok <label> <got> <want>
  if [ "$2" = "$3" ]; then PASS=$(( PASS + 1 ))
  else FAIL=$(( FAIL + 1 )); printf 'FAIL %s: got [%s] want [%s]\n' "$1" "$2" "$3"; fi
}
has() {  # has <label> <haystack-file> <needle>
  if grep -q -- "$3" "$2"; then PASS=$(( PASS + 1 ))
  else FAIL=$(( FAIL + 1 )); printf 'FAIL %s: output does not contain [%s]\n' "$1" "$3"; fi
}
hasnt() {
  if grep -q -- "$3" "$2"; then FAIL=$(( FAIL + 1 )); printf 'FAIL %s: output DOES contain [%s]\n' "$1" "$3"
  else PASS=$(( PASS + 1 )); fi
}

# ---------------------------------------------------------------- PREDICATE CASES ----------
# Extract iface_up / iface_down / iface_ready from the shipped script, by marker so the test
# follows the code rather than a line number.
sed -n '/^iface_up() {/,/^iface_ready() /p' "$SCRIPT" > "$T/pred.sh"
grep -q '^iface_ready() ' "$T/pred.sh" || { echo "extraction failed: no iface_ready"; exit 1; }

N="$T/net"; mkdir -p "$N"
mk() {   # mk <name> <flags-or-empty> <operstate-or-empty>
  mkdir -p "$N/$1"
  [ -n "$2" ] && printf '%s\n' "$2" > "$N/$1/flags"
  [ -n "$3" ] && printf '%s\n' "$3" > "$N/$1/operstate"
  return 0
}
# The two readings MEASURED on the Pager, 2026-11-10, which are the ones that matter:
mk measured_up      0x1103 unknown     # IFF_UP set; this device says "unknown", never "up"
mk measured_down    0x1102 down        # IFF_UP clear; genuinely down, with pineapd running
# flags present, every nibble class:
mk odd_f            0x100f up
mk even_A           0x100A up
mk odd_B            0x100B up
# flags says UP while operstate disagrees -- flags must win, and operstate must not veto:
mk up_carrierdown   0x1003 down
mk up_nostate       0x1003 ""
# no flags at all: operstate is the fallback, not the primary
mk noflags_up       "" up
mk noflags_unknown  "" unknown
mk noflags_down     "" down
mk noflags_lldown   "" lowerlayerdown
mk noflags_weird    "" testing
mk noflags_nostate  "" ""
# and "absent" is deliberately NOT created.

r() { ( . "$T/pred.sh" >/dev/null 2>&1; NET_SYS="$N"; iface_up "$1"; echo $? ); }
ok "up:   measured 0x1103/unknown"        "$(r measured_up)"      0
ok "down: measured 0x1102/down"           "$(r measured_down)"    1
ok "up:   0x100f"                         "$(r odd_f)"            0
ok "down: 0x100A"                         "$(r even_A)"           1
ok "up:   0x100B"                         "$(r odd_B)"            0
ok "up:   flags odd beats operstate down" "$(r up_carrierdown)"   0
ok "up:   flags odd, no operstate"        "$(r up_nostate)"       0
ok "up:   no flags, operstate up"         "$(r noflags_up)"       0
ok "up:   no flags, operstate unknown"    "$(r noflags_unknown)"  0
ok "down: no flags, operstate down"       "$(r noflags_down)"     1
ok "down: no flags, lowerlayerdown"       "$(r noflags_lldown)"   1
ok "2:    no flags, unrecognised state"   "$(r noflags_weird)"    2
ok "2:    no flags, no operstate"         "$(r noflags_nostate)"  2
ok "2:    ABSENT netdev is not a claim of down" "$(r absent)"     2

# The three predicates must disagree about rc 2 in exactly one direction: it is not "down", and it
# is not "ready". This is the distinction whose absence caused the restore()-loop regression.
d() { ( . "$T/pred.sh" >/dev/null 2>&1; NET_SYS="$N"; iface_down "$1" && echo yes || echo no ); }
y() { ( . "$T/pred.sh" >/dev/null 2>&1; NET_SYS="$N"; iface_ready "$1" && echo yes || echo no ); }
ok "iface_down: absent is NOT down"       "$(d absent)"           no
ok "iface_ready: absent is NOT ready"     "$(y absent)"           no
ok "iface_down: 0x1102 is down"           "$(d measured_down)"    yes
ok "iface_ready: 0x1102 is not ready"     "$(y measured_down)"    no
ok "iface_down: 0x1103 is not down"       "$(d measured_up)"      no
ok "iface_ready: 0x1103 is ready"         "$(y measured_up)"      yes

# A recovery wait must keep waiting for an ABSENT interface. Using iface_down here exits on
# iteration 0 and suppresses the follow-up warning, which is the 2026-11-10 regression.
wait_iters() {   # wait_iters <predicate> <if>
  # shellcheck disable=SC2034  # NET_SYS is read by the predicates sourced from pred.sh
  ( . "$T/pred.sh" >/dev/null 2>&1; NET_SYS="$N"; i=0
    while [ "$i" -lt 5 ]; do
      case "$1" in ready) iface_ready "$2" && break ;; down) iface_down "$2" || break ;; esac
      i=$(( i + 1 ))
    done; echo "$i" )
}
ok "wait(ready): absent keeps waiting"    "$(wait_iters ready absent)"       5
ok "wait(down):  absent stops at once"    "$(wait_iters down absent)"        0
ok "wait(ready): up stops at once"        "$(wait_iters ready measured_up)"  0
ok "wait(ready): down keeps waiting"      "$(wait_iters ready measured_down)" 5

# ---------------------------------------------------------------- STUBBED END TO END --------
# Drive the real script with a fake PATH and assert on the operator-facing output. This is the
# section that catches a park announced but not performed, and a warning contradicted by the line
# after it.
B="$T/bin"; mkdir -p "$B"
mkstub() { printf '#!/bin/sh\n%s\n' "$2" > "$B/$1"; chmod +x "$B/$1"; }
mkstub ip        'exit 0'
mkstub ifconfig  'exit 0'
mkstub tcpdump   'sleep 30'
mkstub PINEAPPLE_EXAMINE_BSSID   'exit 0'
mkstub PINEAPPLE_EXAMINE_CHANNEL 'exit 0'
mkstub PINEAPPLE_EXAMINE_RESET   'exit 0'
mkstub pagerinj  'printf "sent=92 failed=0\n" >&2; exit 0'
CH=8
mkstub iw "case \"\$*\" in *info*) printf 'channel %s (2447 MHz), width: 20 MHz\n' \"\$(cat $T/ch)\" ;; esac; exit 0"
printf '%s\n' "$CH" > "$T/ch"

run() {   # run <pidof-rc> <net-fixture-name> -> output file
  mkstub pidof "exit $1"
  out="$T/out.$$"
  PATH="$B:$PATH" NET_SYS="$N" PAGERINJ="$B/pagerinj" \
    sh "$SCRIPT" "$2" FC:58:5A:08:42:15 8 1 0 >"$out" 2>&1 || true
  printf '%s' "$out"
}

# pineapd DOWN: the warning must stand alone. The first revision printed, one line later,
# "parking with EXAMINE for 30s (pineapd left running)" -- unconditionally.
O=$(run 1 measured_up)
has   "pineapd down: says so"                   "$O" 'pineapd is NOT running'
has   "pineapd down: says it is not parked"     "$O" 'NOT PARKED'
hasnt "pineapd down: does NOT claim a park"     "$O" 'parking with EXAMINE'
hasnt "pineapd down: does NOT claim it running" "$O" 'left running'

# pineapd UP, radio on the target channel: the park is announced AND confirmed.
O=$(run 0 measured_up)
has "parked: announces the park"      "$O" 'parking with EXAMINE'
has "parked: confirms it by read-back" "$O" 'park confirmed'
has "parked: reaches the fire"         "$O" 'FRAMES LEFT THE RADIO'

# pineapd UP, radio on the WRONG channel: a silent park failure used to be indistinguishable from a
# successful one, because both EXAMINE commands were >/dev/null 2>&1 and nothing read the channel.
printf '%s\n' 11 > "$T/ch"
O=$(run 0 measured_up)
has "unparked: park FAILED is reported"      "$O" 'park FAILED'
has "unparked: and names the wrong channel"  "$O" 'wanted 8'
printf '%s\n' "$CH" > "$T/ch"

# A genuinely down interface: warn, try to bring it up, and still fire -- the gate is a hint, not a
# veto, which is the change that actually unblocked the 2026-11-10 bench.
O=$(run 0 measured_down)
has "down iface: warns"             "$O" 'reads DOWN'
has "down iface: still fires"       "$O" 'firing'

# An absent interface: rc 2 must say "cannot tell", never "is down".
O=$(run 0 absent)
has   "absent iface: says it cannot tell" "$O" 'cannot tell whether'
hasnt "absent iface: does not claim DOWN" "$O" 'reads DOWN'

printf '== %s checks, %s failed ==\n' "$(( PASS + FAIL ))" "$FAIL"
[ "$FAIL" = 0 ]

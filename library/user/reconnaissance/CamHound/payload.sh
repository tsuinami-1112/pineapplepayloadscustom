#!/bin/bash
# Title: CamHound
# Description: Wi-Fi camera census and response for the Pager. Lists every camera-vendor and
#              camera-capable 802.11 device PineAP Recon can hear, categorises it, grades it on
#              a 0-100 confidence scale, and (on request) locks on one suspect to test whether it
#              is streaming (Watch), whether it reacts to movement (Stimulus test) or where it is
#              (Locate). Identity scan is passive and free; Watch/Locate pause Recon hopping for
#              the duration of the lock. No LAN join. With RESPONSE=1 a fourth rung appears on the
#              device card: read the target's PMF/beacon-protection posture from its own beacon,
#              then disconnect it with deauth+disassoc, channel-switch announcements, or all three,
#              and judge from Recon whether it actually went quiet. RESPONSE defaults to 0, in
#              which case nothing is transmitted and the device card is unchanged.
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
SOUND=0                 # * RINGTONE alert on NEW CONFIRMED (0 = off)
SHOW_MODULES=1          # modules list in the menu
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
# response rung (recon+response). RESPONSE=0 keeps the payload recon-only and silent.
RESPONSE=0              # * master switch for the response rung (0 = recon only)
RESPONSE_CONFIRM=1      # * blocking confirmation dialog before any transmit (0 = act on accept alone)
AUTO_RESPOND=0          # * let the funnel offer Disrupt by itself (needs RESPONSE=1; 0 = manual only)
# shellcheck disable=SC2034
SCAN_IF="wlan0"         # reserved: posture cross-check iface, the enabled dummy sta on radio0 (2.4 GHz only)
BCN_CAP_SECS=4          # seconds to wait for a beacon when reading a target's posture
BCN_CAP_COUNT=5         # beacons to capture per posture read (first usable one is parsed)
POSTURE_TTL=300         # * seconds a posture badge stays cached per BSSID
RESP_LOCK_SECS=20       # * EXAMINE lock duration held across a response (must exceed fire + settle)
RESP_SETTLE_SECS=6      # * wait after transmitting before re-reading the target to judge the effect
LOOT_DIR="/root/loot/CamHound"
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
    THR_STREAM_UP=$(cfg THR_STREAM_UP "$THR_STREAM_UP" 1)
    RESPONSE=$(cfg RESPONSE "$RESPONSE" 0)
    RESPONSE_CONFIRM=$(cfg RESPONSE_CONFIRM "$RESPONSE_CONFIRM" 0)
    RESP_LOCK_SECS=$(cfg RESP_LOCK_SECS "$RESP_LOCK_SECS" 5)
    RESP_SETTLE_SECS=$(cfg RESP_SETTLE_SECS "$RESP_SETTLE_SECS" 1)
    AUTO_RESPOND=$(cfg AUTO_RESPOND "$AUTO_RESPOND" 0)
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
vendor_of() {   # vendor_of mac -> sets VENDOR[mac] (clean, <=14) and VLOW[mac] (lowercase full)
  local mac="$1" hex key line v=""
  [ -n "${VLOW[$mac]+x}" ] && return 0
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
  VLOW[$mac]="${v,,}"; VENDOR[$mac]=$(clean_text "${v:--}" 14)
}

# is_rand mac -> locally administered bit set
is_rand() { [[ ${1:1:1} =~ [26aeAE] ]]; }

# band_of freq -> 2 | 5 | 6 | ?
band_of() {
  local f="$1"
  if (( f >= 5925 )); then printf 6; elif (( f >= 4900 )); then printf 5; elif (( f >= 2400 )); then printf 2; else printf '?'; fi
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

# inj_probe must run in the PARENT shell: it populates INJ_OK, and csa_injectable is
# reached from posture_from_caps inside $( ), where writes to globals are discarded.
# shellcheck disable=SC2120   # `force` is deliberate API for a manual re-probe; no call site yet
inj_probe() {   # inj_probe [force] -> 0 when INJ_OK is usable
  local phy d line freq ch dis rows=""
  [ "$1" = force ] || { (( INJ_PROBED != 0 && EPOCHSECONDS - INJ_PROBE_TS < POSTURE_TTL )) && return $(( INJ_PROBED == 1 ? 0 : 1 )); }
  INJ_PROBE_TS=$EPOCHSECONDS; INJ_PROBED=-1; INJ_OK=()
  command -v iw >/dev/null 2>&1 || return 1
  # Every phy is probed and merged: pineapd picks its own inject interface, and each phy
  # registers only its own bands, so band/channel keys do not collide across them.
  for d in "$INJ_SYSFS"/*; do
    [ -e "$d" ] || continue
    phy=${d##*/}
    rows+=$(iw phy "$phy" channels 2>/dev/null)$'\n'
  done
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
# Matching "MHz [n]" loosely also covers the "phy%d %d MHz [%d]:" variant in the same binary.
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
#   DEAUTH  PINEAPPLE_DEAUTH_CLIENT     [bssid] [target] [channel]  deauth + disassoc
#   CSA     PINEAPPLE_DEAUTH_CLIENT_CSA [bssid] [channel]           channel-switch announcements
#   BOTH    PINEAPPLE_DEAUTH_CLIENT_ALL [bssid] [target] [channel]  all three frame types
response_cmd() {
  case "$1" in
    DEAUTH) printf 'PINEAPPLE_DEAUTH_CLIENT' ;;
    CSA)    printf 'PINEAPPLE_DEAUTH_CLIENT_CSA' ;;
    BOTH)   printf 'PINEAPPLE_DEAUTH_CLIENT_ALL' ;;
    *)      printf '' ;;
  esac
}

# posture_opts <badge> -> viable attack keys, best first; empty when nothing can reach the air
posture_opts() {
  case "$1" in
    'NOINJ'|'NONE') printf '' ;;                 # regulatory wall, or beacon protection: nothing works
    'C')            printf 'CSA BOTH DEAUTH' ;;  # PMF required: deauth is ignored but stays offered
    '?')            printf 'CSA BOTH DEAUTH' ;;  # posture unread: CSA lands on every badge but NONE
    *)              printf 'BOTH DEAUTH CSA' ;;
  esac
}

# posture_expect <badge> <attack key> -> works | partial | blocked | unknown
# Labels each option honestly in the picker so a deliberate no-hope attempt is still the operator's call.
posture_expect() {
  local b="$1" k="$2"
  [ "$b" = NOINJ ] && { printf 'blocked'; return 0; }
  [ "$b" = '?' ]   && { printf 'unknown'; return 0; }
  case "$k" in
    DEAUTH)      case "$b" in 'D+C') printf 'works' ;; 'D?+C') printf 'partial' ;; *) printf 'blocked' ;; esac ;;
    CSA|BOTH)    case "$b" in 'NONE') printf 'blocked' ;; *) printf 'works' ;; esac ;;
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
  rm -f "$LOCK_FILE" "$CHILD_FILE" /tmp/cs_up_?.pcap /tmp/cs_dn_?.pcap /tmp/cs_ot_?.pcap /tmp/cs_*.err /tmp/cs_signal "$LOOT_DIR/inventory.tsv.new" /tmp/cs_rows.tmp
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
 | [.mac, (.packets // 0), ($ssid | tostring | gsub("[|;\n\r\t]"; "_") | .[0:32]), ($best.channel // 0), ($best.freq // 0), $sig, (if $hid then 1 else 0 end), $t]
 | map(tostring) | join("|")'
JQ_CLI='.[] | ((.probes // .probed_ssids // .probed // []) ) as $p0
 | (if ($p0 | type) == "array" then $p0 else [$p0] end) as $p
 | [.mac, (.ap_mac // .bssid // "-"), (.packets // 0), (.signal // .rssi // "-"),
    ($p | map(if type == "object" then (.ssid // "") else tostring end) | map(gsub("[|;,\n\r\t]"; "_")) | join(",")),
    (.freq // 0), (.time // .last_seen // 0), (.channel // 0)]
 | map(tostring) | join("|")'

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
parse_cli_fallback() {   # stdout: mac|ap_mac|packets|signal|probes|freq|time|channel
  local json frag mac ap pk sig fr t ch
  json=$(cat); json=${json//\},\{/$'\n'}
  while IFS= read -r frag; do
    [[ $frag =~ \"mac\":\"([^\"]+)\" ]] || continue
    mac=${BASH_REMATCH[1]}; ap="-"; pk=0; sig="-"; fr=0; t=0; ch=0
    [[ $frag =~ \"ap_mac\":\"([^\"]*)\" ]] && ap=${BASH_REMATCH[1]}
    [[ $frag =~ \"packets\":([0-9]+) ]] && pk=${BASH_REMATCH[1]}
    [[ $frag =~ \"signal\":(-?[0-9]+) ]] && sig=${BASH_REMATCH[1]}
    [[ $frag =~ \"freq\":([0-9]+) ]] && fr=${BASH_REMATCH[1]}
    [[ $frag =~ \"time\":([0-9]+) ]] && t=${BASH_REMATCH[1]}
    [[ $frag =~ \"channel\":([0-9]+) ]] && ch=${BASH_REMATCH[1]}
    printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$mac" "${ap:--}" "$pk" "$sig" "" "$fr" "$t" "$ch"
  done <<<"$json"
}
recon_lines() {   # recon_lines APS|CLIENTS -> lines on stdout
  local what="$1" prog
  [ "$what" = APS ] && prog="$JQ_APS" || prog="$JQ_CLI"
  if [ "$HAVE_JQ" = 1 ]; then
    timeout 15 _pineap RECON "$what" format=json 2>/dev/null | jq -r "$prog" 2>/dev/null
  elif [ "$what" = APS ]; then
    timeout 15 _pineap RECON APS format=json 2>/dev/null | parse_aps_fallback
  else
    timeout 15 _pineap RECON CLIENTS format=json 2>/dev/null | parse_cli_fallback
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
  if [ "$fr" != 0 ] && [ -n "$fr" ]; then FREQ[$mac]="$fr"; BAND[$mac]=$(band_of "$fr"); fi
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
  command -v jq >/dev/null 2>&1 && HAVE_JQ=1
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
    [ "$(cat "$LOCK_FILE" 2>/dev/null)" = "$MAIN_PID" ] && rm -f "$LOCK_FILE" "$CHILD_FILE" ) >/dev/null 2>&1 &
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

band_rank() { case "$1" in CONFIRMED) printf 3 ;; LIKELY) printf 2 ;; STREAM|POSSIBLE) printf 1 ;; *) printf 0 ;; esac; }

run_cycle() {
  local line mac pk ssid ch fr sig hid t ap probes k=0 top=0 u=0 bz=0 r prev now_rank
  SEEN_THIS_CYCLE=(); NEW_LIKELY=(); NEW_CONFIRMED=(); NEW_LANE=(); CLIENTS_OF=(); SCORED=(); KITCL=(); KITAP=(); NOALERT=(); RSSI_IMPROVED=()
  CYCLE=$((CYCLE + 1))
  mapfile -t AP_LINES < <(recon_lines APS)
  mapfile -t CLI_LINES < <(recon_lines CLIENTS)
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
    [ "$fr" = 0 ] && [ "$ap" != "-" ] && fr=${FREQ[$ap]:-0}
    [ "$ch" = 0 ] && [ "$ap" != "-" ] && ch=${CH[$ap]:-0}
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
    now_rank=$(band_rank "${BANDNAME[$mac]}"); prev=${ALERTED_BAND[$mac]:-0}
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
      # secondary path: a CONFIRMED device that cannot be Watched at all (no tcpdump, not associated)
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
  r="${RSSI_LAST[$mac]:-}"; [ -n "$r" ] && r=$(printf '%d' "$r" 2>/dev/null)
  budget=$((ROW_W - 3 - 1 - 1 - 1 - ${#r} - 1))   # "NN " + " " + prox + glyph + rssi
  for t in ${TAGS[$mac]}; do
    [ "$t" = BUSY ] && continue
    if (( ${#tags} + ${#t} + (${#tags} > 0 ? 1 : 0) <= budget )); then tags+="${tags:+ }$t"; fi
  done
  [ -z "$tags" ] && tags="${TAGS[$mac]%% *}"
  ROW=$(printf '%2d %s %s%s%s' "$(( ${CONF[$mac]} > 99 ? 99 : ${CONF[$mac]} ))" "$tags" "${PROX[$mac]:-?}" "$glyph" "$r")
  [ "${BUSY[$mac]}" = 1 ] && ROW+=" busy"
  ROW=${ROW:0:$ROW_W}
}

# sort_macs KIND -> SORTED (bash insertion into buckets; zero fork)
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
    esac
    local p=3; case "${PROX[$mac]}" in N) p=0 ;; M) p=1 ;; F) p=2 ;; esac
    local kit=0; [ "${KITAP[$mac]}" = "?" ] && kit=1
    local bz=0; [ "${BUSY[$mac]}" = 1 ] && bz=1
    local rs=${RSSI_LAST[$mac]:--200}; [[ $rs =~ ^-?[0-9]+$ ]] || rs=-200
    if [ "$kind" = modules ]; then printf -v key '%d%d%04d%03d' $((1 - kit)) $((1 - bz)) $((200 + rs > 0 ? 400 - (200 + rs) : 400)) $((999 - ${CONF[$mac]}))
    else printf -v key '%d%d%03d' $((3 - $(band_rank "${BANDNAME[$mac]}"))) "$p" $((999 - ${CONF[$mac]})); fi
    keyed+=("$key $mac")
  done
  SORTED=()
  local -a tmp; local i j item
  tmp=("${keyed[@]}")
  for ((i = 1; i < ${#tmp[@]}; i++)); do item="${tmp[i]}"; j=$((i - 1)); while (( j >= 0 )) && [[ "${tmp[j]}" > "$item" ]]; do tmp[j + 1]="${tmp[j]}"; j=$((j - 1)); done; tmp[j + 1]="$item"; done
  for item in "${tmp[@]}"; do SORTED+=("${item#* }"); done
}

review_list() {
  local mac last_band="" i
  while :; do
    sort_macs hits
    ROW_TEXT=("Resume scan"); ROW_MAC=("")
    last_band=""
    for mac in "${SORTED[@]}"; do
      if [ "${BANDNAME[$mac]}" != "$last_band" ]; then last_band="${BANDNAME[$mac]}"; ROW_TEXT+=("-- $last_band --"); ROW_MAC+=(""); fi
      row_for "$mac"
      for i in "${ROW_TEXT[@]}"; do [ "$i" = "$ROW" ] && { ROW="${ROW:0:$((ROW_W - 5))} ${mac:13}"; break; }; done
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

detail_card() {
  local mac="$1" def="${2:-}" age wrow drow
  [ -n "$mac" ] || return 0
  while :; do
    age=$(( EPOCHSECONDS - ${LAST_SEEN[$mac]:-$EPOCHSECONDS} ))
    tag_lines "$mac"
    LOG "[$MODE] ${CONF[$mac]} ${BANDNAME[$mac]} ${ROLE[$mac]} $mac"$'\n'"cat: ${CAT[$mac]} ${VENDOR[$mac]:--}"$'\n'"ssid: ${SSID_CLEAN[$mac]:--} ch${CH[$mac]:-?} ${BAND[$mac]:-?}GHz"$'\n'"rssi ${RSSI_LAST[$mac]:--} best ${RSSI_BEST[$mac]:--} ${PROX[$mac]:-?} ${age}s ago"$'\n'"${TAGTXT%$'\n'}"
    if watchable "$mac"; then wrow="Watch"; elif [ "$HAVE_TCPDUMP" != 1 ]; then wrow="Watch (no tcpdump)"; else wrow="Watch n/a (not associated)"; fi
    [ "$def" = watch ] && def="$wrow" || def="Back"
    drow=""; [ "$RESPONSE" = 1 ] && drow=$(disrupt_row "$mac")
    pick_list "${CONF[$mac]} ${ID_LABEL[$mac]:-${TAGS[$mac]%% *}} ${mac:9}" "$def" "$wrow" ${drow:+"$drow"} "Locate" "Ignore for session" "Back" || return 0
    case "$PICK" in
      "Disrupt"*) disrupt_menu "$mac" ;;
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
# Table-driven settings menu over the starred recon keys: key|kind|floor|label. Values are applied
# to the running session and persisted with PAYLOAD_SET_CONFIG; Reset deletes the overrides and
# restores the config-block defaults captured at start (cfg_snapshot_defaults runs before
# load_overrides). The response-rung keys are deliberately not listed here.
SETTINGS_TABLE='CYCLE_SECS|int|5|scan period, s
THR_STREAM_UP|int|1|STREAM big uplink fr/s
COOLDOWN_SECS|int|0|re-alert suppression, s
DEDUPE_H|int|0|dedupe horizon, h (0 off)
RSSI_MIN|int|-100|list gate dBm (0 off)
ALERT_DIALOG|bool|0|ALERT on new CONFIRMED
SOUND|bool|0|ringtone on CONFIRMED
AUTO_WATCH|bool|0|offer Watch
AUTO_LOCATE|bool|0|offer Locate'
declare -A CFG_DEFAULT
cfg_snapshot_defaults() { local key _; while IFS='|' read -r key _; do [ -n "$key" ] && CFG_DEFAULT[$key]="${!key}"; done <<<"$SETTINGS_TABLE"; }
settings_row() {   # settings_row KEY -> sets S_KIND S_FLOOR S_LABEL from the table
  local key kind floor label; S_KIND=""; S_FLOOR=0; S_LABEL=""
  while IFS='|' read -r key kind floor label; do [ "$key" = "$1" ] && { S_KIND=$kind; S_FLOOR=$floor; S_LABEL=$label; return 0; }; done <<<"$SETTINGS_TABLE"
  return 1
}
S_KIND=""; S_FLOOR=0; S_LABEL=""
cfg_note_set() {   # cfg_note_set KEY VALUE|"" -> keep CFG_NOTE/CFG_OVERRIDES (start screen, report footer) in step with the overrides in force
  local w; local -a keep=()
  for w in $CFG_NOTE; do [ "${w%%=*}" = "$1" ] || keep+=("$w"); done
  [ -n "$2" ] && keep+=("$1=$2")
  CFG_NOTE=""; for w in "${keep[@]}"; do CFG_NOTE+=" $w"; done; CFG_OVERRIDES=${#keep[@]}
}
settings_apply() {   # settings_apply KEY VALUE -> live variable + persisted override
  local key="$1" val="$2"
  printf -v "$key" '%s' "$val"; cfg_note_set "$key" "$val"
  if command -v PAYLOAD_SET_CONFIG >/dev/null 2>&1 && PAYLOAD_SET_CONFIG "$PAYLOAD_NAME" "$key" "$val" >/dev/null 2>&1; then LOG "$key -> $val (saved)"
  else LOG yellow "$key -> $val (this run only)"; fi
  log cfg "set $key=$val"
  [ "$key" = DEDUPE_H ] && DEDUPE_RUN=1
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
  DEDUPE_RUN=1   # the response-rung overrides stay in force and stay counted
  log cfg "reset defaults"; LOG "settings reset to defaults"
}
settings_menu() {
  local key resp rc; local -a items
  while :; do
    items=("Back")   # first, so the default is on the page LIST_PICKER shows: Back + eight keys fill page 1, the ninth and Reset sit behind More...
    while IFS='|' read -r key _; do [ -n "$key" ] && items+=("$key = ${!key}"); done <<<"$SETTINGS_TABLE"
    items+=("Reset defaults")
    pick_list "Settings (saved on device)" "Back" "${items[@]}" || return 0
    case "$PICK" in "Back") return 0 ;; "Reset defaults") settings_reset; continue ;; esac
    key=${PICK%% = *}; settings_row "$key" || continue
    if [ "$S_KIND" = bool ]; then
      pick_list "$key: $S_LABEL" "$( [ "${!key}" = 1 ] && printf On || printf Off )" "On" "Off" "Back" || continue
      case "$PICK" in On) resp=1 ;; Off) resp=0 ;; *) continue ;; esac
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

# scan_loop: cycles until B opens Review and the operator picks Exit
scan_loop() {
  local rc
  set_state SCAN
  LOG "[$MODE] scanning. B = review/pause"
  while :; do
    run_cycle; emit_cycle
    if (( RECON_EMPTY >= 3 )); then
      RECON_EMPTY=0
      if confirm "Recon list empty. Start a 60 s Recon scan?"; then PINEAPPLE_RECON_NEW 60 >/dev/null 2>&1; LOG "Recon started (60 s)"; fi
    fi
    offer_dialogs
    set_state SCAN
    timeout "$CYCLE_SECS" WAIT_FOR_BUTTON_PRESS B >/dev/null 2>&1; rc=$?
    if (( rc == 0 )); then
      local t0=$EPOCHSECONDS
      review_list || return 1
      PAUSED_SECS=$((PAUSED_SECS + EPOCHSECONDS - t0))
      set_state SCAN
    elif (( rc != 124 )); then sleep 1; fi
  done
}

main_menu() {
  local def="Scan"
  while :; do
    local -a menu=("Scan"); (( DEDUPE_H > 0 )) && menu+=("Scan (fresh)"); menu+=("Review hits"); [ "$SHOW_MODULES" = 1 ] && menu+=("Unidentified modules"); menu+=("Mode" "Settings" "Write report" "Exit")
    pick_list "CamHound $VERSION [$MODE] sigs:$SIG_COUNT" "$def" "${menu[@]}" || { def="Exit"; continue; }
    case "$PICK" in
      "Scan") scan_loop || def="Exit" ;;
      "Scan (fresh)") DEDUPE_RUN=0; LOG "fresh scan: earlier runs ignored"; log mode "dedupe off for this run"; scan_loop || def="Exit" ;;
      "Review hits") review_list || def="Exit" ;;
      "Unidentified modules") modules_list ;;
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
         printf "%d %d %d %d %d %d\n", n, f, b, g, mx, cv }' "$1"
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
  [ -z "$c3" ] && { LOCK_TEXT="$RECON_IF: no channel read-back"; return 0; }   # cannot verify: proceed
  if [ "$c1" = "$c2" ] && [ "$c2" = "$c3" ]; then
    [ "$c3" = "$want" ] || [ "$want" = 0 ] && return 0
    PINEAPPLE_EXAMINE_CHANNEL "$want" "$secs" >/dev/null 2>&1; sleep 1; c3=$(cur_channel)
    LOCK_TEXT="locked by channel: $RECON_IF ch $c3"
    [ "$c3" = "$want" ] && return 1
    LOCK_TEXT="ch $c3 != $want, lock failed"; return 2
  fi
  LOCK_TEXT="$RECON_IF still hopping ($c1/$c2/$c3): lock failed"; return 2
}
cur_channel() { iwinfo "$RECON_IF" info 2>/dev/null | sed -n 's/.*Channel: \([0-9]*\).*/\1/p' | head -1; }
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
  local mac="$1" n secs ub us up delta10 asym_s rec10 i
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
  lock_target "$WATCH_BSSID" "$secs" >/dev/null; (( $? == 2 )) && { LOG yellow "$LOCK_TEXT"; unlock_target; set_state SCAN; return 1; }
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
# Operator-driven disconnect. Nothing transmits unless RESPONSE=1 AND the operator picks an attack
# from the device card; there is no automatic path from a detection to the air.
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
  [ "$present" = 0 ] && { printf 'MOVED'; return 0; }           # dropped out of recon entirely
  [ -z "$p0" ] || [ "$p0" = - ] && { printf 'INCONCLUSIVE'; return 0; }
  [ -z "$p1" ] || [ "$p1" = - ] && { printf 'INCONCLUSIVE'; return 0; }
  [[ $p0 =~ ^[0-9]+$ && $p1 =~ ^[0-9]+$ ]] || { printf 'INCONCLUSIVE'; return 0; }
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

# resp_snapshot -> RS_PK/RS_T (packets, last-seen) for the subjects of the attempt, from one Recon read:
# a client target measures itself; a broadcast (AP) target measures the AP's visible, non-random clients.
# The AP's own counter is never the subject: it keeps beaconing whatever happens to its clients.
declare -A RS_PK RS_T
resp_snapshot() {
  local m a pk sig pr fr t ch s
  RS_PK=(); RS_T=()
  while IFS='|' read -r m a pk sig pr fr t ch; do
    m=${m,,}; a=${a,,}
    if [ "$R_TARGET" = ff:ff:ff:ff:ff:ff ]; then [ "$a" = "$R_BSSID" ] || continue; is_rand "$m" && continue
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
  local -a subjects=(); local -A P0=() T0=()
  cmd=$(response_cmd "$k")
  [ -n "$cmd" ] || return 1
  if ! command -v "$cmd" >/dev/null 2>&1; then
    LOG red "$cmd not present in this firmware"; log resp "missing $cmd"; return 1
  fi
  resp_snapshot
  for m in "${!RS_PK[@]}"; do subjects+=("$m"); P0[$m]="${RS_PK[$m]}"; T0[$m]="${RS_T[$m]}"; done
  if [ "$R_TARGET" = ff:ff:ff:ff:ff:ff ]; then
    if (( ${#subjects[@]} == 0 )); then                        # nothing to disconnect, nothing to measure
      LOG red "no visible clients on ${R_BSSID:9}: nothing to disconnect"; log resp "refused $R_BSSID no clients"
      resp_write "$mac" "$badge" "$k" "$cmd" - - - NO_CLIENTS
      set_state RESPOND_NIL; return 1
    fi
  else
    (( ${#subjects[@]} == 0 )) && { subjects=("$R_TARGET"); P0[$R_TARGET]=-; T0[$R_TARGET]=-; }
  fi
  n=${#subjects[@]}
  lock_target "$R_BSSID" "$RESP_LOCK_SECS" "$R_CH"; rc=$?
  case $rc in 0) lock=ok ;; 1) lock=by-channel ;; *) lock=failed ;; esac
  if (( rc == 2 )); then
    unlock_target
    LOG red "lock failed: $LOCK_TEXT"; log resp "lock-failed $R_BSSID $LOCK_TEXT"
    for m in "${subjects[@]}"; do resp_write "$mac" "$badge" "$k" "$cmd" "$lock" "${P0[$m]}" - LOCK_FAILED "$m"; done
    set_state INCONCLUSIVE; return 1
  fi
  set_state RESPOND
  LOG "$k -> ${R_BSSID:9} ch $R_CH"$'\n'"lock: $lock, $n subject(s)"
  log resp "fire $k $R_BSSID $R_TARGET ch$R_CH badge=$badge lock=$lock subjects=$n"
  if [ "$k" = CSA ]; then "$cmd" "$R_BSSID" "$R_CH" >/dev/null 2>&1
  else "$cmd" "$R_BSSID" "$R_TARGET" "$R_CH" >/dev/null 2>&1; fi
  sleep "$RESP_SETTLE_SECS"
  resp_snapshot
  unlock_target
  for m in "${subjects[@]}"; do
    p0="${P0[$m]}"; t0="${T0[$m]}"; present=1; p1=-; t1=-
    if [ -n "${RS_PK[$m]+x}" ]; then p1="${RS_PK[$m]}"; t1="${RS_T[$m]}"; else present=0; fi
    verdict=$(resp_verdict "$p0" "$t0" "$p1" "$t1" "$present")
    case "$verdict" in MOVED) nmv=$((nmv + 1)) ;; NO_EFFECT) nne=$((nne + 1)) ;; *) ninc=$((ninc + 1)) ;; esac
    resp_write "$mac" "$badge" "$k" "$cmd" "$lock" "$p0" "$p1" "$verdict" "$m"
    log resp "subject $m $verdict pk $p0 -> $p1 present=$present"
  done
  verdict=$(resp_aggregate "$nmv" "$nne" "$ninc")
  log resp "verdict $verdict $R_TARGET moved=$nmv no_effect=$nne inconclusive=$ninc of $n"
  case "$verdict" in
    MOVED)     set_state RESPOND_HIT; LOG green "$verdict: $nmv/$n quiet" ;;
    NO_EFFECT) set_state RESPOND_NIL; LOG yellow "$verdict: $nne/$n still transmitting" ;;
    *)         set_state INCONCLUSIVE; LOG yellow "$verdict: $ninc/$n unsettled, $nmv quiet" ;;
  esac
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
  [ "${ROLE[$mac]}" = cli ] && bss="${AP_OF[$mac]:--}" || bss="$mac"
  if [ -n "${POSTURE[$bss]}" ] && (( EPOCHSECONDS - ${POSTURE_TS[$bss]:-0} < POSTURE_TTL )); then
    printf 'Disrupt [%s]' "${POSTURE[$bss]}"
  else
    printf 'Disrupt'
  fi
}

disrupt_menu() {   # the three attacks, ordered and labelled by what the beacon says will work
  local mac="$1" badge opts k exp items=() pickmap=() i=0 choice
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
    items+=("$(printf '%s (%s)' "$k" "$exp")"); pickmap+=("$k"); i=$((i + 1))
  done
  pick_list "Disrupt [$badge] ${R_TARGET:9}" "${items[0]}" "${items[@]}" "Back" || return 0
  [ "$PICK" = Back ] && return 0
  choice=""
  for ((i = 0; i < ${#items[@]}; i++)); do [ "$PICK" = "${items[$i]}" ] && choice="${pickmap[$i]}"; done
  [ -n "$choice" ] || return 0
  if [ "$RESPONSE_CONFIRM" = 1 ]; then
    confirm "$choice on ${R_TARGET:9} via ${R_BSSID:9} ch $R_CH?" || { LOG "cancelled"; return 0; }
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
    printf '\n== AP -> clients (top 20 per AP; module clients marked *; BASE? = hidden AP with 1-4 clients on a module/mixed OUI) ==\n'
    for mac in "${!AP_OF[@]}"; do ap="${AP_OF[$mac]}"; [ "$ap" != "-" ] && tree[$ap]+=" $mac"; done
    for ap in "${!tree[@]}"; do
      n2=0; line=""; local nonrand=0 base=""
      for mac in ${tree[$ap]}; do
        is_rand "$mac" || nonrand=$((nonrand + 1))
        (( n2 >= 20 )) && continue; n2=$((n2 + 1))
        l="${mac:9}"; [ "${VEND_TYPE[$mac]}" = VENDOR_MODULE ] && l="*$l"; line+=" $l(${VENDOR[$mac]:0:6})"
      done
      if [ "${HIDDEN[$ap]}" = 1 ] && (( nonrand >= 1 && nonrand <= 4 )) && { [ "${VEND_TYPE[$ap]}" = VENDOR_MODULE ] || [ "${VEND_TYPE[$ap]}" = VENDOR_WEAK ]; }; then base=" BASE?"; fi
      printf '%s %s %s [%s]%s:%s\n' "$ap" "${SSID_CLEAN[$ap]:-<hidden>}" "${VENDOR[$ap]:--}" "${BANDNAME[$ap]:-none}" "$base" "$line"
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
st_stub_ui() {   # laptop run: DuckyScript commands absent
  for c in LOG LED VIBRATE RINGTONE ALERT PROMPT ERROR_DIALOG PINEAPPLE_EXAMINE_BSSID PINEAPPLE_EXAMINE_CHANNEL PINEAPPLE_EXAMINE_RESET _pineap; do
    command -v "$c" >/dev/null 2>&1 || eval "$c() { :; }"
  done
}
st_device() {   # st_device mac role "vendor text" "ssid" hidden ap_of
  local m="$1"
  ROLE[$m]="$2"; VLOW[$m]="${3,,}"; VENDOR[$m]="${3:0:14}"; unset "VEND_TYPE[$m]"; SSID_CLEAN[$m]="$4"; HIDDEN[$m]="$5"; AP_OF[$m]="${6:--}"
  LAST_SEEN[$m]=$EPOCHSECONDS; N_SEEN[$m]=1; FIRST_SEEN[$m]=$EPOCHSECONDS; KITAP[$m]=""; unset "KITCL[$m]" "BEH[$m]" "BEH_GATE[$m]" "BEH_VERDICT[$m]" "EVENT_FLAG[$m]" "BUSY[$m]" "PROBES[$m]"
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
  # 5 proximity
  RSSI_HIST[aa:00:00:00:00:01]="-70 -58 -65"; BAND[aa:00:00:00:00:01]=2; MODE=ROOM; apply_mode; prox_of aa:00:00:00:00:01; st "prox ROOM -58 best = N" "${PROX[aa:00:00:00:00:01]}" N
  RSSI_HIST[aa:00:00:00:00:01]="-79"; prox_of aa:00:00:00:00:01; st "prox ROOM -79 = F" "${PROX[aa:00:00:00:00:01]}" F
  MODE=SITE; apply_mode; prox_of aa:00:00:00:00:01; st "prox SITE -79 = M" "${PROX[aa:00:00:00:00:01]}" M; MODE=ROOM; apply_mode
  # 6 rows / status / inventory
  RSSI_LAST[aa:00:00:00:00:01]=-58; PROX[aa:00:00:00:00:01]=N; row_for aa:00:00:00:00:01; st "row fits ROW_W" "$(( ${#ROW} <= ROW_W ))" 1
  st "row text" "$ROW" "90 HIK-OUI NA-58"
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
  # three operator-selectable attacks: command mapping, viability, honest per-option labels
  st "cmd DEAUTH"  "$(response_cmd DEAUTH)" "PINEAPPLE_DEAUTH_CLIENT"
  st "cmd CSA"     "$(response_cmd CSA)"    "PINEAPPLE_DEAUTH_CLIENT_CSA"
  st "cmd BOTH"    "$(response_cmd BOTH)"   "PINEAPPLE_DEAUTH_CLIENT_ALL"
  st "cmd unknown is empty" "$(response_cmd WAT)" ""
  st "opts no PMF prefers BOTH"   "$(posture_opts 'D+C')"  "BOTH DEAUTH CSA"
  st "opts PMF required leads CSA" "$(posture_opts C)"     "CSA BOTH DEAUTH"
  st "opts beacon prot offers none" "$(posture_opts NONE)" ""
  st "opts no-inject offers none"  "$(posture_opts NOINJ)" ""
  st "opts unread leads CSA"       "$(posture_opts '?')"   "CSA BOTH DEAUTH"
  st "expect deauth vs no PMF"     "$(posture_expect 'D+C' DEAUTH)"  "works"
  st "expect deauth vs optional PMF" "$(posture_expect 'D?+C' DEAUTH)" "partial"
  st "expect deauth vs required PMF" "$(posture_expect C DEAUTH)"    "blocked"
  st "expect csa vs required PMF"  "$(posture_expect C CSA)"         "works"
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
  st "verdict no follow-up"     "$(resp_verdict 100 50 - - 1)"     "INCONCLUSIVE"
  st "verdict non-numeric"      "$(resp_verdict x 50 y 60 1)"      "INCONCLUSIVE"
  POSTURE[aa:00:00:00:00:10]=C; POSTURE_TS[aa:00:00:00:00:10]=$EPOCHSECONDS
  st "disrupt row shows cached badge" "$(disrupt_row aa:00:00:00:00:10)" "Disrupt [C]"
  st "disrupt row bare when uncached" "$(disrupt_row aa:00:00:00:00:13)" "Disrupt"
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
  rm -f "$tmp/responses.tsv"; resp_write aa:00:00:00:00:10 C CSA PINEAPPLE_DEAUTH_CLIENT_CSA ok 10 10 MOVED aa:00:00:00:00:11
  st "response row: measured target override" "$(sed -n 2p "$tmp/responses.tsv" | cut -d'|' -f5)" "aa:00:00:00:00:11"
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
  cfg_note_set CYCLE_SECS ""; st "settings: reset keeps the response-rung overrides counted" "$CFG_OVERRIDES:$CFG_NOTE" "1: RESPONSE=1"; CFG_OVERRIDES=0; CFG_NOTE=""
  CYCLE_SECS=20; cfg_snapshot_defaults; CYCLE_SECS=7; st "settings: default captured" "${CFG_DEFAULT[CYCLE_SECS]}" "20"
  settings_row CYCLE_SECS; st "settings: table row" "$S_KIND $S_FLOOR" "int 5"
  settings_row NOSUCHKEY; st "settings: unknown key rc" "$?" 1
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
(( CFG_OVERRIDES > 0 )) && { LOG yellow "cfg: $CFG_OVERRIDES overrides"; log cfg "$CFG_NOTE"; }
log run "start v$VERSION run=$RUN_ID sigs=$SIG_COUNT($SIG_SOURCE) jq=$HAVE_JQ tcpdump=$HAVE_TCPDUMP bands=${BANDS_LINE:-?} mode=$MODE loaded=$LOADED_ROWS dedupe_h=$DEDUPE_H"
LOG "CamHound $VERSION [$MODE]"$'\n'"sigs: $SIG_COUNT ($SIG_SOURCE)$( [ "$HAVE_JQ" = 1 ] || printf ' no-jq')$( [ "$HAVE_TCPDUMP" = 1 ] || printf ' no-tcpdump')"$'\n'"bands: ${BANDS_LINE:-?}"$'\n'"prox: uncal"
[ "$HAVE_TCPDUMP" = 1 ] || LOG yellow "no tcpdump (or no hexdump/od): Watch disabled"
main_menu
REPORT_DONE_AT_EXIT=1; write_report quiet
exit 0

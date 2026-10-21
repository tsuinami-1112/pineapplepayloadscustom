#!/bin/bash
# shellcheck disable=SC2034   # config and scan-state declarations are copied verbatim; the hook uses a subset
# Title: CamHound (Recon hook)
# Description: Run CamHound's Watch (live view), Stimulus test or Locate on the AP or client that is
#              selected in the Recon menu. The same file is installed as recon/client/CamHound and
#              recon/access_point/CamHound; it branches at run time on the selected-client variable.
#              GENERATED FILE: dev/CamHound/gen_hooks.sh copies the config block, the lib block and
#              the watch-core block verbatim from library/user/reconnaissance/CamHound/payload.sh.
#              Edit the user payload and regenerate; dev/CamHound/check_sync.sh verifies the copies.
# Author: tsuinami-1112
# Version: 1.0
# Category: reconnaissance
# Dependencies: _pineap, tcpdump + hexdump (Watch), iwinfo, /lib/hak5/oui.txt; cam_signatures.txt next
#               to this file or in the user payload directory (both are probed).
#
# LED State Descriptions
# SETUP          - loading signatures and preflight
# CYAN VERYFAST  - Watch running (Recon hopping paused by the EXAMINE lock)
# R SOLID        - Watch reached STREAM or EVENT (+ one long vibe)
# YELLOW         - Watch INCONCLUSIVE (+ one short vibe)
# B/C/Y/R SOLID  - Locate tiers cold/warm/strong/hot (click per sample, vibe at hot)
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
RSSI_MIN=0              # * optional list gate on session rssi_best (0 = off, widest net)
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
ROW_W=22                # list row budget (spike 19; expected 36-40 on the default theme)
RECON_IF="wlan1mon"     # PineAP monitor radio (tri-band)
# response rung (recon+response). RESPONSE=0 keeps the payload recon-only and silent.
RESPONSE=0              # * master switch for the response rung (0 = recon only)
RESPONSE_CONFIRM=1      # * blocking confirmation dialog before any transmit (0 = act on accept alone)
AUTO_RESPOND=0          # * let the funnel offer Disrupt by itself (needs RESPONSE=1; 0 = manual only)
# shellcheck disable=SC2034
SCAN_IF="wlan0"         # reserved: posture cross-check iface, the enabled dummy sta on radio0 (2.4 GHz only)
BCN_CAP_SECS=4          # seconds to wait for a beacon when reading a target's posture
BCN_CAP_COUNT=5         # beacons to capture per posture read (first usable one is parsed)
POSTURE_TTL=300         # * seconds a posture badge stays cached per BSSID
RESP_LOCK_SECS=20       # EXAMINE lock duration held across a response
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
  [IDLE]="asleep, disarmed or local-record" [NONE]="traffic seen, no camera pattern")

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
  command -v PAYLOAD_GET_CONFIG >/dev/null 2>&1 || return 0
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
  AUTO_RESPOND=$(cfg AUTO_RESPOND "$AUTO_RESPOND" 0)
  POSTURE_TTL=$(cfg POSTURE_TTL "$POSTURE_TTL" 0)
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
declare -A POSTURE POSTURE_TS

hex_octet() {   # hex_octet <hexstring> <index0> -> decimal octet, nonzero rc if short
  local b="${1:$(( $2 * 2 )):2}"
  [ ${#b} -eq 2 ] || return 1
  [[ $b =~ ^[0-9a-fA-F]{2}$ ]] || return 1
  printf '%d' "$(( 16#$b ))"
}

csa_injectable() {   # csa_injectable <band> <channel> -> 0 when the radio may legally transmit
  local b="$1" c="$2"
  [[ $c =~ ^[0-9]+$ ]] || return 1
  case "$b" in
    2) return 0 ;;
    5) (( c >= 36 && c <= 48 )) && return 0
       (( c >= 149 && c <= 165 )) && return 0
       return 1 ;;          # 52-144 is DFS: cfg80211 marks it NO_IR, injection is dropped
    *) return 1 ;;          # 6 GHz is NO_IR for injection, and always WPA3 anyway
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
  if [ -n "${POSTURE[$bssid]}" ] && (( now - ${POSTURE_TS[$bssid]:-0} < POSTURE_TTL )); then
    POSTURE_LAST="${POSTURE[$bssid]}"; printf '%s' "$POSTURE_LAST"; return 0
  fi
  # A channel we may not transmit on needs no capture: the answer is NOINJ whatever the beacon says.
  if [ "$(posture_from_caps - - "$band" "$ch")" = NOINJ ]; then
    POSTURE[$bssid]=NOINJ; POSTURE_TS[$bssid]=$now; POSTURE_LAST=NOINJ; printf 'NOINJ'; return 0
  fi
  # Recon hops while unlocked, so a 4 s capture on one BSSID mostly misses; hold the channel for it.
  if [ "$WATCH_LOCKED" != 1 ]; then lock_target "$bssid" $(( BCN_CAP_SECS + 5 )) "$ch" >/dev/null; locked_here=1; fi
  if f=$(capture_beacon "$bssid"); then posture_read_pcap "$f" "$band" "$ch" >/dev/null; b="$POSTURE_BADGE"; rm -f "$f"; else POSTURE_RSN=-; POSTURE_EXT=-; b='?'; fi
  (( locked_here )) && unlock_target
  if [ "$b" != '?' ]; then POSTURE[$bssid]="$b"; POSTURE_TS[$bssid]=$now; fi   # a failed read is not cached
  POSTURE_LAST="$b"; printf '%s' "$b"
}
# --- response posture end ---

cleanup() {
  [ "$(cat "$LOCK_FILE" 2>/dev/null)" = "$$" ] || return 0
  trap - EXIT INT TERM
  kill_children
  if [ "$WATCH_LOCKED" = 1 ]; then _pineap EXAMINE CANCEL >/dev/null 2>&1; PINEAPPLE_EXAMINE_RESET >/dev/null 2>&1; fi
  [ -n "$RUN_ID" ] && [ "$REPORT_DONE_AT_EXIT" != 1 ] && write_report quiet
  rm -f "$LOCK_FILE" "$CHILD_FILE" /tmp/cs_up_?.pcap /tmp/cs_dn_?.pcap /tmp/cs_ot_?.pcap /tmp/cs_*.err /tmp/cs_signal /tmp/cs_inv.new /tmp/cs_rows.tmp
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
    ROLE[$mac]="$role"; FIRST_SEEN[$mac]=$EPOCHSECONDS; N_SEEN[$mac]=0; RSSI_HIST[$mac]=""
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
declare -A RSSI_IMPROVED
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
upsert_rows() {   # upsert_rows mac... -> merge these rows into inventory.tsv
  local m f="$LOOT_DIR/inventory.tsv"
  { for m in "$@"; do [ -n "${ROLE[$m]}" ] && inv_row "$m"; done; } >/tmp/cs_rows.tmp
  [ -s /tmp/cs_rows.tmp ] || return 0
  [ -s "$f" ] || printf '%s\n' "$INV_HDR" >"$f"
  awk -F'|' 'NR==FNR { new[$4]=$0; next } /^#/ { print; next } { if ($4 in new) { print new[$4]; delete new[$4] } else print } END { for (k in new) print new[k] }' /tmp/cs_rows.tmp "$f" >/tmp/cs_inv.new 2>/dev/null && mv /tmp/cs_inv.new "$f"
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
  command -v tcpdump >/dev/null 2>&1 && command -v hexdump >/dev/null 2>&1 && HAVE_TCPDUMP=1
  [ -r "$OUI_FILE" ] || OUI_FILE="$OUI_FILE_ALT"
  [ -r "$OUI_FILE" ] || LOG yellow "no oui.txt: vendor rows disabled, OUI rows only"
  for i in wlan0 wlan1 wlan1mon wlan0cli wlan0mon; do a=$(cat "/sys/class/net/$i/address" 2>/dev/null); [ -n "$a" ] && OWN_MACS+="${a,,} "; done
  a=$(uci -q get pineapd.wlan1mon.bands 2>/dev/null || uci -q get pineapd.wlan1.bands 2>/dev/null); a=${a//[![:alnum:],]/}
  [ -n "$a" ] && { BANDS_LINE="$a"; [[ $a != *6* ]] && BANDS_LINE+=" (6 GHz not scanned)"; }
  if [ -f "$INSTALL_DIR/cam_signatures.txt" ]; then load_signatures "$INSTALL_DIR/cam_signatures.txt"; SIG_SOURCE="file"; fi
  if (( SIG_COUNT < 10 )); then load_signatures <(builtin_signatures); SIG_SOURCE="built-in"; fi
  (( SIG_COUNT == 0 )) && { set_state FAIL; ERROR_DIALOG "CamHound: no signatures" 2>/dev/null; exit 0; }
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
  if [ "$KEEP_RAW" = 1 ]; then { printf '# %s up %s\n' "$EPOCHSECONDS" "$WATCH_MAC"; cat "/tmp/cs_up_$x.b"; printf '# dn\n'; cat "/tmp/cs_dn_$x.b"; } >>"$LOOT_DIR/raw_$RUN_ID.txt" 2>/dev/null; fi
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
  watch_prepare "$mac" "$secs" || return 1
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

resp_write() {   # resp_write <mac> <badge> <attack> <cmd> <lock> <pk0> <pk1> <verdict>
  local f="$LOOT_DIR/responses.tsv" bp=-
  [ "$POSTURE_EXT" = - ] || bp=$(hex_octet "$POSTURE_EXT" 10 2>/dev/null) || bp=-
  [ -s "$f" ] || printf '%s\n' "$RESP_HDR" >"$f" 2>/dev/null
  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
    "$EPOCHSECONDS" "$1" "${ROLE[$1]:--}" "$R_BSSID" "$R_TARGET" "$R_CH" "$R_BAND" \
    "$2" "${POSTURE_RSN:--}" "$bp" "$3" "$4" "$5" "$6" "$7" "$8" >>"$f" 2>/dev/null
}

resp_fire() {   # resp_fire <mac> <attack key> <badge> -> 0 when a verdict was reached
  local mac="$1" k="$2" badge="$3" cmd lock rc s p0=- t0=- p1=- t1=- present=1 verdict
  cmd=$(response_cmd "$k")
  [ -n "$cmd" ] || return 1
  if ! command -v "$cmd" >/dev/null 2>&1; then
    LOG red "$cmd not present in this firmware"; log resp "missing $cmd"; return 1
  fi
  if s=$(recon_stat "$R_TARGET"); then read -r p0 t0 <<<"$s"; fi
  lock_target "$R_BSSID" "$RESP_LOCK_SECS" "$R_CH"; rc=$?
  case $rc in 0) lock=ok ;; 1) lock=by-channel ;; *) lock=failed ;; esac
  if (( rc == 2 )); then
    unlock_target
    LOG red "lock failed: $LOCK_TEXT"; log resp "lock-failed $R_BSSID $LOCK_TEXT"
    resp_write "$mac" "$badge" "$k" "$cmd" "$lock" "$p0" - LOCK_FAILED
    set_state INCONCLUSIVE; return 1
  fi
  set_state RESPOND
  LOG "$k -> ${R_BSSID:9} ch $R_CH"$'\n'"lock: $lock"
  log resp "fire $k $R_BSSID $R_TARGET ch$R_CH badge=$badge lock=$lock"
  if [ "$k" = CSA ]; then "$cmd" "$R_BSSID" "$R_CH" >/dev/null 2>&1
  else "$cmd" "$R_BSSID" "$R_TARGET" "$R_CH" >/dev/null 2>&1; fi
  sleep "$RESP_SETTLE_SECS"
  if s=$(recon_stat "$R_TARGET"); then read -r p1 t1 <<<"$s"; else present=0; fi
  unlock_target
  verdict=$(resp_verdict "$p0" "$t0" "$p1" "$t1" "$present")
  resp_write "$mac" "$badge" "$k" "$cmd" "$lock" "$p0" "$p1" "$verdict"
  log resp "verdict $verdict $R_TARGET pk $p0 -> $p1 present=$present"
  case "$verdict" in
    MOVED)     set_state RESPOND_HIT; LOG green "$verdict: target went quiet" ;;
    NO_EFFECT) set_state RESPOND_NIL; LOG yellow "$verdict: still transmitting (pk $p0 -> $p1)" ;;
    *)         set_state INCONCLUSIVE; LOG yellow "$verdict: recon could not settle it" ;;
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
  posture_of "$R_BSSID" "$R_BAND" "$R_CH" >/dev/null; badge="$POSTURE_LAST"
  opts=$(posture_opts "$badge")
  LOG "[$badge] ${R_BSSID:9} ch$R_CH ${R_BAND}GHz"$'\n'"target ${R_TARGET:9}"$'\n'"$(posture_why "$badge")"
  if [ -z "$opts" ]; then
    LOG red "$(posture_why "$badge")"
    confirm "Nothing is expected to work ($badge). Try anyway?" || return 0
    opts='BOTH DEAUTH CSA'
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
    'NONE')  printf 'PMF + beacon protection: nothing here works' ;;
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

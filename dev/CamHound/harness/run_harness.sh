#!/bin/bash
# Laptop harness for CamHound. Runs the user payload against stub DuckyScript commands, a fake
# _pineap (RECON fixtures in fix/), a fake tcpdump (synthetic pcaps) and a fake iwinfo, then checks
# the verdicts and the loot. Writes only under a temp directory and /tmp/cs_*.
# Needs bash 5 and jq; uses busybox hexdump/awk when busybox is installed (closer to the Pager).
# Usage: dev/CamHound/harness/run_harness.sh [live|stimulus|lock|nojq|locate|all]
set -u
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../../.." && pwd)
SRC="$ROOT/library/user/reconnaissance/CamHound/payload.sh"
T=$(mktemp -d); LOOT="$T/loot"; FAIL=0
export HARNESS_LOG="$T/log" HARNESS_FIX="$HERE/fix" HARNESS_ANSWERS="$T/answers" HARNESS_CFG="$T/cfg" DUCKYSCRIPT_USER_CONFIRMED=1
mkdir -p "$T/bin"; if command -v busybox >/dev/null 2>&1; then for a in hexdump awk od sort timeout; do ln -sf "$(command -v busybox)" "$T/bin/$a"; done; fi
# fast copy: 5 s windows, four live windows, short stimulus windows, fixture OUI table, temp loot
sed -e 's/^WIN_SECS=10 /WIN_SECS=5 /' -e 's/^LIVE_WINDOWS=6 /LIVE_WINDOWS=4 /' \
    -e 's/^WIN_BASE_S=30; WIN_STIM_S=20; WIN_POST_S=20 /WIN_BASE_S=6; WIN_STIM_S=5; WIN_POST_S=5 /' -e 's/^QUIET_SECS=15 /QUIET_SECS=3 /' \
    -e "s|^OUI_FILE=\"/lib/hak5/oui.txt\"; OUI_FILE_ALT=\"/rom/lib/hak5/oui.txt\"|OUI_FILE=\"$HERE/fix/oui.txt\"; OUI_FILE_ALT=\"$HERE/fix/oui.txt\"|" \
    -e 's/^RESP_SETTLE_SECS=6 /RESP_SETTLE_SECS=1 /' -e 's/^BCN_CAP_SECS=4 /BCN_CAP_SECS=2 /' \
    -e "s|^INJ_SYSFS=\"/sys/class/ieee80211\"|INJ_SYSFS=\"$T/phy\"|" \
    -e "s|^LOOT_DIR=\"/root/loot/CamHound\"|LOOT_DIR=\"$LOOT\"|" "$SRC" >"$T/payload_fast.sh"
grep -q "LOOT_DIR=\"$LOOT\"" "$T/payload_fast.sh" || { echo "sed on the config block failed"; exit 1; }
grep -q "INJ_SYSFS=\"$T/phy\"" "$T/payload_fast.sh" || { echo "sed on INJ_SYSFS failed"; exit 1; }
mkdir -p "$T/phy/phy0"          # one fake phy; the iw stub answers 'iw phy phy0 channels' with a US-like table
printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"
PATHX="$HERE/stubs:$T/bin:$PATH"
reset() { [ "${1:-}" = keep ] || rm -rf "$LOOT"; rm -rf "$T/log" "$T"/rules*.c* /tmp/cs_harness_chan /tmp/cs_harness_pps /tmp/cs_run.pid /tmp/cs_children; mkdir -p "$LOOT"; echo 0 >/tmp/cs_harness_cycle; }
rules() { local f="$T/rules_$1"; shift; printf '%s\t%s\n' "$@" >"$f"; export HARNESS_RULES="$f"; }
answers() { printf '%s\n' "$@" >"$HARNESS_ANSWERS"; }
check() { if eval "$2"; then printf 'PASS %s\n' "$1"; else printf 'FAIL %s\n' "$1"; FAIL=$((FAIL + 1)); fi; }
run() { PATH="$PATHX" timeout 300 bash "$T/payload_fast.sh" >/dev/null 2>"$T/stderr"; }
COMMON=('Watch now' 0 'Watch top' 0 'Locate' 0 'Exit CamHound' 1 'Recon list' 0)

s_live() {   # Live view on the Reolink NVR AP -> STREAM, conf 80 -> 100
  reset; rules live '^CamHound' 'Scan,Exit' 'Review hits' '4,Exit' '^[0-9]+ REO' 'Watch,Back' '^Watch ' 'Live view' '^(STREAM|EVENT|NONE|IDLE|DOWN|QUIET)' 'Back' "${COMMON[@]}"
  answers t t B t t t t; run
  check "live: CONFIRMED block has Hikvision and Reolink" "grep -q 'HIK-OUI aa:bb:01' $T/log && grep -q 'REO-OUI 00:00:10' $T/log"
  check "live: Watch verdict STREAM" "grep -q 'PICKER\[STREAM 00:00:10\]' $T/log"
  check "live: EXAMINE lock released" "grep -q 'PINEAPPLE_EXAMINE_RESET' $T/log"
  check "live: no lock file, no tcpdump left" "[ ! -e /tmp/cs_run.pid ] && [ \"\$(pgrep -x tcpdump | wc -l)\" = 0 ]"
  check "live: watched row reaches 100 in inventory" "grep -q '|ec:71:db:00:00:10|ap|NVRKIT|[^|]*|REO-OUI|100|' $LOOT/inventory.tsv"
}
s_stimulus() {   # Stimulus test on the Wyze client -> EVENT
  reset; rules stim '^CamHound' 'Scan,Exit' 'Review hits' '8,Exit' '^[0-9]+ WYZE' 'Watch,Back' '^Watch ' 'Stimulus test (~90 s)' '^(STREAM|EVENT|NONE|IDLE|DOWN|QUIET)' 'Back' "${COMMON[@]}"
  answers t t B; run
  check "stimulus: PROMPT then ALERT sequence" "grep -q '^PROMPT Baseline' $T/log && grep -q '^ALERT Now move' $T/log"
  check "stimulus: verdict EVENT" "grep -q 'PICKER\[EVENT 20:00:01\]' $T/log"
  check "stimulus: watch tsv row" "grep -q '|stim|1|' $LOOT/watch_*.tsv"
}
s_lock() {   # second instance refused; SIGKILL of the first is cleaned by the watchdog
  reset; rules lock '^CamHound' 'Scan' "${COMMON[@]}"; answers t t t t t t t t t t t t
  PATH="$PATHX" bash "$T/payload_fast.sh" >/dev/null 2>&1 & local p1=$!; sleep 7
  PATH="$PATHX" timeout 60 bash "$T/payload_fast.sh" >/dev/null 2>&1
  check "lock: second instance refused" "grep -q 'already running' $T/log"
  kill -9 $p1 2>/dev/null; sleep 5
  check "lock: watchdog removed the lock after SIGKILL" "[ ! -e /tmp/cs_run.pid ]"
  check "lock: watchdog cancelled EXAMINE" "grep -q 'EXAMINE CANCEL' $T/log"
  for p in $(pgrep -x sleep); do tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null | grep -q ' 1000' && kill "$p" 2>/dev/null; done; true
}
s_nojq() {   # fallback parser gives the same mac|conf rows as jq
  reset; rules nojq '^CamHound' 'Scan,Exit' 'Review hits' 'Exit' "${COMMON[@]}"; answers t t B; run
  cut -d'|' -f4,9 "$LOOT/inventory.tsv" | grep -v '^mac' | sort >"$T/rows_jq"
  local d nojq="$T/nojq"; mkdir -p "$nojq"
  for d in ${PATH//:/ }; do [ -x "$d/jq" ] || continue; for f in "$d"/*; do [ -e "$nojq/$(basename "$f")" ] || ln -s "$f" "$nojq/"; done; done; rm -f "$nojq/jq"
  local keep=""; for d in ${PATH//:/ }; do [ -x "$d/jq" ] || keep="$keep:$d"; done
  reset; rules nojq2 '^CamHound' 'Scan,Exit' 'Review hits' 'Exit' "${COMMON[@]}"; answers t t B
  PATH="$HERE/stubs:$T/bin:$nojq${keep}" timeout 300 bash "$T/payload_fast.sh" >/dev/null 2>"$T/stderr"
  cut -d'|' -f4,9 "$LOOT/inventory.tsv" | grep -v '^mac' | sort >"$T/rows_nojq"
  check "nojq: fallback parser used" "grep -q 'jq=0' $LOOT/events.log"
  check "nojq: identical mac|conf rows" "[ -s $T/rows_jq ] && cmp -s $T/rows_jq $T/rows_nojq"
}
s_locate() {   # Locate on the Hikvision AP: bars, tiers, clean stop
  reset; rules loc '^CamHound' 'Scan,Exit' 'Review hits' '3,Exit' '^[0-9]+ HIK' 'Locate,Back' "${COMMON[@]}"; answers t t B t t t t A; run
  check "locate: MONITOR started and bars drawn" "grep -q '^MONITOR MONITOR c0:56:e3' $T/log && grep -q 'dBm \[' $T/log"
  check "locate: stop logged" "grep -q 'locate stop' $LOOT/events.log"
}
s_disrupt() {   # RESPONSE=1: Disrupt on the Reolink AP against log-only stubs; posture, lock, loot row
  reset; printf 'CYCLE_SECS=5\nRESPONSE=1\n' >"$HARNESS_CFG"
  rules disrupt '^CamHound' 'Scan,Exit' 'Review hits' '4,Exit' '^[0-9]+ REO' 'Disrupt,Back' '^Disrupt \[' '1' ' via ' '1' "${COMMON[@]}"
  answers t t B; run; printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"
  check "disrupt: posture read under a lock on the target channel" "grep -q 'TCPDUMP beacon ec71db000010' $T/log && grep -q 'PINEAPPLE_EXAMINE_BSSID ec:71:db:00:00:10' $T/log"
  check "disrupt: badge D+C from the synthetic beacon" "grep -q 'PICKER\[Disrupt \[D+C\]' $T/log"
  check "disrupt: regulatory probe ran against the fixture phy" "grep -q '^IW phy phy0 channels' $T/log"
  check "disrupt: stub command called with bssid, broadcast target, channel 36" "grep -q '^PINEAPPLE_DEAUTH_CLIENT_ALL ec:71:db:00:00:10 ff:ff:ff:ff:ff:ff 36' $T/log"
  check "disrupt: lock verified ok (not by channel)" "grep -q 'lock: ok' $T/log"
  check "disrupt: one loot row per client, 16 fields, badge and raw caps" "[ \"\$(grep -c '^[0-9]' $LOOT/responses.tsv)\" = 2 ] && [ \"\$(sed -n 2p $LOOT/responses.tsv | awk -F'|' '{print NF}')\" = 16 ] && grep -q '|ec:71:db:00:00:11|36|5|D+C|0c00|' $LOOT/responses.tsv && grep -q '|ec:71:db:00:00:12|36|5|D+C|0c00|' $LOOT/responses.tsv"
  check "disrupt: aggregate verdict over both clients" "grep -q 'verdict MOVED ff:ff:ff:ff:ff:ff moved=2 no_effect=0 inconclusive=0 of 2' $LOOT/events.log"
  # guard: an AP with no visible clients (the Hikvision setup AP) is refused before anything is sent
  reset; printf 'CYCLE_SECS=5\nRESPONSE=1\n' >"$HARNESS_CFG"
  rules disrupt2 '^CamHound' 'Scan,Exit' 'Review hits' '3,Exit' '^[0-9]+ HIK' 'Disrupt,Back' '^Disrupt \[' '1' ' via ' '1' "${COMMON[@]}"
  answers t t B; run; printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"
  check "disrupt: AP without clients refused, nothing sent" "grep -q 'no visible clients' $T/log && ! grep -q '^PINEAPPLE_DEAUTH_CLIENT' $T/log && grep -q '|NO_CLIENTS$' $LOOT/responses.tsv"
  check "disrupt: cached badge shown on the card afterwards" "grep -q 'items=.*Disrupt \[D+C\]' $T/log"
  check "disrupt: EXAMINE released, no lock file" "grep -q 'PINEAPPLE_EXAMINE_RESET' $T/log && [ ! -e /tmp/cs_run.pid ]"
}
s_persist() {   # a second run with DEDUPE_H=24 stays silent on known devices; first_seen carries over; RAND rows are not stored
  reset; rules persist1 '^CamHound' 'Scan,Exit' 'Review hits' '4,Exit' '^[0-9]+ REO' 'Watch,Back' '^Watch ' 'Live view' '^(STREAM|EVENT|NONE|IDLE|DOWN|QUIET)' 'Back' "${COMMON[@]}"
  answers t t B t t t t; run
  local fs1; fs1=$(grep '|ec:71:db:00:00:10|' "$LOOT/inventory.tsv" | cut -d'|' -f1)
  check "persist: first run alerted, watched and stored rows" "grep -q 'REO-OUI 00:00:10' $T/log && [ -n \"$fs1\" ] && grep -q '|ec:71:db:00:00:10|ap|NVRKIT|[^|]*|REO-OUI|100|80|55|STREAM|' $LOOT/inventory.tsv"
  check "persist: randomised client not stored" "! grep -q '|02:ab:cd:00:00:01|' $LOOT/inventory.tsv"
  reset keep; printf 'CYCLE_SECS=5\nDEDUPE_H=24\n' >"$HARNESS_CFG"
  rules persist2 '^CamHound' 'Scan,Exit' 'Review hits' 'Exit' "${COMMON[@]}"; answers t t B; run; printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"
  check "persist: known devices not re-alerted" "! grep -q '^LOG red CONFIRMED' $T/log && ! grep -q '^LOG yellow LIKELY' $T/log && grep -q 'dedupe known ec:71:db:00:00:10' $LOOT/events.log"
  check "persist: first_seen carried over" "[ \"\$(grep '|ec:71:db:00:00:10|' $LOOT/inventory.tsv | cut -d'|' -f1)\" = \"$fs1\" ]"
  check "persist: SEEN tag and returning count" "grep -q '|ec:71:db:00:00:10|.*SEEN' $LOOT/inventory.tsv && grep -q 'returning [1-9]' $LOOT/report_*.txt"
  check "persist: Watch evidence carried into the second run" "grep -q '|ec:71:db:00:00:10|ap|NVRKIT|[^|]*|REO-OUI|100|80|55|STREAM|' $LOOT/inventory.tsv"
}
s_settings() {   # Settings menu: NUMBER_PICKER sets and persists a key, Reset deletes the overrides
  reset; printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"
  rules settings '^CamHound' 'Settings,Settings,Exit' '^Settings' 'CYCLE_SECS = 5,Back,Reset defaults,Back' '^CYCLE_SECS' '7' 'Reset all saved' '1' "${COMMON[@]}"
  answers t; run
  check "settings: value applied and persisted" "grep -q '^LOG CYCLE_SECS -> 7 (saved)' $T/log && grep -q 'cfg set CYCLE_SECS=7' $LOOT/events.log && grep -q 'PAYLOAD_SET_CONFIG camhound CYCLE_SECS 7' $T/log"
  check "settings: reset deletes the override and logs it" "grep -q 'cfg reset defaults' $LOOT/events.log && ! grep -q '^CYCLE_SECS=' $HARNESS_CFG && grep -q 'PAYLOAD_DEL_CONFIG camhound CYCLE_SECS' $T/log"
  check "settings: menu shows the live value after reset" "grep -q 'PICKER\[Settings.*CYCLE_SECS = 20;' $T/log"
  printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"
}
case "${1:-all}" in
  live) s_live ;; stimulus) s_stimulus ;; lock) s_lock ;; nojq) s_nojq ;; locate) s_locate ;; disrupt) s_disrupt ;; persist) s_persist ;; settings) s_settings ;;
  all) s_live; s_stimulus; s_lock; s_nojq; s_locate; s_disrupt; s_persist; s_settings ;;
  *) echo "usage: $0 [live|stimulus|lock|nojq|locate|disrupt|persist|settings|all]"; exit 2 ;;
esac
printf '== harness: %s failure(s); temp dir %s ==\n' "$FAIL" "$T"
exit $(( FAIL > 0 ))

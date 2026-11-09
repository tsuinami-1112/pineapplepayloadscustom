#!/bin/bash
# Laptop harness for CamHound. Runs the user payload against stub DuckyScript commands (including
# NUMBER_PICKER and PAYLOAD_SET/DEL_CONFIG), a fake _pineap (RECON fixtures in fix/), a fake tcpdump
# (synthetic pcaps; HARNESS_NO_BEACON=1 makes its beacon branch capture nothing), a fake iwinfo and a
# fake iw (US-like channel table, answered for whatever phy the net fixture under NET_SYSFS names
# as wlan1mon's phy (phy0), so the probe takes its resolved path; the INJ_SYSFS directory is reached
# only by the fallback), then checks the verdicts and the loot. Writes only under a temp directory and /tmp/cs_*. The LIST_PICKER stub answers only with items on the page it
# was handed: for an answer further down the list it presses 'More...' first, as an operator would,
# and it refuses (exit 1, logged 'not on this page') an answer that is on no page.
# Needs bash 5 and jq; uses busybox hexdump/awk when busybox is installed (closer to the Pager).
# Usage: dev/CamHound/harness/run_harness.sh [live|stimulus|lock|nojq|locate|disrupt|members|cliscope|blind|noinj|persist|settings|bands|devices|all]
set -u
# ONE RUN AT A TIME. Scenarios share /tmp/cs_run.pid, /tmp/cs_children, /tmp/cs_harness_* and the
# payload's own fixed temp paths, so two concurrent runs corrupt each other - and the failures
# surface in whichever scenario was unlucky, NOT the one you changed, which is the most misleading
# symptom available. On 2026-11-05 that produced two phantom `live` failures while the real change
# was in resp_fire. Refuse instead of racing.
exec 9>/tmp/cs_harness.lock
if command -v flock >/dev/null 2>&1 && ! flock -n 9; then
  echo "== harness: another run holds /tmp/cs_harness.lock; refusing (concurrent runs corrupt each other) =="
  exit 2
fi
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../../.." && pwd)
SRC="$ROOT/library/user/reconnaissance/CamHound/payload.sh"
T=$(mktemp -d); LOOT="$T/loot"; FAIL=0
export HARNESS_LOG="$T/log" HARNESS_FIX="$HERE/fix" HARNESS_ANSWERS="$T/answers" HARNESS_CFG="$T/cfg" DUCKYSCRIPT_USER_CONFIRMED=1
mkdir -p "$T/bin"; if command -v busybox >/dev/null 2>&1; then for a in hexdump awk od sort timeout; do ln -sf "$(command -v busybox)" "$T/bin/$a"; done; fi
# fast copy: 5 s windows, four live windows, short stimulus windows, fixture OUI table, temp loot
sed -e 's/^WIN_SECS=10 /WIN_SECS=5 /' -e 's/^LIVE_WINDOWS=6 /LIVE_WINDOWS=4 /' \
    -e 's/^WIN_BASE_S=30; WIN_STIM_S=20; WIN_POST_S=20 /WIN_BASE_S=6; WIN_STIM_S=5; WIN_POST_S=5 /' -e 's/^QUIET_SECS=15 /QUIET_SECS=3 /' \
    -e "s|^OUI_FILE=\"/lib/hak5/oui.txt\"; OUI_FILE_ALT=\"/rom/lib/hak5/oui.txt\"|OUI_FILE=\"$HERE/fix/oui.txt\"; OUI_FILE_ALT=\"$HERE/fix/oui.txt\"|" \
    -e 's/^RESP_SETTLE_SECS=6 /RESP_SETTLE_SECS=1 /' -e 's/^CLI_CAP_SECS=4 /CLI_CAP_SECS=2 /' -e 's/^BCN_CAP_SECS=4 /BCN_CAP_SECS=2 /' \
    -e "s|^INJ_SYSFS=\"/sys/class/ieee80211\"|INJ_SYSFS=\"$T/phy\"|" -e "s|^NET_SYSFS=\"/sys/class/net\"|NET_SYSFS=\"$T/net\"|" \
    -e 's/^BANDS_PROBE_N=12; BANDS_PROBE_WAIT=0.5 /BANDS_PROBE_N=2; BANDS_PROBE_WAIT=0.1 /' \
    -e "s|^LOOT_DIR=\"/root/loot/CamHound\"|LOOT_DIR=\"$LOOT\"|" "$SRC" >"$T/payload_fast.sh"
grep -q "LOOT_DIR=\"$LOOT\"" "$T/payload_fast.sh" || { echo "sed on the config block failed"; exit 1; }
grep -q "INJ_SYSFS=\"$T/phy\"" "$T/payload_fast.sh" || { echo "sed on INJ_SYSFS failed"; exit 1; }
grep -q "NET_SYSFS=\"$T/net\"" "$T/payload_fast.sh" || { echo "sed on NET_SYSFS failed"; exit 1; }
grep -q '^BANDS_PROBE_N=2; BANDS_PROBE_WAIT=0.1 ' "$T/payload_fast.sh" || { echo "sed on BANDS_PROBE_N failed"; exit 1; }
mkdir -p "$T/phy/phy0"          # fallback-merge fixture only: with the net tree below naming phy0, no scenario lists this directory
mkdir -p "$T/net/wlan1mon/phy80211"; printf 'phy0\n' >"$T/net/wlan1mon/phy80211/name"   # RECON_IF's phy: the probe reads this one, no merge
printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"
PATHX="$HERE/stubs:$T/bin:$PATH"
reset() { [ "${1:-}" = keep ] || rm -rf "$LOOT"; rm -rf "$T/log" "$T"/rules*.c* /tmp/cs_harness_chan /tmp/cs_harness_pps /tmp/cs_harness_bands /tmp/cs_run.pid /tmp/cs_children; mkdir -p "$LOOT"; echo 0 >/tmp/cs_harness_cycle; }
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
  # and the same comparison over RECON DEVICES, the path a 1.1.3 unit takes
  reset; rules nojq3 '^CamHound' 'Scan,Exit' 'Review hits' 'Exit' "${COMMON[@]}"; answers t t B; HARNESS_NO_CLIENTS=1 run
  cut -d'|' -f4,9 "$LOOT/inventory.tsv" | grep -v '^mac' | sort >"$T/rows_jq_dev"
  reset; rules nojq4 '^CamHound' 'Scan,Exit' 'Review hits' 'Exit' "${COMMON[@]}"; answers t t B
  HARNESS_NO_CLIENTS=1 PATH="$HERE/stubs:$T/bin:$nojq${keep}" timeout 300 bash "$T/payload_fast.sh" >/dev/null 2>"$T/stderr"
  cut -d'|' -f4,9 "$LOOT/inventory.tsv" | grep -v '^mac' | sort >"$T/rows_nojq_dev"
  check "nojq: identical rows from RECON DEVICES on both parsers" "grep -q 'client verb: DEVICES' $LOOT/events.log && grep -q . $T/rows_jq_dev && cmp -s $T/rows_jq_dev $T/rows_nojq_dev"
}
s_locate() {   # Locate on the Hikvision AP: bars, tiers, clean stop
  reset; rules loc '^CamHound' 'Scan,Exit' 'Review hits' '3,Exit' '^[0-9]+ HIK' 'Locate,Back' "${COMMON[@]}"; answers t t B t t t t A; run
  check "locate: MONITOR started and bars drawn" "grep -q '^MONITOR MONITOR c0:56:e3' $T/log && grep -q 'dBm \[' $T/log"
  check "locate: stop logged" "grep -q 'locate stop' $LOOT/events.log"
}
s_csainj() {   # the optional CSA injector: pagerinj in place of the firmware CSA command
  # CSA_INJECTOR is NOT starred -- cfg() takes integers only, so a path cannot arrive through
  # PAYLOAD_SET_CONFIG -- so this arm patches a SECOND copy of the payload rather than writing the
  # saved config. Only the config-block assignment is rewritten; everything under test
  # (csa_newchan, csa_issue, the lock budget) is the shipped code, unmodified.
  sed -e "s|^CSA_INJECTOR=\"\"|CSA_INJECTOR=\"$HERE/stubs/pagerinj\"|" "$T/payload_fast.sh" >"$T/payload_csa.sh"
  grep -q "^CSA_INJECTOR=\"$HERE/stubs/pagerinj\"" "$T/payload_csa.sh" || { echo "sed on CSA_INJECTOR failed"; exit 1; }
  # Reolink AP, ch 36 band 5, so csa_newchan must announce 40 -- never 36, which would announce no
  # move at all and which pagerinj refuses outright without --allow-same-chan.
  reset; printf 'CYCLE_SECS=5\nRESPONSE=1\n' >"$HARNESS_CFG"
  rules csainj '^CamHound' 'Scan,Exit' 'Review hits' '4,Exit' '^[0-9]+ REO' 'Disrupt,Back' '^Disrupt \[' '2' ' ch ' '1' "${COMMON[@]}"
  answers t t B; PATH="$PATHX" timeout 300 bash "$T/payload_csa.sh" >/dev/null 2>"$T/stderr"
  check "csainj: BOTH still sends the opcode-400 deauth" \
    "grep -q '^PINEAPPLE_DEAUTH_CLIENT ec:71:db:00:00:10 ff:ff:ff:ff:ff:ff 36\$' $T/log"
  check "csainj: the CSA leg went to the injector, not the firmware command" \
    "grep -q '^PAGERINJ ' $T/log && ! grep -q '^PINEAPPLE_DEAUTH_CLIENT_CSA' $T/log"
  check "csainj: it got the iface, the bssid, a DIFFERENT channel and a non-zero count" \
    "grep -qE '^PAGERINJ -i wlan1mon --csa --bssid ec:71:db:00:00:10 --chan 40 --count 3' $T/log"
  check "csainj: the loot names the injector, so a reader can tell which CSA this was" \
    "grep -q '|PINEAPPLE_DEAUTH_CLIENT+pagerinj:ch40:n3|' $LOOT/responses.tsv"
  check "csainj: the injector leg is logged with its rc" \
    "grep -qE 'csa inject pagerinj:ch40:n3 rc=0' $LOOT/events.log"
  # A failing injector must not read as a sent CSA, and must not retract the deauth that already
  # left. CMD_REFUSED in particular would be a lie: a frame WAS transmitted.
  reset; printf 'CYCLE_SECS=5\nRESPONSE=1\n' >"$HARNESS_CFG"
  rules csainj2 '^CamHound' 'Scan,Exit' 'Review hits' '4,Exit' '^[0-9]+ REO' 'Disrupt,Back' '^Disrupt \[' '2' ' ch ' '1' "${COMMON[@]}"
  answers t t B; HARNESS_INJ_FAIL=1 PATH="$PATHX" timeout 300 bash "$T/payload_csa.sh" >/dev/null 2>"$T/stderr"
  check "csainj: a failing injector leaves the deauth sent and says the CSA did not" \
    "grep -q '^PINEAPPLE_DEAUTH_CLIENT ec:71:db:00:00:10 ff:ff:ff:ff:ff:ff 36\$' $T/log && grep -q 'csa leg failed' $LOOT/events.log"
  check "csainj: a failed CSA leg is not recorded in the loot as a sent one" \
    "! grep -q '+pagerinj' $LOOT/responses.tsv && ! grep -q '|CMD_REFUSED\$' $LOOT/responses.tsv"
}

s_disrupt() {   # shipped default (RESPONSE=1 from the config block, nothing written to the saved config): Disrupt on the Reolink AP against log-only stubs; posture, lock, loot row
  reset; printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"
  rules disrupt '^CamHound' 'Scan,Exit' 'Review hits' '4,Exit' '^[0-9]+ REO' 'Disrupt,Back' '^Disrupt \[' '1' ' ch ' '1' "${COMMON[@]}"
  answers t t B; run
  check "disrupt: fires at the shipped default, with no RESPONSE override in the saved config" "! grep -q '^RESPONSE=' $HARNESS_CFG && grep -q '^PINEAPPLE_DEAUTH_CLIENT' $T/log"
  check "disrupt: posture read under a lock on the target channel" "grep -q 'TCPDUMP beacon ec71db000010' $T/log && grep -q 'PINEAPPLE_EXAMINE_BSSID ec:71:db:00:00:10' $T/log"
  check "disrupt: badge D+C from the synthetic beacon" "grep -q 'PICKER\[Disrupt \[D+C\]' $T/log"
  check "disrupt: regulatory probe ran against phy0, the phy the net fixture names" "grep -q '^IW phy phy0 channels' $T/log"
  check "disrupt: regulatory probe parsed the fixture (no fallback)" "! grep -q 'regulatory probe failed' $T/log"
  check "disrupt: probe read the transmitting phy, not a merge" "grep -q 'inj probe: tx phy phy0' $LOOT/events.log && ! grep -q 'tx phy unresolved' $LOOT/events.log && ! grep -q 'tx phy unresolved' $T/log"
  check "disrupt: stub command called with bssid, broadcast target, channel 36" "grep -q '^PINEAPPLE_DEAUTH_CLIENT ec:71:db:00:00:10 ff:ff:ff:ff:ff:ff 36' $T/log"
  check "disrupt: lock verified ok (not by channel)" "grep -q 'lock: ok' $T/log"
  check "disrupt: one loot row per client, 16 fields, badge and raw caps" "[ \"\$(grep -c '^[0-9]' $LOOT/responses.tsv)\" = 2 ] && [ \"\$(sed -n 2p $LOOT/responses.tsv | awk -F'|' '{print NF}')\" = 16 ] && grep -q '|ec:71:db:00:00:11|36|5|D+C|0c00|' $LOOT/responses.tsv && grep -q '|ec:71:db:00:00:12|36|5|D+C|0c00|' $LOOT/responses.tsv"
  check "disrupt: aggregate verdict over both clients" "grep -q 'verdict MOVED ff:ff:ff:ff:ff:ff scope=bss moved=2 no_effect=0 inconclusive=0 of 2' $LOOT/events.log"
  # BOTH is TWO commands, because no firmware command combines them. PINEAPPLE_DEAUTH_CLIENT_ALL
  # carries the CSA command id (StartDeauthAll emits li a0,402 at 0x0086c62c, the same id as
  # StartDeauthCsa) and builds no deauth frame at all, and pineapd's real deauth+CSA opcode 401 is
  # reached by nothing in the Go daemon. So resp_fire issues the opcode-400 deauth itself and then
  # the CSA, which is what 401 would have done. Page item 2; item 1 is DEAUTH.
  reset; printf 'CYCLE_SECS=5\nRESPONSE=1\n' >"$HARNESS_CFG"
  rules disrupt3 '^CamHound' 'Scan,Exit' 'Review hits' '4,Exit' '^[0-9]+ REO' 'Disrupt,Back' '^Disrupt \[' '2' ' ch ' '1' "${COMMON[@]}"
  answers t t B; run; printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"
  check "disrupt: BOTH sends the opcode-400 deauth and never _ALL" \
    "grep -q '^PINEAPPLE_DEAUTH_CLIENT ec:71:db:00:00:10 ff:ff:ff:ff:ff:ff 36\$' $T/log && ! grep -q '^PINEAPPLE_DEAUTH_CLIENT_ALL' $T/log"
  check "disrupt: BOTH also sends the CSA leg, bssid and channel only" \
    "grep -q '^PINEAPPLE_DEAUTH_CLIENT_CSA ec:71:db:00:00:10 36\$' $T/log"
  check "disrupt: both legs are logged and the loot names them" \
    "grep -q 'cmd PINEAPPLE_DEAUTH_CLIENT_CSA rc=0' $LOOT/events.log && grep -q '|PINEAPPLE_DEAUTH_CLIENT+CSA|' $LOOT/responses.tsv"
  check "disrupt: the picker labels BOTH deauth-only and CSA fw-broken" \
    "grep -q 'items=DEAUTH bss (works);BOTH bss (deauth only);CSA bss (fw-broken);' $T/log"
  check "disrupt: the targeted sweep still runs after BOTH" \
    "grep -qE 'sweep PINEAPPLE_DEAUTH_CLIENT ec:71:db:00:00:10 targeted=2 of 2' $LOOT/events.log"
  # guard: an AP with no visible clients (the Hikvision setup AP) is refused before anything is sent
  reset; printf 'CYCLE_SECS=5\nRESPONSE=1\n' >"$HARNESS_CFG"
  rules disrupt2 '^CamHound' 'Scan,Exit' 'Review hits' '3,Exit' '^[0-9]+ HIK' 'Disrupt,Back' '^Disrupt \[' '1' ' ch ' '1' "${COMMON[@]}"
  answers t t B; run; printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"
  check "disrupt: AP without clients refused, nothing sent" "grep -qE 'no visible clients|no clients heard' $T/log && ! grep -q '^PINEAPPLE_DEAUTH_CLIENT' $T/log && grep -q '|NO_CLIENTS$' $LOOT/responses.tsv"
  check "disrupt: cached badge shown on the card afterwards" "grep -q 'items=.*Disrupt \[D+C\]' $T/log"
  check "disrupt: EXAMINE released, no lock file" "grep -q 'PINEAPPLE_EXAMINE_RESET' $T/log && [ ! -e /tmp/cs_run.pid ]"
}
s_blind() {   # RESPONSE=1 with no beacon capturable: the ? badge asks before firing blind; accepted leads CSA, declined sends nothing
  reset; printf 'CYCLE_SECS=5\nRESPONSE=1\n' >"$HARNESS_CFG"
  rules blind '^CamHound' 'Scan,Exit' 'Review hits' '4,Exit' '^[0-9]+ REO' 'Disrupt,Back' 'Fire blind' '1' '^Disrupt \[' '3' ' ch ' '1' "${COMMON[@]}"
  answers t t B; HARNESS_NO_BEACON=1 run
  check "blind: capture attempted under a lock, nothing captured, badge ?" "grep -q 'TCPDUMP beacon suppressed ec71db000010' $T/log && grep -q 'PINEAPPLE_EXAMINE_BSSID ec:71:db:00:00:10' $T/log && grep -q '^LOG \[[?]\] 00:00:10 ch36 5GHz' $T/log"
  check "blind: Fire blind confirm shown and accepted" "grep -q 'CONFIRM\[Posture unread on 00:00:10: no beacon captured. Fire blind[?]\] -> 1' $T/log"
  # DEAUTH leads and is the only key the badge still speaks for; BOTH and CSA read fw-broken on
  # every badge because neither can construct a valid pineapd request (see payload posture_expect).
  check "blind: picker leads with DEAUTH, BOTH and CSA marked fw-broken, all bss-wide" "grep -q 'PICKER\[Disrupt \[[?]\] ff:ff:ff\] items=DEAUTH bss (unknown);BOTH bss (unknown);CSA bss (fw-broken);' $T/log"
  check "blind: the confirm names every client, not the broadcast target" "grep -q 'CONFIRM\[CSA on EVERY client of 00:00:10 ch 36[?]\] -> 1' $T/log"
  check "blind: CSA does not sweep, because the command takes no target" "! grep -qE '^PINEAPPLE_DEAUTH_CLIENT ' $T/log"
  check "blind: CSA fired with bssid and channel only, badge ? in the event" "grep -q '^PINEAPPLE_DEAUTH_CLIENT_CSA ec:71:db:00:00:10 36$' $T/log && grep -q 'fire CSA ec:71:db:00:00:10 ff:ff:ff:ff:ff:ff ch36 badge=? ' $LOOT/events.log"
  check "blind: loot rows carry badge ? and caps -" "grep -q '|ec:71:db:00:00:11|36|5|?|-|-|CSA|PINEAPPLE_DEAUTH_CLIENT_CSA|ok|' $LOOT/responses.tsv && grep -q '|ec:71:db:00:00:12|36|5|?|-|-|CSA|' $LOOT/responses.tsv"
  reset; printf 'CYCLE_SECS=5\nRESPONSE=1\n' >"$HARNESS_CFG"
  rules blind2 '^CamHound' 'Scan,Exit' 'Review hits' '4,Exit' '^[0-9]+ REO' 'Disrupt,Back' 'Fire blind' '0' '^Disrupt \[' '1' ' ch ' '1' "${COMMON[@]}"
  answers t t B; HARNESS_NO_BEACON=1 run; printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"
  check "blind: declined -> no picker, nothing sent, no loot row" "grep -q 'Fire blind[?]\] -> 0' $T/log && ! grep -q 'PICKER\[Disrupt \[' $T/log && ! grep -q '^PINEAPPLE_DEAUTH_CLIENT' $T/log && [ ! -e $LOOT/responses.tsv ]"
}
s_noinj() {   # the Reolink AP moved to DFS channel 52: gate 1 refuses before any capture or lock; "try anyway" declined sends nothing
  reset; printf 'CYCLE_SECS=5\nRESPONSE=1\n' >"$HARNESS_CFG"; mkdir -p "$T/fix_noinj"
  for f in "$HERE"/fix/*; do sed 's/"channel":36,"hidden":0,"freq":5180/"channel":52,"hidden":0,"freq":5260/' "$f" >"$T/fix_noinj/$(basename "$f")"; done
  grep -q '"channel":52' "$T/fix_noinj/aps.json" || { echo "sed on the noinj fixture failed"; FAIL=$((FAIL + 1)); }
  rules noinj '^CamHound' 'Scan,Exit' 'Review hits' '4,Exit' '^[0-9]+ REO' 'Disrupt,Back' 'Nothing is expected' '0' '^Disrupt \[' '1' ' ch ' '1' "${COMMON[@]}"
  answers t t B; HARNESS_FIX="$T/fix_noinj" run; printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"
  check "noinj: NOINJ decided without a capture or a lock" "grep -q '^LOG \[NOINJ\] 00:00:10 ch52 5GHz' $T/log && ! grep -q 'TCPDUMP beacon' $T/log && ! grep -q 'PINEAPPLE_EXAMINE_BSSID' $T/log"
  check "noinj: try-anyway confirm shown, declined, nothing sent" "grep -q 'CONFIRM\[Nothing is expected to work (NOINJ). Try anyway[?]\] -> 0' $T/log && ! grep -q 'PICKER\[Disrupt \[' $T/log && ! grep -q '^PINEAPPLE_DEAUTH_CLIENT' $T/log"
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
s_settings() {   # Settings: Recon page sets and persists a key; Response page's confirm-off asks first; Reset clears every table key
  reset; printf 'CYCLE_SECS=5\nRESPONSE=1\n' >"$HARNESS_CFG"
  rules settings '^CamHound' 'Settings,Settings,Exit' '^Settings' 'Recon settings,Back,Response settings,Reset defaults,Recon settings,Back' \
    '^Recon settings' 'CYCLE_SECS = 5,Back,Back' '^Response settings' 'RESPONSE_CONFIRM = 1,Back' '^RESPONSE_CONFIRM:' 'Off' 'Switch off the confirmation' '0' \
    '^CYCLE_SECS' '7' 'Reset all saved' '1' "${COMMON[@]}"
  answers t; run
  check "settings: value applied and persisted" "grep -q '^LOG CYCLE_SECS -> 7 (saved)' $T/log && grep -q 'cfg set CYCLE_SECS=7' $LOOT/events.log && grep -q 'PAYLOAD_SET_CONFIG camhound CYCLE_SECS 7' $T/log"
  check "settings: top page is Back, Recon, Response, Reset" "grep -q 'PICKER\[Settings (saved on device)\] items=Back;Recon settings;Response settings;Reset defaults;' $T/log"
  check "settings: response page lists the seven response keys with live values" "grep -q 'PICKER\[Response settings\] items=Back;RESPONSE = 1;RESPONSE_CONFIRM = 1;AUTO_RESPOND = 0;SWEEP_TARGETED = 1;RESP_LOCK_SECS = [0-9]*;RESP_SETTLE_SECS = [0-9]*;POSTURE_TTL = [0-9]*;' $T/log"
  check "settings: switching the pre-transmit confirm off asks first; declined keeps it on" "grep -q 'CONFIRM\[Switch off the confirmation before every transmit[?]\] -> 0' $T/log && ! grep -q 'PAYLOAD_SET_CONFIG camhound RESPONSE_CONFIRM' $T/log"
  check "settings: reset deletes the recon override and the response override" "grep -q 'cfg reset defaults' $LOOT/events.log && ! grep -q '^CYCLE_SECS=' $HARNESS_CFG && ! grep -q '^RESPONSE=' $HARNESS_CFG && grep -q 'PAYLOAD_DEL_CONFIG camhound RESPONSE$' $T/log"
  check "settings: recon page shows the live value after reset" "grep -q 'PICKER\[Recon settings\] items=Back;CYCLE_SECS = 20;' $T/log"
  printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"
}
s_cliscope() {   # RESPONSE=1: Disrupt on the Wyze CLIENT row -- the only menu that holds both scopes
  # DEAUTH (page item 1, and what pick_list preselects) is the one targeted option: cli scope,
  # the picked device alone. It leads since 2026-11-09 because it is the only key that transmits.
  reset; printf 'CYCLE_SECS=5\nRESPONSE=1\n' >"$HARNESS_CFG"
  rules cli1 '^CamHound' 'Scan,Exit' 'Review hits' '8,Exit' '^[0-9]+ WYZE' 'Disrupt,Back' '^Disrupt \[' '1' ' ch ' '1' "${COMMON[@]}"
  answers t t B; run
  check "cliscope: client row offers a mixed marker list, DEAUTH preselected" "grep -q 'PICKER\[Disrupt \[D+C\] 20:00:01\] items=DEAUTH (works);BOTH bss (deauth only);CSA bss (fw-broken);' $T/log"
  check "cliscope: DEAUTH confirm names the one device, not the BSS" "grep -q 'CONFIRM\[DEAUTH on 20:00:01 via 11:22:33 ch 6[?]\] -> 1' $T/log"
  check "cliscope: DEAUTH sent with the client as its target" "grep -q '^PINEAPPLE_DEAUTH_CLIENT 9c:3d:cf:11:22:33 a4:da:22:20:00:01 6$' $T/log"
  check "cliscope: cli scope measures the picked device alone" "grep -q 'scope=cli subjects=1' $LOOT/events.log && [ \"\$(grep -c '^[0-9]' $LOOT/responses.tsv)\" = 1 ]"
  check "cliscope: no picked line when the pick is the only subject" "! grep -q 'picked a4:da:22:20:00:01' $LOOT/events.log"
  # BOTH (page item 2 now) is BSS-wide from that same client row, which is the asymmetry this
  # arm exists for: the row names one device and the frame reaches the whole BSS.
  reset; printf 'CYCLE_SECS=5\nRESPONSE=1\n' >"$HARNESS_CFG"
  rules cli2 '^CamHound' 'Scan,Exit' 'Review hits' '8,Exit' '^[0-9]+ WYZE' 'Disrupt,Back' '^Disrupt \[' '2' ' ch ' '1' "${COMMON[@]}"
  answers t t B; run; printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"
  check "cliscope: BOTH confirm names every client of the BSS" "grep -q 'CONFIRM\[BOTH on EVERY client of 11:22:33 ch 6[?]\] -> 1' $T/log"
  check "cliscope: bss scope from a client row measures all four clients" "grep -q 'scope=bss subjects=4' $LOOT/events.log && [ \"\$(grep -c '^[0-9]' $LOOT/responses.tsv)\" = 4 ]"
  check "cliscope: the loot covers the collateral, not just the pick" "grep -q '|a4:da:22:20:00:01|' $LOOT/responses.tsv && grep -q '|3c:6a:2c:00:00:01|' $LOOT/responses.tsv && grep -q '|00:fc:8b:00:00:01|' $LOOT/responses.tsv"
  check "cliscope: the picked device's own verdict is still named" "grep -q 'picked a4:da:22:20:00:01 ' $LOOT/events.log && grep -q '^LOG picked 20:00:01: ' $T/log"
}
s_bands() {   # BAND6=1: the band write at start (trusted on read-back), the status line, the footer, the restore at exit
  reset; printf 'CYCLE_SECS=5\nBAND6=1\n' >"$HARNESS_CFG"
  rules bands '^CamHound' 'Scan,Exit' 'Review hits' 'Exit' "${COMMON[@]}"; answers t t B; run; printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"
  check "bands: written once at start as the device's bands plus 6, verified on the live channel" "[ \"\$(grep -c '^PINEAPPLE_SET_BANDS wlan1mon 2 5 6$' $T/log)\" = 1 ] && grep -q 'bands set 2 5 6 (was 2,5; live 6 GHz=yes, uci=2,5,6)' $LOOT/events.log"
  check "bands: status line and report footer carry the run's bands" "grep -q '^LOG bands: 2,5,6' $T/log && grep -q 'bands 2,5,6' $LOOT/report_*.txt"
  check "bands: restored at exit, after the report" "grep -q '^PINEAPPLE_SET_BANDS wlan1mon 2 5$' $T/log && grep -q 'bands restored 2,5' $LOOT/events.log && [ \"\$(cat /tmp/cs_harness_bands)\" = 2,5 ]"
  reset; printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"
  rules bands2 '^CamHound' 'Scan,Exit' 'Review hits' 'Exit' "${COMMON[@]}"; answers t t B; run
  check "bands: nothing written at the default" "! grep -q '^PINEAPPLE_SET_BANDS' $T/log && grep -q '6 GHz not scanned' $T/log"
  # the behaviour measured on 1.1.3: the call is accepted and changes nothing -- say so, and still restore the issued write
  reset; printf 'CYCLE_SECS=5\nBAND6=1\n' >"$HARNESS_CFG"
  rules bands3 '^CamHound' 'Scan,Exit' 'Review hits' 'Exit' "${COMMON[@]}"; answers t t B; HARNESS_BANDS_NOOP=1 run; printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"
  check "bands: a no-op write is reported, not claimed" "grep -q '^LOG yellow band write not applied: radio stayed on 2,5' $T/log && grep -q 'bands: write not applied' $LOOT/events.log && grep -q '6 GHz not scanned' $LOOT/report_*.txt"
  check "bands: an issued but untrusted write is still restored at exit" "[ \"\$(grep -c '^PINEAPPLE_SET_BANDS wlan1mon 2 5$' $T/log)\" = 1 ] && grep -q 'restored 2,5 (write was never trusted' $LOOT/events.log && [ ! -e $LOOT/.bands_orig ]"
  # switched on from Settings (BAND6 is the tenth Recon key, behind More...): applied at once, restored at exit
  reset; printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"
  rules bands4 '^CamHound' 'Settings,Exit' '^Settings' 'Recon settings,Back' '^Recon settings' 'BAND6 = 0,Back' '^BAND6:' 'On' "${COMMON[@]}"; answers t; run; printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"
  check "bands: Settings toggle applies the write now and persists the key" "grep -q 'PAYLOAD_SET_CONFIG camhound BAND6 1' $T/log && grep -q '^PINEAPPLE_SET_BANDS wlan1mon 2 5 6$' $T/log && grep -q '^LOG bands: 2,5,6' $T/log && grep -q '^PINEAPPLE_SET_BANDS wlan1mon 2 5$' $T/log"
  # a run killed mid-way leaves the state file; the next start restores from it before anything else
  reset; printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"; printf '2,5' >"$LOOT/.bands_orig"
  rules bands5 '^CamHound' 'Exit' "${COMMON[@]}"; answers t; run
  check "bands: a state file left by a killed run is replayed at the next start" "grep -q '^PINEAPPLE_SET_BANDS wlan1mon 2 5$' $T/log && grep -q 'restored 2,5 left by a previous run' $LOOT/events.log && [ ! -e $LOOT/.bands_orig ]"
  # a BAND6 run killed from the UI (SIGKILL): its own watchdog puts the bands back, keyed on the record's pid
  reset; printf 'CYCLE_SECS=5\nBAND6=1\n' >"$HARNESS_CFG"
  rules bands6 '^CamHound' 'Scan' "${COMMON[@]}"; answers t t t t t t t t t t t t
  PATH="$PATHX" bash "$T/payload_fast.sh" >/dev/null 2>&1 & local p6=$!
  for _ in $(seq 1 40); do grep -q '^PINEAPPLE_SET_BANDS wlan1mon 2 5 6$' "$T/log" 2>/dev/null && break; sleep 0.5; done
  sleep 2; kill -9 $p6 2>/dev/null; sleep 6; printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"
  check "bands: the killed run's own watchdog puts the bands back and drops the record" "[ \"\$(grep -c '^PINEAPPLE_SET_BANDS wlan1mon 2 5$' $T/log)\" = 1 ] && grep -q 'restored 2,5 by the watchdog' $LOOT/events.log && [ ! -e $LOOT/.bands_orig ] && [ ! -e /tmp/cs_run.pid ] && [ \"\$(cat /tmp/cs_harness_bands)\" = 2,5 ]"
  for p in $(pgrep -x sleep); do tr '\0' ' ' <"/proc/$p/cmdline" 2>/dev/null | grep -q ' 1000' && kill "$p" 2>/dev/null; done; true
}
s_devices() {   # 1.1.3: no CLIENTS verb, so clients come from RECON DEVICES (devices that neither beacon nor answer probes), with no association
  reset; rules devices '^CamHound' 'Scan,Exit' 'Review hits' 'Exit' "${COMMON[@]}"; answers t t B; HARNESS_NO_CLIENTS=1 run
  check "devices: the verb probe picked DEVICES after CLIENTS was refused" "grep -q 'client verb: DEVICES' $LOOT/events.log && grep -q '^RECON DEVICES' $T/log"
  check "devices: client rows exist, role cli, no association" "awk -F'|' '\$4==\"a4:da:22:20:00:01\" && \$5==\"cli\" && \$15==\"-\"' $LOOT/inventory.tsv | grep -q ."
  check "devices: APs are not duplicated as clients" "! grep -q '|9c:3d:cf:11:22:33|cli|' $LOOT/inventory.tsv && grep -q '|9c:3d:cf:11:22:33|ap|' $LOOT/inventory.tsv"
}
s_members() {   # the real-firmware shape: clients with NO association, membership read off the air
  # Every other disrupt scenario drives fixtures whose ap_mac column no shipped firmware emits, so
  # the NO_CLIENTS refusal that this work exists to fix had no coverage at all. HARNESS_NO_CLIENTS=1
  # forces the 1.1.3 path (RECON DEVICES, ap_mac "-"), which is what the operator's unit returns.
  # Index 6, not 4: under the DEVICES shape the review list orders differently and 4 is the
  # "-- LIKELY --" divider. The checks below pin the BSSID the capture ran against, so if this
  # index ever drifts again the scenario fails loudly instead of quietly testing another row.
  local R=('^CamHound' 'Scan,Exit' 'Review hits' '6,Exit' '^[0-9]+ REO' 'Disrupt,Back' '^Disrupt \[' '1' ' ch ' '1')
  reset; printf 'CYCLE_SECS=5\nRESPONSE=1\n' >"$HARNESS_CFG"
  rules mem1 "${R[@]}" "${COMMON[@]}"; answers t t B; HARNESS_NO_CLIENTS=1 run
  check "members: capture armed with the OR filter, snap 128, frame cap 800" \
    "grep -qE '^TCPDUMP members ec71db000010 snap=128 count=800 or=1' $T/log"
  check "members: two stations recovered from the air" "grep -q 'members ec:71:db:00:00:10 n=2 ' $LOOT/events.log"
  check "members: they became the subjects, with no association in the JSON" \
    "grep -q 'scope=bss subjects=2' $LOOT/events.log && grep -q 'client verb: DEVICES' $LOOT/events.log"
  check "members: the attack was sent" "grep -q '^PINEAPPLE_DEAUTH_CLIENT ec:71:db:00:00:10 ff:ff:ff:ff:ff:ff 36' $T/log"
  # The targeted sweep. The broadcast frame above is kept AND one targeted deauth goes to each
  # recovered member, because on the bench a targeted deauth dropped a phone that ignored both
  # broadcast forms. Asserted per member, so a sweep that fires once and stops is caught.
  check "members: a targeted deauth follows the broadcast, one per recovered station" \
    "grep -q '^PINEAPPLE_DEAUTH_CLIENT ec:71:db:00:00:10 ec:71:db:00:00:11 36$' $T/log && grep -q '^PINEAPPLE_DEAUTH_CLIENT ec:71:db:00:00:10 ec:71:db:00:00:12 36$' $T/log"
  check "members: the sweep count is logged against the subject count" \
    "grep -qE 'sweep PINEAPPLE_DEAUTH_CLIENT ec:71:db:00:00:10 targeted=2 of 2' $LOOT/events.log"
  check "members: one loot row per recovered station" \
    "[ \"\$(grep -c '^[0-9]' $LOOT/responses.tsv)\" = 2 ] && grep -q '|ec:71:db:00:00:11|' $LOOT/responses.tsv && grep -q '|ec:71:db:00:00:12|' $LOOT/responses.tsv"
  check "members: the dwell and lock figures are logged for resp_clamp_lock" \
    "grep -qE 'members .* dwell=[0-9]+s lock=[0-9]+s' $LOOT/events.log"
  check "members: the measurement lock was re-armed, not stretched" \
    "grep -qE 're-armed ec:71:db:00:00:10 [0-9]+s for the measurement' $LOOT/events.log"
  check "members: EXAMINE released and no lock file left" "grep -q 'PINEAPPLE_EXAMINE_RESET' $T/log && [ ! -e /tmp/cs_run.pid ]"
  # armed, heard nobody -> NO_CLIENTS. This is the arm that used to be the whole bug.
  reset; printf 'CYCLE_SECS=5\nRESPONSE=1\n' >"$HARNESS_CFG"
  rules mem2 "${R[@]}" "${COMMON[@]}"; answers t t B; HARNESS_NO_CLIENTS=1 HARNESS_NO_MEMBERS=1 run
  check "members: silent BSS refuses NO_CLIENTS and sends nothing" \
    "grep -q 'no clients heard on 00:00:10' $T/log && ! grep -q '^PINEAPPLE_DEAUTH_CLIENT' $T/log && grep -q '|NO_CLIENTS\$' $LOOT/responses.tsv"
  check "members: resp_fire itself released the lock on that refusal" \
    "grep -q 'unlocked after refusal' $LOOT/events.log && grep -q 'PINEAPPLE_EXAMINE_RESET' $T/log"
  # tcpdump refuses the filter -> NO_CAPTURE, a different answer from an empty BSS
  reset; printf 'CYCLE_SECS=5\nRESPONSE=1\n' >"$HARNESS_CFG"
  rules mem3 "${R[@]}" "${COMMON[@]}"; answers t t B; HARNESS_NO_CLIENTS=1 HARNESS_NO_ARM=1 run
  check "members: a capture that cannot arm refuses NO_CAPTURE, not NO_CLIENTS" \
    "grep -q '|NO_CAPTURE\$' $LOOT/responses.tsv && ! grep -q '|NO_CLIENTS\$' $LOOT/responses.tsv && ! grep -q '^PINEAPPLE_DEAUTH_CLIENT' $T/log"
  # records arrive but are cut below rt+16 -> SNAP_SHORT, and the message names the fix
  reset; printf 'CYCLE_SECS=5\nRESPONSE=1\n' >"$HARNESS_CFG"
  rules mem4 "${R[@]}" "${COMMON[@]}"; answers t t B; HARNESS_NO_CLIENTS=1 HARNESS_SHORT_SNAP=1 run
  check "members: truncated records refuse SNAP_SHORT and name the constant" \
    "grep -q '|SNAP_SHORT\$' $LOOT/responses.tsv && grep -q 'raise CLI_CAP_SNAP' $T/log && ! grep -q '^PINEAPPLE_DEAUTH_CLIENT' $T/log"
  check "members: the short capture is reported with its radiotap length" \
    "grep -qE 'refused .* SNAP_SHORT members=0 itmax=18 recs=[0-9]+ short=[1-9]' $LOOT/events.log && grep -qE 'members .* trunc=[1-9]' $LOOT/events.log"
  # a file exists but is not a pcap -> NO_CAPTURE. Without this arm, resp_members discarding
  # bss_clients' exit status is invisible: the selftest cannot see it, because it covers
  # bss_clients directly and never goes through resp_members.
  reset; printf 'CYCLE_SECS=5\nRESPONSE=1\n' >"$HARNESS_CFG"
  rules mem6 "${R[@]}" "${COMMON[@]}"; answers t t B; HARNESS_NO_CLIENTS=1 HARNESS_BAD_PCAP=1 run
  check "members: an unreadable capture is NO_CAPTURE, not an empty BSS" \
    "grep -q '|NO_CAPTURE\$' $LOOT/responses.tsv && grep -q 'not a readable pcap' $T/log && ! grep -q '^PINEAPPLE_DEAUTH_CLIENT' $T/log"
  # Heard stations that Recon has no row for. Until 2026-11-09 this refused NO_MATCH and sent
  # NOTHING -- and THIS ARM ASSERTED THAT REFUSAL AS CORRECT, which is why the defect survived
  # fourteen scenarios and ninety-four checks. It was caught on the bench instead: seven
  # consecutive Disrupts on a real camera AP logged `members n=1 why=ok itmax=56 recs=286..468`
  # (the capture heard the station cleanly) and then `refused NO_MATCH members=1` with pk_before
  # and pk_after both '-', zero frames on the air -- while the GUI's AP-row deauth, the same
  # opcode-400 broadcast frame resp_fire builds, dropped that client on demand.
  # The cause was one array doing two jobs: a station needs a Recon row and a stable address to be
  # SCORED, but neither to be DEAUTHED. So the transmit set is now the heard set, and these
  # stations are scored INCONCLUSIVE rather than handed an invented verdict.
  reset; printf 'CYCLE_SECS=5\nRESPONSE=1\n' >"$HARNESS_CFG"
  rules mem7 "${R[@]}" "${COMMON[@]}"; answers t t B; HARNESS_NO_CLIENTS=1 HARNESS_ALIEN_MEMBERS=1 run
  check "members: heard but unmeasurable TRANSMITS, and no longer refuses" \
    "grep -q '^PINEAPPLE_DEAUTH_CLIENT ec:71:db:00:00:10 ff:ff:ff:ff:ff:ff 36' $T/log && ! grep -q '|NO_MATCH\$' $LOOT/responses.tsv && ! grep -q '|NO_CLIENTS\$' $LOOT/responses.tsv"
  check "members: the sweep reaches a station Recon has no row for" \
    "grep -q '^PINEAPPLE_DEAUTH_CLIENT ec:71:db:00:00:10 ec:71:db:aa:00:01 36\$' $T/log && grep -q '^PINEAPPLE_DEAUTH_CLIENT ec:71:db:00:00:10 ec:71:db:aa:00:02 36\$' $T/log"
  check "members: an unmeasurable subject scores INCONCLUSIVE, never MOVED or NO_EFFECT" \
    "grep -q '|ec:71:db:aa:00:01|' $LOOT/responses.tsv && grep -qE '\|INCONCLUSIVE\$' $LOOT/responses.tsv && ! grep -qE '\|(MOVED|NO_EFFECT)\$' $LOOT/responses.tsv"
  check "members: the fire line separates the transmit set from the measurable set" \
    "grep -qE 'fire DEAUTH .* subjects=2 measurable=0 heard=2' $LOOT/events.log"
  # the firmware refuses the attack command -> CMD_REFUSED, never a measurement verdict.
  # Before this existed, a refusal was written to responses.tsv as NO_EFFECT or MOVED, which reads
  # as the firmware fact "CSA does not move this camera" -- an open question this rung is meant to
  # answer, so a swallowed refusal filed a fabricated answer to it.
  reset; printf 'CYCLE_SECS=5\nRESPONSE=1\n' >"$HARNESS_CFG"
  rules mem8 "${R[@]}" "${COMMON[@]}"; answers t t B; HARNESS_NO_CLIENTS=1 HARNESS_FIRE_REFUSE=1 run
  check "members: a refused command is CMD_REFUSED, not a verdict" \
    "grep -q '|CMD_REFUSED\$' $LOOT/responses.tsv && ! grep -qE '\|(MOVED|NO_EFFECT)\$' $LOOT/responses.tsv"
  check "members: the refusal is reported with the command rc and its stderr" \
    "grep -qE 'cmd PINEAPPLE_DEAUTH_CLIENT rc=1 err=.*not permitted' $LOOT/events.log && grep -q 'refused (rc 1)' $T/log"
  check "members: the lock is released and no verdict is logged on a refusal" \
    "grep -q 'unlocked after refusal' $LOOT/events.log && ! grep -qE '^.*resp verdict ' $LOOT/events.log"
  # the OR filter refused, the uplink-only fallback arms and still finds everyone
  reset; printf 'CYCLE_SECS=5\nRESPONSE=1\n' >"$HARNESS_CFG"
  rules mem5 "${R[@]}" "${COMMON[@]}"; answers t t B; HARNESS_NO_CLIENTS=1 HARNESS_NO_OR=1 run
  printf 'CYCLE_SECS=5\n' >"$HARNESS_CFG"
  check "members: the OR filter failing falls back to uplink-only and still fires" \
    "grep -q 'OR filter did not arm' $LOOT/events.log && grep -qE '^TCPDUMP members ec71db000010 snap=128 count=800 or=2' $T/log && grep -q 'scope=bss subjects=2' $LOOT/events.log"
}
case "${1:-all}" in
  csainj) s_csainj ;; live) s_live ;; stimulus) s_stimulus ;; lock) s_lock ;; nojq) s_nojq ;; locate) s_locate ;; disrupt) s_disrupt ;; members) s_members ;; cliscope) s_cliscope ;; blind) s_blind ;; noinj) s_noinj ;; persist) s_persist ;; settings) s_settings ;; bands) s_bands ;; devices) s_devices ;;
  all) s_csainj; s_live; s_stimulus; s_lock; s_nojq; s_locate; s_disrupt; s_members; s_cliscope; s_blind; s_noinj; s_persist; s_settings; s_bands; s_devices ;;
  *) echo "usage: $0 [live|stimulus|lock|nojq|locate|disrupt|members|cliscope|blind|noinj|persist|settings|bands|devices|all]"; exit 2 ;;
esac
printf '== harness: %s failure(s); temp dir %s ==\n' "$FAIL" "$T"
exit $(( FAIL > 0 ))

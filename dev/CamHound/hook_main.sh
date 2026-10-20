
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

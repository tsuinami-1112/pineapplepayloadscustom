#!/bin/bash
# shellcheck disable=SC2034   # config and scan-state declarations are copied verbatim; the hook uses a subset
# Title: CamHound (Recon hook)
# Description: Run CamHound's Watch (live view), Stimulus test, Locate or Disrupt on the AP or
#              client that is selected in the Recon menu. The same file is installed as
#              recon/client/CamHound and recon/access_point/CamHound; it branches at run time on
#              the selected-client variable. Disrupt appears only when RESPONSE=1, reads the
#              target's protection posture from its beacon and then disconnects it with
#              deauth+disassoc, channel-switch announcements, or all three; with RESPONSE=0 (the
#              default) the hook transmits nothing.
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
# MAGENTA        - response transmitting (channel locked for the burst)
# GREEN          - response MOVED: the target stopped transmitting (+ one long vibe)
# YELLOW         - response NO_EFFECT or INCONCLUSIVE
# FINISH, OFF    - clean exit


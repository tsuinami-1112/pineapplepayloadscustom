#!/bin/bash
# shellcheck disable=SC2034   # config and scan-state declarations are copied verbatim; the hook uses a subset
# Title: CamScout (Recon hook)
# Description: Run CamScout's Watch (live view), Stimulus test or Locate on the AP or client that is
#              selected in the Recon menu. The same file is installed as recon/client/CamScout and
#              recon/access_point/CamScout; it branches at run time on the selected-client variable.
#              GENERATED FILE: dev/CamScout/gen_hooks.sh copies the config block, the lib block and
#              the watch-core block verbatim from library/user/reconnaissance/CamScout/payload.sh.
#              Edit the user payload and regenerate; dev/CamScout/check_sync.sh verifies the copies.
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


# SPDX-License-Identifier: Apache-2.0
# Shared helpers for scenarios/*/run.sh (sourced, runs on the host: bash + make + Docker).
#
#   AUTO=1            no pauses (recordings, rehearsal); PAUSE_SECONDS=n waits n s instead
#   BOARD=...         board (default: the W5500-EVB-Pico2, the board the decisions are for)
#   REVIEWER="name"   the person on stage (scenario 5 opens an investigation in this name)
#   CLEAR=0           do not clear the screen at the start
#
# The whole run is also written to out/scenarios/<N>/transcript.log (with colours;
# view with `cat`, or `sed 's/\x1b\[[0-9;]*m//g'` for plain text).
#
# Every step prints the command as the audience would type it, waits for Enter, then runs
# it. The real call adds OUT_ROOT/DECISIONS so the scenario works on its own copy under
# out/scenarios/<N>/ and never changes tracked files. Step durations: out/scenarios/<N>/timings.txt

set -uo pipefail
BOARD=${BOARD:-w5500_evb_pico2/rp2350a/m33}
BD=${BOARD//\//_}
SC=out/scenarios/${SCENARIO}
STEP=0
B=$'\e[1m'; R=$'\e[0m'; DIM=$'\e[2m'; CY=$'\e[1;36m'; YE=$'\e[1;33m'

# make with the scenario workspace (OUT_ROOT, DECISIONS) and quiet output
MAKE_CMD=${MAKE_CMD:-make}
smake() {
  ${MAKE_CMD} --no-print-directory -s "$@" BOARD="${BOARD}" OUT_ROOT="${SC}" DECISIONS="${SC}/decisions"
}

helper() { ${MAKE_CMD} --no-print-directory -s scenario-helper ARGS="$*"; }

title() {
  TITLE_TEXT="Scenario ${SCENARIO}: $1"$'\n'"$2"
  [[ "${CLEAR:-1}" == "1" ]] && { clear 2>/dev/null || true; }
  printf '%s\n' "${CY}Scenario ${SCENARIO}: $1${R}"
  printf '%s\n\n' "${DIM}$2${R}"
}

pause() {
  if [[ "${AUTO:-0}" == "1" ]]; then sleep "${PAUSE_SECONDS:-0}"; else read -r -s -p "" _ || true; fi
}

# step "what the audience should notice" "command as shown" -- command as run...
step() {
  local note="$1" shown="$2"; shift 3
  STEP=$((STEP + 1))
  printf '\n%s\n' "${YE}[${STEP}] ${note}${R}"
  printf '%s' "${B}\$ ${shown}${R}"
  pause
  printf '\n'
  local t0=${EPOCHREALTIME/[.,]/} ms
  "$@" || printf '%s\n' "${DIM}(exit code $?)${R}"
  ms=$(( (${EPOCHREALTIME/[.,]/} - t0) / 1000 ))
  printf '%s\t%d.%d s\t%s\n' "${STEP}" $((ms / 1000)) $((ms % 1000 / 100)) "${shown}" >> "${SC}/timings.txt"
}

# say "text": a line for the audience, no command
say() { printf '\n%s\n' "${B}$*${R}"; pause; }

setup() {  # setup v1.0[,v1.1]
  helper setup "${SCENARIO}" --releases "$1" --board "${BOARD}" || exit 1
  : > "${SC}/timings.txt"
  # from here on everything on screen also goes to the transcript
  printf '%s\n\n' "${TITLE_TEXT:-Scenario ${SCENARIO}}" > "${SC}/transcript.log"
  exec 3>&1 4>&2 > >(tee -a "${SC}/transcript.log") 2>&1
  TEE_PID=$!
  trap 'exec 1>&3 2>&4; wait "${TEE_PID}" 2>/dev/null' EXIT
}

done_msg() {
  printf '\n%s\n' "${CY}End of scenario ${SCENARIO}.${R} ${DIM}Workspace: ${SC}/ (make reset deletes it)${R}"
}

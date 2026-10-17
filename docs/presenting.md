# Presenting (Phase 9)

## The day before

```bash
make doctor                               # every pin and checksum PASS, offline
make prepare REVIEWER="Your Name"         # v1.0 + v1.1 built, scanned; v1.0 VEX + gate
make ready   REVIEWER="Your Name"         # all rows OK
make record-1 ... make record-5           # fallback recordings (see below)
```

Rehearse on the talk date: `GATE_DATE=2026-11-12 make ready` and run each scenario once
with `GATE_DATE=2026-11-12` exported, so due dates and snapshot age are evaluated as on stage.

## On stage

| Command | What it does | Tool time (presenter PC, 2026-10-17) |
| --- | --- | --- |
| `make demo` | menu of the five scenarios + readiness + reset | - |
| `make scenario-1` | 8 steps | 32 s (two scans of about 13 s each) |
| `make scenario-2` | 6 steps | 4 s |
| `make scenario-3` | 4 steps | 2 s |
| `make scenario-4` | 6 steps | 6 s |
| `make scenario-5` | 7 steps | 21 s (one scan; the first synthetic scan builds the OSV copy) |
| `make reset` | deletes `out/scenarios/` | < 1 s |

Tool time only; each step waits for Enter before it runs, so the pace is yours. Every
run writes the real step times to `out/scenarios/<N>/timings.txt` and everything that
was on screen to `out/scenarios/<N>/transcript.log` (with colours: `cat` it, or strip
them with `sed 's/\x1b\[[0-9;]*m//g'`). `CLEAR=0 make scenario-1` keeps the screen
instead of clearing it at the start.

Terminal: dark background, font size so that 100 columns fit (the tables are rendered for
100 columns, `CRA_WIDTH` changes it), at most about 25 lines per step.

## Fallback recordings

```bash
make record-3                 # runs scenario 3 with AUTO=1 PAUSE_SECONDS=3, records it
make play-3 [SPEED=2]         # replays it: no Docker, no network, no state
```

Recordings use util-linux `script --log-timing` / `scriptreplay` (installed on every
Ubuntu/WSL2), not asciinema: one less tool to pin, and replay needs nothing but the two
files in `recordings/`. They contain your terminal output only. Commit them if you want
them on a second machine.

## If something fails on stage

- A step fails: the scenario continues with the next step (exit code is shown dimmed).
- Docker is down: `make play-N`.
- A scenario left a strange state: `make reset`, start the scenario again.
- The v1.0 gate does not PASS any more (scenario 5 start): run `make gate VERSION=v1.0
  BOARD=w5500_evb_pico2/rp2350a/m33` to see which rule; usually a rebuild after
  uncommitted changes (R2) or a decision edited after `make vex` (R8).

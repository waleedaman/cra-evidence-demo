# Reproducibility (Phase 3)

`make reproduce-check VERSION=v1.0 [BOARD=...]` builds the firmware twice from scratch,
each time in a fresh container, in **two different build directories**, and compares the
SHA-256 of every artifact. It also compares against the release build in `out/`.

## Result

| Target | Artifacts | Same build path | Different build path |
| --- | --- | --- | --- |
| `w5500_evb_pico2/rp2350a/m33` | `.elf .uf2 .hex .bin` | identical | identical (with prefix map) |
| `native_sim/native/64` | `zephyr.elf zephyr.exe` | identical | identical (with prefix map) |

Measured in a test workspace with the same pinned versions; `make reproduce-check` re-checks it on any machine.

## What we had to fix

**Absolute paths in debug information.** Without changes, `.bin`, `.uf2` and `.hex`
were already identical across build directories, but `zephyr.elf` was not: it contains
about 1 200 absolute paths of the west workspace and the build directory (DWARF debug info
and `__FILE__`). For native_sim, `zephyr.exe` additionally embeds paths from the native
simulator runner, which is compiled outside Zephyr's normal compile options.

Fix in `app/CMakeLists.txt`:

```cmake
zephyr_compile_options(-ffile-prefix-map=${CMAKE_BINARY_DIR}=build
                       -ffile-prefix-map=${WEST_TOPDIR}=ws)
target_compile_options(native_simulator INTERFACE ...same maps...)   # native_sim only
```

**The first version of this fix was itself wrong, and `make reproduce-check` caught it.**
GCC applies the *last* matching `-ffile-prefix-map`. We listed the build-dir map first
and the workspace map second. Our build directories live inside the workspace
(`/ws/build/...`), so the workspace map won, and the build path leaked into the ELF as
`ws/build/repro-a/...` vs `ws/build/repro-b/...`. The test workspace had the build
directories *outside* the workspace, so it passed there and failed on the presenter
machine. Fix: workspace map first, build-dir map last.

After the fix the ELF contains 0 references to either path. The remaining absolute paths
point into the Zephyr SDK (headers and precompiled libraries), which sits at the fixed path
`/opt/toolchains/zephyr-sdk-<version>` inside the tooling image. Inside the tooling container the
paths are also fixed (`/ws/...`), so builds on different machines see the same paths anyway;
the prefix maps make the result independent of that convention too.

## What did not need fixing

- **Timestamps.** Zephyr v4.4.2 embeds no build date in this configuration; no
  `SOURCE_DATE_EPOCH` handling was needed. The boot banner shows `git describe` of Zephyr
  (`v4.4.2`), which is deterministic as long as the tag is present (`make fetch`) and the
  tree is clean (`make doctor`).
- **The app's git commit.** `APP_BUILD_VERSION` is generated but only used by the shell
  and binary-descriptor features, both disabled here, so committing to this repo does not
  change the firmware.

## Inputs that legitimately change the hash

- **The demo CA certificate.** It is compiled into the firmware as the trust anchor.
  Every clone generates its own (`make certs`), so firmware from two clones differs
  unless they share `certs/generated/`. The provenance records the certificate's SHA-256.
- Anything in `pins.env`, `west.yml`, `app/` or the tooling image.

## Not reproducible by design

- SPDX documents (`Created:` timestamp, see `docs/sbom.md`).
- The provenance statement (`finishedOn`, `sourceDirty`) and its signature.

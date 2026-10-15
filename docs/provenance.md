# Build provenance (Phase 3)

`make provenance VERSION=v1.0 [BOARD=...]` writes and signs a statement that says
*which inputs produced which outputs*. `make verify` checks it, fully offline.

## Format

An [in-toto Statement v1](https://in-toto.io/Statement/v1) with a
[SLSA Provenance v1](https://slsa.dev/provenance/v1) predicate, signed as a DSSE
envelope in a Sigstore bundle (`application/vnd.dev.sigstore.bundle.v0.3+json`).

| File | Content |
| --- | --- |
| `out/<v>/<board>/provenance.intoto.json` | the statement (unsigned, for reading) |
| `out/<v>/<board>/provenance.sigstore.json` | the signed bundle; `make verify` reads the statement **from here** |
| `keys/cosign.pub` | public key, committed |
| `keys/cosign.key` | private key, git-ignored, created by `make keys` |

### Subjects (outputs)

Every firmware artifact (`zephyr.elf`, `.uf2`, `.hex`, `.bin`, or `zephyr.exe` for
native_sim) **and** every SPDX document of the build. Signing the SBOM together with the
firmware binds the two: the SBOM cannot be swapped without breaking the signature.

### Predicate (inputs)

- `buildType`: `https://cra-evidence-demo.invalid/buildtypes/zephyr-west-docker/v1`, our
  name for "west build of `app/` inside the pinned tooling image". The `.invalid` domain is
  reserved, so it can never be mistaken for a fetchable URL.
- `externalParameters`: version, board, application dir, manifest, `sourceDirty`.
- `internalParameters`: toolchain variant, compiler version, SHA-256 of `.config`, build dir.
- `resolvedDependencies`: this repo's git commit; Zephyr and every module (git commit, plus
  the CPE/PURL from `module.yml` as annotations); the ci-base image digest; the two Zephyr
  SDK archives (SHA-256); the embedded demo CA certificate (SHA-256).
- `runDetails.builder`: `id` is our local Docker builder; `version` and
  `builderDependencies` carry the tooling image ID.

SLSA v1 has no `materials` field (that was v0.2); inputs go into `resolvedDependencies`.

## Signing offline

cosign 3.x defaults to a TUF-fetched signing config and Rekor (transparency log) upload.
For an offline key-based signature both must be switched off explicitly:

```
cosign attest-blob --key keys/cosign.key --statement provenance.intoto.json \
  --bundle provenance.sigstore.json --use-signing-config=false --tlog-upload=false --yes
cosign verify-blob-attestation --key keys/cosign.pub --bundle provenance.sigstore.json \
  --type slsaprovenance1 --insecure-ignore-tlog=true zephyr.uf2
```

`--tlog-upload` is marked deprecated in cosign 3.x (it still works and prints a warning).
Tested with cosign 3.1.3 with all network access blocked: signing and verification work,
a modified artifact fails with "provided artifact digests do not match digests in
statement", a different public key fails with "accepted signatures do not match threshold".

### What this signature does and does not prove

- It proves the statement was signed with `keys/cosign.key` and the artifacts match it.
- It does **not** prove *when* it was signed (no transparency log, no timestamp authority)
  and it says nothing about who holds the key. That is why verify prints
  "Skipping tlog verification is an insecure practice". For a real product: a protected
  key (HSM/KMS) or keyless signing with Rekor, decided by your release process.
- `make keys` uses an empty key password unless `COSIGN_PASSWORD` is set. Demo only.
- The tooling image ID is a *local* image ID (the image was built, not pulled from a
  registry), so a third party cannot fetch it by that digest.

## What `make verify` checks

1. cosign: signature and subject digest for every firmware artifact.
2. SHA-256 of every SBOM document against the signed statement.
3. The signed dependencies against `pins.env`: Zephyr commit, every module commit,
   ci-base digest, Zephyr SDK archive.
4. `sourceDirty` is false (built from committed source).

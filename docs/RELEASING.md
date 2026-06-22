# Releasing

The maintainer's runbook for cutting a Legant release. Releases are automated by
GoReleaser on a pushed tag.

## Cut a release

1. Update `CHANGELOG.md` — move items from *Unreleased* into the new version.
2. Tag and push:

   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

3. `.github/workflows/release.yml` runs GoReleaser (cross-platform binaries +
   checksums) and builds/pushes the multi-arch `ghcr.io/legant-dev/legant` image.
4. Verify the GitHub Release assets, then announce.

> Homebrew tap publishing is opt-in and commented out in `.goreleaser.yaml` (so a
> first release can't fail on a missing tap). Enable it once a tap repo exists.

## Before a release: dependency + secret hygiene

```bash
# Vulnerable dependencies (also gated in CI):
go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# A fast heuristic secret sweep (review every hit):
git grep -nE "(BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|xox[baprs]-|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{20,})" || echo "no obvious secrets"
```

The only secret-shaped strings in the tree are self-describing local-dev
placeholders (`legant:legant` dev creds, `change-me-to-a-32-byte…` examples) and
the ephemeral, generated conformance-vector key — none are real credentials.

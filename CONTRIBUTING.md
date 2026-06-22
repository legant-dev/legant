# Contributing to Legant

Thanks for your interest! Legant is open-source delegated authorization for AI
agents. This guide covers how to build, test, and propose changes.

## Ground rules

- **Be honest in claims.** Legant's positioning is deliberately precise about what
  it does and doesn't do (see the README's caveats, `docs/THREAT_MODEL.md`, and the
  per-demo "honest scope" notes). Don't add a feature claim the code can't back, and
  don't weaken an existing honest caveat.
- **Security-sensitive by nature.** Changes to the delegation engine, the SDKs, the
  gateway, or revocation get extra scrutiny. For a *vulnerability*, follow
  [`SECURITY.md`](SECURITY.md) — don't open a public issue or PR for it.
- **Keep the three SDKs in lockstep.** Go, TypeScript, and Python implement the same
  verify/authorize behavior, guarded by the golden conformance vectors in
  `clients/conformance`. A change to one usually means a change to all three plus the
  vectors.

## Development setup

Requirements: **Go 1.26+**, **PostgreSQL 16+** (for the issuer; the SDKs and most
demos need neither), and optionally Docker, Node (for the TS SDK), and Python.

```bash
git clone <your fork>
cd legant
go build ./...
go test -race ./...          # full suite (spins up against Postgres where needed)
make demo                    # a no-database delegation walkthrough
```

The single binary embeds migrations, templates, and static assets:

```bash
make build && ./bin/legant --help
```

### The demos are the fastest way to learn the system

Every `make demo-*` target is a self-contained, narrated walkthrough (most need
only Go — no DB, no Docker). Start with `make demo`, `make demo-twoasks`, and
`make demo-splice`. See the README's demo gallery for the full list.

### Per-language SDKs

```bash
# TypeScript
cd clients/typescript && npm install && npm test
# Python
cd clients/python && python3 -m unittest discover -s tests
```

## Making a change

1. **Open an issue first** for anything non-trivial, so we can agree on direction.
2. Branch from `main`. Keep changes focused.
3. Match the surrounding code: its comment density, naming, and idiom. Comments
   should explain *why*, not narrate the *what*.
4. Add or update tests. For SDK/engine behavior changes, update the conformance
   vectors and run all three SDKs.
5. `gofmt -w` your Go; `go vet ./...` and `go test -race ./...` must pass.
6. Update docs (README, `docs/`) when you change behavior or add a surface.

## Pull requests

- Describe the *why*, link the issue, and note any honesty caveats you considered.
- Keep the diff reviewable; split unrelated changes.
- CI (build, vet, test, `govulncheck`) must be green.

By contributing, you agree your contributions are licensed under the project's
[Apache 2.0 license](LICENSE).

<!-- For a SECURITY vulnerability, do NOT open a PR — see SECURITY.md. -->

## What & why

What does this change, and why? Link the issue it addresses (`Fixes #…`).

## Type

- [ ] Bug fix
- [ ] Feature
- [ ] Docs / demo
- [ ] Refactor / chore

## Checklist

- [ ] `go build ./...`, `go vet ./...`, and `go test -race ./...` pass
- [ ] `gofmt`'d
- [ ] If engine/SDK behavior changed: conformance vectors updated and **all three
      SDKs** (Go / TS / Python) updated and tested
- [ ] Docs updated (README / `docs/`) if behavior or a surface changed
- [ ] No new claim that overstates a guarantee; existing honest caveats preserved

## Notes for reviewers

Anything you want a reviewer to look at closely (security-sensitive paths,
attenuation, revocation, audience handling, …).

# Contributing to tiny-url

Thanks for your interest. This is a personal project but external
contributions are welcome — the gating is small.

## Reporting issues

- **Security issues**: please follow [`SECURITY.md`](SECURITY.md). Don't
  open a public GitHub issue for security findings.
- **Bugs and feature requests**: open a GitHub issue with reproduction
  steps (for bugs) or a clear use case (for features).

## Development setup

Prerequisites:

- **Go 1.25 or later** (matches `go.mod`)
- **Docker** (only if you want to build/run the container image)
- **make** (optional but the targets are convenient)

Clone and verify:

```bash
git clone https://github.com/Hassani-Jr/tiny-url.git
cd tiny-url
make check        # gofmt + vet + test (race detector + coverage)
make run          # builds and runs on :8080 with the memory backend
```

## Dev loop

| Command         | What it does                                                |
|-----------------|-------------------------------------------------------------|
| `make build`    | compile to `./tiny-url` with the git SHA injected           |
| `make run`      | build and run with default config                            |
| `make test`     | `go vet` + `go test -race -cover`                            |
| `make fuzz`     | run each fuzzer for 60 s (CI does the same on every push)    |
| `make fmt`      | `gofmt -w .`                                                 |
| `make lint`     | fmt + vet + fail on unformatted files                        |
| `make check`    | what CI runs: lint + test                                    |
| `make docker`   | build the distroless image                                   |
| `make docker-run` | build the image and run it on :8080                       |

CI runs the same checks (`.github/workflows/ci.yml`). Anything that
passes `make check` locally should pass CI.

## Code style

- **Formatting**: `gofmt`. Enforced by CI; `make fmt` will fix.
- **Vet**: `go vet ./...`. Enforced by CI.
- **Comments**: explain the *why*, not the *what*. Identifiers should
  document the what. Pick a hidden constraint, a non-obvious tradeoff,
  or a workaround for a known bug — and write it down.
- **Tests**: every new exported function / endpoint needs at least one
  test. Add to the existing `_test.go` file when reasonable; create a
  new one when the new code is genuinely separate.
- **No dependencies without a reason**: this project is single-binary
  with a deliberately small dependency tree. New imports should be
  load-bearing, not "it would be slightly nicer."

## Tests

The suite has three layers:

1. **Unit tests** next to each package (`*_test.go`). Most of the
   coverage lives here.
2. **End-to-end test** (`app_test.go`) drives the real handler chain
   through `httptest.NewServer`. Catches middleware-ordering /
   route-registration drift that unit tests can't see.
3. **Fuzz tests** for the validators (`services/validation_fuzz_test.go`).
   Property-based: never panic, accepted inputs honor the documented
   contract.

Useful invocations:

```bash
go test ./services/...                        # one package
go test -run TestRotate ./handlers/           # one test
go test -fuzz=FuzzValidateCustomCode -fuzztime=2m ./services/  # extended fuzz
```

## Commit style

- One logical change per commit when feasible.
- Subject line: imperative, ≤ 70 chars (`Add X` not `Added X`).
- Body: motivation and tradeoffs, not a diff narration.
- For multi-paragraph context, wrap at ~72 chars.

Example:

```
Drop XHR check from PATCH for consistency with DELETE

Both endpoints are bearer-token-gated; a cross-origin page can't
read the token out of localStorage on this origin. The XHR check
adds friction without raising the bar.
```

## Pull requests

- Fork and PR from a feature branch (`git checkout -b feature/foo`).
- Make sure CI is green before requesting review.
- Squash-merge is the default; the maintainer will handle that.
- For non-trivial changes, open an issue first to confirm direction —
  saves churn on review.

## What's in scope

- Bug fixes and security hardening of existing functionality.
- Performance improvements with measured before/after numbers.
- Operational features (observability, configurability) that align
  with the existing trust model.

## What's out of scope (without prior discussion)

- Multi-tenant accounts, OAuth, geo-blocking, A/B redirects, custom
  domains per code. Each is a substantial product direction; please
  open a discussion issue first.
- New external dependencies that aren't strictly necessary.
- Heavyweight refactors that don't enable a concrete improvement.

## Repository conventions

- `main` is the only long-lived branch. CI runs on every push and PR.
- Tagged releases follow semver (`v1.0.0`, `v1.0.1`, …). Pushing a tag
  triggers `.github/workflows/release.yml` which builds the Docker
  image, pushes to `ghcr.io/hassani-jr/tiny-url`, and creates a
  GitHub Release with auto-generated notes.
- Pre-release tags (`v1.0.0-rc.1`, `v1.0.0-beta.1`) are marked as
  pre-releases automatically and don't move the `latest` Docker tag.

## Recommended branch protection

The maintainer should configure these on `main` (one-time GitHub
setting under **Settings → Branches → Branch protection rules**):

- Require pull request reviews before merging
- Require status checks to pass before merging:
  - `build · vet · test`
  - `docker build`
  - `fuzz validators (60s each)`
- Require branches to be up to date before merging
- Disallow force pushes to `main`

This isn't enforced by anything in the repo — it has to be set in
GitHub. Document only.

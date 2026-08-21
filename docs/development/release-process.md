# Release Process

## Versioning policy

MTScan uses Semantic Versioning:

```text
MAJOR.MINOR.PATCH
```

For stable releases:

- **MAJOR** — incompatible CLI/API/storage behavior or other breaking public-interface change.
- **MINOR** — backward-compatible feature.
- **PATCH** — backward-compatible bug or security fix.

Pre-release identifiers follow SemVer when used, for example:

```text
1.1.0-alpha.1
1.1.0-beta.1
1.1.0-rc.1
1.1.0
```

The current release is `1.0.2`.

## Source of version truth

The repository `VERSION` file contains the canonical release version. The root README and `CHANGELOG.md` should agree with it.

## Changelog policy

`CHANGELOG.md` follows Keep a Changelog categories:

- `Added`
- `Changed`
- `Deprecated`
- `Removed`
- `Fixed`
- `Security`

Keep an `Unreleased` section for changes on `develop`.

## Release checklist

1. Ensure `develop` contains the intended release state.
2. Update `VERSION`.
3. Move relevant `Unreleased` entries into a dated version section.
4. Verify README and documentation links/version references.
5. Run the complete unit/regression suite.
6. Run runtime validation for CLI and webapp behavior.
7. Run required real-tool compatibility and isolated integration tests for the release scope.
8. Run security scanning and dependency audit.
9. Verify installation on the supported release environments selected for that release.
10. Prepare a release PR from `develop` to the release branch (normally `main`).
11. Merge only after all required release gates pass.
12. Tag the merged release commit as `v<version>`.
13. Publish release notes from the changelog and retained test evidence.
14. Synchronize `develop` with the merged `main` state so the next development cycle starts from the released history.

## Pre-release changes

When a future alpha, beta, or release-candidate line is used, unstable interfaces may still change, but breaking changes must be documented in `CHANGELOG.md` and, when architectural, in an ADR. Pre-release status is not permission for undocumented behavior changes.

## Security releases

Security fixes should include a `Security` changelog entry that is informative without exposing an unpatched exploit before coordinated disclosure. Follow [SECURITY.md](../../SECURITY.md).

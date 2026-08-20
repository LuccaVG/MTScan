# Release Process

## Versioning policy

MTScan uses Semantic Versioning:

```text
MAJOR.MINOR.PATCH
```

After stable `1.0.0`:

- **MAJOR** — incompatible CLI/API/storage behavior or other breaking public-interface change.
- **MINOR** — backward-compatible feature.
- **PATCH** — backward-compatible bug or security fix.

Pre-release identifiers follow SemVer. The current human-facing **1.0.0 Alpha** is represented as:

```text
1.0.0-alpha
```

Future pre-release examples:

```text
1.0.0-alpha.2
1.0.0-beta.1
1.0.0-rc.1
1.0.0
```

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
5. Run unit/regression tests.
6. Run required integration and real-tool compatibility tests.
7. Run security scanning and dependency audit.
8. Verify installation on the supported release environments selected for that release.
9. Prepare a release PR from `develop` to the release branch (normally `main`).
10. Tag the merged release commit as `v<version>`.
11. Publish release notes from the changelog and test evidence.
12. Re-open an empty `Unreleased` section on `develop` if needed.

## Breaking changes during alpha

The `1.0.0-alpha` line can still change unstable interfaces, but breaking changes must still be documented in `CHANGELOG.md` and, when architectural, in an ADR. Alpha status is not permission for undocumented behavior changes.

## Security releases

Security fixes should include a `Security` changelog entry that is informative without exposing an unpatched exploit before coordinated disclosure. Follow [SECURITY.md](../../SECURITY.md).

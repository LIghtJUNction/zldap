# Releasing zldap

Set the repository's `CARGO_REGISTRY_TOKEN` Actions secret to a crates.io token authorized to publish zldap. Run the **Release** workflow from the current default branch. No registry credential is needed for pull-request CI or the publication dry run.

| `bump` input | Effect |
| --- | --- |
| `current` | Publish the version already in `Cargo.toml`; use this for the first release. |
| `patch` | Increase the patch number. |
| `minor` | Increase the minor number and reset patch to zero. |
| `major` | Increase the major number and reset minor and patch to zero. |

The workflow commits each version change to `Cargo.toml`, the root `Cargo.lock`, and the local zldap entry in `comparison/Cargo.lock` together, then validates that exact commit. Third-party comparison versions and checksums stay unchanged. The shared CI gates include the three operating systems, Rust 1.74 and stable, rustfmt, clippy, documentation, wasm32 and embedded/aarch64 compilation, Miri, the pinned differential tests, package policy, and publication dry run.

After the gates pass, the workflow checks version availability, publishes the crate, verifies its registry SHA-256, and creates the Git tag and GitHub Release. The `.crate` and `SHA256SUMS` are attached to the release. These actions share one run; a tag pushed by `GITHUB_TOKEN` does not need to trigger another workflow.

## Retrying a failure

If a bump was committed but publication failed, dispatch `current` to retry that version. Choosing the same bump again would create another version.

If publication succeeded but tag or GitHub Release creation failed, dispatch `current` with `resume=true` on the same release commit. Recovery accepts only an identical package archive; it never treats an arbitrary occupied version as success. It also verifies existing tags instead of moving them. A default branch that has advanced, a changed archive, or a registry outage blocks recovery and needs investigation; the workflow does not rewrite repository history.

## Manual checks

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/check_package.py
cargo package --locked
cargo publish --dry-run --locked
```

Keep the root `Cargo.lock` in format 3 for Cargo 1.74. The release helper updates package versions directly without network resolution or regenerating either lockfile, preserving the comparison workspace's pinned dependency graph.

<!-- Thanks for the pull request. Keep it focused; one change per PR is easier to review. -->

## What this changes

<!-- A short description of the change and why. Explain the why, not just the what. -->

## How it was tested

<!-- Commands you ran, tests added, simulator numbers, hardware checks. -->

## Checklist

- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets` is clean
- [ ] `cargo build -p meshstar-core --no-default-features` still builds (no_std)
- [ ] New decoders have a garbage-does-not-panic test (and a fuzz target if on-air)
- [ ] New bounded structures have an exhaustion test
- [ ] Protocol changes are backed by simulator data (and `docs/BENCHMARKS.md` updated if relevant)
- [ ] Docs updated where relevant
- [ ] No unverified foreign-protocol claims (marked `// UNVERIFIED:` if needed)

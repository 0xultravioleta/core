//! Guards `[profile.release] overflow-checks = true` for the workspace.
//!
//! In a debug build this always passes (overflow checks are on by default). Its
//! real job is under `cargo test --release`: it fails if the release-profile
//! setting is ever dropped and integer overflow starts wrapping silently in the
//! artifacts we publish (CLI, napi addon, maturin wheel).

#[test]
fn u64_overflow_panics_in_release() {
    let a = std::hint::black_box(u64::MAX);
    let b = std::hint::black_box(1u64);
    let overflowed = std::panic::catch_unwind(|| a + b);
    assert!(
        overflowed.is_err(),
        "u64 overflow did not panic: [profile.release] overflow-checks was dropped"
    );
}

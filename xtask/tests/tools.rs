//! Release verification subprocess timeout, reaping, and output-cap tests (INV-21).

use std::process::Command;
use std::time::Duration;

use crate::tools::{capture_check, wait_for_check};

#[test]
fn a_timed_out_release_check_is_killed_and_reaped() {
    let mut child = Command::new("sh")
        .args(["-c", "exec sleep 60"])
        .spawn()
        .unwrap();
    let error = wait_for_check(&mut child, Duration::from_millis(20)).unwrap_err();
    assert!(error.to_string().contains("release check timed out"));
    assert!(!child.try_wait().unwrap().unwrap().success());
}

#[test]
fn release_check_capture_rejects_excess_output() {
    let error =
        capture_check(Command::new("head").args(["-c", "4194305", "/dev/zero"])).unwrap_err();
    assert!(error
        .to_string()
        .contains("release check output exceeds 4 MiB"));
}

use super::*;

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
    let error = capture_with_timeout(
        Command::new("sh").args(["-c", "head -c 4194305 /dev/zero && exec sleep 60"]),
        Duration::from_secs(2),
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("release check output exceeds 4 MiB"));
}

#[test]
fn release_check_capture_times_out_waiting_for_output() {
    let error = capture_with_timeout(Command::new("sleep").arg("60"), Duration::from_millis(20))
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("release check output did not finish before the deadline")
    );
}

#[test]
fn release_check_capture_preserves_complete_output_at_the_limit() {
    let output = capture_check(Command::new("head").args(["-c", "4194304", "/dev/zero"])).unwrap();
    assert_eq!(output.len() as u64, MAX_CHECK_OUTPUT_BYTES);
}

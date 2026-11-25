use super::*;

#[test]
fn in_flight_limiter_caps_each_project_independently() {
    crate::metrics::init_for_tests();
    let limiter = InFlightLimiter::new(1, "test.rejected");
    let a = ProjectId::for_tests("a");
    let b = ProjectId::for_tests("b");
    let held = limiter.try_acquire(&a);
    assert!(held.is_ok());
    assert_eq!(
        limiter.try_acquire(&a).err(),
        Some(ApiError::TooManyInFlight)
    );
    assert!(limiter.try_acquire(&b).is_ok());
    drop(held);
    assert!(limiter.try_acquire(&a).is_ok());
}

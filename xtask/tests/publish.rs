use super::*;

#[test]
fn the_publish_run_must_report_one_image_in_the_report_step() {
    let image = "ghcr.io/repository:tag@sha256:digest";
    let decoy = format!("publish\tBuild image\t2026-11-20T15:26:54Z   IMAGE: {image}\n");
    let report =
        format!("publish\tReport pinned reference\t2026-11-20T15:26:54Z   IMAGE: {image}\n");
    assert!(reported_image(&decoy).is_err());
    assert_eq!(reported_image(&format!("{decoy}{report}")).unwrap(), image);
    assert!(reported_image(&format!("{report}{report}")).is_err());
}

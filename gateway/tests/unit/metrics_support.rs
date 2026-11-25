use super::*;

pub(crate) fn init_for_tests() {
    use cadence::NopMetricSink;
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| set_global_default(StatsdClient::from_sink("test", NopMetricSink)));
}

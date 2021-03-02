// Built-in uses
use std::time::Duration;
// External uses
use serde::Deserialize;
// Local uses
use crate::envy_load;

/// Configuration for the Alaya sender crate.
#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct ATPWatchConfig {
    /// Amount of confirmations for the priority operation to be processed.
    /// In production this should be a non-zero value because of block reverts.
    pub confirmations_for_atp_event: u64,
    /// How often we want to poll the Alaya node.
    /// Value in milliseconds.
    pub atp_node_poll_interval: u64,
}

impl ATPWatchConfig {
    pub fn from_env() -> Self {
        envy_load!("atp_watch", "ATP_WATCH_")
    }

    /// Converts `self.atp_node_poll_interval` into `Duration`.
    pub fn poll_interval(&self) -> Duration {
        Duration::from_millis(self.atp_node_poll_interval)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configs::test_utils::set_env;

    fn expected_config() -> ATPWatchConfig {
        ATPWatchConfig {
            confirmations_for_atp_event: 0,
            atp_node_poll_interval: 300,
        }
    }

    #[test]
    fn from_env() {
        let config = r#"
ATP_WATCH_CONFIRMATIONS_FOR_ATP_EVENT="0"
ATP_WATCH_ATP_NODE_POLL_INTERVAL="300"
        "#;
        set_env(config);

        let actual = ATPWatchConfig::from_env();
        assert_eq!(actual, expected_config());
    }

    /// Checks the correctness of the config helper methods.
    #[test]
    fn methods() {
        let config = expected_config();

        assert_eq!(
            config.poll_interval(),
            Duration::from_millis(config.atp_node_poll_interval)
        );
    }
}

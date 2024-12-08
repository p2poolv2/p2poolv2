use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct NetworkConfig {
    pub(crate) listen_address: String,
    pub(crate) dial_peers: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Config {
    pub(crate) network: NetworkConfig,
}

impl Config {
    pub(crate) fn load(path: &str) -> Result<Self, config::ConfigError> {
        config::Config::builder()
            .add_source(config::File::with_name(path))
            .build()?
            .try_deserialize()
    }
}
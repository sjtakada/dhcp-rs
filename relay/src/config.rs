//
// DHCP-RS
//   Copyright (C) 2024-2025, Toshiaki Takada
//

use std::collections::HashMap;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub global: ConfigGlobal,
    pub vrf: HashMap<String, ConfigVrf>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigGlobal {
    pub smart_relay: Option<ConfigSmartRelay>,
    pub agent_option: Option<ConfigAgentOption>,
    pub debug: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigSmartRelay {
    pub enabled: bool,
    pub retry_count: Option<u8>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigAgentOption {
    pub enabled: bool,
    pub format: Option<ConfigAgentOptionFormat>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigAgentOptionFormat {
    pub circuit_id: String,
    pub remote_id: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfigVrf {
    pub interfaces: ConfigInterface,
    pub dhcp_servers: ConfigDhcpServers,
}

#[derive(Debug, Deserialize)]
pub struct ConfigInterface {
    pub downstream: Option<Vec<String>>,
    pub upstream: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigDhcpServers {
    pub ipv4addr: Option<Vec<String>>,
    pub ipv6addr: Option<Vec<String>>,
}

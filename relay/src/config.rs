//
// DHCP-RS
//   Copyright (C) 2024-2025, Toshiaki Takada
//

use std::collections::HashMap;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub config_global: ConfigGlobal,
    pub config_vrf: HashMap<String, ConfigVrf>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigGlobal {
    pub smart_relay: ConfigSmartRelay,
    pub debug: bool,
}

#[derive(Debug, Deserialize)]
pub struct ConfigSmartRelay {
    pub enabled: bool,
    pub retry_count: u8,
}

#[derive(Debug, Deserialize)]
pub struct ConfigVrf {
    pub interfaces: ConfigInterface,
    pub dhcp_servers: ConfigDhcpServers,
}

#[derive(Debug, Deserialize)]
pub struct ConfigInterface {
    pub downstream: Vec<String>,
    pub upstream: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigDhcpServers {
    pub ipv4addr: Vec<String>,
    pub ipv6addr: Vec<String>,
}

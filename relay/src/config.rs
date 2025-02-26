//
// DHCP-RS
//   Copyright (C) 2024-2025, Toshiaki Takada
//

use std::net::Ipv4Addr;
use std::net::AddrParseError;

/// Relay Agent config.
pub struct RelayConfig {
    /// List of interfaces to listen to DHCP packets.
    interfaces: Vec<String>,

    /// DHCP Servers.
    servers: Vec<Ipv4Addr>,
}

impl RelayConfig {
    pub fn new() -> RelayConfig {
        RelayConfig {
            interfaces: Vec::new(),
            servers: Vec::new(),
        }
    }

    pub fn set_interface(&mut self, name: &str) {
        self.interfaces.push(name.to_string());
    }

    pub fn set_server(&mut self, addr_str: &str) -> Result<(), AddrParseError> {
        let addr: Ipv4Addr = addr_str.parse()?;

        self.servers.push(addr);
        Ok(())
    }

    pub fn get_servers(&self) -> &Vec<Ipv4Addr> {
        &self.servers
    }
}

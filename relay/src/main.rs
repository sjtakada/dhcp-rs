//
// DHCP-RS
//   Copyright (C) 2024-2025, Toshiaki Takada
//

use relay::agent::*;
use relay::config::*;

fn main() {
    println!("Starting DHCP Relay");

    // TBD: command line options

    // TBD: config, JSON or YAML?

    let mut config = RelayConfig::new();
    let res = config.set_server("192.168.100.2");
    println!("*** config.set_server {:?}", res);

    let agent = RelayAgent::new(config);

    agent.start();
}

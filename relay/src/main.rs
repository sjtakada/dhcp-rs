//
// DHCP-RS
//   Copyright (C) 2024-2025, Toshiaki Takada
//

use std::rc::Rc;

use relay::agent::*;
use relay::config::*;

fn main() {
    println!("Starting DHCP Relay");

    // TBD: command line options
    // TBD: config, JSON or YAML?

    let mut config = RelayConfig::new();
    let res = config.set_server("192.168.100.2");


    let agent = Rc::new(RelayAgent::new(config));
    RelayAgent::init(agent.clone());

    if let Err(err) = agent.start() {
        println!("* Stopped DHCP Relay: {:?}", err);
    }
}

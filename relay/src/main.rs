//
// DHCP-RS
//   Copyright (C) 2024-2025, Toshiaki Takada
//

use std::env;
use std::rc::Rc;
use std::fs;

use relay::agent::*;
use relay::config::*;

/// Program main.
fn main() {
    let args: Vec<String> = env::args().collect();
    println!("* Starting DHCP Relay");
    let config_file = if args.len() < 2 {
        "config.json"
    } else {
        &args[1]
    };

    let json_data: String = fs::read_to_string(config_file).unwrap();
    let config: Config = serde_json::from_str(&json_data).expect("!!! JSON data error");
    if config.is_debug_enabled() {
        println!("* Read config from {} {:?}", config_file, config);
    }

    let agent = Rc::new(RelayAgent::new(config));
    RelayAgent::init(agent.clone());

    if let Err(err) = agent.start() {
        println!("* Stopped DHCP Relay: {:?}", err);
    }
}

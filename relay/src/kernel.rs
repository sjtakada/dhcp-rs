//
// DHCP-RS
//   Copyright (C) 2024-2025 Toshiaki Takada
//

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use rtable::prefix::*;

#[cfg(target_os = "linux")]
use crate::netlink::*;
use crate::*;

/// Kernel Link Abstraction.
pub struct KernelLink {

    /// Inerface Index.
    pub ifindex: i32,

    /// Interface name.
    pub name: String,

    /// Interface Type.
    pub hwtype: u16,

    /// Hardward Address.
    pub hwaddr: [u8; 6],

    /// MTU.
    pub mtu: u32,
}

impl KernelLink {

    /// Constructor.
    pub fn new(index: i32, name: &str, hwtype: u16, hwaddr: [u8; 6], mtu: u32) -> KernelLink {
        KernelLink {
            ifindex: index,
            name: String::from(name),
            hwtype: hwtype,
            hwaddr: hwaddr,
            mtu: mtu,
        }
    }
}

/// Kernel Address Abstraction.
pub struct KernelAddr<T: Addressable> {

    /// Interface Index.
    pub ifindex: i32,

    /// Address prefix.
    pub address: Prefix<T>,

    /// Destination address prefix for peer.
    pub destination: Option<Prefix<T>>,

    /// Secondary address.
    pub secondary: bool,

    /// Unnumbered.
    pub unnumbered: bool,

    /// Label.
    pub label: Option<String>,
}

impl<T: Addressable> KernelAddr<T> {

    /// Constructor.
    pub fn new(ifindex: i32, prefix: Prefix<T>, destination: Option<Prefix<T>>,
               secondary: bool, unnumbered: bool, label: Option<String>) -> KernelAddr<T> {
        KernelAddr::<T> {
            ifindex: ifindex,
            address: prefix,
            destination: destination,
            secondary: secondary,
            unnumbered: unnumbered,
            label: label,
        }
    }
}

/// Kernel Driver trait.
pub trait KernelDriver {

    /// Register Add Link callback function.
    fn register_add_link(&self, f: Box<dyn Fn(KernelLink)>);

    /// Register Delete Link callback function.
    fn register_delete_link(&self, f: Box<dyn Fn(KernelLink)>);

    /// Register Add IPv4 Address callback function.
    fn register_add_ipv4_address(&self, f: Box<dyn Fn(KernelAddr<Ipv4Addr>)>);

    /// Register Delete IPv4 Address callback function.
    fn register_delete_ipv4_address(&self, f: Box<dyn Fn(KernelAddr<Ipv4Addr>)>);

    /// Register Add IPv6 Address callback function.
    fn register_add_ipv6_address(&self, f: Box<dyn Fn(KernelAddr<Ipv6Addr>)>);

    /// Register Delete IPv6 Address callback function.
    fn register_delete_ipv6_address(&self, f: Box<dyn Fn(KernelAddr<Ipv6Addr>)>);


    /// Send a command to kernel to retrieve all link information.
    fn get_link_all(&self) -> Result<(), DhcpError>;

    /*
    /// Set MTU.
    fn set_mtu(&self, mtu: u16) -> bool; // ? Error

    /// Set link up.
    fn set_link_up(&self) -> bool;

    /// Set link down.
    fn set_link_down(&self) -> bool;
     */


    /// Get all IPv4 addresses from system.
    fn get_ipv4_address_all(&self) -> Result<(), DhcpError>;

    /// Get all IPv6 addresses from system.
    fn get_ipv6_address_all(&self) -> Result<(), DhcpError>;
}

/// Kernel driver.
pub struct Kernel {

    /// Kernel driver for Linux.
    driver: Arc<dyn KernelDriver>,
}

/// Kernel implementation.
impl Kernel {

    /// Constructor.
    pub fn new() -> Kernel {
        if let Some(driver) = get_driver() {
            Kernel {
                driver: Arc::new(driver),
            }
        } else {
            panic!("Failed to intitialize Kernel");
        }
    }

    /// Initialization.
    pub fn init(&mut self) {

        if let Err(err) = self.driver.get_link_all() {
            println!("Kernel get_link_all error {}", err);
        }

        if let Err(err) = self.driver.get_ipv4_address_all() {
            println!("Kernel get_get_ipv4_address_all error {}", err);
        }

        if let Err(err) = self.driver.get_ipv6_address_all() {
            println!("Kernel get_get_ipv6_address_all error {}", err);
        }
    }

    /// Return driver.
    pub fn driver(&self) -> Arc<dyn KernelDriver> {
        self.driver.clone()
    }
}

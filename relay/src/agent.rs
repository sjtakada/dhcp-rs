//
// DHCP-RS
//   Copyright (C) 2024-2025, Toshiaki Takada
//
use std::rc::Rc;
use std::cell::Cell;
use std::cell::RefCell;
use std::os::unix::io::AsRawFd;
use std::net::UdpSocket;
use std::net::SocketAddrV4;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::collections::HashMap;

use nix::cmsg_space;
use nix::sys::socket::recvmsg;
use nix::sys::socket::sendmsg;
use nix::sys::socket::setsockopt;
//use nix::sys::socket::sockaddr;
use nix::sys::socket::ControlMessage;
use nix::sys::socket::ControlMessageOwned;
use nix::sys::socket::MsgFlags;
use nix::sys::socket::RecvMsg;
//use nix::sys::socket::SockaddrLike;
use nix::sys::socket::SockaddrIn;
use nix::sys::socket::sockopt::Ipv4PacketInfo;
use nix::sys::socket::sockopt::ReusePort;
use nix::unistd;
use libc::*;

use rtable::prefix::Prefixable;

use crate::*;
use crate::message::*;
use crate::config::*;
use crate::kernel::*;

/// Collections of IPv4 and IPv6 connected addresses.
pub struct Connected {
    /// IPv4 addreses.
    v4: Vec<Rc<KernelAddr<Ipv4Addr>>>,

    /// IPv6 addresses.
    v6: Vec<Rc<KernelAddr<Ipv6Addr>>>,
}

impl Connected {
    pub fn new() -> Connected {
        Connected {
            v4: Vec::new(),
            v6: Vec::new(),
        }
    }
}

/// Interface.
#[derive(Debug)]
pub struct Interface {

    /// Kernel Link.
    link: KernelLink,

    /// Upstream flag.
    upstream: Cell<bool>,

    /// Downstream flag.
    downstream: Cell<bool>,

    /// Circuit ID.
    circuit_id: String,

    /// Remote ID.
    remote_id: String,

    /// Hash index for smart relay.
    sindex: Cell<usize>,
}

impl Interface {
    pub fn new(link: KernelLink, hostname: &str) -> Interface {
        let upstream = Cell::new(false);
        let downstream = Cell::new(false);
        let circuit_id = format!("{}:{}", hostname, link.name);
        let remote_id = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                link.hwaddr[0], link.hwaddr[1], link.hwaddr[2],
                                link.hwaddr[3], link.hwaddr[4], link.hwaddr[5]);
        Interface {
            upstream,
            downstream,
            link,
            circuit_id,
            remote_id,
            sindex: Cell::new(0),
        }
    }
}

/// Relay Agent.
pub struct RelayAgent {

    /// Relay config.
    config: Config,

    /// Kernel driver interface.
    kernel: RefCell<Kernel>,

    /// Hostname.
    hostname: RefCell<String>,

    /// Name to ifindex map.
    name2index: RefCell<HashMap<String, i32>>,

    /// Ifindex to Interface map.
    index2link: RefCell<HashMap<i32, Interface>>,

    /// Ifindex to Connected.
    index2conn: RefCell<HashMap<i32, Connected>>,

    /// IPv4 address to KernelAddress map.
    ipv4addr2index: RefCell<HashMap<Ipv4Addr, i32>>,

    /// Counter per Agent IP.
    counter: RefCell<HashMap<Ipv4Addr, u32>>,
}

impl RelayAgent {
    pub fn new(config: Config) -> RelayAgent {
        let debug = match config.global.debug {
            Some(debug) => debug,
            None => false,
        };

        RelayAgent {
            config: config,
            kernel: RefCell::new(Kernel::new(debug)),
            hostname: RefCell::new(String::new()),
            name2index: RefCell::new(HashMap::new()),
            index2link: RefCell::new(HashMap::new()),
            index2conn: RefCell::new(HashMap::new()),
            ipv4addr2index: RefCell::new(HashMap::new()),
            counter: RefCell::new(HashMap::new()),
        }
    }

    /// Increment agent server counter.
    pub fn inc_agent_server_counter(&self, agent_ip: &Ipv4Addr) {
        let mut binding = self.counter.borrow_mut();
        *binding.entry(agent_ip.clone()).or_insert(0) += 1;
    }

    /// Decrement agent server counter.
    pub fn reset_agent_server_counter(&self, agent_ip: &Ipv4Addr) {
        let mut binding = self.counter.borrow_mut();
        if let Some(entry) = binding.get_mut(agent_ip) {
            *entry = 0;
        }
    }

    /// Get agent server counter.
    pub fn get_agent_server_counter(&self, agent_ip: &Ipv4Addr) -> u32 {
        let binding = self.counter.borrow();
        if let Some(entry) = binding.get(agent_ip) {
            *entry
        } else {
            0
        }
    }

    /// Set upstream by name.
    pub fn set_upstream_by_name(&self, name: &str, flag: bool) -> Result<(), DhcpError> {
        if let Some(ifindex) = self.name2index.borrow().get(name) {
            let binding = self.index2link.borrow();
            let intf = binding.get(&ifindex).unwrap();
            intf.upstream.replace(flag);
            Ok(())
        } else {
            Err(DhcpError::UnknownError)
        }
    }

    /// Set downstream by name.
    pub fn set_downstream_by_name(&self, name: &str, flag: bool) -> Result<(), DhcpError> {
        if let Some(ifindex) = self.name2index.borrow().get(name) {
            let binding = self.index2link.borrow();
            let intf = binding.get(&ifindex).unwrap();
            intf.downstream.replace(flag);
            Ok(())
        } else {
            Err(DhcpError::UnknownError)
        }
    }

    /// Lookup ifindex by IPv4addr.
    pub fn get_ifindex_by_ipv4addr(&self, addr: &Ipv4Addr) -> Option<i32> {
        let binding = self.ipv4addr2index.borrow();
        if let Some(ifindex) = binding.get(addr) {
            Some(*ifindex)
        } else {
            None
        }
    }

    /// Return retry count if smart relay is enabled.
    pub fn is_smart_relay_enabled(&self) -> Option<u8> {
        if let Some(relay_config) = &self.config.global.smart_relay {
            if relay_config.enabled {
                if let Some(retry_count) = relay_config.retry_count {
                    Some(retry_count)
                } else {
                    Some(3)
                }
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Determine Agent IP by ifindex.
    pub fn get_agent_ipv4_addr(&self, ifindex: i32) -> Ipv4Addr {
        let binding = self.index2link.borrow_mut();
        let intf = binding.get(&ifindex).unwrap();  // Should not panic, should it?
        let sindex = intf.sindex.get();

        // Select agent IP.
        let binding = self.index2conn.borrow();
        let conn = binding.get(&ifindex).unwrap();
        let kaddr = &conn.v4[sindex % conn.v4.len()];
        let octets = kaddr.address.octets();

        Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])
    }

    /// Increment sindex on an interface.
    pub fn inc_intf_sindex(&self, ifindex: i32) {
        let binding = self.index2link.borrow_mut();
        let intf = binding.get(&ifindex).unwrap();  // Should not panic, should it?
        //let sindex = intf.sindex.get();
        let sindex = intf.sindex.get();
        intf.sindex.replace(sindex + 1);
    }

    /// Retrieve PKTINFO from a control message.
    pub fn get_pktinfo_from_recvmsg(&self, res: RecvMsg<SockaddrIn>) -> Option<in_pktinfo> {
        while let Ok(mut cmsg) = res.cmsgs() {
            if let Some(item) = cmsg.next() {
                match item {
                    ControlMessageOwned::Ipv4PacketInfo(info) => {
                        return Some(info)
                    }
                    _ => {
                        println!("!!! Unknown ControlMessage {:?}", item);
                    }
                }
            }
        }

        None
    }

    /// Add a link to agent.
    pub fn get_add_link(&self, kl: KernelLink) {
        let ifindex = kl.ifindex;
        let name = kl.name.clone();
        let intf = Interface::new(kl, self.hostname.borrow().as_str());

        self.name2index.borrow_mut().insert(name, ifindex);
        self.index2link.borrow_mut().insert(ifindex, intf);
    }

    /// Add an IPv4 address to agent.
    pub fn get_add_ipv4_address(&self, ka: KernelAddr<Ipv4Addr>) {
        let ifindex = ka.ifindex;
        let address = ka.address.address().clone();
        let ka = Rc::new(ka);

        if !self.index2conn.borrow().contains_key(&ifindex) {
            let conn = Connected::new();
            self.index2conn.borrow_mut().insert(ifindex, conn);
        };

        let mut binding = self.index2conn.borrow_mut();
        let conn = binding.get_mut(&ifindex).unwrap();
        conn.v4.push(ka);

        self.ipv4addr2index.borrow_mut().insert(address, ifindex);
    }

    /// Add an IPv6 address to agent.
    pub fn get_add_ipv6_address(&self, _ka: KernelAddr<Ipv6Addr>) {
        // TBD
    }

    /// Initialize Agent's kernel callbacks.
    pub fn init(agent: Rc<RelayAgent>) {
        let clone = agent.clone();
        agent.kernel.borrow_mut().driver().register_add_link(
            Box::new(move |kl: KernelLink| {
                clone.get_add_link(kl);
            }));

        let clone = agent.clone();
        agent.kernel.borrow_mut().driver().register_add_ipv4_address(
            Box::new(move |ka: KernelAddr<Ipv4Addr>| {
                clone.get_add_ipv4_address(ka);
            }));

        let clone = agent.clone();
        agent.kernel.borrow_mut().driver().register_add_ipv6_address(
            Box::new(move |ka: KernelAddr<Ipv6Addr>| {
                clone.get_add_ipv6_address(ka);
            }));

        // Get hostname.
        let hostname_osstr = unistd::gethostname().expect("Failed getting hostname");
        let hostname = hostname_osstr.into_string().expect("Hostname wasn't valid UTF-8");
        agent.hostname.replace(hostname);
    }

    pub fn handle_boot_request(&self, mut dhcp_message: DhcpMessage,
                               config_vrf: &ConfigVrf,
                               sock: &UdpSocket, _fd: i32, ifindex: i32) -> Result<usize, DhcpError> {
        println!("* Handle BOOTREQUEST");

        let mut agent_ip = self.get_agent_ipv4_addr(ifindex);

        // Agent IP selection for Smart-relay.
        if let Some(retry_count) = self.is_smart_relay_enabled() {
            let count = self.get_agent_server_counter(&agent_ip);
            if count as u8 >= retry_count {
                self.reset_agent_server_counter(&agent_ip);
                self.inc_intf_sindex(ifindex);

                agent_ip = self.get_agent_ipv4_addr(ifindex);
            }
        }

        // Check if the received interface is a downstream interface.
        let binding = self.index2link.borrow();
        let intf = binding.get(&ifindex).unwrap();  // Should not panic, should it?
        if !intf.downstream.get() {
            println!("!!! Received DHCP packet on non-downstream interface {:?}", intf.link.name);
            return Ok(0)
        }
        let circuit_id = intf.circuit_id.as_str();
        let remote_id = intf.remote_id.as_str();

        let rai = RelayAgentInformation::from(Some(circuit_id), Some(remote_id));
        dhcp_message.options.push(DhcpOption::RelayAgentInformation(rai));
        dhcp_message.giaddr = agent_ip;

        let (buf, len) = dhcp_message.octets()?;
        if self.config.is_debug_enabled(){
            println!("*** DHCP message len: {}", len);
        }

        let mut count = 0;
        if let Some(ipv4addr) = &config_vrf.dhcp_servers.ipv4addr {
            // Increment counter.
            self.inc_agent_server_counter(&agent_ip);

            for server in ipv4addr {
                let server_addr = match server.parse::<Ipv4Addr>() {
                    Ok(addr) => addr,
                    Err(_) => {
                        println!("!!! Invalid IP address in config {}", server);
                        continue;
                    }
                };

                let dst = SocketAddrV4::new(server_addr, 67);
                let result = sock.send_to(&buf[..len as usize], dst);
                match result {
                    Ok(_) => {
                        println!("* Relayed BOOTREQUEST packet to {:?}", server_addr);
                        count += 1;
                    }
                    Err(err) => println!("!!! Error: {:?}", err),
                }
            }
        }

        Ok(count)
    }

    pub fn handle_boot_reply(&self, mut dhcp_message: DhcpMessage,
                             _config_vrf: &ConfigVrf,
                             _sock: &UdpSocket, fd: i32,
                             ifindex: i32) -> Result<usize, DhcpError> {
        println!("* Handle BOOTREPLY");

        // Check if the received interface is an upstream interface.
        let binding = self.index2link.borrow_mut();
        let intf = binding.get(&ifindex).unwrap();  // Should not panic, should it?
        if !intf.upstream.get() {
            println!("!!! Received DHCP packet on non-upstream interface {:?}", intf.link.name);
            return Ok(0)
        }

        // Check giaddr in DHCP message and lookup an ifindex.
        let agent_ip = dhcp_message.giaddr;
        let ifindex = match self.get_ifindex_by_ipv4addr(&agent_ip) {
            Some(ifindex) => ifindex,
            None => return Err(DhcpError::UnknownAgentAddressError(agent_ip)),
        };
        dhcp_message.giaddr = Ipv4Addr::new(0, 0, 0, 0);

        // Reset counter.
        self.reset_agent_server_counter(&agent_ip);

        // Strip Relay Agent Information if present.
        if let Some(index) = dhcp_message.options.iter().position(|x| {
            match *x {
                DhcpOption::RelayAgentInformation(_) => true,
                _ => false,
            }
        }) {
            dhcp_message.options.remove(index);
        }

        let (buf, len) = dhcp_message.octets()?;
        if self.config.is_debug_enabled(){
            println!("*** DHCP message len: {}", len);
            //println!("{:?}", &buf[..len as usize]);
        }

        let dst = SockaddrIn::new(255, 255, 255, 255, 68);
        let iov = [IoSlice::new(&buf[..])];
        let addr = in_addr {s_addr: 0xffffffff};
        let ipi = in_pktinfo { ipi_ifindex: ifindex, ipi_spec_dst: in_addr { s_addr: 0 }, ipi_addr: addr };
        let cmsg = ControlMessage::Ipv4PacketInfo(&ipi);

        match sendmsg::<SockaddrIn>(fd, &iov, &[cmsg], MsgFlags::empty(), Some(&dst)) {
            Ok(len) => {
                println!("* Relayed BOOTREPLY packet {:?}", len);
                Ok(1)
            }
            Err(_errno) => Err(DhcpError::IoError(std::io::Error::last_os_error())),
        }
    }

    pub fn config_check(&self) -> Result<(), DhcpError> {
        // Validate interface config.  TBD/Vrf
        let vrf = "default";

        // Check interfaces downstream & upstream.
        if let Some(config_vrf) = self.config.vrf.get(vrf) {
            let config_intf = &config_vrf.interfaces;
            if let Some(ref upstream) = config_intf.upstream {
                for name in upstream {
                    if let Err(_) = self.set_upstream_by_name(name, true) {
                        println!("!!! No such interface {:?}", name);
                    }
                }
            }

            if let Some(ref downstream) = config_intf.downstream {
                for name in downstream {
                    if let Err(_) = self.set_downstream_by_name(name, true) {
                        println!("!!! No such interface {:?}", name);
                    }
                }
            }
        }

        Ok(())
    }

    pub fn start(&self) -> Result<(), DhcpError> {
        // Initialize Kernel interface.
        self.kernel.borrow_mut().init();

        // Check and process the config.
        self.config_check().unwrap();

        // Open DHCP UDP socket.
        let sock = UdpSocket::bind("0.0.0.0:67")?;
        let fd = sock.as_raw_fd();
        let mut cmsg = cmsg_space!(in_pktinfo);

        let res = sock.set_broadcast(true).expect("set broadcast call failed");
        println!("* Set socket broadcast {:?}", res);

        // TODO check result.
        let res = setsockopt(&sock, Ipv4PacketInfo, &true).unwrap();
        println!("* Set setsockopt Ipv4PacketInfo {:?}", res);

        let res = setsockopt(&sock, ReusePort, &true).unwrap();
        println!("* Set setsockopt ReusePort {:?}", res);

        loop {
            let mut buf: &mut [u8] = &mut [0; 2048];
            let mut iov = [IoSliceMut::new(&mut buf)];
            let res: RecvMsg<SockaddrIn> = recvmsg(fd, &mut iov, Some(&mut cmsg), MsgFlags::empty()).unwrap();  // TBD

            if self.config.is_debug_enabled(){
                println!("*** Received {:?}", res);
            }
            let bytes = res.bytes;
            let pktinfo = match self.get_pktinfo_from_recvmsg(res) {
                Some(pktinfo) => pktinfo,
                None => {
                    println!("!!! Failed to retrieve IP_PKTINFO");
                    continue;
                }
            };

            //let dst_ip = Ipv4Addr::from(ntohl(pktinfo.ipi_spec_dst.s_addr));
            let ifindex = pktinfo.ipi_ifindex;

            // TBD: identify VRF through the received interface.
            let vrf = "default";
            let config_vrf = match self.config.vrf.get(vrf) {
                Some(config_vrf) => config_vrf,
                None => {
                    println!("!!! No config exists for {}", vrf);
                    continue;
                }
            };

            // Decode BOOTP/DHCP frame.
            match DhcpMessage::new_from(&iov[0][..bytes]) {
                // Extract DHCP message.
                Ok(dhcp_message) => {
                    if self.config.is_debug_enabled(){
                        println!("*** {:?}", dhcp_message);
                    }

                    let result = match dhcp_message.op {
                        BootpMessageType::BOOTREQUEST => {
                            self.handle_boot_request(dhcp_message, config_vrf, &sock, fd, ifindex)
                        }
                        BootpMessageType::BOOTREPLY => {
                            self.handle_boot_reply(dhcp_message, config_vrf, &sock, fd, ifindex)
                        }
                    };

                    if let Err(err) = result {
                        println!("!!! Error: {:?}", err);
                    }
                }
                // Most likely decode error.
                Err(err) => {
                    println!("!!! Error: {:?}", err);
                }
            }
        }
    }
}

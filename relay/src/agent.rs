//
// DHCP-RS
//   Copyright (C) 2024-2025, Toshiaki Takada
//
use std::rc::Rc;
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
use libc::*;

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

/// Relay Agent.
pub struct RelayAgent {

    /// Relay config.
    config: RelayConfig,

    /// Kernel driver interface.
    kernel: RefCell<Kernel>,

    /// Ifindex to KernelLink map.
    index2link: RefCell<HashMap<i32, Rc<KernelLink>>>,

    /// Name to KernelLink map.
    name2link: RefCell<HashMap<String, Rc<KernelLink>>>,

    /// Ifindex to Connected.
    index2conn: RefCell<HashMap<i32, Connected>>,

    /// IPv4 address to KernelAddress map.
    ipv4addr2index: RefCell<HashMap<Ipv4Addr, i32>>,
}

impl RelayAgent {
    pub fn new(config: RelayConfig) -> RelayAgent {
        RelayAgent {
            config: config,
            kernel: RefCell::new(Kernel::new()),
            index2link: RefCell::new(HashMap::new()),
            name2link: RefCell::new(HashMap::new()),
            index2conn: RefCell::new(HashMap::new()),
            ipv4addr2index: RefCell::new(HashMap::new()),
        }
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
        let kl = Rc::new(kl);

        self.index2link.borrow_mut().insert(ifindex, kl.clone());
        self.name2link.borrow_mut().insert(name, kl.clone());
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
    }

    pub fn start(&self) -> Result<(), DhcpError> {
        // Initialize Kernel interface.
        self.kernel.borrow_mut().init();


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

        let mut ds_ifindex = 0;

        loop {
            let mut buf: &mut [u8] = &mut [0; 2048];
            let mut iov = [IoSliceMut::new(&mut buf)];
            let res: RecvMsg<SockaddrIn> = recvmsg(fd, &mut iov, Some(&mut cmsg), MsgFlags::empty()).unwrap();

            println!("Received request {:?}", res);
            //println!("Received request: size {:?}, address {:?}, flags {:?}", result.bytes, result.address, result.flags);

            let pktinfo = match self.get_pktinfo_from_recvmsg(res) {
                Some(pktinfo) => pktinfo,
                None => {
                    println!("Failed to retrieve IP_PKTINFO");
                    continue;
                }
            };

            let dst_ip = Ipv4Addr::from(ntohl(pktinfo.ipi_spec_dst.s_addr));
            let ifindex = pktinfo.ipi_ifindex;

            if let Ok(mut dhcp_message) = DhcpMessage::new_from(&iov[0][..]) {
                println!("* {:?}", dhcp_message);

                //for option in dhcp_message.options {
                //    
                // }

                match dhcp_message.op {
                    // XXX remember received interface and IP address
                    // and put it in agent option
                    BootpMessageType::BOOTREQUEST => {
                        println!("* Received BOOTREQUEST");

                        // record downstream ifindex for later use.
                        ds_ifindex = ifindex;

                        dhcp_message.giaddr = dst_ip;

                        if let Ok((buf, len)) = dhcp_message.octets() {

                            println!("* len = {}", len);
                            //println!("{:?}", &buf[..len as usize]);

                            for &server in self.config.get_servers() {
                                let dst = SocketAddrV4::new(server, 67);
                                let res = sock.send_to(&buf[..len as usize], dst);
                                println!("*** sock.send_to {:?}", res);
                            }
                        } else {
                            println!("! Endode error");
                        }
                    }
                    // Decode agent option and use the IP as a source interface to send broadcast back to client
                    BootpMessageType::BOOTREPLY => {
                        println!("* Received BOOTREPLY");

                        if let Ok((buf, len)) = dhcp_message.octets() {
                            println!("* len = {}", len);
                            //println!("{:?}", &buf[..len as usize]);

                            let dst = SockaddrIn::new(255, 255, 255, 255, 68);
                            let iov = [IoSlice::new(&buf[..])];
                            //let fds = [fd];
                            let addr = in_addr {s_addr: 0xffffffff};
                            let ipi = in_pktinfo { ipi_ifindex: ds_ifindex, ipi_spec_dst: in_addr { s_addr: 0 }, ipi_addr: addr };
                            let cmsg = ControlMessage::Ipv4PacketInfo(&ipi);

                            let res = sendmsg::<SockaddrIn>(fd, &iov, &[cmsg], MsgFlags::empty(), Some(&dst));
                            println!("{:?}", res);
                        } else {
                            println!("! Endode error");
                        }
                    }
                }
            }
        }
    }
}

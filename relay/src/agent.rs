//
// DHCP-RS
//   Copyright (C) 2024-2025, Toshiaki Takada
//
use std::os::unix::io::AsRawFd;
use std::net::UdpSocket;
use std::net::SocketAddrV4;
use std::io::IoSlice;
use std::io::IoSliceMut;

use nix::cmsg_space;
//use nix::sys::uio::*;
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

use libc::in_addr;
use libc::in_pktinfo;
use libc::ntohl;

use crate::*;
use crate::message::*;
use crate::config::*;

/// Relay Agent.
pub struct RelayAgent {

    /// Relay config.
    config: RelayConfig,
}

impl RelayAgent {
    pub fn new(config: RelayConfig) -> RelayAgent {
        RelayAgent { config }
    }

    pub fn get_ifindex_from_recvmsg(&self, res: RecvMsg<SockaddrIn>) -> i32 {
        let mut ifindex = 0;

        //while let Ok(mut cmsg) = res.cmsgs() {
        for mut cmsg in res.cmsgs() {
            if let Some(item) = cmsg.next() {
                match item {
                    ControlMessageOwned::Ipv4PacketInfo(info) => {
                        ifindex = info.ipi_ifindex;
                    }
                    _ => {
                        // placeholder
                    }
                }
            }
        }

        ifindex
    }

    pub fn start(&self) {
        let sock = UdpSocket::bind("0.0.0.0:67").expect("Error: UdpSocket::bind()");
        let fd = sock.as_raw_fd();
        let mut cmsg = cmsg_space!(in_pktinfo);

        sock.set_broadcast(true).expect("set broadcast call failed");

        // TODO check result.
        setsockopt(&sock, Ipv4PacketInfo, &true).unwrap();
        setsockopt(&sock, ReusePort, &true).unwrap();

        let mut ds_ifindex = 0;

        loop {
            let mut buf: &mut [u8] = &mut [0; 2048];
            let mut iov = [IoSliceMut::new(&mut buf)];

            let res: RecvMsg<SockaddrIn> = recvmsg(fd, &mut iov, Some(&mut cmsg), MsgFlags::empty()).unwrap();
            println!("Received request res {:?}", res);
            //println!("Received request: size {:?}, address {:?}, flags {:?}", result.bytes, result.address, result.flags);

            let mut agent_ip = None;
            let mut ifindex = 0;

            //while let Ok(mut cmsg) = res.cmsgs() {
            for mut cmsg in res.cmsgs() {
                println!("{:?}", cmsg);
                if let Some(item) = cmsg.next() {
                    match item {
                        ControlMessageOwned::Ipv4PacketInfo(info) => {
                            println!("{:?}", info);
                            ifindex = info.ipi_ifindex;
                            agent_ip = Some(Ipv4Addr::from(ntohl(info.ipi_spec_dst.s_addr)));
                        }
                        _ => {
                            println!("Unknown control message");
                        }
                    }
                }
            }

            if let Ok(mut dhcp_message) = DhcpMessage::new_from(&iov[0][..]) {
                println!("{:?}", dhcp_message);

                //for option in dhcp_message.options {
                //    
                // }

                println!("{:?}", iov.len());

                match dhcp_message.op {
                    // XXX remember received interface and IP address
                    // and put it in agent option
                    BootpMessageType::BOOTREQUEST => {
                        println!("*** from client");

                        // record downstream ifindex for later use.
                        ds_ifindex = ifindex;

                        dhcp_message.giaddr = agent_ip.unwrap();

                        if let Ok((buf, len)) = dhcp_message.octets() {

                            println!("len = {}", len);
                            println!("{:?}", &buf[..len as usize]);

                            for &server in self.config.get_servers() {
                                let dst = SocketAddrV4::new(server, 67);
                                let res = sock.send_to(&buf[..len as usize], dst);
                                println!("*** sock.send_to {:?}", res);
                            }
                        } else {
                            println!("*** Endode error");
                        }
                    }
                    // Decode agent option and use the IP as a source interface to send broadcast back to client
                    BootpMessageType::BOOTREPLY => {
                        println!("*** from server");

                        if let Ok((buf, len)) = dhcp_message.octets() {
                            println!("len = {}", len);
                            println!("{:?}", &buf[..len as usize]);

                            //let bcast = Ipv4Addr::new(255, 255, 255, 255);
                            let dst = SockaddrIn::new(255, 255, 255, 255, 68);

                            let iov = [IoSlice::new(&buf[..])];
                            //let fds = [fd];
                            let addr = in_addr {s_addr: 0xffffffff};
                            let ipi = in_pktinfo { ipi_ifindex: ds_ifindex, ipi_spec_dst: in_addr { s_addr: 0 }, ipi_addr: addr };
                            let cmsg = ControlMessage::Ipv4PacketInfo(&ipi);

                            let res = sendmsg::<SockaddrIn>(fd, &iov, &[cmsg], MsgFlags::empty(), Some(&dst));
                            println!("{:?}", res);
                        } else {
                            println!("*** Endode error");

                        }
                    }
                }
            }
        }
    }
}

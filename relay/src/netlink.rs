//
// DHCP-RS
//   Copyright (C) 2024-2025, Toshiaki Takada
//

use std::io;
use std::str;
use std::mem::{size_of, zeroed};
use std::cell::Cell;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use libc::c_int;

use rtable::prefix::*;

use crate::*;
use crate::kernel::*;
use crate::address_family::*;

const RTMGRP_LINK: libc::c_int = 1;
const RTMGRP_IPV4_IFADDR: libc::c_int = 0x10;
const RTMGRP_IPV4_ROUTE: libc::c_int = 0x40;
const RTMGRP_IPV6_IFADDR: libc::c_int = 0x100;
const RTMGRP_IPV6_ROUTE: libc::c_int = 0x400;

const NETLINK_RECV_BUFSIZ: usize = 4096;
const NLMSG_ALIGNTO: usize = 4usize;

/// struct rtattr
#[repr(C)]
pub struct Rtattr {
    pub rta_len: u16,
    pub rta_type: u16,
}

/// Dump Netlink message.
fn nlmsg_dump(h: &Nlmsghdr) {
    unsafe {
        let x = h as *const _ as *mut libc::c_char;
        let mut i: usize = 0;
        while i < h.nlmsg_len as usize {
            println!("{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                   *(x.add(i + 0)), *(x.add(i + 1)), *(x.add(i + 2)), *(x.add(i + 3)),
                   *(x.add(i + 4)), *(x.add(i + 5)), *(x.add(i + 6)), *(x.add(i + 7)));
            i += 8;
        }
    }
}

pub fn nlmsg_align(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

fn nlmsg_hdrlen() -> usize {
    nlmsg_align(size_of::<libc::nlmsghdr>())
}

fn nlmsg_length(len: usize) -> usize {
    nlmsg_hdrlen() + len
}

fn nlmsg_data() -> usize {
    size_of::<libc::nlmsghdr>()
}

fn nlmsg_attr<T>() -> usize {
    nlmsg_data() + nlmsg_align(size_of::<T>())
}

fn nlmsg_attr_ok(buf: &[u8]) -> bool {
    // Ensure the size of buffer has enough space for Rtattr.
    if buf.len() >= size_of::<Rtattr>() {
        let rta = buf as *const _ as *const Rtattr;
        let rta_len = unsafe { (*rta).rta_len as usize };
        if rta_len >= size_of::<Rtattr>() && rta_len <= buf.len() {
            true
        } else {
            false
        }
    } else {
        false
    }
}

fn nlmsg_parse_attr<'a>(buf: &'a [u8]) -> AttrMap {
    let mut m = AttrMap::new();
    let mut b = &buf[..];

    while nlmsg_attr_ok(b) {
        let rta = b as *const _ as *const Rtattr;
        unsafe {
            let rta_len = (*rta).rta_len as usize;
            let rta_type = (*rta).rta_type as i32;
            let _payload_len = rta_len - size_of::<Rtattr>();

            m.insert(rta_type, &b[size_of::<Rtattr>()..rta_len]);

            b = &b[nlmsg_align(rta_len)..];
        }
    }

    //debug!("Attrs: {:?}", m.keys().collect::<Vec<&i32>>());
    m
}

/// Typedefs.
pub type AttrMap<'a> = HashMap<c_int, &'a [u8]>;


/// struct nlmsghdr from /usr/include/linux/netlink.h.
///
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                          nlmsg_len                            |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |          nlmsg_type           |          nlmsg_flags          |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                          nlmsg_seq                            |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                          nlmsg_pid                            |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
#[repr(C)]
pub struct Nlmsghdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}


/// struct rtmsg from rtnetlink.h.
///
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |  rtm_family   |  rtm_dst_len  |  rtm_src_len  |    rtm_tos    |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |  rtm_table    |  rtm_protocol |   rtm_scope   |    rtm_type   |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                          rtm_flags                            |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///

#[repr(C)]
struct Rtmsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,

    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,

    rtm_flags: u32,
}

/// struct rtgenmsg from rtnetlink.h.
#[repr(C)]
struct Rtgenmsg {
    rtgen_family: libc::c_uchar
}

/// struct ifinfomsg from rtnetlink.h.
#[repr(C)]
struct Ifinfomsg {
    ifi_family: u8,
    _ifi_pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

/// struct ifaddrmsg from if_addr.h.
#[repr(C)]
struct Ifaddrmsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

/// Dummy placeholder for netlink_talk
#[repr(C)]
struct NlDummy {
}

struct Buffer {
    p: [u8; NETLINK_RECV_BUFSIZ],
}

impl Buffer {
    pub fn new() -> Buffer {
        Buffer {
            p: [0; NETLINK_RECV_BUFSIZ],
        }
    }
}

/// Netlink kernel callbacks.
/// It passes info up to application, but cannot handle error here.
pub struct NetlinkKernelCallback {

    /// Add Link callback.
    pub add_link: Option<Box<dyn Fn(KernelLink)>>,

    /// Delete Link callback.
    pub delete_link: Option<Box<dyn Fn(KernelLink)>>,

    /// Add IPv4 Address callback.
    pub add_ipv4_address: Option<Box<dyn Fn(KernelAddr<Ipv4Addr>)>>,

    /// Delete IPv4 Address callback.
    pub delete_ipv4_address: Option<Box<dyn Fn(KernelAddr<Ipv4Addr>)>>,

    /// Add IPv6 Address callback.
    pub add_ipv6_address: Option<Box<dyn Fn(KernelAddr<Ipv6Addr>)>>,

    /// Delete IPv6 Address callback.
    pub delete_ipv6_address: Option<Box<dyn Fn(KernelAddr<Ipv6Addr>)>>,
}

impl NetlinkKernelCallback {

    pub fn new() -> NetlinkKernelCallback {
        NetlinkKernelCallback {
            add_link: None,
            delete_link: None,
            add_ipv4_address: None,
            delete_ipv4_address: None,
            add_ipv6_address: None,
            delete_ipv6_address: None,
        }
    }

    pub fn call_add_link(&self, link: KernelLink) {
        if let Some(f) = &self.add_link {
            (*f)(link);
        } else {
            println!("Add link callback function is not set.");
        }
    }

    pub fn call_delete_link(&self, link: KernelLink) {
        if let Some(f) = &self.delete_link {
            (*f)(link);
        } else {
            println!("Delete link callback function is not set.");
        }
    }

    pub fn call_add_ipv4_address(&self, addr: KernelAddr<Ipv4Addr>) {
        if let Some(f) = &self.add_ipv4_address {
            (*f)(addr);
        } else {
            println!("Add IPv4 address callback function is not set.");
        }
    }

    pub fn call_delete_ipv4_address(&self, addr: KernelAddr<Ipv4Addr>) {
        if let Some(f) = &self.delete_ipv4_address {
            (*f)(addr);
        } else {
            println!("Delete IPv4 address callback function is not set.");
        }
    }
    
    pub fn call_add_ipv6_address(&self, addr: KernelAddr<Ipv6Addr>) {
        if let Some(f) = &self.add_ipv6_address {
            (*f)(addr);
        } else {
            println!("Add IPv6 address callback function is not set.");
        }
    }

    pub fn call_delete_ipv6_address(&self, addr: KernelAddr<Ipv6Addr>) {
        if let Some(f) = &self.delete_ipv6_address {
            (*f)(addr);
        } else {
            println!("Delete IPv6 address callback function is not set.");
        }
    }
}

/// Netlink Socket handler.
pub struct Netlink {

    /// Debug flag.
    debug: bool,

    /// File descriptor for Netlink socket.
    sock: c_int,
    
    /// PID associated with this Netlink socket.
    pid: u32,

    /// Sequence number of messsage.
    seq: Cell<u32>,

    /// Receive buffer.
    buf: RefCell<Buffer>,

    /// Kernel callback functions.
    pub callback: RefCell<NetlinkKernelCallback>,
}

#[repr(C)]
struct Request {
    nlmsghdr: Nlmsghdr,
    rtmsg: Rtmsg,
    buf: [u8; 4096],	// TBD
}

impl Request {
    pub fn offset(&self) -> usize {
        (self.nlmsghdr.nlmsg_len as usize) - (size_of::<Nlmsghdr>() + size_of::<Rtmsg>())
    }
}

impl Netlink {
    /// Constructor - open Netlink socket and bind.
    pub fn new(debug: bool) -> Result<Netlink, io::Error> {
        let sock = unsafe {
            libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE)
        };
        if sock < 0 {
            return Err(io::Error::last_os_error());
        };

        let mut snl = unsafe { zeroed::<libc::sockaddr_nl>() };
        snl.nl_family = libc::AF_NETLINK as u16;
        snl.nl_groups = RTMGRP_LINK as u32 |
                        RTMGRP_IPV4_IFADDR as u32 | RTMGRP_IPV4_ROUTE as u32 |
                        RTMGRP_IPV6_IFADDR as u32 | RTMGRP_IPV6_ROUTE as u32;
        let mut socklen: libc::socklen_t = size_of::<libc::sockaddr_nl>() as u32;
        let ret = unsafe {
            libc::bind(
                sock,
                &snl as *const _ as *const libc::sockaddr,
                socklen,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        let ret = unsafe {
            libc::getsockname(
                sock,
                &mut snl as *const _ as *mut libc::sockaddr,
                &mut socklen)
        };
        if ret < 0 || socklen != size_of::<libc::sockaddr_nl>() as u32 {
            return Err(io::Error::last_os_error());
        }

        // TODO: set socket non-blocking. only for event socket.

        Ok(Netlink {
            debug,
            sock,
            pid: snl.nl_pid,
            seq: Cell::new(0u32),
            buf: RefCell::new(Buffer::new()),
            callback: RefCell::new(NetlinkKernelCallback::new()),
        })
    }

    /// Send a request message through Netlink.
    /// Expect to receive response.
    fn send_request(&self, family: libc::c_int, nlmsg_type: libc::c_int) -> Result<(), io::Error> {
        struct Request {
            nlmsghdr: Nlmsghdr,
            rtgenmsg: Rtgenmsg,
        }

        let seq = self.seq.get() + 1;
        self.seq.set(seq);

        let mut snl = unsafe { zeroed::<libc::sockaddr_nl>() };
        snl.nl_family = libc::AF_NETLINK as u16;
        
        let mut req = unsafe { zeroed::<Request>() };
        req.nlmsghdr.nlmsg_len = size_of::<Request>() as u32;
        req.nlmsghdr.nlmsg_type = nlmsg_type as u16;
        req.nlmsghdr.nlmsg_flags = libc::NLM_F_ROOT as u16 |
                                   libc::NLM_F_MATCH as u16 |
                                   libc::NLM_F_REQUEST as u16;
        req.nlmsghdr.nlmsg_pid = self.pid;
        req.nlmsghdr.nlmsg_seq = seq;
        req.rtgenmsg.rtgen_family = family as u8;

        let ret = unsafe {
            libc::sendto(self.sock,
                         &req as *const _ as *const libc::c_void,
                         size_of::<Request>(), 0,
                         &snl as *const _ as *const libc::sockaddr,
                         size_of::<libc::sockaddr_nl>() as u32)
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    /// Parse Netlink header and call parser to parse message payload.
    fn parse_info<T>(&self, parser: &dyn Fn(&Netlink, &Nlmsghdr, &T, &AttrMap) -> bool) -> Result<(), DhcpError> {
        'outer: loop {
            let mut buffer = self.buf.borrow_mut();

            let mut iov = unsafe { zeroed::<libc::iovec>() };
            iov.iov_base = &mut buffer.p as *const _ as *mut libc::c_void;
            iov.iov_len = NETLINK_RECV_BUFSIZ;
            let mut snl = unsafe { zeroed::<libc::sockaddr_nl>() };
            let mut msg = unsafe { zeroed::<libc::msghdr>() };
            msg.msg_name = &mut snl as *const _ as *mut libc::c_void;
            msg.msg_namelen = size_of::<libc::sockaddr_nl>() as u32;
            msg.msg_iov = &mut iov as *const _ as *mut libc::iovec;
            msg.msg_iovlen = 1;

            let ret = unsafe {
                libc::recvmsg(self.sock, &msg as *const _ as *mut libc::msghdr, 0)
            };

            if ret < 0 {
                //info!("Error from recvmsg"); 
                // Check errno,
                // errno == EINTR
                //   break
                // errno == EWOULDBLOCK || errno == EAGAIN
                //   break
                // or something else
                // continue
                continue;
            } else if ret == 0 {
                //info!("No data received");
                break 'outer;
            }

            if msg.msg_namelen != size_of::<libc::sockaddr_nl>() as u32 {
                // sender address length error
                break 'outer;
            }

            let recvlen = ret as usize;
            let recvbuf = &buffer.p[..recvlen];
            let mut p = 0;
            while p < recvlen {
                if p + size_of::<Nlmsghdr>() > recvlen {
                    //error!("No enough space for Nlmsghdr in recv buffer.");
                    break;
                }

                let mut buf = &recvbuf[p..];
                let header = buf as *const _ as *const Nlmsghdr;
                let nlmsg_len = unsafe { (*header).nlmsg_len };
                let nlmsg_type = unsafe { (*header).nlmsg_type as i32 };
                buf = &buf[..nlmsg_len as usize];

                match nlmsg_type  {
                    libc::NLMSG_DONE => break 'outer,
                    libc::NLMSG_ERROR => {
                        let _errbuf = &buf[nlmsg_data()..];
                        let nlmsgerr = buf as *const _ as *const libc::nlmsgerr;

                        return Err(DhcpError::NetlinkError(format!("{:?}", nlmsgerr)))
                    },
                    _ => {
                    }
                }

                //debug!("Nlmsg: type: {}, len: {}", nlmsg_type, nlmsg_len);

                if (nlmsg_len as usize) < nlmsg_attr::<T>() {
                    return Err(DhcpError::NetlinkError("Insufficient Nlmsg length".to_string()))
                }

                let databuf = &buf[nlmsg_data()..];
                let data = databuf as *const _ as *const T;
                let attrbuf = &buf[nlmsg_attr::<T>()..];
                let map = nlmsg_parse_attr(attrbuf);
                let _ret = unsafe { parser(self, &(*header), &(*data), &map) };
                // TODO check return value?

                p += nlmsg_len as usize;
            }
        }

        Ok(())
    }

    fn parse_dummy(&self, _h: &Nlmsghdr, _ifi: &NlDummy, _attr: &AttrMap) -> bool {
        //debug!("Nlmsg type {}", h.nlmsg_type);
        true
    }

    fn parse_interface(&self, h: &Nlmsghdr, ifi: &Ifinfomsg, attr: &AttrMap) -> bool {
        assert!(h.nlmsg_type == libc::RTM_NEWLINK);

        let ifindex = ifi.ifi_index;
        let hwaddr: [u8; 6] = match attr.get(&(libc::IFLA_ADDRESS as i32)) {
            Some(hwaddr) if hwaddr.len() == 6 => {
                [hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]]
            },
            Some(hwaddr) => {
                println!("!!! Invalid hwaddr length {}", hwaddr.len());
                [0, 0, 0, 0, 0, 0]
            },
            None => {
                [0, 0, 0, 0, 0, 0]
            }
        };

        /* TBD
        let mtu = match attr.get(&(libc::IFLA_MTU as i32)) {
            Some(mtu) => decode_num::<u32>(*mtu),
            None => 0u32,  // maybe set default?
        };
        */
        let mtu = 1500;
        let ifname = match attr.get(&(libc::IFLA_IFNAME as i32)) {
            Some(ifname) => {
                match str::from_utf8(ifname) {
                    // A little tricky, but need to trim the trailing '\0' char.
                    Ok(ifname) => ifname.trim_matches(char::from(0)),
                    Err(_) => "(Non-utf8)",
                }
            },
            None => "(Unknown)"
        };

        if self.debug {
            println!("*** parse_interface() {} {} {} {:?} {}",
                     ifindex, ifname, ifi.ifi_type, hwaddr, mtu);
        }

        // Callback to add Link.
        let kc = self.callback.borrow();
        let ka = KernelLink::new(ifi.ifi_index, ifname, ifi.ifi_type as u16, hwaddr, mtu);
        kc.call_add_link(ka);

        true
    }

    fn parse_interface_address<T>(&self, h: &Nlmsghdr, ifa: &Ifaddrmsg, attr: &AttrMap) -> bool
    where T: AddressFamily + Addressable {
        assert!(h.nlmsg_type == libc::RTM_NEWADDR || h.nlmsg_type == libc::RTM_DELADDR);

        if ifa.ifa_family as i32 != T::address_family() {
            return false
        }

        let mut local = attr.get(&(libc::IFA_LOCAL as i32));
        let mut address = attr.get(&(libc::IFA_ADDRESS as i32));
        if let None = local {
            local = address;
        }
        if let None = address {
            address = local;
        }

        let _broad = match address {
            Some(address) if address == local.unwrap() => {
                Some(address)
            },
            _ => {
                attr.get(&(libc::IFA_BROADCAST as i32))
            }
        };

        let index = ifa.ifa_index as i32;
        let kc = self.callback.borrow();

        match (ifa.ifa_family as i32, h.nlmsg_type) {
            (libc::AF_INET, libc::RTM_NEWADDR) => {
                let prefix = Prefix::<Ipv4Addr>::from_slice(address.unwrap(), ifa.ifa_prefixlen);
                let ka = KernelAddr::<Ipv4Addr>::new(index, prefix, None, false, false, None);
                kc.call_add_ipv4_address(ka);

                if self.debug {
                    println!("*** parse_interface_address() {} Ipv4Addr {:?}", index, prefix);
                }
            }
            (libc::AF_INET, libc::RTM_DELADDR) => {
                let prefix = Prefix::<Ipv4Addr>::from_slice(address.unwrap(), ifa.ifa_prefixlen);
                let ka = KernelAddr::<Ipv4Addr>::new(index, prefix, None, false, false, None);
                kc.call_delete_ipv4_address(ka);
            }
            (libc::AF_INET6, libc::RTM_NEWADDR) => {
                let prefix = Prefix::<Ipv6Addr>::from_slice(address.unwrap(), ifa.ifa_prefixlen);
                let ka = KernelAddr::<Ipv6Addr>::new(index, prefix, None, false, false, None);
                kc.call_add_ipv6_address(ka);

                if self.debug {
                    println!("*** parse_interface_address() {} Ipv6Addr {:?}", index, prefix);
                }
            }
            (libc::AF_INET6, libc::RTM_DELADDR) => {
                let prefix = Prefix::<Ipv6Addr>::from_slice(address.unwrap(), ifa.ifa_prefixlen);
                let ka = KernelAddr::<Ipv6Addr>::new(index, prefix, None, false, false, None);
                kc.call_delete_ipv6_address(ka);
            }
            _ => {
                println!("!!! Invalid family or message type");
                return false
            }
        }

        true
    }

}

impl KernelDriver for Netlink {

    /// Register Add Link callback.
    fn register_add_link(&self, f: Box<dyn Fn(KernelLink)>) {
        self.callback.borrow_mut().add_link.replace(f);
    }

    /// Register Delete Link callback function.
    fn register_delete_link(&self, f: Box<dyn Fn(KernelLink)>) {
        self.callback.borrow_mut().delete_link.replace(f);
    }

    /// Register Add IPv4 Address callback function.
    fn register_add_ipv4_address(&self, f: Box<dyn Fn(KernelAddr<Ipv4Addr>)>) {
        self.callback.borrow_mut().add_ipv4_address.replace(f);
    }

    /// Register Delete IPv4 Address callback function.
    fn register_delete_ipv4_address(&self, f: Box<dyn Fn(KernelAddr<Ipv4Addr>)>) {
        self.callback.borrow_mut().delete_ipv4_address.replace(f);
    }

    /// Register Add IPv6 Address callback function.
    fn register_add_ipv6_address(&self, f: Box<dyn Fn(KernelAddr<Ipv6Addr>)>) {
        self.callback.borrow_mut().add_ipv6_address.replace(f);
    }

    /// Register Delete IPv6 Address callback function.
    fn register_delete_ipv6_address(&self, f: Box<dyn Fn(KernelAddr<Ipv6Addr>)>) {
        self.callback.borrow_mut().delete_ipv6_address.replace(f);
    }

    /// Get all links from kernel.
    fn get_link_all(&self) -> Result<(), DhcpError> {
        println!("* Get all links from the kernel");

        if let Err(err) = self.send_request(libc::AF_PACKET, libc::RTM_GETLINK as i32) {
            return Err(DhcpError::NetlinkError(err.to_string()))
        }

        if let Err(err) = self.parse_info(&Netlink::parse_interface) {
            return Err(DhcpError::NetlinkError(err.to_string()))
        }

        Ok(())
    }

    /// Get all IPv4 addresses from kernel.
    fn get_ipv4_address_all(&self) -> Result<(), DhcpError> {
        println!("* Get all IPv4 addresses from the kernel" );

        if let Err(err) = self.send_request(libc::AF_INET, libc::RTM_GETADDR as i32) {
            return Err(DhcpError::NetlinkError(err.to_string()))
        }

        if let Err(err) = self.parse_info(&Netlink::parse_interface_address::<Ipv4Addr>) {
            return Err(DhcpError::NetlinkError(err.to_string()))
        }

        Ok(())
    }

    /// Get all IPv6 addresses from system.
    fn get_ipv6_address_all(&self) -> Result<(), DhcpError> {
        Ok(())
    }
        

}

/// Public interface to get driver.
pub fn get_driver(debug: bool) -> Option<Netlink> {
    match Netlink::new(debug) {
	Ok(netlink) => Some(netlink),
        Err(err) => {
            println!("Failed to initlaize Netlink driver {}", err);
            None
        }
    }
}

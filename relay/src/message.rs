//
// DHCP-RS
//   Copyright (C) 2024-2025, Toshiaki Takada
//

use std::mem::transmute;
use std::fmt;
use std::net::Ipv4Addr;

use crate::*;
use crate::encode::*;
use crate::options::*;

/// DHCP message.
pub struct DhcpMessage {
    /// Message type.
    pub op: BootpMessageType,
    
    /// Hardware type.
    pub htype: u8,

    /// Hardware address len.
    pub hlen: u8,

    /// Hops.
    pub hops: u8,

    /// Transaction ID.
    pub xid: u32,

    /// Seconds elapsed.
    pub secs: u16,

    /// BOOTP flags.
    pub flags: u16,

    /// Client IP address.
    pub ciaddr: Ipv4Addr,

    /// Your (client) IP address.
    pub yiaddr: Ipv4Addr,

    /// Next Server IP address.
    pub siaddr: Ipv4Addr,

    /// Relay agent IP address.
    pub giaddr: Ipv4Addr,

    /// Client Hardware address.
    pub chaddr: [u8; 16],
    
    /// Server host name.
    pub sname: [u8; 64],

    /// Boot file name.
    pub file: [u8; 128],

    /// Options.
    pub options: Vec<DhcpOption>,
}

fn chaddr_str(hlen: u8, chaddr: &[u8; 16]) -> String {
    let len = ((if hlen <= 16 { hlen } else { 16 }) as usize) * 3 - 1;
    let mut s = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:",
                        chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5], chaddr[6], chaddr[7],
                        chaddr[8], chaddr[9], chaddr[10], chaddr[11], chaddr[12], chaddr[13], chaddr[14], chaddr[15]
    );

    s.truncate(len);
    s
}

fn u8_to_string(s: &[u8]) -> String {
    if s[0] == 0 {
        String::from("(empty)")
    } else {
        match std::str::from_utf8(s) {
            Ok(s) => s.to_string(),
            Err(_) => String::from("(error)")
        }
    }
}

impl fmt::Debug for DhcpMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "op: {:?}, htype: {}, hlen: {}, hops: {}, xid: {:#8x}, secs: {}, flags: {:#x}, ciaddr: {}, yiaddr: {}, siaddr: {}, giaddr: {}, chaddr: {}, sname: {}, file: {}, options: {:?}",
               self.op, self.htype, self.hlen, self.hops, self.xid, self.secs, self.flags,
               self.ciaddr, self.yiaddr, self.siaddr, self.giaddr, chaddr_str(self.hlen, &self.chaddr),
               u8_to_string(&self.sname), u8_to_string(&self.file), &self.options)
    }
}

/// DhcpMessage implementation.
impl DhcpMessage {
    /// Parse DHCP message.
    pub fn new_from(buf: &[u8]) -> Result<DhcpMessage, DhcpError> {
        let op: BootpMessageType = decode_u8(&buf[..])?.try_into()?;
        let mut chaddr: [u8; 16] = [0; 16];
        let mut sname: [u8; 64] = [0; 64];
        let mut file: [u8; 128] = [0; 128];
        let mut cookie: [u8; 4] = [0; 4];

        decode_data(&mut chaddr, &buf[28..44])?;
        decode_data(&mut sname, &buf[44..108])?;
        decode_data(&mut file, &buf[108..236])?;
        decode_data(&mut cookie, &buf[236..240])?;

        // Check magic cookie for DHCP message.
        // TBD: return code
        if cookie != [0x63u8, 0x82, 0x53, 0x63] {
            return Err(DhcpError::DecodeError)
        }
        
        // TBD: should check size of received packet, minimum 300 or so.

        // TBD: Htype may be one of defined for ARP.
        Ok(DhcpMessage {
            op,
            htype: decode_u8(&buf[1..])?,
            hlen: decode_u8(&buf[2..])?,
            hops: decode_u8(&buf[3..])?,
            xid: decode_u32(&buf[4..])?,
            secs: decode_u16(&buf[8..])?,
            flags: decode_u16(&buf[10..])?,
            ciaddr: decode_ipv4(&buf[12..])?,
            yiaddr: decode_ipv4(&buf[16..])?,
            siaddr: decode_ipv4(&buf[20..])?,
            giaddr: decode_ipv4(&buf[24..])?,
            chaddr,
            sname,
            file,
            options: DhcpMessage::options_from(&buf[240..])?,
        })
    }

    /// Parse DHCP options and return a vector.
    pub fn options_from(buf: &[u8]) -> Result<Vec<DhcpOption>, DhcpError> {
        let mut opt_vec = Vec::new();
        let mut b = &buf[..];
        while b.len() > 0 {
            let code: DhcpOptionCode = unsafe { transmute(b[0] as u8) };
            let opt: Result<(usize, DhcpOption), DhcpError> = match code {
                DhcpOptionCode::Pad => {
                    Ok((1, DhcpOption::Pad))
                }
                DhcpOptionCode::SubnetMask => {
                    let (len, addr) = option_ipv4(&b)?;
                    Ok((len, DhcpOption::SubnetMask(addr)))
                }
                DhcpOptionCode::TimeOffset => {
                    let (len, v) = option_i32(&b)?;
                    Ok((len, DhcpOption::TimeOffset(v)))
                }
                DhcpOptionCode::Router => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::Router(vec)))
                }
                DhcpOptionCode::TimeServer => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::TimeServer(vec)))
                }
                DhcpOptionCode::NameServer => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::NameServer(vec)))
                }
                DhcpOptionCode::DomainServer => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::DomainServer(vec)))
                }
                DhcpOptionCode::LogServer => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::LogServer(vec)))
                }
                DhcpOptionCode::QuotesServer => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::QuotesServer(vec)))
                }
                DhcpOptionCode::LPRServer => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::LPRServer(vec)))
                }
                DhcpOptionCode::ImpressServer => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::ImpressServer(vec)))
                }
                DhcpOptionCode::RLPServer => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::RLPServer(vec)))
                }
                DhcpOptionCode::HostName => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::HostName(s)))
                }
                DhcpOptionCode::BootFileSize => {
                    let (len, v) = option_u16(&b)?;
                    Ok((len, DhcpOption::BootFileSize(v)))
                }
                DhcpOptionCode::MeritDumpFile => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::MeritDumpFile(s)))
                }
                DhcpOptionCode::DomainName => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::DomainName(s)))
                }
                DhcpOptionCode::SwapServer => {
                    let (len, addr) = option_ipv4(&b)?;
                    Ok((len, DhcpOption::SwapServer(addr)))
                }
                DhcpOptionCode::RootPath => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::RootPath(s)))
                }
                DhcpOptionCode::ExtensionsFile => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::ExtensionsFile(s)))
                }
                DhcpOptionCode::ForwardOnOff => {
                    let (len, v) = option_bool(&b)?;
                    Ok((len, DhcpOption::ForwardOnOff(v)))
                }
                DhcpOptionCode::SrcRteOnOff => {
                    let (len, v) = option_bool(&b)?;
                    Ok((len, DhcpOption::SrcRteOnOff(v)))
                }
                DhcpOptionCode::PolicyFilter => {
                    let (len, vec) = option_ipv4_pair_vec(&b, 8)?;
                    Ok((len, DhcpOption::PolicyFilter(vec)))
                }
                DhcpOptionCode::MaxDGAssembly => {
                    let (len, v) = option_u16(&b)?;
                    Ok((len, DhcpOption::MaxDGAssembly(v)))
                }
                DhcpOptionCode::DefaultIPTTL => {
                    let (len, v) = option_u8(&b)?;
                    Ok((len, DhcpOption::DefaultIPTTL(v)))
                }
                DhcpOptionCode::MTUTimeout => {
                    let (len, v) = option_u32(&b)?;
                    Ok((len, DhcpOption::MTUTimeout(v)))
                }
                DhcpOptionCode::MTUPlateau => {
                    let (len, vec) = option_u16_vec(&b, 2)?;
                    Ok((len, DhcpOption::MTUPlateau(vec)))
                }
                DhcpOptionCode::MTUInterface => {
                    let (len, v) = option_u16(&b)?;
                    Ok((len, DhcpOption::MTUInterface(v)))
                }
                DhcpOptionCode::MTUSubnet => {
                    let (len, v) = option_bool(&b)?;
                    Ok((len, DhcpOption::MTUSubnet(v)))
                }
                DhcpOptionCode::BroadcastAddress => {
                    let (len, addr) = option_ipv4(&b)?;
                    Ok((len, DhcpOption::BroadcastAddress(addr)))
                }
                DhcpOptionCode::MaskDiscovery => {
                    let (len, v) = option_bool(&b)?;
                    Ok((len, DhcpOption::MaskDiscovery(v)))
                }
                DhcpOptionCode::MaskSupplier => {
                    let (len, v) = option_bool(&b)?;
                    Ok((len, DhcpOption::MaskSupplier(v)))
                }
                DhcpOptionCode::RouterDiscovery => {
                    let (len, v) = option_bool(&b)?;
                    Ok((len, DhcpOption::RouterDiscovery(v)))
                }
                DhcpOptionCode::RouterRequest => {
                    let (len, addr) = option_ipv4(&b)?;
                    Ok((len, DhcpOption::RouterRequest(addr)))
                }
                DhcpOptionCode::StaticRoute => {
                    let (len, vec) = option_ipv4_pair_vec(&b, 8)?;
                    Ok((len, DhcpOption::StaticRoute(vec)))
                }
                DhcpOptionCode::Trailers => {
                    let (len, v) = option_bool(&b)?;
                    Ok((len, DhcpOption::Trailers(v)))
                }
                DhcpOptionCode::ARPTimeout => {
                    let (len, v) = option_u32(&b)?;
                    Ok((len, DhcpOption::ARPTimeout(v)))
                }
                DhcpOptionCode::Ethernet => {
                    let (len, v) = option_bool(&b)?;
                    Ok((len, DhcpOption::Ethernet(v)))
                }
                DhcpOptionCode::DefaultTCPTTL => {
                    let (len, v) = option_u8(&b)?;
                    Ok((len, DhcpOption::DefaultTCPTTL(v)))
                }
                DhcpOptionCode::KeepaliveTime => {
                    let (len, v) = option_u32(&b)?;
                    Ok((len, DhcpOption::KeepaliveTime(v)))
                }
                DhcpOptionCode::KeepaliveData => {
                    let (len, v) = option_bool(&b)?;
                    Ok((len, DhcpOption::KeepaliveData(v)))
                }
                DhcpOptionCode::NISDomain => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::NISDomain(s)))
                }
                DhcpOptionCode::NISServers => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::NISServers(vec)))
                }
                DhcpOptionCode::NTPServers => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::NTPServers(vec)))
                }
                DhcpOptionCode::VendorSpecific => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::VendorSpecific(vec)))
                }
                DhcpOptionCode::NetBIOSNameSrv => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::NetBIOSNameSrv(vec)))
                }
                DhcpOptionCode::NetBIOSDistSrv => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::NetBIOSDistSrv(vec)))
                }
                DhcpOptionCode::NetBIOSNodeType => {
                    let (len, v) = option_u8(&b)?;
                    Ok((len, DhcpOption::NetBIOSNodeType(v)))
                }
                DhcpOptionCode::NetBIOSScope => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::NetBIOSScope(s)))
                }
                DhcpOptionCode::XWindowFont => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::XWindowFont(vec)))
                }
                DhcpOptionCode::XWindowManager => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::XWindowManager(vec)))
                }
                DhcpOptionCode::AddressRequest => {
                    let (len, addr) = option_ipv4(&b)?;
                    Ok((len, DhcpOption::AddressRequest(addr)))
                }
                DhcpOptionCode::AddressTime => {
                    let (len, v) = option_u32(&b)?;
                    Ok((len, DhcpOption::AddressTime(v)))
                }
                DhcpOptionCode::Overload => {
                    let (len, v) = option_u8(&b)?;
                    Ok((len, DhcpOption::Overload(v)))
                }
                DhcpOptionCode::DHCPMsgType => {
                    let (len, v) = option_u8(&b)?;
                    Ok((len, DhcpOption::DHCPMsgType(v.try_into()?)))
                }
                DhcpOptionCode::DHCPServerId => {
                    let (len, addr) = option_ipv4(&b)?;
                    Ok((len, DhcpOption::DHCPServerId(addr)))
                }
                DhcpOptionCode::ParameterList => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    let vec: Vec<DhcpOptionCode> = vec.iter().map(|&x| unsafe { transmute(x as u8) }).collect();
                    Ok((len, DhcpOption::ParameterList(vec)))
                }
                DhcpOptionCode::Message => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::Message(s)))
                }
                DhcpOptionCode::MaxMessageSize => {
                    let (len, v) = option_u16(&b)?;
                    Ok((len, DhcpOption::MaxMessageSize(v)))
                }
                DhcpOptionCode::RenewalTime => {
                    let (len, v) = option_u32(&b)?;
                    Ok((len, DhcpOption::RenewalTime(v)))
                }
                DhcpOptionCode::RebindingTime => {
                    let (len, v) = option_u32(&b)?;
                    Ok((len, DhcpOption::RebindingTime(v)))
                }
                DhcpOptionCode::VendorClassId => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::VendorClassId(s)))
                }
                DhcpOptionCode::ClientId => {
                    let (len, mut id) = option_u8_vec(&b, 0)?;
                    if len < 2 {
                        Err(DhcpError::DecodeError)
                    } else {
                        let t = id[0];
                        id.remove(0);
                        Ok((len, DhcpOption::ClientId(DhcpClientId { t, id })))
                    }
                }
                DhcpOptionCode::NetWareIPDomain => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::NetWareIPDomain(s)))
                }
                // TBD: Sub-option decoding is not supported yet.
                DhcpOptionCode::NetWareIPInformation => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::NetWareIPInformation(vec)))
                }
                DhcpOptionCode::NISPlusDomain => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::NISPlusDomain(s)))
                }
                DhcpOptionCode::NISPlusServerAddr => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::NISPlusServerAddr(vec)))
                }
                DhcpOptionCode::TFTPServerName => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::TFTPServerName(s)))
                }
                DhcpOptionCode::BootfileName => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::BootfileName(s)))
                }
                DhcpOptionCode::MobileIPHomeAgent => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::MobileIPHomeAgent(vec)))
                }
                DhcpOptionCode::SMTPServer => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::SMTPServer(vec)))
                }
                DhcpOptionCode::POP3Server => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::POP3Server(vec)))
                }
                DhcpOptionCode::NNTPServer => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::NNTPServer(vec)))
                }
                DhcpOptionCode::WWWServer => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::WWWServer(vec)))
                }
                DhcpOptionCode::FingerServer => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::FingerServer(vec)))
                }
                DhcpOptionCode::IRCServer => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::IRCServer(vec)))
                }
                DhcpOptionCode::StreetTalkServer => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::StreetTalkServer(vec)))
                }
                DhcpOptionCode::STDAServer => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::STDAServer(vec)))
                }
                // TBD: Each user-class decoding is not supported yet.
                DhcpOptionCode::UserClass => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::UserClass(vec)))
                }
                DhcpOptionCode::DirectoryAgent => {
                    let (len, (mandatory, addrs)) = option_bool_ipv4_vec(&b, 5)?;
                    Ok((len, DhcpOption::DirectoryAgent(SlpDirectoryAgent { mandatory, addrs })))
                }
                DhcpOptionCode::ServiceScope => {
                    let (len, (mandatory, scopes)) = option_bool_string(&b, 1)?;
                    Ok((len, DhcpOption::ServiceScope(SlpServiceScope { mandatory, scopes })))
                }
                DhcpOptionCode::RapidCommit => {
                    if b[1] != 0 {
                        Err(DhcpError::InvalidOptionLength)
                    } else {
                        Ok((2, DhcpOption::RapidCommit))
                    }
                }
                DhcpOptionCode::ClientFQDN => {
                    let (len, client_fqdn) = option_client_fqdn(&b)?;
                    Ok((len, DhcpOption::ClientFQDN(client_fqdn)))
                }
                DhcpOptionCode::RelayAgentInformation => {
                    let (len, agent_info) = option_relay_agent_info(&b)?;
                    Ok((len, DhcpOption::RelayAgentInformation(agent_info)))
                }
                DhcpOptionCode::ISNS => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::ISNS(vec)))
                }
                DhcpOptionCode::NDSServers => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::NDSServers(vec)))
                }
                DhcpOptionCode::NDSTreeName => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::NDSTreeName(s)))
                }
                DhcpOptionCode::NDSContext => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::NDSContext(s)))
                }
                DhcpOptionCode::BCMCSControllerDomainNameList => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::BCMCSControllerDomainNameList(vec)))
                }
                DhcpOptionCode::BCMCSControllerIPv4Address => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::BCMCSControllerIPv4Address(vec)))
                }
                DhcpOptionCode::Authentication => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::Authentication(vec)))
                }
                DhcpOptionCode::ClientLastTransactionTime => {
                    let (len, v) = option_u32(&b)?;
                    Ok((len, DhcpOption::ClientLastTransactionTime(v)))
                }
                DhcpOptionCode::AssociatedIP => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::AssociatedIP(vec)))
                }
                DhcpOptionCode::ClientSystem => {
                    let (len, v) = option_u16(&b)?;
                    Ok((len, DhcpOption::ClientSystem(v)))
                }
                DhcpOptionCode::ClientNDI => {
                    let len = b[1];
                    if len != 3 {
                        Err(DhcpError::InvalidOptionLength)
                    } else {
                        Ok((3, DhcpOption::ClientNDI((b[2], b[3], b[4]))))
                    }
                }
                DhcpOptionCode::LDAP => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::LDAP(vec)))
                }
                DhcpOptionCode::UuidGuid => {
                    let (len, (v, vec)) = option_u8_u8_vec(&b, 1)?;
                    Ok((len, DhcpOption::UuidGuid((v, vec))))
                }
                DhcpOptionCode::UserAuth => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::UserAuth(s)))
                }
                DhcpOptionCode::GeoconfCivic => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::GeoconfCivic(vec)))
                }
                DhcpOptionCode::PCode => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::PCode(s)))
                }
                DhcpOptionCode::TCode => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::TCode(s)))
                }
                DhcpOptionCode::IPv6OnlyPreferred => {
                    let (len, v) = option_u32(&b)?;
                    Ok((len, DhcpOption::IPv6OnlyPreferred(v)))
                }
                DhcpOptionCode::DHCP4o6S46SAddr => {
                    let (len, addr) = option_ipv6(&b)?;
                    Ok((len, DhcpOption::DHCP4o6S46SAddr(addr)))
                }
                DhcpOptionCode::NetinfoAddress => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::NetinfoAddress(vec)))
                }
                DhcpOptionCode::NetinfoTag => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::NetinfoTag(vec)))
                }
                DhcpOptionCode::CaptivePortal => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::CaptivePortal(s)))
                }
                DhcpOptionCode::AutoConfig => {
                    let (len, v) = option_u8(&b)?;
                    if v != 0 && v != 1 {
                        Err(DhcpError::InvalidValue)
                    } else {
                        Ok((len, DhcpOption::AutoConfig(v)))
                    }
                }
                DhcpOptionCode::NameServiceSearch => {
                    let (len, vec) = option_u16_vec(&b, 2)?;
                    Ok((len, DhcpOption::NameServiceSearch(vec)))
                }
                DhcpOptionCode::SubnetSelection => {
                    let (len, addr) = option_ipv4(&b)?;
                    Ok((len, DhcpOption::SubnetSelection(addr)))
                }
                DhcpOptionCode::DomainSearch => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::DomainSearch(s)))
                }
                DhcpOptionCode::SIPServers => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::SIPServers(vec)))
                }
                DhcpOptionCode::ClasslessStaticRoute => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::ClasslessStaticRoute(vec)))
                }
                DhcpOptionCode::CableLabsClientConfig => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::CableLabsClientConfig(vec)))
                }
                DhcpOptionCode::GeoConf => {
                    let (len, vec) = option_u8_vec(&b, 16)?;
                    Ok((len, DhcpOption::GeoConf(vec)))
                }
                DhcpOptionCode::VIVendorClass => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::VIVendorClass(vec)))
                }
                DhcpOptionCode::VIVendorSpecificInformation => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::VIVendorSpecificInformation(vec)))
                }
                DhcpOptionCode::PanaAgent => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::PanaAgent(vec)))
                }
                DhcpOptionCode::V4Lost => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::V4Lost(vec)))
                }
                DhcpOptionCode::CapwapAcV4 => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::CapwapAcV4(vec)))
                }
                DhcpOptionCode::IPv4AddressMoS => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::IPv4AddressMoS(vec)))
                }
                DhcpOptionCode::IPv4FQDNMoS => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::IPv4FQDNMoS(vec)))
                }
                DhcpOptionCode::SipUAConfigurationServiceDomains => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::SipUAConfigurationServiceDomains(s)))
                }
                DhcpOptionCode::IPv4AddressANDSF => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::IPv4AddressANDSF(vec)))
                }
                DhcpOptionCode::V4SZTPRedirect => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::V4SZTPRedirect(s)))
                }
                DhcpOptionCode::RDNSSSelection => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::RDNSSSelection(vec)))
                }
                DhcpOptionCode::V4DotsRI => {
                    let (len, s) = option_string(&b, 1)?;
                    Ok((len, DhcpOption::V4DotsRI(s)))
                }
                DhcpOptionCode::V4DotsAddress => {
                    let (len, vec) = option_ipv4_vec(&b, 4)?;
                    Ok((len, DhcpOption::V4DotsAddress(vec)))
                }
                DhcpOptionCode::BulkLeaseQueryStatusCode => {
                    let (len, (v, s)) = option_u8_string(&b, 1)?;
                    Ok((len, DhcpOption::BulkLeaseQueryStatusCode((v, s))))
                }
                DhcpOptionCode::BulkLeaseQueryBaseTime => {
                    let (len, v) = option_u32(&b)?;
                    Ok((len, DhcpOption::BulkLeaseQueryBaseTime(v)))
                }
                DhcpOptionCode::BulkLeaseQueryStartTimeOfState => {
                    let (len, v) = option_u32(&b)?;
                    Ok((len, DhcpOption::BulkLeaseQueryStartTimeOfState(v)))
                }
                DhcpOptionCode::BulkLeaseQueryQueryStartTime => {
                    let (len, v) = option_u32(&b)?;
                    Ok((len, DhcpOption::BulkLeaseQueryQueryStartTime(v)))
                }
                DhcpOptionCode::BulkLeaseQueryQueryEndTime => {
                    let (len, v) = option_u32(&b)?;
                    Ok((len, DhcpOption::BulkLeaseQueryQueryEndTime(v)))
                }
                DhcpOptionCode::BulkLeaseQueryDhcpState => {
                    let (len, v) = option_u8(&b)?;
                    // TBD: should check the value.
                    Ok((len, DhcpOption::BulkLeaseQueryDhcpState(v)))
                }
                DhcpOptionCode::BulkLeaseQueryDataSource => {
                    let (len, v) = option_u8(&b)?;
                    // TBD: should check the value.
                    Ok((len, DhcpOption::BulkLeaseQueryDataSource(v)))
                }
                DhcpOptionCode::V4PCPServer => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::V4PCPServer(vec)))
                }
                DhcpOptionCode::V4PortParams => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::V4PortParams(vec)))
                }
                DhcpOptionCode::MudURLV4 => {
                    let (len, s) = option_string(&b, 0)?;
                    Ok((len, DhcpOption::MudURLV4(s)))
                }
                DhcpOptionCode::V4DNR => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::V4DNR(vec)))
                }
                DhcpOptionCode::PXELinuxMagic => {
                    let (len, v) = option_u32(&b)?;
                    if v != 0xF100747E {
                        Err(DhcpError::InvalidValue)
                    } else {
                        Ok((len, DhcpOption::PXELinuxMagic(v)))
                    }
                }
                DhcpOptionCode::ConfigurationFile => {
                    let (len, s) = option_string(&b, 0)?;
                    Ok((len, DhcpOption::ConfigurationFile(s)))
                }
                DhcpOptionCode::PathPrefix => {
                    let (len, s) = option_string(&b, 0)?;
                    Ok((len, DhcpOption::PathPrefix(s)))
                }
                DhcpOptionCode::RebootTime => {
                    let (len, v) = option_u32(&b)?;
                    Ok((len, DhcpOption::RebootTime(v)))
                }
                DhcpOptionCode::Option6RD => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::Option6RD(vec)))
                }
                DhcpOptionCode::V4AccessDomain => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::V4AccessDomain(vec)))
                }
                DhcpOptionCode::SubnetAllocation => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::SubnetAllocation(vec)))
                }
                DhcpOptionCode::VirtualSubnetSelection => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::VirtualSubnetSelection(vec)))
                }
                DhcpOptionCode::End => {
                    Ok((1, DhcpOption::End))
                }
                _ => {
                    let (len, vec) = option_u8_vec(&b, 0)?;
                    Ok((len, DhcpOption::Unknown((code, vec))))
                }
            };

            // Collect a parsed option.
            match opt {
                Ok((len, option)) => {
                    b = &b[(len as usize)..];
                    if let DhcpOption::End = option {
                        break;
                    }
                    opt_vec.push(option);
                }
                Err(err) => return Err(err),
            }
        }

        Ok(opt_vec)
    }

    // Encode DHCP options to buffer.
    pub fn options_to(&self, buf: &mut [u8]) -> Result<usize, DhcpError> {
        let mut len = 0;

        for opt in &self.options {
            let result = match opt {
                //DhcpOption::Pad => {}
                DhcpOption::SubnetMask(v) => {
                    encode_option(&mut buf[len..], DhcpOptionCode::SubnetMask as u8,
                                  |b: &mut [u8]| { encode_ipv4(b, *v) })
                }
                //DhcpOption::TimeOffset(_v) => {}
                //DhcpOption::Router(_v) => {}
                //DhcpOption::TimeServer(_v) => {}
                //DhcpOption::NameServer(_v) => {}
                //DhcpOption::DomainServer(_v) => {}
                //DhcpOption::LogServer(_v) => {}
                //DhcpOption::QuotesServer(_v) => {}
                //DhcpOption::LPRServer(_v) => {}
                //DhcpOption::ImpressServer(_v) => {}
                //DhcpOption::RLPServer(_v) => {}
                DhcpOption::HostName(v) => {
                    encode_option(&mut buf[len..], DhcpOptionCode::HostName as u8,
                                  |b: &mut [u8]| { encode_string(b, v) })
                }
                //DhcpOption::BootFileSize(_v) => {}
                //DhcpOption::MeritDumpFile(_v) => {}
                DhcpOption::DomainName(v) => {
                    encode_option(&mut buf[len..], DhcpOptionCode::DomainName as u8,
                                  |b: &mut [u8]| { encode_string(b, v) })
                }
                /*
                DhcpOption::SwapServer(_v) => {}
                DhcpOption::RootPath(_v) => {}
                DhcpOption::ExtensionsFile(_v) => {}
                DhcpOption::ForwardOnOff(_v) => {}
                DhcpOption::SrcRteOnOff(_v) => {}
                DhcpOption::PolicyFilter(_v) => {}
                DhcpOption::MaxDGAssembly(_v) => {}
                DhcpOption::DefaultIPTTL(_v) => {}
                DhcpOption::MTUTimeout(_v) => {}
                DhcpOption::MTUPlateau(_v) => {}
                DhcpOption::MTUInterface(_v) => {}
                DhcpOption::MTUSubnet(_v) => {}
                DhcpOption::BroadcastAddress(_v) => {}
                DhcpOption::MaskDiscovery(_v) => {}
                DhcpOption::MaskSupplier(_v) => {}
                DhcpOption::RouterRequest(_v) => {}
                DhcpOption::StaticRoute(_v) => {}
                DhcpOption::Trailers(_v) => {}
                DhcpOption::ARPTimeout(_v) => {}
                DhcpOption::Ethernet(_v) => {}
                DhcpOption::DefaultTCPTTL(_v) => {}
                 */
                //DhcpOption::KeepaliveTime(_v) => {}
                //DhcpOption::KeepaliveData(_v) => {}
                //DhcpOption::NISDomain(_v) => {}
                //DhcpOption::NISServers(_v) => {}
                //DhcpOption::NTPServers(_v) => {}
                //DhcpOption::VendorSpecific(_v) => {}
                //DhcpOption::NetBIOSNameSrv(_v) => {}
                //DhcpOption::NetBIOSDistSrv(_v) => {}
                //DhcpOption::NetBIOSNodeType(_v) => {}
                //DhcpOption::NetBIOSScope(_v) => {}
                //DhcpOption::XWindowFont(_v) => {}
                //DhcpOption::XWindowManager(_v) => {}
                DhcpOption::AddressRequest(v) => {
                    encode_option(&mut buf[len..], DhcpOptionCode::AddressRequest as u8,
                                  |b: &mut [u8]| { encode_ipv4(b, *v) })
                }
                DhcpOption::AddressTime(v) => {
                    encode_option(&mut buf[len..], DhcpOptionCode::AddressTime as u8,
                                  |b: &mut [u8]| { encode_u32(b, *v) })
                }
                //DhcpOption::Overload(_v) => {}
                DhcpOption::DHCPMsgType(v) => {
                    encode_option(&mut buf[len..], DhcpOptionCode::DHCPMsgType as u8,
                                  |b: &mut [u8]| { encode_u8(b, unsafe { transmute(*v as u8) }) })
                }
                DhcpOption::DHCPServerId(v) => {
                    encode_option(&mut buf[len..], DhcpOptionCode::DHCPServerId as u8,
                                  |b: &mut [u8]| { encode_ipv4(b, *v) })
                }
                DhcpOption::ParameterList(vec) => {
                    encode_option(&mut buf[len..], DhcpOptionCode::ParameterList as u8,
                                  |b: &mut [u8]| {
                                      let v: Vec<_> = vec.iter().map(|x| unsafe { transmute(*x as u8) }).collect();
                                      encode_data(b, &v)
                                  })
                }
                //DhcpOption::Message(_v) => {}
                //DhcpOption::MaxMessageSize(_v) => {}
                //DhcpOption::RenewalTime(_v) => {}
                //DhcpOption::RebindingTime(_v) => {}
                //DhcpOption::VendorClassId(_v) => {}
                //DhcpOption::ClientId(_v) => {}
                DhcpOption::RelayAgentInformation(rai) => {
                    encode_option(&mut buf[len..], DhcpOptionCode::RelayAgentInformation as u8,
                                  |b: &mut [u8]| {
                                      let mut len = 0;
                                      let mut b = &mut b[..];
                                      if let Some(circuit_id) = &rai.circuit_id {
                                          b[0] = DhcpAgentSubOptionCode::CircuitID as u8;
                                          b[1] = circuit_id.len() as u8;
                                          len += 2 + encode_data(&mut b[2..], circuit_id.as_ref()).unwrap();
                                      }
                                      b = &mut b[len..];
                                      if let Some(remote_id) = &rai.remote_id {
                                          b[0] = DhcpAgentSubOptionCode::RemoteID as u8;
                                          b[1] = remote_id.len() as u8;
                                          len += 2 + encode_data(&mut b[2..], remote_id.as_ref()).unwrap();
                                      }
                                      Ok(len)
                                  })
                }
                //DhcpOption:: => {}
                _ => {
                    Err(DhcpError::EncodeError)
                }
            };

            len += result?;
        }

        Ok(len)
    }

    // Generate DHCP datagram from a message.
    pub fn octets(&self) -> Result<([u8; 512], u16), DhcpError> {
        // The size of minimum datagram size, which would be maximum DHCP frame size.
        let mut buf: [u8; 512] = [0; 512];
        let mut len = 240;

        // Encode BOOTP compatible fields.
        encode_u8(&mut buf[0..], unsafe { transmute(self.op as u8) })?;
        encode_u8(&mut buf[1..], self.htype)?;
        encode_u8(&mut buf[2..], self.hlen)?;
        encode_u8(&mut buf[3..], self.hops)?;
        encode_u32(&mut buf[4..], self.xid)?;
        encode_u16(&mut buf[8..], self.secs)?;
        encode_u16(&mut buf[10..], self.flags)?;
        encode_ipv4(&mut buf[12..], self.ciaddr)?;
        encode_ipv4(&mut buf[16..], self.yiaddr)?;
        encode_ipv4(&mut buf[20..], self.siaddr)?;
        encode_ipv4(&mut buf[24..], self.giaddr)?;
        encode_data(&mut buf[28..], &self.chaddr)?;
        encode_data(&mut buf[44..], &self.sname)?;
        encode_data(&mut buf[108..], &self.file)?;

        // Encode DHCP Magic Cookie.
        encode_data(&mut buf[236..], &[0x63u8, 0x82, 0x53, 0x63])?;

        // Encode DHCP options.
        len += self.options_to(&mut buf[240..])?;

        // Encode End marker.
        len += encode_u8(&mut buf[len..], DhcpOptionCode::End as u8)?;

        // Append padding if it necessary.
        if len < 300 {
            len = 300;
        }

        Ok((buf, len as u16))
    }
}


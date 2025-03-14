#![allow(dead_code)]
//
// DHCP-RS
//   Copyright (C) 2024-2025, Toshiaki Takada
//

pub mod address_family;
pub mod netlink;
pub mod kernel;
pub mod encode;
pub mod options;
pub mod message;
pub mod agent;
pub mod config;

use std::fmt;
use std::convert::TryFrom;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum DhcpError {
    #[error("Invalid BOOTP Message Type")]
    InvalidBootpMessageType,
    //#[error("Invalid Hardware Type")]
    //InvalidHardwareType,
    //#[error("TBD")]
    //InvalidHardwareLen,
    #[error("Insuffcient buffer size {0}")]
    InsufficientBufferSize(String),
    #[error("Unkown Option")]
    UnknownOption,
    #[error("Invalid DHCP Message Type")]
    InvalidDhcpMessageType,
    #[error("Invalid Option Length")]
    InvalidOptionLength,
    #[error("Invalid Value {0}")]
    InvalidValue(String),
    #[error("Encode error {0}")]
    EncodeError(String),
    #[error("Decode error {0}")]
    DecodeError(String),
    #[error("I/O error")]
    IoError(#[from] std::io::Error),
    #[error("Netlink error {0}")]
    NetlinkError(String),
    #[error("Config error")]
    ConfigError,
    #[error("Unknown error")]
    UnknownError,
}

/// IPv4 Address Mask Pair.
#[derive(Debug, PartialEq)]
pub struct Ipv4AddrPair(Ipv4Addr, Ipv4Addr);

/// BOOTP Mesage type.
#[derive(PartialEq, Copy, Clone)]
pub enum BootpMessageType {
    BOOTREQUEST = 1,
    BOOTREPLY = 2,
}

impl fmt::Debug for BootpMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            BootpMessageType::BOOTREQUEST => write!(f, "BOOTREQUEST"),
            BootpMessageType::BOOTREPLY => write!(f, "BOOTREPLY"),
        }
    }
}

impl TryFrom<u8> for BootpMessageType {
    type Error = DhcpError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == BootpMessageType::BOOTREQUEST as u8 => Ok(BootpMessageType::BOOTREQUEST),
            x if x == BootpMessageType::BOOTREPLY as u8 => Ok(BootpMessageType::BOOTREPLY),
            _ => Err(DhcpError::InvalidBootpMessageType),
        }
    }
}


/// DHCP Message Type.
#[derive(PartialEq, Copy, Clone)]
pub enum DhcpMessageType {
    DHCPDISCOVER = 1,
    DHCPOFFER = 2,
    DHCPREQUEST = 3,
    DHCPDECLINE = 4,
    DHCPACK = 5,
    DHCPNAK = 6,
    DHCPRELEASE = 7,
    DHCPINFORM = 8,
    DHCPFORCERENEW = 9,
    DHCPLEASEQUERY = 10,
    DHCPLEASEUNASSIGNED = 11,
    DHCPLEASEUNKNOWN = 12,
    DHCPLEASEACTIVE = 13,
    DHCPBULKLEASEQUERY = 14,
    DHCPLEASEQUERYDONE = 15,
    DHCPACTIVELEASEQUERY = 16,
    DHCPLEASEQUERYSTATUS = 17,
    DHCPTLS = 18,
}

impl fmt::Debug for DhcpMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            DhcpMessageType::DHCPDISCOVER => write!(f, "DHCPDISCOVER"),
            DhcpMessageType::DHCPOFFER => write!(f, "DHCPOFFER"),
            DhcpMessageType::DHCPREQUEST => write!(f, "DHCPREQUEST"),
            DhcpMessageType::DHCPDECLINE => write!(f, "DHCPDECLINE"),
            DhcpMessageType::DHCPACK => write!(f, "DHCPACK"),
            DhcpMessageType::DHCPNAK => write!(f, "DHCPNAK"),
            DhcpMessageType::DHCPRELEASE => write!(f, "DHCPRELEASE"),
            DhcpMessageType::DHCPINFORM => write!(f, "DHCPINFORM"),
            DhcpMessageType::DHCPFORCERENEW => write!(f, "DHCPFORCERENEW"),
            DhcpMessageType::DHCPLEASEQUERY => write!(f, "DHCPLEASEQUERY"),
            DhcpMessageType::DHCPLEASEUNASSIGNED => write!(f, "DHCPLEASEUNASSIGNED"),
            DhcpMessageType::DHCPLEASEUNKNOWN => write!(f, "DHCPLEASEUNKNOWN"),
            DhcpMessageType::DHCPLEASEACTIVE => write!(f, "DHCPLEASEACTIVE"),
            DhcpMessageType::DHCPBULKLEASEQUERY => write!(f, "DHCPBULKLEASEQUERY"),
            DhcpMessageType::DHCPLEASEQUERYDONE => write!(f, "DHCPLEASEQUERYDONE"),
            DhcpMessageType::DHCPACTIVELEASEQUERY => write!(f, "DHCPACTIVELEASEQUERY"),
            DhcpMessageType::DHCPLEASEQUERYSTATUS => write!(f, "DHCPLEASEQUERYSTATUS"),
            DhcpMessageType::DHCPTLS => write!(f, "DHCPTLS"),
        }
    }
}

impl TryFrom<u8> for DhcpMessageType {
    type Error = DhcpError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == DhcpMessageType::DHCPDISCOVER as u8 => Ok(DhcpMessageType::DHCPDISCOVER),
            x if x == DhcpMessageType::DHCPOFFER as u8 => Ok(DhcpMessageType::DHCPOFFER),
            x if x == DhcpMessageType::DHCPREQUEST as u8 => Ok(DhcpMessageType::DHCPREQUEST),
            x if x == DhcpMessageType::DHCPDECLINE as u8 => Ok(DhcpMessageType::DHCPDECLINE),
            x if x == DhcpMessageType::DHCPACK as u8 => Ok(DhcpMessageType::DHCPACK),
            x if x == DhcpMessageType::DHCPNAK as u8 => Ok(DhcpMessageType::DHCPNAK),
            x if x == DhcpMessageType::DHCPRELEASE as u8 => Ok(DhcpMessageType::DHCPRELEASE),
            x if x == DhcpMessageType::DHCPINFORM as u8 => Ok(DhcpMessageType::DHCPINFORM),
            x if x == DhcpMessageType::DHCPFORCERENEW as u8 => Ok(DhcpMessageType::DHCPFORCERENEW),
            x if x == DhcpMessageType::DHCPLEASEQUERY as u8 => Ok(DhcpMessageType::DHCPLEASEQUERY),
            x if x == DhcpMessageType::DHCPLEASEUNASSIGNED as u8 => Ok(DhcpMessageType::DHCPLEASEUNASSIGNED),
            x if x == DhcpMessageType::DHCPLEASEUNKNOWN as u8 => Ok(DhcpMessageType::DHCPLEASEUNKNOWN),
            x if x == DhcpMessageType::DHCPLEASEACTIVE as u8 => Ok(DhcpMessageType::DHCPLEASEACTIVE),
            x if x == DhcpMessageType::DHCPBULKLEASEQUERY as u8 => Ok(DhcpMessageType::DHCPBULKLEASEQUERY),
            x if x == DhcpMessageType::DHCPLEASEQUERYDONE as u8 => Ok(DhcpMessageType::DHCPLEASEQUERYDONE),
            x if x == DhcpMessageType::DHCPACTIVELEASEQUERY as u8 => Ok(DhcpMessageType::DHCPACTIVELEASEQUERY),
            x if x == DhcpMessageType::DHCPLEASEQUERYSTATUS as u8 => Ok(DhcpMessageType::DHCPLEASEQUERYSTATUS),
            _ => Err(DhcpError::InvalidDhcpMessageType),
        }
    }
}

/// DHCP Option Code.
///   https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
///
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum DhcpOptionCode {
    Pad = 0,					// RFC2132
    SubnetMask = 1,				// RFC2132
    TimeOffset = 2,				// RFC2132
    Router = 3,					// RFC2132
    TimeServer = 4,				// RFC2132
    NameServer = 5,				// RFC2132
    DomainServer = 6,				// RFC2132
    LogServer = 7,				// RFC2132
    QuotesServer = 8,				// RFC2132
    LPRServer = 9,				// RFC2132
    ImpressServer = 10,				// RFC2132
    RLPServer = 11,				// RFC2132
    HostName = 12,				// RFC2132
    BootFileSize = 13,				// RFC2132
    MeritDumpFile = 14,				// RFC2132
    DomainName = 15,				// RFC2132
    SwapServer = 16,				// RFC2132
    RootPath = 17,				// RFC2132
    ExtensionsFile = 18,			// RFC2132
    ForwardOnOff = 19,				// RFC2132
    SrcRteOnOff = 20,				// RFC2132
    PolicyFilter = 21,				// RFC2132
    MaxDGAssembly = 22,				// RFC2132
    DefaultIPTTL = 23,				// RFC2132
    MTUTimeout = 24,				// RFC2132
    MTUPlateau = 25,				// RFC2132
    MTUInterface = 26,				// RFC2132
    MTUSubnet = 27,				// RFC2132
    BroadcastAddress = 28,			// RFC2132
    MaskDiscovery = 29,				// RFC2132
    MaskSupplier = 30,				// RFC2132
    RouterDiscovery = 31,			// RFC2132
    RouterRequest = 32,				// RFC2132
    StaticRoute = 33,				// RFC2132
    Trailers = 34,				// RFC2132
    ARPTimeout = 35,				// RFC2132
    Ethernet = 36,				// RFC2132
    DefaultTCPTTL = 37,				// RFC2132
    KeepaliveTime = 38,				// RFC2132
    KeepaliveData = 39,				// RFC2132
    NISDomain = 40,				// RFC2132
    NISServers = 41,				// RFC2132
    NTPServers = 42,				// RFC2132
    VendorSpecific = 43,			// RFC2132
    NetBIOSNameSrv = 44,			// RFC2132
    NetBIOSDistSrv = 45,			// RFC2132
    NetBIOSNodeType = 46,			// RFC2132
    NetBIOSScope = 47,				// RFC2132
    XWindowFont = 48,				// RFC2132
    XWindowManager = 49,			// RFC2132
    AddressRequest = 50,			// RFC2132
    AddressTime = 51,				// RFC2132
    Overload = 52,				// RFC2132
    DHCPMsgType = 53,				// RFC2132
    DHCPServerId = 54,				// RFC2132
    ParameterList = 55,				// RFC2132
    Message = 56,				// RFC2132
    MaxMessageSize = 57,			// RFC2132
    RenewalTime = 58,				// RFC2132
    RebindingTime = 59,				// RFC2132
    VendorClassId = 60,				// RFC2132
    ClientId = 61,				// RFC2132, RFC4361
    NetWareIPDomain = 62,			// RFC2242
    NetWareIPInformation = 63,			// RFC2242 (TBD)
    NISPlusDomain = 64,				// RFC2132
    NISPlusServerAddr = 65,			// RFC2132
    TFTPServerName = 66,			// RFC2132
    BootfileName = 67,				// RFC2132
    MobileIPHomeAgent = 68,			// RFC2132
    SMTPServer = 69,				// RFC2132
    POP3Server = 70,				// RFC2132
    NNTPServer = 71,				// RFC2132
    WWWServer = 72,				// RFC2132
    FingerServer = 73,				// RFC2132
    IRCServer = 74,				// RFC2132
    StreetTalkServer = 75,			// RFC2132
    STDAServer = 76,				// RFC2132
    UserClass = 77,				// RFC3004
    DirectoryAgent = 78,			// RFC2610
    ServiceScope = 79,				// RFC2610
    RapidCommit = 80,				// RFC4039
    ClientFQDN = 81,				// RFC4702
    RelayAgentInformation = 82,			// RFC3046
    ISNS = 83,					// RFC4174
    Unassigned84 = 84,
    NDSServers = 85,				// RFC2241
    NDSTreeName = 86,				// RFC2241
    NDSContext = 87,				// RFC2241
    BCMCSControllerDomainNameList = 88,		// RFC4280
    BCMCSControllerIPv4Address = 89,		// RFC4280
    Authentication = 90,			// RFC3118
    ClientLastTransactionTime = 91,		// RFC4388
    AssociatedIP = 92,				// RFC4388
    ClientSystem = 93,				// RFC4578
    ClientNDI = 94,				// RFC4578
    LDAP = 95,					// RFC3679
    Unassigned96 = 96,
    UuidGuid = 97,				// RFC4578
    UserAuth = 98,				// RFC2485
    GeoconfCivic = 99,				// RFC4776
    PCode = 100,				// RFC4833
    TCode = 101,				// RFC4833
    Unassigned102 = 102,			
    Unassigned103 = 103,
    Unassigned104 = 104,
    Unassigned105 = 105,
    Unassigned106 = 106,
    Unassigned107 = 107,
    IPv6OnlyPreferred = 108,			// RFC8925
    DHCP4o6S46SAddr = 109,			// RFC8539
    Unassigned110 = 110,
    Unassigned111 = 111,
    NetinfoAddress = 112,			// RFC3679
    NetinfoTag = 113,				// RFC3679
    CaptivePortal = 114,			// RFC8910
    Unassigned115 = 115,
    AutoConfig = 116,				// RFC2563
    NameServiceSearch = 117,			// RFC2937
    SubnetSelection = 118,			// RFC3011
    DomainSearch = 119,				// RFC3397
    SIPServers = 120,				// RFC3361
    ClasslessStaticRoute = 121,			// RFC3442
    CableLabsClientConfig = 122,		// RFC3495
    GeoConf = 123,				// RFC6225
    VIVendorClass = 124,			// RFC3925
    VIVendorSpecificInformation = 125,		// RFC3925
    Unassigned126 = 126,
    Unassigned127 = 127,

    // 128-135 are Vender specific and used with PXE boot. RFC4578.
    Option128 = 128,
    Option129 = 129,
    Option130 = 130,
    Option131 = 131,
    Option132 = 132,
    Option133 = 133,
    Option134 = 134,
    Option135 = 135,

    PanaAgent = 136, 				// RFC5192
    V4Lost = 137,				// RFC5223
    CapwapAcV4 = 138,				// RFC5417
    IPv4AddressMoS = 139,			// RFC5678
    IPv4FQDNMoS = 140,				// RFC5678
    SipUAConfigurationServiceDomains = 141,	// RFC6011
    IPv4AddressANDSF = 142,			// RFC6153
    V4SZTPRedirect = 143,			// RFC8572
    GeoLoc = 144,				// RFC6225
    ForcerenewNonceCapable = 145,		// RFC6704
    RDNSSSelection = 146,			// RFC6731
    V4DotsRI = 147,				// RFC8973
    V4DotsAddress = 148,			// RFC8973
    Unassigned149 = 149,
    VendorSpececif150 = 150,  			// TBD?
    BulkLeaseQueryStatusCode = 151,		// RFC6926
    BulkLeaseQueryBaseTime = 152,		// RFC6926
    BulkLeaseQueryStartTimeOfState = 153,	// RFC6926
    BulkLeaseQueryQueryStartTime = 154,		// RFC6926
    BulkLeaseQueryQueryEndTime = 155,		// RFC6926
    BulkLeaseQueryDhcpState = 156,		// RFC6926
    BulkLeaseQueryDataSource = 157,		// RFC6926
    V4PCPServer = 158,				// RFC7291
    V4PortParams = 159,				// RFC7618
    Unassigned160 = 160,
    MudURLV4 = 161,				// RFC8520
    V4DNR = 162,				// RFC9463

    // 163-174 are unassgined.
    Unassigned163 = 163,
    Unassigned164 = 164,
    Unassigned165 = 165,
    Unassigned166 = 166,
    Unassigned167 = 167,
    Unassigned168 = 168,
    Unassigned169 = 169,
    Unassigned170 = 170,
    Unassigned171 = 171,
    Unassigned172 = 172,
    Unassigned173 = 173,
    Unassigned174 = 174,

    // Tentatively assigned.
    Etherboot175 = 175,
    IPTelephone = 176,
    Etherboot177 = 177,

    // 178-207 are unassgined.
    Unassigned178 = 178,
    Unassigned179 = 179,
    Unassigned180 = 180,
    Unassigned181 = 181,
    Unassigned182 = 182,
    Unassigned183 = 183,
    Unassigned184 = 184,
    Unassigned185 = 185,
    Unassigned186 = 186,
    Unassigned187 = 187,
    Unassigned188 = 188,
    Unassigned189 = 189,
    Unassigned190 = 190,
    Unassigned191 = 191,
    Unassigned192 = 192,
    Unassigned193 = 193,
    Unassigned194 = 194,
    Unassigned195 = 195,
    Unassigned196 = 196,
    Unassigned197 = 197,
    Unassigned198 = 198,
    Unassigned199 = 199,
    Unassigned200 = 200,
    Unassigned201 = 201,
    Unassigned202 = 202,
    Unassigned203 = 203,
    Unassigned204 = 204,
    Unassigned205 = 205,
    Unassigned206 = 206,
    Unassigned207 = 207,

    PXELinuxMagic = 208,			// RFC5071
    ConfigurationFile = 209,			// RFC5071
    PathPrefix = 210,				// RFC5071
    RebootTime = 211,				// RFC5071
    Option6RD = 212,				// RFC5969
    V4AccessDomain = 213,			// RFC5986

    // 214-219 are unassigned.
    Unassigned214 = 214,
    Unassigned215 = 215,
    Unassigned216 = 216,
    Unassigned217 = 217,
    Unassigned218 = 218,
    Unassigned219 = 219,

    SubnetAllocation = 220,			// RFC6656
    VirtualSubnetSelection = 221,		// RFC6607
    Unassigned222 = 222,
    Unassigned223 = 223,

    // Reserved (Private use)
    Rserved224 = 224,
    Rserved225 = 225,
    Rserved226 = 226,
    Rserved227 = 227,
    Rserved228 = 228,
    Rserved229 = 229,
    Rserved230 = 230,
    Rserved231 = 231,
    Rserved232 = 232,
    Rserved233 = 233,
    Rserved234 = 234,
    Rserved235 = 235,
    Rserved236 = 236,
    Rserved237 = 237,
    Rserved238 = 238,
    Rserved239 = 239,
    Rserved240 = 240,
    Rserved241 = 241,
    Rserved242 = 242,
    Rserved243 = 243,
    Rserved244 = 244,
    Rserved245 = 245,
    Rserved246 = 246,
    Rserved247 = 247,
    Rserved248 = 248,
    Rserved249 = 249,
    Rserved250 = 250,
    Rserved251 = 251,
    Rserved252 = 252,
    Rserved253 = 253,
    Rserved254 = 254,
    End = 255,					// RFC2132
}
    
/// DHCP Relay Agent Information Sub-option.
#[derive(Debug)]
pub enum DhcpAgentSubOptionCode {
    CircuitID = 1,
    RemoteID = 2,
}

/// DHCP Client Id for Option 61.
#[derive(Debug)]
pub struct DhcpClientId {
    t: u8,
    id: Vec<u8>,
}

/// SLP Directory Agent Option (78).
#[derive(Debug)]
pub struct SlpDirectoryAgent {
    mandatory: bool,
    addrs: Vec<Ipv4Addr>,
}

/// SLP Service Scope Option (79).
#[derive(Debug)]
pub struct SlpServiceScope {
    mandatory: bool,
    scopes: String,
}

/// Client FQDN Option (81).
#[derive(Debug)]
pub struct ClientFQDN {
    flags: u8,
    rcode1: u8,
    rcode2: u8,
    fqdn: String,
}

/// Relay Agent Information Option (82).
#[derive(Debug)]
pub struct RelayAgentInformation {
    circuit_id: Option<Vec<u8>>,
    remote_id: Option<Vec<u8>>,
}

impl RelayAgentInformation {
    pub fn from(circuit_id: Option<&str>, remote_id: Option<&str>) -> RelayAgentInformation {
        let circuit_id = match circuit_id {
            Some(circuit_id) => Some(circuit_id.as_bytes().to_vec()),
            None => None,
        };
        let remote_id = match remote_id {
            Some(remote_id) => Some(remote_id.as_bytes().to_vec()),
            None => None,
        };

        RelayAgentInformation {
            circuit_id,
            remote_id,
        }
    }
}

/// DHCP option.
#[derive(Debug)]
pub enum DhcpOption {
    /// 0. Pad.
    Pad,

    /// 1. Subnet Mask.
    SubnetMask(Ipv4Addr),

    /// 2. Time Offset.
    TimeOffset(i32),

    /// 3. Router Option.
    Router(Vec<Ipv4Addr>),

    /// 4. Time Server Option.
    TimeServer(Vec<Ipv4Addr>),

    /// 5. Name Server Option.
    NameServer(Vec<Ipv4Addr>),

    /// 6. Domain Name Server Option.
    DomainServer(Vec<Ipv4Addr>),

    /// 7. Log Server Option.
    LogServer(Vec<Ipv4Addr>),

    /// 8. Cookie Server Option.
    QuotesServer(Vec<Ipv4Addr>),

    /// 9. LPR Server Option.
    LPRServer(Vec<Ipv4Addr>),

    /// 10. Impress Server Option.
    ImpressServer(Vec<Ipv4Addr>),

    /// 11. Resource Location Server Option.
    RLPServer(Vec<Ipv4Addr>),

    /// 12. Host Name Option.
    HostName(String),

    /// 13. Boot File Size Option.
    BootFileSize(u16),

    /// 14. Merit Dump File.
    MeritDumpFile(String),

    /// 15. Domain Name.
    DomainName(String),

    /// 16. Swap Server.
    SwapServer(Ipv4Addr),

    /// 17. Root Path.
    RootPath(String),

    /// 18. Extensions Path.
    ExtensionsFile(String),

    /// 19. IP Forwarding Enable/Disable Option.
    ForwardOnOff(bool),

    /// 20. Non-Local Source Routing Enable/Disable Option.
    SrcRteOnOff(bool),

    /// 21. Policy Filter Option.
    PolicyFilter(Vec<Ipv4AddrPair>),

    /// 22. Max Datagram Reassembly Size.
    MaxDGAssembly(u16),
    
    /// 23. Default IP Time-to-live.
    DefaultIPTTL(u8),

    /// 24. Path MTU Aging Timeout Option.
    MTUTimeout(u32),

    /// 25. Path MTU Plateau Table Option.
    MTUPlateau(Vec<u16>),

    /// 26. Interface MTU Option.
    MTUInterface(u16),

    /// 27. All Subnets are Local Option.
    MTUSubnet(bool),

    /// 28. Broadcast Address Option.
    BroadcastAddress(Ipv4Addr),

    /// 29. Perform Mask Discovery Option.
    MaskDiscovery(bool),

    /// 30. Mask Supplier Option.
    MaskSupplier(bool),

    /// 31. Perform Router Discovery Option.
    RouterDiscovery(bool),

    /// 32. Router Solicitation Address Option.
    RouterRequest(Ipv4Addr),

    /// 33. Static Route Option.
    StaticRoute(Vec<Ipv4AddrPair>),

    /// 34. Trailer Encapsulation Option.
    Trailers(bool),

    /// 35. ARP Cache Timeout Option.
    ARPTimeout(u32),

    /// 36. Ethernet Encapsulation Option.
    Ethernet(bool),

    /// 37. TCP Default TTL Option.
    DefaultTCPTTL(u8),

    /// 38. TCP Keepalive Interval Option.
    KeepaliveTime(u32),

    /// 39. TCP Keepalive Garbage Option.
    KeepaliveData(bool),

    /// 40. Network Information Servers Domain Option.
    NISDomain(String),

    /// 41. Network Information Servers Option.
    NISServers(Vec<Ipv4Addr>),

    /// 42. Network Time Protocol Servers Option.
    NTPServers(Vec<Ipv4Addr>),

    /// 43. Vendor Specific Information.
    VendorSpecific(Vec<u8>),

    /// 44. NetBIOS over TCP/IP Name Server Option.
    NetBIOSNameSrv(Vec<Ipv4Addr>),

    /// 45. NetBIOS over TCP/IP Datagram Distribution Server Option.
    NetBIOSDistSrv(Vec<Ipv4Addr>),

    /// 46. NetBIOS over TCP/IP Node Type Option.
    NetBIOSNodeType(u8),

    /// 47. NetBIOS over TCP/IP Scope Option.
    NetBIOSScope(String),

    /// 48. X Window System Font Server Option.
    XWindowFont(Vec<Ipv4Addr>),

    /// 49. X Window System Display Manager Option.
    XWindowManager(Vec<Ipv4Addr>),

    /// 50. Reguested IP Address.
    AddressRequest(Ipv4Addr),

    /// 51. IP Address Lease Time.
    AddressTime(u32),

    /// 52. Option Overload.
    Overload(u8),

    /// 53. DHCP Message Type.
    DHCPMsgType(DhcpMessageType),

    /// 54. Server Identifier.
    DHCPServerId(Ipv4Addr),

    /// 55. Parameter Request List.
    ParameterList(Vec<DhcpOptionCode>),

    /// 56. Message.
    Message(String),

    /// 57. Maximum DHCP Message Size.
    MaxMessageSize(u16),

    /// 58. Renewal (T1) Time Value.
    RenewalTime(u32),

    /// 59. Rebinding (T2) Time Value.
    RebindingTime(u32),

    /// 60. Vendor class identifier.
    VendorClassId(String),

    /// 61. Client-identifier.
    ClientId(DhcpClientId),

    /// 62. The Netware/IP Domain Name Option.
    NetWareIPDomain(String),

    /// 63. The Netware/IP Information Option. TBD
    NetWareIPInformation(Vec<u8>),

    /// 64. Network Information Service+ Domain Option.
    NISPlusDomain(String),

    /// 65. Network Information Service+ Servers Option.
    NISPlusServerAddr(Vec<Ipv4Addr>),

    /// 66. TFTP server name.
    TFTPServerName(String),

    /// 67. Bootfile name.
    BootfileName(String),

    /// 68. Mobile IP Home Agent Option.
    MobileIPHomeAgent(Vec<Ipv4Addr>),

    /// 69. Simple Mail Transport Protocol (SMTP) Server Option.
    SMTPServer(Vec<Ipv4Addr>),

    /// 70. Post Office Protocol (POP3) Server Option.
    POP3Server(Vec<Ipv4Addr>),

    /// 71. Network News Transport Protocol (NNTP) Server Option.
    NNTPServer(Vec<Ipv4Addr>),

    /// 72. Default World Wide Web (WWW) Server Option.
    WWWServer(Vec<Ipv4Addr>),

    /// 73. Default Finger Server Option.
    FingerServer(Vec<Ipv4Addr>),

    /// 74. Default Internet Relay Chat (IRC) Server Option.
    IRCServer(Vec<Ipv4Addr>),

    /// 75. StreeTalk Server Option.
    StreetTalkServer(Vec<Ipv4Addr>),

    /// 76. StreetTalk Directory Assistance (STDA) Server Option.
    STDAServer(Vec<Ipv4Addr>),

    /// 77. User Class option. 
    UserClass(Vec<u8>),

    /// 78. SLP Directory Agent Option.
    DirectoryAgent(SlpDirectoryAgent),

    /// 79. SLP Service Scope Option.
    ServiceScope(SlpServiceScope),

    /// 80. Rapid Commit Option.
    RapidCommit,

    /// 81. The Client FQDN Option.
    ClientFQDN(ClientFQDN),

    /// 82. Relay Ageint Information Option.
    RelayAgentInformation(RelayAgentInformation),

    /// 83. iSNS Option.			TBD
    ISNS(Vec<u8>),

    /// 85. NDS Server Option.
    NDSServers(Vec<Ipv4Addr>),

    /// 86. NDS Tree Name Option.
    NDSTreeName(String),

    /// 87. NDS Context Option.
    NDSContext(String),

    /// 88. Broadcast and Multicast Service Controller Domain Name List for DHCPv4. TBD
    BCMCSControllerDomainNameList(Vec<u8>),

    /// 89. Broadcast and Multicast Service Controller IPv4 Address Option for DHCPv4.
    BCMCSControllerIPv4Address(Vec<Ipv4Addr>),

    /// 90. Authentication option.		TBD
    Authentication(Vec<u8>),

    /// 91. Client Last Transaction Time option.
    ClientLastTransactionTime(u32),

    /// 92. Associated IP option.
    AssociatedIP(Vec<Ipv4Addr>),

    /// 93. Client System Architecture Type Option.
    ClientSystem(u16),

    /// 94. Client Network Interface Identifier Option.	TBD
    ClientNDI((u8, u8, u8)),

    /// 95. LDAP Servers. (used by Apple)               TBD
    LDAP(Vec<u8>),

    /// 97. Client Machine Identifier Option.           TBD
    UuidGuid((u8, Vec<u8>)),

    /// 98. User Authentication Protocol Option.
    UserAuth(String),

    /// 99. Civic Location Option.                      TBD
    GeoconfCivic(Vec<u8>),

    /// 101. TZ-POSIX String Option.
    PCode(String),

    /// 102. TZ-Database String Option.
    TCode(String),

    /// 108. IPv6-Only Preferred Option.
    IPv6OnlyPreferred(u32),

    /// 109. 4o6 Software Source Address Option.
    DHCP4o6S46SAddr(Ipv6Addr),

    /// 112. Netinfo Address.  (used by Apple)          TBD
    NetinfoAddress(Vec<u8>),

    /// 113. Netinfo Tag. (used by Apple)               TBD
    NetinfoTag(Vec<u8>),

    /// 114. IPv4 Captive-Portal Option.
    CaptivePortal(String),

    /// 116. The Auto-Configure Option.
    AutoConfig(u8),

    /// 117. Name Service Search Option.
    NameServiceSearch(Vec<u16>),

    /// 118. IPv4 Subnet Selection Option.
    SubnetSelection(Ipv4Addr),

    /// 119. Domain Search Option.
    DomainSearch(String),

    /// 120. SIP Server DHCP Option.
    SIPServers(Vec<u8>),				// TBD	RFC1035 encoding

    /// 121. Classless Route Option.
    ClasslessStaticRoute(Vec<u8>), 			// TBD

    /// 122. CableLabs Client Configuration Option.
    CableLabsClientConfig(Vec<u8>), 			// TBD sub option

    /// 123. GeoConf Option.
    GeoConf(Vec<u8>),					// TBD

    /// 124. Vendor-Identifying Vendor Class Option.
    VIVendorClass(Vec<u8>),				// TBD

    /// 125. Vendor-Identifying Specific Information Option.
    VIVendorSpecificInformation(Vec<u8>),		// TBD


    /// 136. PANA Authentication Agent DHCPv4 Option.
    PanaAgent(Vec<Ipv4Addr>),
    
    /// 137. LoST Server DHCPv4 Option.			TBD  refer section 4.1.4 RFC 1035 and RFC 3397, 3396
    V4Lost(Vec<u8>),

    /// 138. CAPWAP AC DHCPv4 option.
    CapwapAcV4(Vec<Ipv4Addr>),

    /// 139. MoS IPv4 Address Option for DHCPv4.	// TBD
    IPv4AddressMoS(Vec<u8>),

    /// 140. MoS Domain Name List Option for DHCPv4.	// TBD
    IPv4FQDNMoS(Vec<u8>),

    /// 141. SIP User Agent Configuration Service Domains Option.
    SipUAConfigurationServiceDomains(String),

    /// 142. ANDSF IPv4 Address Option for DHCPv4.
    IPv4AddressANDSF(Vec<Ipv4Addr>),

    /// 143. SZTP Redirect Option.			// TBD  should be Vec<String>
    V4SZTPRedirect(String),

    /// 144. GeoLoc Option.				// TBD
    GeoLoc(Vec<u8>),

    /// 145. Forerenew Nonce Protocol Capability Option // TBD  list of options
    ForcerenewNonceCapable(Vec<u8>),

    /// 146. RDNSS Selection DHCPv4 Option.		// TBD
    RDNSSSelection(Vec<u8>),

    /// 147. DOTS Reference Identifier Option.		// TBD Domain name encoding
    V4DotsRI(String),

    /// 148. DOTS Address Option.
    V4DotsAddress(Vec<Ipv4Addr>),

    /// 151. Bulk Leasequery status-code Option.
    BulkLeaseQueryStatusCode((u8, String)),

    /// 152. Bulk Leasequery base-time Option.
    BulkLeaseQueryBaseTime(u32),

    /// 153. Bulk Leasequery start-time-of-state Option.
    BulkLeaseQueryStartTimeOfState(u32),

    /// 154. Bulk Leasequery query-start-time Option.
    BulkLeaseQueryQueryStartTime(u32),

    /// 155. Bulk Leasequery query-end-time Option.
    BulkLeaseQueryQueryEndTime(u32),

    /// 156. Bulk Leasequery dhcp-state Option.
    BulkLeaseQueryDhcpState(u8),

    /// 157. Bulk Leasequery data-source Option.
    BulkLeaseQueryDataSource(u8),

    /// 158. PCP Server Option.				// TBD
    V4PCPServer(Vec<u8>),

    /// 159. Port Parameters Option.			// TBD
    V4PortParams(Vec<u8>),

    /// 161. MUD URL Option.
    MudURLV4(String),

    /// 162. Encrypted DNS Option.			// TBD
    V4DNR(Vec<u8>),

    /// 208. PXE Linux Magic Option.
    PXELinuxMagic(u32),

    /// 209. Configuration File Option.
    ConfigurationFile(String),

    /// 210. Path Prefix Option.
    PathPrefix(String),

    /// 211. Reboot Time Option.
    RebootTime(u32),

    /// 212. 6rd Option.				// TBD
    Option6RD(Vec<u8>),

    /// 213. Access Network Domain Name Option.		// TBD RFC1035 encoding
    V4AccessDomain(Vec<u8>),

    /// 220. Subnet Allocation Option.			// TBD 
    SubnetAllocation(Vec<u8>),

    /// 221. Virtual Subnet Selection Option.		// TBD
    VirtualSubnetSelection(Vec<u8>),

    /// 255 - End.
    End,

    /// Place holder for Unknown/Unassigned/Vendor Specific option.
    Unknown((DhcpOptionCode, Vec<u8>)),
}

impl fmt::Display for DhcpOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

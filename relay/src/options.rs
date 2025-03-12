//
// DHCP-RS - Relay
//   Copyright (C) 2024-2025, Toshiaki Takada
//

use std::mem::size_of;

use crate::*;
use crate::encode::*;
//use crate::message::*;

/// DHCP Option header length.
const DHCP_OPTION_HLEN: usize = 2;
const DHCP_SUBOPTION_HLEN: usize = 2;

// Utility to decode u8 value as bool for a DHCP option.
pub fn option_bool(buf: &[u8]) -> Result<(usize, bool), DhcpError> {
    let (len, v) = option_u8(&buf)?;
    match v {
        0 => Ok((len, false)),
        1 => Ok((len, true)),
        _ => Err(DhcpError::InvalidValue),
    }
}

// Utility to decode u8 value for a DHCP option.
pub fn option_u8(buf: &[u8]) -> Result<(usize, u8), DhcpError> {
    // The buf must have at least 2 bytes for code and length.
    if buf.len() < DHCP_OPTION_HLEN + size_of::<u8>() {
        Err(DhcpError::InsufficientBufferSize)
    } else {
        let len = buf[1] as usize;
        let b = &buf[DHCP_OPTION_HLEN..];

        if len != size_of::<u8>() {
            Err(DhcpError::InvalidOptionLength)
        } else {
            Ok((DHCP_OPTION_HLEN + len, decode_u8(&b)?))
        }
    }
}

// Utility to decode u16 value for a DHCP option.
pub fn option_u16(buf: &[u8]) -> Result<(usize, u16), DhcpError> {
    // The buf must have at least 2 bytes for code and length.
    if buf.len() < DHCP_OPTION_HLEN + size_of::<u16>() {
        Err(DhcpError::InsufficientBufferSize)
    } else {
        let len = buf[1] as usize;
        let b = &buf[DHCP_OPTION_HLEN..];

        if len != size_of::<u16>() {
            Err(DhcpError::InvalidOptionLength)
        } else {
            Ok((DHCP_OPTION_HLEN + len, decode_u16(&b)?))
        }
    }
}

// Utility to decode a list of u16 values for a DHCP option.
pub fn option_u16_vec(buf: &[u8], min: usize) -> Result<(usize, Vec<u16>), DhcpError> {
    // The buf must have at least 2 bytes for code and length.
    if buf.len() < DHCP_OPTION_HLEN + min {
        Err(DhcpError::InsufficientBufferSize)
    } else {
        let len = buf[1] as usize;
        let b = &buf[DHCP_OPTION_HLEN..];
        let size = size_of::<u16>();

        if b.len() < len || (len % size) != 0 {
            Err(DhcpError::InvalidOptionLength)
        } else {
            let mut vec = Vec::new();
            for offset in (0..len).step_by(size) {
                vec.push(decode_u16(&b[offset..])?);
            }
            Ok((DHCP_OPTION_HLEN + len, vec))
        }
    }
}

// Utility to decode i32 value for a DHCP option.
pub fn option_i32(buf: &[u8]) -> Result<(usize, i32), DhcpError> {
    // The buf must have at least 2 bytes for code and length.
    if buf.len() < DHCP_OPTION_HLEN + size_of::<i32>() {
        Err(DhcpError::InsufficientBufferSize)
    } else {
        let len = buf[1] as usize;
        let b = &buf[DHCP_OPTION_HLEN..];

        if len != size_of::<i32>() {
            Err(DhcpError::InvalidOptionLength)
        } else {
            Ok((DHCP_OPTION_HLEN + len, decode_i32(&b)?))
        }
    }
}

// Utility to decode u32 value for a DHCP option.
pub fn option_u32(buf: &[u8]) -> Result<(usize, u32), DhcpError> {
    // The buf must have at least 2 bytes for code and length.
    if buf.len() < DHCP_OPTION_HLEN + size_of::<u32>() {
        Err(DhcpError::InsufficientBufferSize)
    } else {
        let len = buf[1] as usize;
        let b = &buf[DHCP_OPTION_HLEN..];

        if len != size_of::<u32>() {
            Err(DhcpError::InvalidOptionLength)
        } else {
            Ok((DHCP_OPTION_HLEN + len, decode_u32(&b)?))
        }
    }
}

// Utility to decode u8 vector value for a DHCP option.
pub fn option_u8_vec(buf: &[u8], min: usize) -> Result<(usize, Vec<u8>), DhcpError> {
    // The buf must have at least 2 bytes for code and length.
    if buf.len() < DHCP_OPTION_HLEN + min {
        Err(DhcpError::InsufficientBufferSize)
    } else {
        let len = buf[1] as usize;
        let b = &buf[DHCP_OPTION_HLEN..];

        if b.len() < len {
            Err(DhcpError::InvalidOptionLength)
        } else {
            Ok((DHCP_OPTION_HLEN + len, b[..len].to_vec()))
        }
    }
}

// Utility to decode u8 and u8 vector value for a DHCP option.
pub fn option_u8_u8_vec(buf: &[u8], min: usize) -> Result<(usize, (u8, Vec<u8>)), DhcpError> {
    // The buf must have at least 3 bytes for code, length and type.
    if buf.len() < DHCP_OPTION_HLEN + min {
        Err(DhcpError::InsufficientBufferSize)
    } else {
        let len = buf[1] as usize;
        let v = buf[2];
        let b = &buf[DHCP_OPTION_HLEN..];

        if b.len() < len {
            Err(DhcpError::InvalidOptionLength)
        } else {
            Ok((DHCP_OPTION_HLEN + len, (v, b[1..len].to_vec())))
        }
    }
}

// Utility to decode u8 value and string for a DHCP option.
pub fn option_u8_string(buf: &[u8], min: usize) -> Result<(usize, (u8, String)), DhcpError> {
    // The buf must have at least 3 bytes for code, length and type.
    if buf.len() < DHCP_OPTION_HLEN + min {
        Err(DhcpError::InsufficientBufferSize)
    } else {
        let len = buf[1] as usize;
        let v = buf[2];
        let b = &buf[DHCP_OPTION_HLEN..];

        if b.len() < len {
            Err(DhcpError::InvalidOptionLength)
        } else if let Ok(s) = std::str::from_utf8(&b[1..len]) {
            Ok((DHCP_OPTION_HLEN + len, (v, s.to_string())))
        } else {
            Err(DhcpError::DecodeError)
        }
    }
}

// Utility to decode bool and u8 vector value for a DHCP option.
pub fn option_bool_ipv4_vec(buf: &[u8], min: usize) -> Result<(usize, (bool, Vec<Ipv4Addr>)), DhcpError> {
    // The buf must have at least 3 bytes for code and length + bool.
    if buf.len() < DHCP_OPTION_HLEN + min {
        Err(DhcpError::InsufficientBufferSize)
    } else if buf[1] == 0 {
        Err(DhcpError::InvalidOptionLength)
    } else {
        let len = (buf[1] - 1) as usize;
        // First byte must be bool.
        let v: bool = match buf[2] {
            0 => false,
            1 => true,
            _ => return Err(DhcpError::InvalidValue),
        };
        let b = &buf[DHCP_OPTION_HLEN + 1..];
        let size = size_of::<Ipv4Addr>();

        if b.len() < len || (len % size) != 0 {
            Err(DhcpError::InvalidOptionLength)
        } else {
            let mut vec = Vec::new();
            for offset in (0..len).step_by(size) {
                vec.push(decode_ipv4(&b[offset..])?);
            }
            Ok((DHCP_OPTION_HLEN + 1 + len, (v, vec)))
        }
    }
}

// Utility to decode string value for a DHCP option.
pub fn option_string(buf: &[u8], min: usize) -> Result<(usize, String), DhcpError> {
    // The buf must have at least 2 bytes + min for code, length and string.
    if buf.len() < DHCP_OPTION_HLEN + min {
        Err(DhcpError::InsufficientBufferSize)
    } else {
        let len = buf[1] as usize;
        let b = &buf[DHCP_OPTION_HLEN..];

        if b.len() < len {
            Err(DhcpError::InvalidOptionLength)
        } else if let Ok(s) = std::str::from_utf8(&b[..len]) {
            Ok((DHCP_OPTION_HLEN + len, s.to_string()))
        } else {
            Err(DhcpError::DecodeError)
        }
    }
}

// Utility to decode bool and string value for a DHCP option.
pub fn option_bool_string(buf: &[u8], min: usize) -> Result<(usize, (bool, String)), DhcpError> {
    // The buf must have at least 3 bytes for code and length + bool.
    if buf.len() < DHCP_OPTION_HLEN + min {
        Err(DhcpError::InsufficientBufferSize)
    } else if buf[1] == 0 {
        Err(DhcpError::InvalidOptionLength)
    } else {
        let len = (buf[1] - 1) as usize;
        // First byte must be bool.
        let v: bool = match buf[2] {
            0 => false,
            1 => true,
            _ => return Err(DhcpError::InvalidValue),
        };
        let b = &buf[DHCP_OPTION_HLEN + 1..];

        if b.len() < len {
            Err(DhcpError::InvalidOptionLength)
        } else if let Ok(s) = std::str::from_utf8(&b[..len]) {
            Ok((DHCP_OPTION_HLEN + 1 + len, (v, s.to_string())))
        } else {
            Err(DhcpError::DecodeError)
        }
    }
}

// Utility to decode an IPv4 address for a DHCP option.
pub fn option_ipv4(buf: &[u8]) -> Result<(usize, Ipv4Addr), DhcpError> {
    // The buf must have at least 2 bytes for code and length.
    if buf.len() < DHCP_OPTION_HLEN + size_of::<Ipv4Addr>() {
        Err(DhcpError::InsufficientBufferSize)
    } else {
        let len = buf[1] as usize;
        let b = &buf[DHCP_OPTION_HLEN..];

        if len != size_of::<Ipv4Addr>() {
            Err(DhcpError::InvalidOptionLength)
        } else {
            Ok((DHCP_OPTION_HLEN + len, decode_ipv4(&b)?))
        }
    }
}

// Utility to decode an IPv6 address for a DHCP option.
pub fn option_ipv6(buf: &[u8]) -> Result<(usize, Ipv6Addr), DhcpError> {
    // The buf must have at least 2 bytes for code and length.
    if buf.len() < DHCP_OPTION_HLEN + size_of::<Ipv6Addr>() {
        Err(DhcpError::InsufficientBufferSize)
    } else {
        let len = buf[1] as usize;
        let b = &buf[DHCP_OPTION_HLEN..];

        if len != size_of::<Ipv6Addr>() {
            Err(DhcpError::InvalidOptionLength)
        } else {
            Ok((DHCP_OPTION_HLEN + len, decode_ipv6(&b)?))
        }
    }
}

// Utility to decode a list of IPv4 address for a DHCP option.
pub fn option_ipv4_vec(buf: &[u8], min: usize) -> Result<(usize, Vec<Ipv4Addr>), DhcpError> {
    // The buf must have at least 2 bytes for code and length.
    if buf.len() < DHCP_OPTION_HLEN + min {
        Err(DhcpError::InsufficientBufferSize)
    } else {
        let len = buf[1] as usize;
        let b = &buf[DHCP_OPTION_HLEN..];
        let size = size_of::<Ipv4Addr>();

        if b.len() < len || (len % size) != 0 {
            Err(DhcpError::InvalidOptionLength)
        } else {
            let mut vec = Vec::new();
            for offset in (0..len).step_by(size) {
                vec.push(decode_ipv4(&b[offset..])?);
            }
            Ok((DHCP_OPTION_HLEN + len, vec))
        }
    }
}

// Utility to decode a list of IPv4 address pair for a DHCP option.
pub fn option_ipv4_pair_vec(buf: &[u8], min: usize) -> Result<(usize, Vec<Ipv4AddrPair>), DhcpError> {
    // The buf must have at least 2 bytes for code and length.
    if buf.len() < DHCP_OPTION_HLEN + min {
        Err(DhcpError::InsufficientBufferSize)
    } else {
        let len = buf[1] as usize;
        let b = &buf[DHCP_OPTION_HLEN..];
        let size = size_of::<Ipv4AddrPair>();

        if b.len() < len || (len % size) != 0 {
            Err(DhcpError::InvalidOptionLength)
        } else {
            let mut vec = Vec::new();
            for offset in (0..len).step_by(size) {
                let addr1 = decode_ipv4(&b[offset..])?;
                let addr2 = decode_ipv4(&b[offset + 4..])?;
                vec.push(Ipv4AddrPair(addr1, addr2));
            }
            Ok((DHCP_OPTION_HLEN + len, vec))
        }
    }
}

// Utility to decode a Client FQDN DHCP option.
pub fn option_client_fqdn(buf: &[u8]) -> Result<(usize, ClientFQDN), DhcpError> {
    // The buf must have at least 5 bytes for code, length, flags, rcode1 and rcode2.
    if buf.len() < DHCP_OPTION_HLEN + 3 {
        Err(DhcpError::InsufficientBufferSize)
    } else {
        let len = buf[1] as usize;
        let b = &buf[DHCP_OPTION_HLEN..];
        if b.len() < len {
            Err(DhcpError::InvalidOptionLength)
        } else {
            let flags = b[0];
            let rcode1 = b[1];
            let rcode2 = b[2];
            let mut fqdn = String::new();
            if len > 3 {
                if let Ok(s) = std::str::from_utf8(&b[3..len - 3]) {
                    fqdn = s.to_string();
                } else {
                    return Err(DhcpError::DecodeError)
                }
            }
            Ok((DHCP_OPTION_HLEN + len, ClientFQDN { flags, rcode1, rcode2, fqdn }))
        }
    }
}

// Utility to decode a Relay Agent Information DHCP option.
pub fn option_relay_agent_info(buf: &[u8]) -> Result<(usize, RelayAgentInformation), DhcpError> {
    // The buf must have at least 2 bytes.
    if buf.len() < DHCP_OPTION_HLEN + DHCP_SUBOPTION_HLEN {
        Err(DhcpError::InsufficientBufferSize)
    } else {
        let len = buf[1] as usize;
        let b = &buf[DHCP_OPTION_HLEN..];
        if b.len() < len {
            Err(DhcpError::InvalidOptionLength)
        } else {
            let mut circuit_id = None;
            let mut remote_id = None;

            let mut sb = &b[..len];
            while sb.len() >= DHCP_SUBOPTION_HLEN {
                let t = sb[0];
                let l = sb[1] as usize;
                if l + DHCP_SUBOPTION_HLEN > sb.len() {
                    return Err(DhcpError::DecodeError)
                }
                match t {
                    x if x == DhcpAgentSubOptionCode::CircuitID as u8 => {
                        circuit_id = Some(sb[DHCP_SUBOPTION_HLEN..DHCP_SUBOPTION_HLEN + l].to_vec());
                    }
                    x if x == DhcpAgentSubOptionCode::RemoteID as u8 => {
                        remote_id = Some(sb[DHCP_SUBOPTION_HLEN..DHCP_SUBOPTION_HLEN + l].to_vec());
                    }
                    _ => return Err(DhcpError::DecodeError),
                }
                sb = &sb[DHCP_SUBOPTION_HLEN + l..];
            }

            Ok((DHCP_OPTION_HLEN + len, RelayAgentInformation { circuit_id, remote_id }))
        }
    }
}

// Utility function to encode DHCP option.
pub fn encode_option<F: Fn(&mut [u8]) -> Result<usize, DhcpError>>(buf: &mut [u8], t: u8, f: F) -> Result<usize, DhcpError> {
    let len = f(&mut buf[2..])?;
    encode_u8(&mut buf[0..], t as u8)?;
    encode_u8(&mut buf[1..], len as u8)?;

    Ok(len + 2)
}


///
/// Unit tests.
///
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_option_bool() {
        let opt: [u8; 3] = [19, 1, 0x00];
        let res =  option_bool(&opt);
        match res {
            Err(e) => assert!(false, "Error: {:?}", e),
            Ok((len, v)) => {
                assert_eq!(len, 3);
                assert_eq!(v, false);
            }
        }

        let opt: [u8; 3] = [19, 1, 0x01];
        let res =  option_bool(&opt);
        match res {
            Err(e) => assert!(false, "Error: {:?}", e),
            Ok((len, v)) => {
                assert_eq!(len, 3);
                assert_eq!(v, true);
            }
        }

        let opt: [u8; 3] = [19, 1, 0x02];
        let res =  option_bool(&opt);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InvalidValue),
            Ok((len, v)) => assert!(false, "Error: {:?} {:?}", len, v),
        }
    }

    #[test]
    pub fn test_option_u8() {
        let opt: [u8; 3] = [23, 1, 0x10];
        let res =  option_u8(&opt);
        match res {
            Err(e) => assert!(false, "Error: {:?}", e),
            Ok((len, v)) => {
                assert_eq!(len, 3);
                assert_eq!(v, 0x10);
            }
        }

        let opt: [u8; 3] = [23, 2, 0x10];
        let res =  option_u8(&opt);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InvalidOptionLength),
            Ok((len, v)) => assert!(false, "Error: {:?} {:?}", len, v),
        }
    }

    #[test]
    pub fn test_option_u16() {
        let opt: [u8; 4] = [13, 2, 0x12, 0x34];
        let res =  option_u16(&opt);
        match res {
            Err(e) => assert!(false, "Error: {:?}", e),
            Ok((len, v)) => {
                assert_eq!(len, 4);
                assert_eq!(v, 0x1234);
            }
        }

        let opt: [u8; 4] = [13, 3, 0x12, 0x34];
        let res =  option_u16(&opt);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InvalidOptionLength),
            Ok((len, v)) => assert!(false, "Error: {:?} {:?}", len, v),
        }

        let opt: [u8; 3] = [13, 2, 0x10];
        let res =  option_u16(&opt);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InsufficientBufferSize),
            Ok((len, v)) => assert!(false, "Error: {:?} {:?}", len, v),
        }
    }

    #[test]
    pub fn test_option_u16_vec() {
        let opt: [u8; 6] = [25, 4, 0x12, 0x34, 0x56, 0x78];
        let res =  option_u16_vec(&opt, 2);
        match res {
            Err(e) => assert!(false, "Error: {:?}", e),
            Ok((len, vec)) => {
                assert_eq!(len, 6);
                assert_eq!(vec, [0x1234, 0x5678]);
            }
        }

        let opt: [u8; 6] = [25, 5, 0x12, 0x34, 0x56, 0x78];
        let res =  option_u16_vec(&opt, 2);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InvalidOptionLength),
            Ok((len, vec)) => assert!(false, "Error: {:?} {:?}", len, vec),
        }

        let opt: [u8; 6] = [25, 6, 0x12, 0x34, 0x56, 0x78];
        let res =  option_u16_vec(&opt, 6);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InsufficientBufferSize),
            Ok((len, vec)) => assert!(false, "Error: {:?} {:?}", len, vec),
        }
    }


    #[test]
    pub fn test_option_i32() {
        let opt: [u8; 6] = [2, 4, 0x12, 0x34, 0x56, 0x78];
        let res =  option_i32(&opt);
        match res {
            Err(e) => assert!(false, "Error: {:?}", e),
            Ok((len, v)) => {
                assert_eq!(len, 6);
                assert_eq!(v, 0x12345678);
            }
        }

        let opt: [u8; 6] = [2, 4, 0xFF, 0xFF, 0xFF, 0xFF];
        let res =  option_i32(&opt);
        match res {
            Err(e) => assert!(false, "Error: {:?}", e),
            Ok((len, v)) => {
                assert_eq!(len, 6);
                assert_eq!(v, -1);
            }
        }

        let opt: [u8; 6] = [2, 3, 0x12, 0x34, 0x56, 0x78];
        let res =  option_i32(&opt);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InvalidOptionLength),
            Ok((len, v)) => assert!(false, "Error: {:?} {:?}", len, v),
        }

        let opt: [u8; 5] = [2, 3, 0x12, 0x34, 0x56];
        let res =  option_i32(&opt);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InsufficientBufferSize),
            Ok((len, v)) => assert!(false, "Error: {:?} {:?}", len, v),
        }
    }

    #[test]
    pub fn test_option_u32() {
        let opt: [u8; 6] = [24, 4, 0x12, 0x34, 0x56, 0x78];
        let res =  option_u32(&opt);
        match res {
            Err(e) => assert!(false, "Error: {:?}", e),
            Ok((len, v)) => {
                assert_eq!(len, 6);
                assert_eq!(v, 0x12345678);
            }
        }

        let opt: [u8; 6] = [24, 4, 0xFF, 0xFF, 0xFF, 0xFF];
        let res =  option_u32(&opt);
        match res {
            Err(e) => assert!(false, "Error: {:?}", e),
            Ok((len, v)) => {
                assert_eq!(len, 6);
                assert_eq!(v, 0xFFFFFFFF);
            }
        }

        let opt: [u8; 6] = [24, 3, 0x12, 0x34, 0x56, 0x78];
        let res =  option_u32(&opt);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InvalidOptionLength),
            Ok((len, v)) => assert!(false, "Error: {:?} {:?}", len, v),
        }

        let opt: [u8; 5] = [24, 3, 0x12, 0x34, 0x56];
        let res =  option_u32(&opt);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InsufficientBufferSize),
            Ok((len, v)) => assert!(false, "Error: {:?} {:?}", len, v),
        }
    }

    #[test]
    pub fn test_option_u8_vec() {
        let opt: [u8; 6] = [55, 4, 0x12, 0x34, 0x56, 0x78];
        let res =  option_u8_vec(&opt, 0);
        match res {
            Err(e) => assert!(false, "Error: {:?}", e),
            Ok((len, vec)) => {
                assert_eq!(len, 6);
                assert_eq!(vec, [0x12, 0x34, 0x56, 0x78]);
            }
        }

        let opt: [u8; 6] = [55, 5, 0x12, 0x34, 0x56, 0x78];
        let res =  option_u8_vec(&opt, 0);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InvalidOptionLength),
            Ok((len, vec)) => assert!(false, "Error: {:?} {:?}", len, vec),
        }

        let opt: [u8; 6] = [55, 6, 0x12, 0x34, 0x56, 0x78];
        let res =  option_u8_vec(&opt, 8);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InsufficientBufferSize),
            Ok((len, vec)) => assert!(false, "Error: {:?} {:?}", len, vec),
        }
    }

    #[test]	// TBD
    pub fn test_option_u8_u8_vec() {
        let opt: [u8; 7] = [97, 5, 0x10, 0x12, 0x34, 0x56, 0x78];
        let res =  option_u8_u8_vec(&opt, 1);
        match res {
            Err(e) => assert!(false, "Error: {:?}", e),
            Ok((len, (v, vec))) => {
                assert_eq!(len, 7);
                assert_eq!(v, 0x10);
                assert_eq!(vec, [0x12, 0x34, 0x56, 0x78]);
            }
        }

        let opt: [u8; 7] = [97, 6, 0x10, 0x12, 0x34, 0x56, 0x78];
        let res =  option_u8_u8_vec(&opt, 1);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InvalidOptionLength),
            Ok((len, (v, vec))) => assert!(false, "Error: {:?} {:?} {:?}", len, v, vec),
        }

        let opt: [u8; 7] = [97, 6, 0x10, 0x12, 0x34, 0x56, 0x78];
        let res =  option_u8_u8_vec(&opt, 8);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InsufficientBufferSize),
            Ok((len, (v, vec))) => assert!(false, "Error: {:?} {:?} {:?}", len, v, vec),
        }
    }

    /* TBD
    #[test]
    pub fn test_option_u8_string() {
    }
    */

    #[test]
    pub fn test_option_bool_ipv4_vec() {
        let opt: [u8; 7] = [78, 5, 0x01, 192, 168, 1, 10];
        let res =  option_bool_ipv4_vec(&opt, 5);
        match res {
            Err(e) => assert!(false, "Error: {:?}", e),
            Ok((len, (v, vec))) => {
                assert_eq!(len, 7);
                assert_eq!(v, true);
                assert_eq!(vec, ["192.168.1.10".parse::<Ipv4Addr>().unwrap()]);
            }
        }

        let opt: [u8; 7] = [78, 5, 0x02, 192, 168, 1, 10];
        let res =  option_bool_ipv4_vec(&opt, 5);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InvalidValue),
            Ok((len, (v, vec))) => assert!(false, "Error: {:?} {:?} {:?}", len, v, vec),
        }

        let opt: [u8; 7] = [78, 4, 0x01, 192, 168, 1, 10];
        let res =  option_bool_ipv4_vec(&opt, 5);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InvalidOptionLength),
            Ok((len, (v, vec))) => assert!(false, "Error: {:?} {:?} {:?}", len, v, vec),
        }

        let opt: [u8; 6] = [78, 5, 0x01, 192, 168, 1];
        let res =  option_bool_ipv4_vec(&opt, 5);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InsufficientBufferSize),
            Ok((len, (v, vec))) => assert!(false, "Error: {:?} {:?} {:?}", len, v, vec),
        }
    }

    #[test]
    pub fn test_option_string() {
        let opt: [u8; 6] = [12, 4, b'D', b'H', b'C', b'P'];
        let res =  option_string(&opt, 1);
        match res {
            Err(e) => assert!(false, "Error: {:?}", e),
            Ok((len, s)) => {
                assert_eq!(len, 6);
                assert_eq!(s, "DHCP");
            }
        }

        let opt: [u8; 6] = [12, 5, b'D', b'H', b'C', b'P'];
        let res =  option_string(&opt, 1);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InvalidOptionLength),
            Ok((len, s)) => assert!(false, "Error: {:?} {:?}", len, s),
        }

        let opt: [u8; 6] = [12, 6, b'D', b'H', b'C', b'P'];
        let res =  option_string(&opt, 5);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InsufficientBufferSize),
            Ok((len, s)) => assert!(false, "Error: {:?} {:?}", len, s),
        }
    }

    #[test]
    pub fn test_option_bool_string() {
        let opt: [u8; 7] = [79, 5, 0x01, b'D', b'H', b'C', b'P'];
        let res =  option_bool_string(&opt, 2);
        match res {
            Err(e) => assert!(false, "Error: {:?}", e),
            Ok((len, (v, s))) => {
                assert_eq!(len, 7);
                assert_eq!(v, true);
                assert_eq!(s, "DHCP");
            }
        }

        let opt: [u8; 7] = [79, 5, 0x02, b'D', b'H', b'C', b'P'];
        let res =  option_bool_string(&opt, 2);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InvalidValue),
            Ok((len, (v, s))) => assert!(false, "Error: {:?} {:?} {:?}", len, v, s),
        }

        let opt: [u8; 7] = [79, 6, 0x00, b'D', b'H', b'C', b'P'];
        let res =  option_bool_string(&opt, 2);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InvalidOptionLength),
            Ok((len, (v, s))) => assert!(false, "Error: {:?} {:?} {:?}", len, v, s),
        }

        let opt: [u8; 7] = [79, 5, 0x00, b'D', b'H', b'C', b'P'];
        let res =  option_bool_string(&opt, 6);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InsufficientBufferSize),
            Ok((len, (v, s))) => assert!(false, "Error: {:?} {:?} {:?}", len, v, s),
        }
    }

    #[test]
    pub fn test_option_ipv4() {
        let opt: [u8; 6] = [1, 4, 192, 168, 1, 10];
        let res =  option_ipv4(&opt);
        match res {
            Err(e) => assert!(false, "Error: {:?}", e),
            Ok((len, addr)) => {
                assert_eq!(len, 6);
                assert_eq!(addr, "192.168.1.10".parse::<Ipv4Addr>().unwrap());
            }
        }

        let opt: [u8; 6] = [1, 3, 192, 168, 1, 10];
        let res =  option_ipv4(&opt);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InvalidOptionLength),
            Ok((len, addr)) => assert!(false, "Error: {:?} {:?}", len, addr),
        }

        let opt: [u8; 5] = [1, 4, 192, 168, 1];
        let res =  option_ipv4(&opt);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InsufficientBufferSize),
            Ok((len, addr)) => assert!(false, "Error: {:?} {:?}", len, addr),
        }
    }

    #[test]
    pub fn test_option_ipv6() {
        let opt: [u8; 18] = [109, 16,
                            0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let res =  option_ipv6(&opt);
        match res {
            Err(e) => assert!(false, "Error: {:?}", e),
            Ok((len, addr)) => {
                assert_eq!(len, 18);
                assert_eq!(addr, "2001::1".parse::<Ipv6Addr>().unwrap());
            }
        }

        let opt: [u8; 18] = [109, 15,
                            0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let res =  option_ipv6(&opt);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InvalidOptionLength),
            Ok((len, addr)) => assert!(false, "Error: {:?} {:?}", len, addr),
        }

        let opt: [u8; 17] = [109, 16,
                            0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let res =  option_ipv6(&opt);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InsufficientBufferSize),
            Ok((len, addr)) => assert!(false, "Error: {:?} {:?}", len, addr),
        }
    }

    #[test]
    pub fn test_option_ipv4_vec() {
        let opt: [u8; 10] = [3, 8, 192, 168, 1, 1, 192, 168, 1, 2];
        let res =  option_ipv4_vec(&opt, 4);
        match res {
            Err(e) => assert!(false, "Error: {:?}", e),
            Ok((len, vec)) => {
                assert_eq!(len, 10);
                assert_eq!(vec, [
                    "192.168.1.1".parse::<Ipv4Addr>().unwrap(),
                    "192.168.1.2".parse::<Ipv4Addr>().unwrap()
                ]);
            }
        }

        let opt: [u8; 10] = [3, 9, 192, 168, 1, 1, 192, 168, 1, 2];
        let res =  option_ipv4_vec(&opt, 4);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InvalidOptionLength),
            Ok((len, vec)) => assert!(false, "Error: {:?} {:?}", len, vec),
        }

        let opt: [u8; 10] = [3, 8, 192, 168, 1, 1, 192, 168, 1, 2];
        let res =  option_ipv4_vec(&opt, 12);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InsufficientBufferSize),
            Ok((len, vec)) => assert!(false, "Error: {:?} {:?}", len, vec),
        }
    }

    #[test]
    pub fn test_option_ipv4_pair_vec() {
        let opt: [u8; 10] = [21, 8, 192, 168, 1, 0, 255, 255, 255, 0];
        let res =  option_ipv4_pair_vec(&opt, 8);
        match res {
            Err(e) => assert!(false, "Error: {:?}", e),
            Ok((len, vec)) => {
                assert_eq!(len, 10);
                assert_eq!(vec, vec![Ipv4AddrPair(
                    "192.168.1.0".parse::<Ipv4Addr>().unwrap(),
                    "255.255.255.0".parse::<Ipv4Addr>().unwrap()
                )]);
            }
        }

        let opt: [u8; 10] = [21, 10, 192, 168, 1, 0, 255, 255, 255, 0];
        let res =  option_ipv4_pair_vec(&opt, 8);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InvalidOptionLength),
            Ok((len, vec)) => assert!(false, "Error: {:?} {:?}", len, vec),
        }

        let opt: [u8; 10] = [21, 8, 192, 168, 1, 0, 255, 255, 255, 0];
        let res =  option_ipv4_pair_vec(&opt, 12);
        match res {
            Err(e) => assert_eq!(e, DhcpError::InsufficientBufferSize),
            Ok((len, vec)) => assert!(false, "Error: {:?} {:?}", len, vec),
        }
    }

    // #[test] TBD
    //
    //pub fn test_client_fqdn() {
    //}

    // #[test] TBD
    //
    //pub fn test_relay_agent_info() {
    //}

    #[test]
    pub fn test_option_subnet_mask() {
        let buf: [u8; 6] = [1, 4, 255, 255, 255, 0];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "SubnetMask(255.255.255.0)");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }
    }

    #[test]
    pub fn test_option_time_offset() {
        let buf: [u8; 6] = [2, 4, 0, 0, 0, 0x64];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "TimeOffset(100)");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }

        let buf: [u8; 6] = [2, 4, 0xff, 0xff, 0xff, 0xff];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "TimeOffset(-1)");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }
    }

    #[test]
    pub fn test_option_router() {
        let buf: [u8; 6] = [3, 4, 192, 168, 1, 1];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "Router([192.168.1.1])");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }

        let buf: [u8; 10] = [3, 8, 192, 168, 1, 1, 192, 168, 1, 2];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "Router([192.168.1.1, 192.168.1.2])");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }
    }

    #[test]
    pub fn test_option_time_server() {
        let buf: [u8; 6] = [4, 4, 192, 168, 1, 3];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "TimeServer([192.168.1.3])");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }

        let buf: [u8; 10] = [4, 8, 192, 168, 1, 3, 192, 168, 1, 4];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "TimeServer([192.168.1.3, 192.168.1.4])");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }
    }

    #[test]
    pub fn test_option_name_server() {
        let buf: [u8; 6] = [5, 4, 192, 168, 1, 5];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "NameServer([192.168.1.5])");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }

        let buf: [u8; 10] = [5, 8, 192, 168, 1, 5, 192, 168, 1, 6];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "NameServer([192.168.1.5, 192.168.1.6])");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }
    }

    #[test]
    pub fn test_option_domain_name_server() {
        let buf: [u8; 6] = [6, 4, 192, 168, 1, 7];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "DomainServer([192.168.1.7])");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }

        let buf: [u8; 10] = [6, 8, 192, 168, 1, 7, 192, 168, 1, 8];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "DomainServer([192.168.1.7, 192.168.1.8])");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }
    }

    #[test]
    pub fn test_option_log_server() {
        let buf: [u8; 6] = [7, 4, 192, 168, 1, 9];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "LogServer([192.168.1.9])");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }

        let buf: [u8; 10] = [7, 8, 192, 168, 1, 9, 192, 168, 1, 10];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "LogServer([192.168.1.9, 192.168.1.10])");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }
    }

    #[test]
    pub fn test_option_cookie_server() {
        let buf: [u8; 6] = [8, 4, 192, 168, 1, 11];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "QuotesServer([192.168.1.11])");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }

        let buf: [u8; 10] = [8, 8, 192, 168, 1, 11, 192, 168, 1, 12];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "QuotesServer([192.168.1.11, 192.168.1.12])");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }
    }

    #[test]
    pub fn test_option_lpr_server() {
        let buf: [u8; 6] = [9, 4, 192, 168, 1, 13];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "LPRServer([192.168.1.13])");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }

        let buf: [u8; 10] = [9, 8, 192, 168, 1, 13, 192, 168, 1, 14];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "LPRServer([192.168.1.13, 192.168.1.14])");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }
    }

    #[test]
    pub fn test_option_impress_server() {
        let buf: [u8; 6] = [10, 4, 192, 168, 1, 15];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "ImpressServer([192.168.1.15])");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }

        let buf: [u8; 10] = [10, 8, 192, 168, 1, 15, 192, 168, 1, 16];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "ImpressServer([192.168.1.15, 192.168.1.16])");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }
    }

    #[test]
    pub fn test_option_rlp_server() {
        let buf: [u8; 6] = [11, 4, 192, 168, 1, 17];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "RLPServer([192.168.1.17])");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }

        let buf: [u8; 10] = [11, 8, 192, 168, 1, 17, 192, 168, 1, 18];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "RLPServer([192.168.1.17, 192.168.1.18])");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }
    }

    #[test]
    pub fn test_option_host_name() {
        // Hostname: 'example.org'
        let buf: [u8; 13] = [12, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'o', b'r', b'g'];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "HostName(\"example.org\")");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }
    }

    #[test]
    pub fn test_option_boot_file_size() {
        let buf: [u8; 4] = [13, 2, 3, 232];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "BootFileSize(1000)");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }
    }

    #[test]
    pub fn test_option_merit_dump_file() {
        let buf: [u8; 10] = [14, 8, b'f', b'i', b'l', b'e', b'n', b'a', b'm', b'e'];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "MeritDumpFile(\"filename\")");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }
    }

    #[test]
    pub fn test_option_domain_name() {
        // Domain Name: 'example.org'
        let buf: [u8; 13] = [15, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'o', b'r', b'g'];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "DomainName(\"example.org\")");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }
    }

    #[test]
    pub fn test_option_swap_server() {
        let buf: [u8; 6] = [16, 4, 192, 168, 1, 19];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "SwapServer(192.168.1.19)");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }
    }

    #[test]
    pub fn test_option_root_path() {
        let buf: [u8; 12] = [17, 10, b'/', b'd', b'e', b'v', b'/', b'n', b'v', b'm', b'e', b'0'];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "RootPath(\"/dev/nvme0\")");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }
    }

    #[test]
    pub fn test_option_extensions_path() {
        let buf: [u8; 10] = [18, 8, b'e', b'x', b't', b'_', b'p', b'a', b't', b'h'];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "ExtensionsFile(\"ext_path\")");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }
    }

    #[test]
    pub fn test_option_forward_on_off() {
        let buf: [u8; 3] = [19, 1, 0];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "ForwardOnOff(false)");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }
    }

    #[test]
    pub fn test_option_source_route_on_off() {
        let buf: [u8; 3] = [20, 1, 1];
        match DhcpMessage::options_from(&buf) {
            Ok(vec) => {
                assert_eq!(vec.len(), 1);
                assert_eq!(vec.first().unwrap().to_string(), "SrcRteOnOff(true)");
            }
            Err(err) => assert!(false, "Error: {:?}", err),
        }
    }
}

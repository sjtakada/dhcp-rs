//
// DHCP.RS 
//   Copyright (C) 2024-2025, Toshiaki Takada
//
// Encode:
//  Low level utility functions to set/get arbitrary value into/from buffer.
//  with unsafe operation.  All integer values are host byte order.
//

use std::mem::size_of;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use crate::DhcpError;

/// Copy arbitrary number of bytes from a slice to other.
pub fn encode_data(buf: &mut [u8], data: &[u8]) -> Result<usize, DhcpError> {
    if buf.len() < data.len() {
        Err(DhcpError::InsufficientBufferSize(format!("for data > {:?}", buf.len())))
    } else {
        let dst = &mut buf[..data.len()];

        dst.copy_from_slice(data);
        Ok(data.len())
    }
}

/// Encode u8 value into buffer.
pub fn encode_u8(buf: &mut [u8], v: u8) -> Result<usize, DhcpError> {
    if buf.len() < size_of::<u8>(){
        Err(DhcpError::InsufficientBufferSize(format!("for u8 > {:?}", buf.len())))
    } else {
        buf[0] = v;
        Ok(size_of::<u8>())
    }
}

/// Encode u16 value into buffer.
pub fn encode_u16(buf: &mut [u8], v: u16) -> Result<usize, DhcpError> {
    if buf.len() < size_of::<u16>() {
        Err(DhcpError::InsufficientBufferSize(format!("for u16 > {:?}", buf.len())))
    } else {
        buf[0] = ((v >> 8) & 0xFF) as u8;
        buf[1] = (v & 0xFF) as u8;
        Ok(size_of::<u16>())
    }
}

/// Encode u32 value into buffer.
pub fn encode_u32(buf: &mut [u8], v: u32) -> Result<usize, DhcpError> {
    if buf.len() < size_of::<u32>() {
        Err(DhcpError::InsufficientBufferSize(format!("for u32 > {:?}", buf.len())))
    } else {
        buf[0] = ((v >> 24) & 0xFF) as u8;
        buf[1] = ((v >> 16) & 0xFF) as u8;
        buf[2] = ((v >> 8) & 0xFF) as u8;
        buf[3] = (v & 0xFF) as u8;
        Ok(size_of::<u32>())
    }
}

/// Encode string into buffer.
pub fn encode_string(buf: &mut [u8], v: &str) -> Result<usize, DhcpError> {
    encode_data(buf, v.as_bytes())
}

/// Encode IPv4 address into buffer.
pub fn encode_ipv4(buf: &mut [u8], v: Ipv4Addr) -> Result<usize, DhcpError> {
    if buf.len() < size_of::<Ipv4Addr>() {
        Err(DhcpError::InsufficientBufferSize(format!("for IPv4ADdr > {:?}", buf.len())))
    } else {
        let octets = v.octets();

        buf[0] = octets[0];
        buf[1] = octets[1];
        buf[2] = octets[2];
        buf[3] = octets[3];
        Ok(size_of::<Ipv4Addr>())
    }
}

/// Return u8 value in host byte order.
pub fn decode_u8(data: &[u8]) -> Result<u8, DhcpError> {
    if data.len() < size_of::<u8>() {
        Err(DhcpError::InsufficientBufferSize(format!("data.len() == {:?} < size_of::<u8>() {:?}", data.len(), size_of::<u8>())))
    } else {
        Ok(data[0])
    }
}

/// Return u16 value in host byte order.
pub fn decode_u16(data: &[u8]) -> Result<u16, DhcpError> {
    if data.len() < size_of::<u16>() {
        Err(DhcpError::InsufficientBufferSize(format!("data.len() == {:?} < size_of::<u16>() {:?}", data.len(), size_of::<u16>())))
    } else {
        Ok((data[0] as u16) << 8 | data[1] as u16)
    }
}

/// Return u32 value in host byte order.
pub fn decode_u32(data: &[u8]) -> Result<u32, DhcpError> {
    if data.len() < size_of::<u32>() {
        Err(DhcpError::InsufficientBufferSize(format!("data.len() == {:?} < size_of::<u32>() {:?}", data.len(), size_of::<u32>())))
    } else {
        Ok((data[0] as u32) << 24 | (data[1] as u32) << 16 | (data[2] as u32) << 8 | data[3] as u32)
    }
}

/// Return i32 value in host byte order.
pub fn decode_i32(data: &[u8]) -> Result<i32, DhcpError> {
    if data.len() < size_of::<i32>() {
        Err(DhcpError::InsufficientBufferSize(format!("data.len() == {:?} < size_of::<i32>() {:?}", data.len(), size_of::<i32>())))
    } else {
        Ok(decode_u32(data)? as i32)
    }
}

/// Return Ipv4Addr.
pub fn decode_ipv4(data: &[u8]) -> Result<Ipv4Addr, DhcpError> {
    if data.len() < size_of::<Ipv4Addr>() {
        Err(DhcpError::InsufficientBufferSize(format!("data.len() == {:?} < size_of::<uIpv4Addr>() {:?}", data.len(), size_of::<Ipv4Addr>())))
    } else {
        Ok(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
    }
}

/// Return Ipv6Addr.
pub fn decode_ipv6(data: &[u8]) -> Result<Ipv6Addr, DhcpError> {
    if data.len() < size_of::<Ipv6Addr>() {
        Err(DhcpError::InsufficientBufferSize(format!("data.len() == {:?} < size_of::<Ipv6Addr>() {:?}", data.len(), size_of::<Ipv6Addr>())))
    } else {
        Ok(Ipv6Addr::from([data[0], data[1], data[2], data[3],
                           data[4], data[5], data[6], data[7],
                           data[8], data[9], data[10], data[11],
                           data[12], data[13], data[14], data[15]
        ]))
    }
}

/// Copy data from buffer.
pub fn decode_data(buf: &mut [u8], data: &[u8]) -> Result<(), DhcpError> {
    if buf.len() < data.len() {
        Err(DhcpError::InsufficientBufferSize(format!("buf.len() == {:?} < data.len() {:?}", buf.len(), data.len())))
    } else {
        let dst = &mut buf[..data.len()];
        dst.copy_from_slice(data);
        Ok(())
    }
}

use pcapng;

use pnet::packet::ethernet::{EtherType, EthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::FromPacket;

use std::error;
use std::fmt;
use std::fs::File;

type L2Payload = (EtherType, Vec<u8>);
type L3Payload = (IpNextHeaderProtocol, Vec<u8>);
type L4Payload = (u16, Vec<u8>);

#[derive(Debug)]
struct Error {
    layer: u8,
}

impl Error {
    pub fn new(layer: u8) -> Error {
        Error { layer }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "an error occured when parsing packets at layer {}",
            self.layer
        )
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "failed parsing packets"
    }
}

fn get_l2_payload(link_type: u16, packet: &[u8]) -> Result<L2Payload, Error> {
    if link_type == 1 {
        match EthernetPacket::new(&packet) {
            Some(ether) => Ok((ether.get_ethertype(), ether.from_packet().payload)),
            None => Err(Error::new(2)),
        }
    } else {
        Err(Error::new(2))
    }
}

fn get_l3_payload(ethertype: EtherType, packet: &[u8]) -> Result<L3Payload, Error> {
    let ipv4_ethertype: u16 = 0x0800;
    let ipv6_ethertype: u16 = 0x86dd;

    // FIXME: use enum?
    match ethertype {
        EtherType(ethertype) if ethertype == ipv4_ethertype => match Ipv4Packet::new(&packet) {
            Some(p4) => Ok((p4.get_next_level_protocol(), p4.from_packet().payload)),
            None => Err(Error::new(3)),
        },
        EtherType(ethertype) if ethertype == ipv6_ethertype => match Ipv6Packet::new(&packet) {
            Some(p6) => Ok((p6.get_next_header(), p6.from_packet().payload)),
            None => Err(Error::new(3)),
        },
        _ => Err(Error::new(3)),
    }
}

fn get_l4_payload(ip_next: IpNextHeaderProtocol, packet: &[u8]) -> Result<L4Payload, Error> {
    if ip_next == IpNextHeaderProtocols::Udp {
        match UdpPacket::new(&packet) {
            Some(udp) => Ok((udp.get_destination(), udp.from_packet().payload)),
            None => Err(Error::new(4)),
        }
    } else {
        Err(Error::new(4))
    }
}

// ethernet packet only now
// TODO: correspond other protocols
// FIXME: too many copy? should profile
fn get_netflow(collector_port: u16, link_type: u16, packet: &[u8]) -> Result<Vec<u8>, Error> {
    get_l2_payload(link_type, packet)
        .and_then(|(ethertype, packet)| get_l3_payload(ethertype, &packet))
        .and_then(|(ip_next, packet)| get_l4_payload(ip_next, &packet))
        .and_then(|(port, payload)| {
            if port == collector_port {
                Ok(payload)
            } else {
                Err(Error::new(5))
            }
        })
}

/// Extract data template of Netflow version 9 from pcap file
pub fn dump_netflow(filename: &str, collector_port: u16) -> Vec<Vec<u8>> {
    let mut fd = File::open(filename).unwrap();
    let mut reader = pcapng::SimpleReader::new(&mut fd);

    reader
        .packets()
        .map(|(iface, packet)| get_netflow(collector_port, iface.link_type, &packet.data[..]))
        .filter(|res| res.is_ok())
        .map(|res| res.unwrap())
        .collect()
}

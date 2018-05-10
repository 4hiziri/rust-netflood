use pcapng;
// use pcapng::{IterPacket, InterfaceDescriptionBlock, EnhancedPacketBlock};
use std::fs::File;
use pnet::packet::ethernet::{EthernetPacket, EtherType, Ethernet};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocols, IpNextHeaderProtocol};
use pnet::packet::FromPacket;
use pnet::packet::udp::UdpPacket;

type L2Payload = (EtherType, Vec<u8>);
type L3Payload = (IpNextHeaderProtocol, Vec<u8>);
type L4Payload = (u16, Vec<u8>);

fn get_l2_payload(link_type: u16, packet: &[u8]) -> Option<L2Payload> {
    if link_type == 1 {
        let ether = EthernetPacket::new(&packet).unwrap();
        Some((ether.get_ethertype(), ether.from_packet().payload))
    } else {
        None
    }
}

fn get_l3_payload(ethertype: EtherType, packet: &[u8]) -> Option<L3Payload> {
    let ipv4_ethertype: u16 = 0x0800;
    let ipv6_ethertype: u16 = 0x86dd;
    let EtherType(ethertype) = ethertype;

    if ethertype == ipv4_ethertype {
        let p4: Ipv4Packet = Ipv4Packet::new(&packet).unwrap();
        Some((p4.get_next_level_protocol(), p4.from_packet().payload))
    } else if ethertype == ipv6_ethertype {
        let p6: Ipv6Packet = Ipv6Packet::new(&packet).unwrap();
        Some((p6.get_next_header(), p6.from_packet().payload))
    } else {
        None
    }
}

fn get_l4_payload(ip_next: IpNextHeaderProtocol, packet: &[u8]) -> Option<L4Payload> {
    if ip_next == IpNextHeaderProtocols::Udp {
        let udp = UdpPacket::new(&packet).unwrap();
        Some((udp.get_destination(), udp.from_packet().payload))
    } else {
        None
    }
}

// ethernet packet only now
// TODO: correspond other protocols
// FIXME: too many copy? should profile
fn get_netflow(collector_port: u16, link_type: u16, packet: &[u8]) -> Option<Vec<u8>> {
    match get_l2_payload(link_type, packet)
        .map(|(ethertype, packet)| get_l3_payload(ethertype, &packet))
        .map(|(ip_next, packet)| get_l4_payload(ip_next, &packet)) {
        Some((port, payload)) => {
            if port == collector_port {
                Some(payload)
            } else {
                None
            }
        }
        None => None,
    }
}

/// Extract data template of Netflow version 9 from pcap file
pub fn dump_data_template(filename: &str, collector_port: u16) {
    let mut fd = File::open(filename).unwrap();
    let mut reader = pcapng::SimpleReader::new(&mut fd);

    let ipv4_ethertype: u16 = 0x0800;
    let ipv6_ethertype: u16 = 0x86dd;

    {
        let mut fd = File::open(filename).unwrap();
        let mut reader = pcapng::SimpleReader::new(&mut fd);

        let test: Vec<Option<Vec<u8>>> = reader
            .packets()
            .map(|(iface, packet)| {
                get_netflow(collector_port, iface.link_type, &packet.data[..])
            })
            .filter(|opt| opt.is_some())
            .collect();

        println!("test_dump {:?}", test);
    }

    for (iface, ref packet) in reader.packets() {
        // Ethernet only
        if iface.link_type != 1 {
            continue;
        }

        let ether = EthernetPacket::new(&packet.data[..]).unwrap();
        let ether_payload = ether.from_packet().payload;

        let next = match ether.get_ethertype() {
            EtherType(ether_type) if ether_type == ipv4_ethertype => {
                let p4: Ipv4Packet = Ipv4Packet::new(&ether_payload).unwrap();
                Some((p4.get_next_level_protocol(), p4.from_packet().payload))
            }
            EtherType(ether_type) if ether_type == ipv6_ethertype => {
                let p6: Ipv6Packet = Ipv6Packet::new(&ether_payload).unwrap();
                Some((p6.get_next_header(), p6.from_packet().payload))
            }
            _ => None,
        };

        if let Some((IpNextHeaderProtocols::Udp, payload)) = next {
            let udp = UdpPacket::new(&payload).unwrap();
            if udp.get_destination() == collector_port {
                let data = udp.from_packet();
                println!("data: {:?}", data);
            }
        }
    }
}

use pcapng;
// use pcapng::Block;
use std::fs::File;
use pnet::packet::ethernet::{EthernetPacket, EtherType};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocols, IpNextHeaderProtocol};
use pnet::packet::FromPacket;
use pnet::packet::udp::UdpPacket;

/// Extract data template of Netflow version 9 from pcap file
pub fn dump_data_template(filename: &str, port: u16) {
    let mut fd = File::open(filename).unwrap();
    let mut reader = pcapng::SimpleReader::new(&mut fd);

    let ipv4_ethertype: u16 = 0x0800;
    let ipv6_ethertype: u16 = 0x86dd;

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
            if udp.get_destination() == port {
                let data = udp.from_packet();
                println!("data: {:?}", data);
            }
        }
    }
}

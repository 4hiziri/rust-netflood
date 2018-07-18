use netflow::netflow::NetFlow9;
use std::net::{IpAddr, UdpSocket};

fn get_udp_sock() -> Option<UdpSocket> {
    for port in 49152..65536 {
        if let Ok(sock) = UdpSocket::bind(format!("0.0.0.0:{}", port)) {
            return Some(sock);
        }
    }

    None
}

pub fn send_netflow(netflow: NetFlow9, dst_addr: IpAddr, dst_port: u16) {
    let payload = netflow.to_bytes();
    let dst = format!("{}:{}", dst_addr, dst_port);

    debug!("Dst: {:?}", dst);

    if let Some(sock) = get_udp_sock() {
        sock.send_to(&payload, dst).expect("couldn't send data");
    } else {
        panic!("cannot get socket");
    }
}

use netflow::netflow::NetFlow9;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};

fn get_udp_sock() -> Option<UdpSocket> {
    for port in 49152..65536 {
        if let Ok(sock) = UdpSocket::bind(format!("127.0.0.1:{}", port)) {
            return Some(sock);
        }
    }

    None
}

pub fn send_netflow(netflow: NetFlow9, dst_addr: &str, dst_port: u16) -> io::Result<usize> {
    let dst_addr: IpAddr = dst_addr.parse().expect("Invalid IP address");
    let dst = SocketAddr::new(dst_addr, dst_port);

    if let Some(sock) = get_udp_sock() {
        sock.send_to(&netflow.to_bytes(), dst)
    } else {
        Err(io::Error::from(io::ErrorKind::AlreadyExists))
    }
}

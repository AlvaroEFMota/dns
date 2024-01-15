type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;
use dns::{BytePacketBuffer, DnsPacket};
use std::net::UdpSocket;


fn main() -> Result<()>{
    let socket = UdpSocket::bind("127.0.0.1:53")?;
    let mut buf = [0; 512];
    loop {
        let (_amt, _src) = socket.recv_from(&mut buf)?;
        let mut byte_buffer = BytePacketBuffer {
            buf: buf,
            pos: 0,
        };
        let dns_packet = DnsPacket::from_buffer(&mut byte_buffer)?;
        println!("{:?}", dns_packet);
        // socket.send_to(buf, &src)?;
    }
    Ok(())
}

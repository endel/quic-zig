use anyhow::Result;
use clap::Parser;
use ring::rand::SecureRandom;
use std::net::{SocketAddr, UdpSocket};

const MAX_DATAGRAM_SIZE: usize = 1350;

#[derive(Parser)]
#[command(name = "quiche-client")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:4433")]
    addr: SocketAddr,

    #[arg(long, default_value = "h3")]
    alpn: String,

    #[arg(long, default_value = "hello from quiche client")]
    msg: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("Connecting to {} with ALPN '{}'", args.addr, args.alpn);

    // Create client config
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.set_application_protos(&[args.alpn.as_bytes()])?;
    config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_disable_active_migration(true);
    config.verify_peer(false);

    // Generate connection ID
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    ring::rand::SystemRandom::new().fill(&mut scid).unwrap();
    let scid = quiche::ConnectionId::from_ref(&scid);

    // Create socket
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_nonblocking(true)?;
    let local_addr = socket.local_addr()?;
    println!("Bound to {}", local_addr);

    // Create connection
    let mut conn = quiche::connect(None, &scid, local_addr, args.addr, &mut config)?;

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    // Send initial packet
    let (write, send_info) = conn.send(&mut out)?;
    socket.send_to(&out[..write], send_info.to)?;
    println!("Sent initial {} bytes", write);

    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(5);
    let mut data_sent = false;
    let stream_id: u64 = 0; // client-initiated bidi stream

    loop {
        if start.elapsed() > timeout {
            println!("Timeout");
            break;
        }

        // Read incoming packets
        let mut got_data = false;
        loop {
            match socket.recv_from(&mut buf) {
                Ok((len, from)) => {
                    got_data = true;
                    let recv_info = quiche::RecvInfo {
                        to: local_addr,
                        from,
                    };
                    match conn.recv(&mut buf[..len], recv_info) {
                        Ok(_) => {}
                        Err(e) => eprintln!("recv error: {:?}", e),
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    eprintln!("socket error: {}", e);
                    break;
                }
            }
        }

        if !got_data {
            conn.on_timeout();
        }

        // Once established, send data
        if conn.is_established() && !data_sent {
            println!("Connection established!");

            match conn.stream_send(stream_id, args.msg.as_bytes(), true) {
                Ok(written) => {
                    println!("Sent on stream {}: {} bytes ({:?})", stream_id, written, args.msg);
                    data_sent = true;
                }
                Err(e) => eprintln!("stream send error: {:?}", e),
            }
        }

        // Check for readable streams
        for sid in conn.readable().collect::<Vec<_>>() {
            let mut stream_buf = [0; 65535];
            match conn.stream_recv(sid, &mut stream_buf) {
                Ok((read, fin)) => {
                    let data = std::str::from_utf8(&stream_buf[..read]).unwrap_or("<binary>");
                    println!("Stream {}: received {} bytes (fin={}): {:?}", sid, read, fin, data);
                    if data_sent {
                        println!("OK");
                        // Flush pending sends and exit
                        loop {
                            match conn.send(&mut out) {
                                Ok((write, si)) => {
                                    let _ = socket.send_to(&out[..write], si.to);
                                }
                                Err(_) => break,
                            }
                        }
                        return Ok(());
                    }
                }
                Err(e) => eprintln!("stream recv error: {:?}", e),
            }
        }

        if conn.is_closed() {
            println!("Connection closed");
            break;
        }

        // Send pending packets
        loop {
            match conn.send(&mut out) {
                Ok((write, send_info)) => {
                    socket.send_to(&out[..write], send_info.to)?;
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    eprintln!("send error: {:?}", e);
                    break;
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    Ok(())
}

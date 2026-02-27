use anyhow::Result;
use clap::Parser;
use std::net::{SocketAddr, UdpSocket};

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
    config.set_application_protos(&[args.alpn.as_bytes()]);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.verify_peer(false); // Don't verify peer certificate (self-signed)

    // Generate connection ID
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    ring::rand::SystemRandom::new().fill(&mut scid).unwrap();
    let scid = quiche::ConnectionId::from_ref(&scid);

    // Create connection
    let mut conn = quiche::connect(None, &scid, "127.0.0.1".parse()?, args.addr, &mut config)?;

    // Create socket
    let bind_addr: SocketAddr = "127.0.0.1:0".parse()?;
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_nonblocking(true)?;

    println!("Bound to {}", socket.local_addr()?);

    let mut buf = vec![0; 65535];
    let mut out = vec![0; 65535];

    // Send initial packet
    let write = conn.send(&mut out)?;
    socket.send_to(&out[..write], args.addr)?;
    println!("Sent {} bytes", write);

    let mut start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(5);

    loop {
        if start.elapsed() > timeout {
            println!("Timeout");
            break;
        }

        match socket.recv_from(&mut buf) {
            Ok((len, peer_addr)) => {
                if len == 0 {
                    continue;
                }

                println!("Received {} bytes from {}", len, peer_addr);

                match conn.recv(&buf[..len]) {
                    Ok(_) => {
                        start = std::time::Instant::now();

                        // Process any available data
                        if conn.is_established() {
                            println!("Connection established!");
                            println!("ALPN: {:?}", conn.application_proto());

                            // TODO: Send and receive data on streams
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Recv error: {:?}", e);
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Send any pending data
                loop {
                    match conn.send(&mut out) {
                        Ok(write) => {
                            if write > 0 {
                                socket.send_to(&out[..write], args.addr)?;
                                println!("Sent {} bytes", write);
                            } else {
                                break;
                            }
                        }
                        Err(quiche::Error::Done) => break,
                        Err(e) => {
                            eprintln!("Send error: {:?}", e);
                            break;
                        }
                    }
                }

                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(e) => {
                eprintln!("Socket error: {}", e);
            }
        }
    }

    Ok(())
}

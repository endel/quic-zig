use anyhow::Result;
use clap::Parser;
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};

#[derive(Parser)]
#[command(name = "quiche-server")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:4434")]
    addr: SocketAddr,

    #[arg(long, default_value = "certs/server.crt")]
    cert: String,

    #[arg(long, default_value = "certs/server.key")]
    key: String,

    #[arg(long, default_value = "h3")]
    alpn: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("Starting quiche server on {}", args.addr);

    // Create server config
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.load_cert_chain_from_pem_file(&args.cert)?;
    config.load_priv_key_from_pem_file(&args.key)?;
    let _ = config.set_application_protos(&[args.alpn.as_bytes()]);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);

    // Bind socket
    let socket = UdpSocket::bind(args.addr)?;
    socket.set_nonblocking(true)?;

    println!("Listening on {}", args.addr);

    let mut connections: HashMap<Vec<u8>, quiche::Connection> = HashMap::new();
    let mut buf = vec![0; 65535];
    let mut out = vec![0; 65535];

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, peer_addr)) => {
                if len == 0 {
                    continue;
                }

                // Parse header to get connection ID
                let mut pkt_buf = buf[..len].to_vec();
                match quiche::Header::from_slice(&mut pkt_buf, quiche::MAX_CONN_ID_LEN) {
                    Ok(hdr) => {
                        let conn_id = hdr.dcid.to_vec();
                        let local_conn_id = quiche::ConnectionId::from_ref(&conn_id);

                        // Get or create connection
                        if !connections.contains_key(&conn_id) {
                            match quiche::accept(&local_conn_id, None, args.addr, peer_addr, &mut config) {
                                Ok(c) => {
                                    connections.insert(conn_id.clone(), c);
                                }
                                Err(_) => continue,
                            }
                        }

                        if let Some(conn) = connections.get_mut(&conn_id) {
                            // Process packet
                            let recv_info = quiche::RecvInfo {
                                from: peer_addr,
                                to: args.addr,
                            };
                            match conn.recv(&mut pkt_buf, recv_info) {
                                Ok(_) => {
                                    // Send any pending data
                                    loop {
                                        match conn.send(&mut out) {
                                            Ok((write, _send_info)) => {
                                                if write > 0 {
                                                    let _ = socket.send_to(&out[..write], peer_addr);
                                                } else {
                                                    break;
                                                }
                                            }
                                            Err(quiche::Error::Done) => break,
                                            Err(_) => break,
                                        }
                                    }
                                }
                                Err(_) => {}
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(e) => {
                eprintln!("Socket error: {}", e);
            }
        }
    }
}

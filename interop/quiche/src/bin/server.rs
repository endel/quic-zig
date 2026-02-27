use anyhow::Result;
use clap::Parser;
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};

const MAX_DATAGRAM_SIZE: usize = 1350;
const LOCAL_CONN_ID_LEN: usize = 8;

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

struct Client {
    conn: quiche::Connection,
    peer_addr: SocketAddr,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("Starting quiche server on {}", args.addr);

    // Create server config
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.load_cert_chain_from_pem_file(&args.cert)?;
    config.load_priv_key_from_pem_file(&args.key)?;
    let _ = config.set_application_protos(&[args.alpn.as_bytes()]);
    config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_disable_active_migration(true);

    // Bind socket
    let socket = UdpSocket::bind(args.addr)?;
    socket.set_nonblocking(true)?;

    println!("Listening on {}", args.addr);

    let mut clients: HashMap<Vec<u8>, Client> = HashMap::new();
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    loop {
        // Read all available packets
        loop {
            match socket.recv_from(&mut buf) {
                Ok((len, peer_addr)) => {
                    if len == 0 {
                        continue;
                    }

                    let mut pkt_buf = buf[..len].to_vec();
                    let hdr = match quiche::Header::from_slice(&mut pkt_buf, LOCAL_CONN_ID_LEN) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    let conn_id = hdr.dcid.to_vec();
                    let local_conn_id = quiche::ConnectionId::from_ref(&conn_id);

                    // Get or create connection
                    if !clients.contains_key(&conn_id) {
                        match quiche::accept(&local_conn_id, None, args.addr, peer_addr, &mut config) {
                            Ok(conn) => {
                                println!("Accepted connection from {}", peer_addr);
                                clients.insert(conn_id.clone(), Client { conn, peer_addr });
                            }
                            Err(e) => {
                                eprintln!("Accept error: {:?}", e);
                                continue;
                            }
                        }
                    }

                    if let Some(client) = clients.get_mut(&conn_id) {
                        let recv_info = quiche::RecvInfo {
                            from: peer_addr,
                            to: args.addr,
                        };
                        match client.conn.recv(&mut pkt_buf, recv_info) {
                            Ok(_) => {}
                            Err(e) => eprintln!("recv error: {:?}", e),
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    eprintln!("socket error: {}", e);
                    break;
                }
            }
        }

        // Process all connections
        let conn_ids: Vec<Vec<u8>> = clients.keys().cloned().collect();
        for conn_id in &conn_ids {
            let client = clients.get_mut(conn_id).unwrap();

            // Check for readable streams and echo
            for stream_id in client.conn.readable().collect::<Vec<_>>() {
                let mut stream_buf = [0; 65535];
                match client.conn.stream_recv(stream_id, &mut stream_buf) {
                    Ok((read, fin)) => {
                        let data = std::str::from_utf8(&stream_buf[..read]).unwrap_or("<binary>");
                        println!("Stream {}: received {} bytes (fin={}): {:?}", stream_id, read, fin, data);

                        let echo = format!("Echo: {}", data);
                        match client.conn.stream_send(stream_id, echo.as_bytes(), true) {
                            Ok(written) => println!("Stream {}: echoed {} bytes", stream_id, written),
                            Err(e) => eprintln!("stream send error: {:?}", e),
                        }
                    }
                    Err(e) => eprintln!("stream recv error: {:?}", e),
                }
            }

            // Send pending packets
            loop {
                match client.conn.send(&mut out) {
                    Ok((write, send_info)) => {
                        let _ = socket.send_to(&out[..write], send_info.to);
                    }
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        eprintln!("send error: {:?}", e);
                        break;
                    }
                }
            }

            // Handle timeouts
            if client.conn.is_closed() {
                println!("Connection closed from {}", client.peer_addr);
            }
        }

        // Remove closed connections
        clients.retain(|_, c| !c.conn.is_closed());

        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

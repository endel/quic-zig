use anyhow::Result;
use clap::Parser;
use mio::{Events, Interest, Poll, Token};
use quiche::h3::NameValue;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

const MAX_DATAGRAM_SIZE: usize = 1350;
const LOCAL_CONN_ID_LEN: usize = 8;
const SERVER: Token = Token(0);

#[derive(Parser)]
#[command(name = "quiche-h3-server")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:4434")]
    addr: SocketAddr,

    #[arg(long, default_value = "certs/server.crt")]
    cert: String,

    #[arg(long, default_value = "certs/server.key")]
    key: String,
}

struct Client {
    conn: quiche::Connection,
    h3: Option<quiche::h3::Connection>,
    peer_addr: SocketAddr,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.load_cert_chain_from_pem_file(&args.cert)?;
    config.load_priv_key_from_pem_file(&args.key)?;
    let _ = config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL);
    config.set_max_idle_timeout(30000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(16_777_216);
    config.set_initial_max_stream_data_bidi_local(6_291_456);
    config.set_initial_max_stream_data_bidi_remote(6_291_456);
    config.set_initial_max_stream_data_uni(1_048_576);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);

    let h3_config = quiche::h3::Config::new()?;

    let std_socket = std::net::UdpSocket::bind(args.addr)?;
    std_socket.set_nonblocking(true)?;
    let mut socket = mio::net::UdpSocket::from_std(std_socket);

    let mut poll = Poll::new()?;
    poll.registry().register(&mut socket, SERVER, Interest::READABLE)?;
    let mut events = Events::with_capacity(1024);

    eprintln!("quiche H3 server listening on {} (mio)", args.addr);

    let mut clients: HashMap<Vec<u8>, Client> = HashMap::new();
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    loop {
        // Compute timeout from all connections
        let timeout = clients.values().filter_map(|c| c.conn.timeout()).min();

        poll.poll(&mut events, timeout)?;

        // Handle timeouts
        let now = Instant::now();
        for client in clients.values_mut() {
            if let Some(t) = client.conn.timeout() {
                if t <= std::time::Duration::ZERO || now.elapsed() >= std::time::Duration::ZERO {
                    client.conn.on_timeout();
                }
            }
        }

        // Receive packets
        'recv: loop {
            match socket.recv_from(&mut buf) {
                Ok((len, peer_addr)) => {
                    if len == 0 { continue; }
                    let mut pkt_buf = buf[..len].to_vec();
                    let hdr = match quiche::Header::from_slice(&mut pkt_buf, LOCAL_CONN_ID_LEN) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    let conn_id = hdr.dcid.to_vec();
                    let local_conn_id = quiche::ConnectionId::from_ref(&conn_id);

                    if !clients.contains_key(&conn_id) {
                        match quiche::accept(&local_conn_id, None, args.addr, peer_addr, &mut config) {
                            Ok(conn) => {
                                clients.insert(conn_id.clone(), Client {
                                    conn,
                                    h3: None,
                                    peer_addr,
                                });
                            }
                            Err(_) => continue,
                        }
                    }

                    if let Some(client) = clients.get_mut(&conn_id) {
                        let recv_info = quiche::RecvInfo { from: peer_addr, to: args.addr };
                        let _ = client.conn.recv(&mut pkt_buf, recv_info);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break 'recv,
                Err(_) => break 'recv,
            }
        }

        // Process connections
        let conn_ids: Vec<Vec<u8>> = clients.keys().cloned().collect();
        for conn_id in &conn_ids {
            let client = clients.get_mut(conn_id).unwrap();

            if client.conn.is_established() && client.h3.is_none() {
                client.h3 = quiche::h3::Connection::with_transport(&mut client.conn, &h3_config).ok();
            }

            if let Some(ref mut h3) = client.h3 {
                loop {
                    match h3.poll(&mut client.conn) {
                        Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                            let mut method = "";
                            let mut path = "";
                            for hdr in &list {
                                if hdr.name() == b":method" {
                                    method = std::str::from_utf8(hdr.value()).unwrap_or("?");
                                }
                                if hdr.name() == b":path" {
                                    path = std::str::from_utf8(hdr.value()).unwrap_or("?");
                                }
                            }

                            let body = format!("Hello from quiche HTTP/3 server! You requested {} {}\n", method, path);
                            let resp = vec![
                                quiche::h3::Header::new(b":status", b"200"),
                                quiche::h3::Header::new(b"content-type", b"text/plain"),
                                quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
                            ];
                            let _ = h3.send_response(&mut client.conn, stream_id, &resp, false);
                            let _ = h3.send_body(&mut client.conn, stream_id, body.as_bytes(), true);
                        }
                        Ok(_) => {}
                        Err(quiche::h3::Error::Done) => break,
                        Err(_) => break,
                    }
                }
            }

            // Send queued packets
            loop {
                match client.conn.send(&mut out) {
                    Ok((write, send_info)) => {
                        let _ = socket.send_to(&out[..write], send_info.to);
                    }
                    Err(quiche::Error::Done) => break,
                    Err(_) => break,
                }
            }
        }

        clients.retain(|_, c| !c.conn.is_closed());
    }
}

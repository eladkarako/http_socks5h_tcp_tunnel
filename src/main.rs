use anyhow::{anyhow, bail, ensure, Context, Result};
use clap::Parser;
use socket2::{Domain, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Parser)]
#[command(author, about, long_about = None)]
struct Args {
    #[arg(short = 'p', long, default_value = "8765")]
    http_port: u16,
    #[arg(short = 'u', long, default_value = "5678")]
    upstream_port: u16,
}

const SOCKS5_GREETING: &[u8] = &[5, 1, 0];
const SOCKS5_ERRORS: &[&str] = &[
    "",
    "General SOCKS server failure",
    "Connection not allowed by ruleset",
    "Network unreachable",
    "Host unreachable",
    "Connection refused",
    "TTL expired",
    "Command not supported",
    "Address type not supported",
];
const BUFFER_SIZE: usize = 8192;
const SOCKET_BUFFER_SIZE: usize = 2_097_152; // 2 MB
const MAX_HOSTNAME_LEN: usize = 255;
const SOCKS5_CONNECT_MAX_LEN: usize = 262;

fn create_listener(port: u16) -> Result<TcpListener> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)
        .context("Failed to create socket")?;
    socket
        .set_send_buffer_size(SOCKET_BUFFER_SIZE)
        .context("Failed to set send buffer size")?;
    socket
        .set_recv_buffer_size(SOCKET_BUFFER_SIZE)
        .context("Failed to set recv buffer size")?;

    let addr = std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::LOCALHOST,
        port,
    );
    socket
        .bind(&std::net::SocketAddr::V4(addr).into())
        .context("Failed to bind socket")?;
    socket.listen(128).context("Failed to listen on socket")?;

    let std_listener = std::net::TcpListener::from(socket);
    std_listener
        .set_nonblocking(true)
        .context("Failed to set non-blocking")?;
    TcpListener::from_std(std_listener)
        .context("Failed to create async listener")
}

#[inline]
fn configure_stream(stream: &TcpStream) -> Result<()> {
    stream.set_nodelay(true).context("Failed to set TCP_NODELAY")?;
    Ok(())
}

#[inline]
fn parse_url(url: &str) -> Result<(&str, u16)> {
    let url = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    let host_port = url
        .split('/')
        .next()
        .ok_or_else(|| anyhow!("No host:port found in URL"))?
        .trim();

    match host_port.split_once(':') {
        Some((h, p)) => {
            let port =
                p.parse::<u16>().context("Invalid port number")?;
            Ok((h, port))
        }
        None => Ok((host_port, 80)),
    }
}

async fn read_and_parse_http_request(
    client: &mut TcpStream,
    buf: &mut [u8; BUFFER_SIZE],
) -> Result<(String, u16, usize)> {
    let n = client
        .read(buf)
        .await
        .context("Failed to read HTTP request from client")?;

    ensure!(n > 0, "Client closed connection without sending data");

    let request = std::str::from_utf8(&buf[..n])
        .context("Invalid UTF-8 in request")?;
    let lines: Vec<&str> = request.lines().collect();

    ensure!(!lines.is_empty(), "Empty HTTP request");

    let request_line: Vec<&str> =
        lines[0].split_whitespace().collect();
    ensure!(
        request_line.len() >= 2,
        "Invalid request line: expected at least 2 tokens, got {}",
        request_line.len()
    );

    let url = request_line[1];
    let (host, port) = parse_url(url).with_context(|| {
        format!("Invalid URL in request: '{}'", url)
    })?;

    ensure!(!host.is_empty(), "Empty hostname extracted from URL");

    ensure!(
        host.len() <= MAX_HOSTNAME_LEN,
        "Hostname too long: {} bytes (max {})",
        host.len(),
        MAX_HOSTNAME_LEN
    );

    Ok((host.to_string(), port, n))
}

async fn connect_to_socks5(upstream_port: u16) -> Result<TcpStream> {
    let addr = format!("127.0.0.1:{}", upstream_port);
    let upstream_stream =
        TcpStream::connect(&addr).await.with_context(|| {
            format!("Failed to connect to SOCKS5 server at {}", addr)
        })?;

    configure_stream(&upstream_stream)
        .context("Failed to configure SOCKS5 stream")?;

    Ok(upstream_stream)
}

async fn socks5_handshake(
    upstream_stream: &mut TcpStream,
    host: &str,
    port: u16,
) -> Result<()> {
    // Send greeting
    upstream_stream
        .write_all(SOCKS5_GREETING)
        .await
        .context("Failed to send SOCKS5 greeting to server")?;

    // Read greeting response
    let mut resp = [0u8; 2];
    upstream_stream.read_exact(&mut resp).await.context(
        "Failed to read SOCKS5 greeting response from server",
    )?;

    ensure!(
        resp[0] == 5,
        "Invalid SOCKS5 version in greeting response: {} (expected 5)",
        resp[0]
    );

    ensure!(
        resp[1] != 0xff,
        "SOCKS5 server rejected all authentication methods"
    );

    // Build and send connect request
    let mut connect_req = [0u8; SOCKS5_CONNECT_MAX_LEN];
    let len = 6 + host.len();

    /* //might be added later, currently assume larger request will be trunked. that's fine.
    ensure!(
        len <= SOCKS5_CONNECT_MAX_LEN,
        "SOCKS5 connect request too large: {} bytes (max {})",
        len,
        SOCKS5_CONNECT_MAX_LEN
    );
    */

    connect_req[0] = 5;
    connect_req[1] = 1; // CONNECT
    connect_req[2] = 0; // reserved
    connect_req[3] = 3; // DOMAINNAME
    connect_req[4] = host.len() as u8;
    connect_req[5..5 + host.len()].copy_from_slice(host.as_bytes());
    connect_req[5 + host.len()] = (port >> 8) as u8;
    connect_req[5 + host.len() + 1] = (port & 0xff) as u8;

    upstream_stream
        .write_all(&connect_req[..len])
        .await
        .with_context(|| {
            format!(
                "Failed to send SOCKS5 connect request for {}:{}",
                host, port
            )
        })?;

    // Read connect response header (4 bytes fixed)
    let mut resp_header = [0u8; 4];
    upstream_stream
        .read_exact(&mut resp_header)
        .await
        .context("Failed to read SOCKS5 connect response header")?;

    ensure!(
        resp_header[0] == 5,
        "Invalid SOCKS5 version in connect response: {} (expected 5)",
        resp_header[0]
    );

    if resp_header[1] != 0 {
        let error_msg = if (resp_header[1] as usize)
            < SOCKS5_ERRORS.len()
        {
            SOCKS5_ERRORS[resp_header[1] as usize].to_string()
        } else {
            format!("Unknown SOCKS5 error code {}", resp_header[1])
        };
        bail!("SOCKS5 connection failed: {}", error_msg);
    }

    // Read address data based on address type
    match resp_header[3] {
        1 => {
            // IPv4: 4 bytes address + 2 bytes port
            let mut addr_port = [0u8; 6];
            upstream_stream
                .read_exact(&mut addr_port)
                .await
                .context(
                    "Failed to read SOCKS5 IPv4 address response",
                )?;
        }
        3 => {
            // Domain name: 1 byte length + domain + 2 bytes port
            let mut len_byte = [0u8; 1];
            upstream_stream
                .read_exact(&mut len_byte)
                .await
                .context("Failed to read SOCKS5 domain length")?;
            let domain_len = len_byte[0] as usize;

            ensure!(
                domain_len <= MAX_HOSTNAME_LEN,
                "SOCKS5 response domain too long: {} bytes (max {})",
                domain_len,
                MAX_HOSTNAME_LEN
            );

            let mut domain_and_port = vec![0u8; domain_len + 2];
            upstream_stream
                .read_exact(&mut domain_and_port)
                .await
                .context("Failed to read SOCKS5 domain response")?;
        }
        4 => {
            // IPv6: 16 bytes address + 2 bytes port
            let mut addr_port = [0u8; 18];
            upstream_stream
                .read_exact(&mut addr_port)
                .await
                .context(
                    "Failed to read SOCKS5 IPv6 address response",
                )?;
        }
        atype => {
            bail!(
                "Unsupported address type in SOCKS5 response: {} (expected 1, 3, or 4)",
                atype
            );
        }
    }

    Ok(())
}
async fn relay_traffic(
    client: TcpStream,
    mut upstream_stream: TcpStream,
    buf: &[u8],
    n: usize,
) -> Result<()> {
    ensure!(n > 0, "No HTTP request data to relay (n={})", n);

    // Send the HTTP request through the tunnel
    upstream_stream.write_all(&buf[..n]).await.context(
        "Failed to send HTTP request through SOCKS5 tunnel",
    )?;

    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) =
        upstream_stream.into_split();

    // Set up bidirectional copy futures
    let client_to_upstream =
        tokio::io::copy(&mut client_read, &mut upstream_write);
    let upstream_to_client =
        tokio::io::copy(&mut upstream_read, &mut client_write);

    // Run both directions in parallel to completion
    let (r1, r2) =
        tokio::join!(client_to_upstream, upstream_to_client);

    let bytes1 = r1.context("Client→Upstream relay failed")?;
    eprintln!("Client→Upstream: {} bytes relayed", bytes1);

    let bytes2 = r2.context("Upstream→Client relay failed")?;
    eprintln!("Upstream→Client: {} bytes relayed", bytes2);

    Ok(())
}

async fn handle_client(
    mut client: TcpStream,
    upstream_port: u16,
) -> Result<()> {
    let peer_addr = client
        .peer_addr()
        .unwrap_or_else(|_| "unknown".parse().unwrap());

    configure_stream(&client).with_context(|| {
        format!(
            "Failed to configure client stream from {}",
            peer_addr
        )
    })?;

    let mut buf = [0u8; BUFFER_SIZE];
    let (host, port, n) =
        read_and_parse_http_request(&mut client, &mut buf)
            .await
            .with_context(|| {
                format!(
                    "Failed to parse HTTP request from {}",
                    peer_addr
                )
            })?;

    let mut upstream_stream = connect_to_socks5(upstream_port)
        .await
        .with_context(|| {
            format!(
                "Failed to connect to SOCKS5 for {}:{} (client: {})",
                host, port, peer_addr
            )
        })?;

    socks5_handshake(&mut upstream_stream, &host, port)
        .await
        .with_context(|| {
            format!(
                "SOCKS5 handshake failed for {}:{} (client: {})",
                host, port, peer_addr
            )
        })?;

    eprintln!(
        "Tunneling {}:{} for client {}",
        host, port, peer_addr
    );

    relay_traffic(client, upstream_stream, &buf, n)
        .await
        .with_context(|| {
            format!(
                "Relay failed for {}:{} (client: {})",
                host, port, peer_addr
            )
        })?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    ensure!(
        args.http_port != args.upstream_port,
        "HTTP port ({}) cannot be the same as upstream port ({})",
        args.http_port,
        args.upstream_port
    );

    let listener =
        create_listener(args.http_port).with_context(|| {
            format!(
                "Failed to bind HTTP listener on 127.0.0.1:{}",
                args.http_port
            )
        })?;

    eprintln!(
        "HTTP proxy listening on 127.0.0.1:{}",
        args.http_port
    );
    eprintln!(
        "Forwarding to upstream SOCKS5h on 127.0.0.1:{}",
        args.upstream_port
    );

    let shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
    let shutdown_clone = shutdown.clone();

    // Spawn signal handler WITHOUT awaiting
    let signal_handle = tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        eprintln!("\nShutting down gracefully...");
        shutdown_clone.notify_waiters();
    });

    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            result = listener.accept() => {
                match result {
                    Ok((client, addr)) => {
                        let upstream_port = args.upstream_port;
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(client, upstream_port).await {
                                eprintln!("Client error from {}: {:#}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("Accept error: {}", e);
                    }
                }
            }
        }
    }

    // Await signal handler after loop exits
    let _ = signal_handle.await;
    eprintln!("Stopped accepting connections.");
    Ok(())
}

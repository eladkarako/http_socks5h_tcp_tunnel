#[cfg(all(not(target_os = "windows"), not(target_os = "android")))]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

use anyhow::{anyhow, Context, Result};

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

fn create_listener(port: u16) -> std::io::Result<TcpListener> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    socket.set_send_buffer_size(SOCKET_BUFFER_SIZE)?;
    socket.set_recv_buffer_size(SOCKET_BUFFER_SIZE)?;

    let addr = std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::LOCALHOST,
        port,
    );
    socket.bind(&std::net::SocketAddr::V4(addr).into())?;
    socket.listen(128)?;

    let std_listener = std::net::TcpListener::from(socket);
    std_listener.set_nonblocking(true)?;
    TcpListener::from_std(std_listener)
}

#[inline]
fn configure_stream(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)?;
    Ok(())
}

#[inline]
fn parse_url(url: &str) -> Option<(&str, u16)> {
    let url = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    let host_port = url.split('/').next()?.trim();

    match host_port.split_once(':') {
        Some((h, p)) => Some((h, p.parse::<u16>().ok()?)),
        None => Some((host_port, 80)),
    }
}
async fn read_and_parse_http_request(
    client: &mut TcpStream,
    buf: &mut [u8; BUFFER_SIZE],
) -> Result<(String, u16, usize)> {
    let n = client.read(buf).await?;

    if n == 0 {
        return Err(anyhow!("Client closed connection"));
    }

    let request = std::str::from_utf8(&buf[..n])
        .context("Invalid UTF-8 in request")?;
    let lines: Vec<&str> = request.lines().collect();

    if lines.is_empty() {
        return Err(anyhow!("Empty request"));
    }

    let request_line: Vec<&str> =
        lines[0].split_whitespace().collect();
    if request_line.len() < 2 {
        return Err(anyhow!("Invalid request line"));
    }

    let url = request_line[1];
    let (host, port) =
        parse_url(url).ok_or_else(|| anyhow!("Invalid URL"))?;

    if host.is_empty() {
        return Err(anyhow!("Empty hostname"));
    }

    if host.len() > MAX_HOSTNAME_LEN {
        return Err(anyhow!("Hostname too long (max 255 bytes)"));
    }

    Ok((host.to_string(), port, n))
}

async fn connect_to_socks5(
    upstream_port: u16
) -> anyhow::Result<TcpStream> {
    let upstream_stream =
        TcpStream::connect(format!("127.0.0.1:{}", upstream_port))
            .await
            .context(format!(
                "Failed to connect to upstream on 127.0.0.1:{}",
                upstream_port
            ))?;

    configure_stream(&upstream_stream)?;
    Ok(upstream_stream)
}
async fn socks5_handshake(
    upstream_stream: &mut TcpStream,
    host: &str,
    port: u16,
) -> Result<()> {
    // Changed this line
    // Send greeting
    upstream_stream
        .write_all(SOCKS5_GREETING)
        .await
        .context("Failed to send SOCKS5 greeting")?;

    // Read greeting response
    let mut resp = [0u8; 2];
    upstream_stream
        .read_exact(&mut resp)
        .await
        .context("Failed to read SOCKS5 greeting response")?;

    if resp[0] != 5 {
        return Err(anyhow!("Invalid SOCKS5 version: {}", resp[0]));
    }

    if resp[1] == 0xff {
        return Err(anyhow!(
            "SOCKS5 server rejected authentication methods"
        ));
    }

    // Build and send connect request
    let mut connect_req = [0u8; SOCKS5_CONNECT_MAX_LEN];
    let len = 6 + host.len();
    connect_req[0] = 5;
    connect_req[1] = 1;
    connect_req[2] = 0;
    connect_req[3] = 3;
    connect_req[4] = host.len() as u8;
    connect_req[5..5 + host.len()].copy_from_slice(host.as_bytes());
    connect_req[5 + host.len()] = (port >> 8) as u8;
    connect_req[5 + host.len() + 1] = (port & 0xff) as u8;

    upstream_stream
        .write_all(&connect_req[..len])
        .await
        .context("Failed to send SOCKS5 connect request")?;

    // Read connect response header (4 bytes fixed)
    let mut resp_header = [0u8; 4];
    upstream_stream
        .read_exact(&mut resp_header)
        .await
        .context("Failed to read SOCKS5 connect response header")?;

    if resp_header[0] != 5 {
        return Err(anyhow!(
            "Invalid SOCKS5 version in connect response: {}",
            resp_header[0]
        ));
    }

    if resp_header[1] != 0 {
        let error_msg =
            if (resp_header[1] as usize) < SOCKS5_ERRORS.len() {
                SOCKS5_ERRORS[resp_header[1] as usize]
            } else {
                "Unknown error code"
            };
        return Err(anyhow!("SOCKS5: {}", error_msg));
    }

    // Read address data based on address type
    match resp_header[3] {
        1 => {
            // IPv4: 4 bytes address + 2 bytes port
            let mut addr_port = [0u8; 6];
            upstream_stream
                .read_exact(&mut addr_port)
                .await
                .context("Failed to read SOCKS5 IPv4 address")?;
        }
        3 => {
            // Domain name: 1 byte length + domain + 2 bytes port
            let mut len_byte = [0u8; 1];
            upstream_stream
                .read_exact(&mut len_byte)
                .await
                .context("Failed to read SOCKS5 domain length")?;
            let domain_len = len_byte[0] as usize;
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
                .context("Failed to read SOCKS5 IPv6 address")?;
        }
        _ => {
            return Err(anyhow!(
                "Unsupported address type in SOCKS5 response"
            ));
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
    // Changed this line
    // Send the HTTP request through the tunnel
    upstream_stream
        .write_all(&buf[..n])
        .await
        .context("Failed to send HTTP request through tunnel")?;

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

    // Handle client→upstream errors
    r1.context("Client→Upstream relay failed")?;

    // Handle upstream→client errors
    r2.context("Upstream→Client relay failed")?;

    Ok(())
}

async fn handle_client(
    mut client: TcpStream,
    upstream_port: u16,
) -> Result<()> {
    // Changed this line
    configure_stream(&client)?;

    let mut buf = [0u8; BUFFER_SIZE];
    let (host, port, n) =
        read_and_parse_http_request(&mut client, &mut buf).await?;

    let mut upstream_stream =
        connect_to_socks5(upstream_port).await?;

    socks5_handshake(&mut upstream_stream, &host, port).await?;

    relay_traffic(client, upstream_stream, &buf, n).await?;

    Ok(())
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let listener = match create_listener(args.http_port) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "Failed to bind HTTP listener on 127.0.0.1:{}: {}",
                args.http_port, e
            );
            std::process::exit(1);
        }
    };
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

    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        eprintln!("\nShutting down gracefully...");
        shutdown_clone.notify_waiters();
    });

    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            result = listener.accept() => {
                match result {
                    Ok((client, _)) => {
                        let upstream_port = args.upstream_port;
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(client, upstream_port).await {
                                eprintln!("Client error: {}", e);
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

    eprintln!("Stopped accepting connections.");
}

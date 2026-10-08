#[cfg(all(not(target_os = "windows"), not(target_os = "android")))]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

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

fn create_listener(port: u16) -> std::io::Result<TcpListener> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    socket.set_send_buffer_size(SOCKET_BUFFER_SIZE)?;
    socket.set_recv_buffer_size(SOCKET_BUFFER_SIZE)?;

    let addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, port);
    socket.bind(&std::net::SocketAddr::V4(addr).into())?;
    socket.listen(128)?;

    let std_listener = std::net::TcpListener::from(socket);
    std_listener.set_nonblocking(true)?;
    TcpListener::from_std(std_listener)
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
    eprintln!("HTTP proxy listening on 127.0.0.1:{}", args.http_port);
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

async fn socks5_handshake(
    upstream_stream: &mut TcpStream,
    host: &str,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    // Send greeting
    upstream_stream
        .write_all(SOCKS5_GREETING)
        .await
        .map_err(|e| format!("Failed to send SOCKS5 greeting: {}", e))?;

    // Read greeting response
    let mut resp = [0u8; 2];
    upstream_stream
        .read_exact(&mut resp)
        .await
        .map_err(|e| format!("Failed to read SOCKS5 greeting response: {}", e))?;

    if resp[0] != 5 {
        return Err(format!("Invalid SOCKS5 version: {}", resp[0]).into());
    }

    if resp[1] == 0xff {
        return Err("SOCKS5 server rejected authentication methods".into());
    }

    // Build and send connect request
    let mut connect_req = [0u8; 262];
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
        .map_err(|e| format!("Failed to send SOCKS5 connect request: {}", e))?;

    // Read and validate connect response
    let mut resp = [0u8; 10];
    let n_resp = upstream_stream
        .read(&mut resp)
        .await
        .map_err(|e| format!("Failed to read SOCKS5 connect response: {}", e))?;

    if n_resp < 2 {
        return Err("SOCKS5 connect response too short".into());
    }

    if resp[0] != 5 {
        return Err(format!("Invalid SOCKS5 version in connect response: {}", resp[0]).into());
    }

    if resp[1] != 0 {
        let error_msg = if (resp[1] as usize) < SOCKS5_ERRORS.len() {
            SOCKS5_ERRORS[resp[1] as usize]
        } else {
            "Unknown error code"
        };
        return Err(format!("SOCKS5: {}", error_msg).into());
    }

    Ok(())
}

#[inline]
fn configure_stream(stream: &TcpStream) -> std::io::Result<()> {
    stream.set_nodelay(true)?; // Not automatically inherited. Each socket needs it set explicitly.
    Ok(())
}
async fn handle_client(
    mut client: TcpStream,
    upstream_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    configure_stream(&client)?;

    let mut buf = [0u8; BUFFER_SIZE];
    let n = client.read(&mut buf).await?;

    if n == 0 {
        return Err("Client closed connection".into());
    }

    let request = std::str::from_utf8(&buf[..n]).map_err(|_| "Invalid UTF-8 in request")?;
    let lines: Vec<&str> = request.lines().collect();

    if lines.is_empty() {
        return Err("Empty request".into());
    }

    let request_line: Vec<&str> = lines[0].split_whitespace().collect();
    if request_line.len() < 2 {
        return Err("Invalid request line".into());
    }

    let url = request_line[1];
    let (host, port) = parse_url(url).ok_or("Invalid URL")?;

    if host.is_empty() {
        return Err("Empty hostname".into());
    }

    if host.len() > 255 {
        return Err("Hostname too long (max 255 bytes)".into());
    }

    let mut upstream_stream = TcpStream::connect(format!("127.0.0.1:{}", upstream_port))
        .await
        .map_err(|e| {
            format!(
                "Failed to connect to upstream on 127.0.0.1:{}: {}",
                upstream_port, e
            )
        })?;

    configure_stream(&upstream_stream)?;

    // Single async call instead of 3 separate writes/reads
    socks5_handshake(&mut upstream_stream, host, port).await?;

    upstream_stream
        .write_all(&buf[..n])
        .await
        .map_err(|e| format!("Failed to send HTTP request through tunnel: {}", e))?;

    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream_stream.into_split();

    let client_to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
    let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut client_write);

    tokio::select! {
        _ = client_to_upstream => {},
        _ = upstream_to_client => {},
    }

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

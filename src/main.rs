#[cfg(all(not(target_os = "windows"), not(target_os = "android")))]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

use clap::Parser;
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

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let listener = match TcpListener::bind(format!("127.0.0.1:{}", args.http_port)).await {
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

    loop {
        match listener.accept().await {
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

async fn handle_client(
    mut client: TcpStream,
    upstream_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
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

    upstream_stream
        .write_all(SOCKS5_GREETING)
        .await
        .map_err(|e| format!("Failed to send SOCKS5 greeting: {}", e))?;

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

    let mut connect_req = vec![5, 1, 0, 3];
    connect_req.push(host.len() as u8);
    connect_req.extend_from_slice(host.as_bytes());
    connect_req.push((port >> 8) as u8);
    connect_req.push((port & 0xff) as u8);

    upstream_stream
        .write_all(&connect_req)
        .await
        .map_err(|e| format!("Failed to send SOCKS5 connect request: {}", e))?;

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
fn parse_url(url: &str) -> Option<(String, u16)> {
    let url = if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else {
        url
    };

    let host_port = url.split('/').next()?.trim();

    if host_port.is_empty() {
        return None;
    }

    let (host, port) = match host_port.split_once(':') {
        Some((h, p)) => {
            let host = h.to_string();
            let port = p.parse::<u16>().ok()?;
            (host, port)
        }
        None => (host_port.to_string(), 80),
    };

    Some((host, port))
}

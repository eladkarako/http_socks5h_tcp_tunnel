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

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let listener = match TcpListener::bind(format!("127.0.0.1:{}", args.http_port)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind HTTP listener on 127.0.0.1:{}: {}", args.http_port, e);
            std::process::exit(1);
        }
    };

    eprintln!("HTTP proxy listening on 127.0.0.1:{}", args.http_port);
    eprintln!("Forwarding to upstream SOCKS5h on 127.0.0.1:{}", args.upstream_port);

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

async fn handle_client(mut client: TcpStream, upstream_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = [0u8; 4096];
    let n = client.read(&mut buf).await?;

    if n == 0 {
        return Err("Client closed connection".into());
    }

    // Parse HTTP request
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

    // Connect to upstream SOCKS5
    let mut upstream_stream = TcpStream::connect(format!("127.0.0.1:{}", upstream_port))
        .await
        .map_err(|e| format!("Failed to connect to upstream on 127.0.0.1:{}: {}", upstream_port, e))?;

    // SOCKS5 handshake: VER=5, NMETHODS=1, METHOD=0(no auth)
    upstream_stream
        .write_all(&[5, 1, 0])
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

    // SOCKS5 connect: VER=5, CMD=1(CONNECT), RSV=0, ATYP=3(domain)
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

    match resp[1] {
        0 => {} // Success
        1 => return Err("SOCKS5: General SOCKS server failure".into()),
        2 => return Err("SOCKS5: Connection not allowed by ruleset".into()),
        3 => return Err("SOCKS5: Network unreachable".into()),
        4 => return Err("SOCKS5: Host unreachable".into()),
        5 => return Err("SOCKS5: Connection refused".into()),
        6 => return Err("SOCKS5: TTL expired".into()),
        7 => return Err("SOCKS5: Command not supported".into()),
        8 => return Err("SOCKS5: Address type not supported".into()),
        code => return Err(format!("SOCKS5: Unknown error code {}", code).into()),
    }

    // Store the original request before reusing buf
    let original_request = buf[..n].to_vec();

    // Send HTTP request through tunnel
    upstream_stream
        .write_all(&original_request)
        .await
        .map_err(|e| format!("Failed to send HTTP request through tunnel: {}", e))?;

    // Bidirectional relay (buf can now be safely reused)
    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream_stream.into_split();

    let client_to_upstream = async {
        let mut buf = [0u8; 8192];
        loop {
            match client_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = upstream_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    if let Err(e) = upstream_write.write_all(&buf[..n]).await {
                        eprintln!("Error writing to upstream: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Error reading from client: {}", e);
                    break;
                }
            }
        }
    };

    let upstream_to_client = async {
        let mut buf = [0u8; 8192];
        loop {
            match upstream_read.read(&mut buf).await {
                Ok(0) => {
                    let _ = client_write.shutdown().await;
                    break;
                }
                Ok(n) => {
                    if let Err(e) = client_write.write_all(&buf[..n]).await {
                        eprintln!("Error writing to client: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("Error reading from upstream: {}", e);
                    break;
                }
            }
        }
    };

    tokio::select! {
        _ = client_to_upstream => {},
        _ = upstream_to_client => {},
    }

    Ok(())
}

fn parse_url(url: &str) -> Option<(String, u16)> {
    let url = if url.starts_with("http://") {
        &url[7..]
    } else if url.starts_with("https://") {
        &url[8..]
    } else {
        url
    };

    let host_port = url.split('/').next()?;

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

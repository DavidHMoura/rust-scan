use anyhow::{bail, Context, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::{CustomType, Text};
use ipnet::IpNet;
use serde::Serialize;
use std::fs;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::timeout;

#[derive(Serialize)]
struct ScanResult {
    ip: String,
    port: u16,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    banner: Option<String>,
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Advanced Asynchronous Port Scanner", long_about = None)]
struct Args {
    #[arg(short = 't', long, help = "Target IP, hostname, or CIDR (e.g., 127.0.0.1, google.com, 192.168.0.0/24)")]
    target: Option<String>,

    #[arg(short = 'o', long, default_value_t = 200, help = "Connection timeout in milliseconds")]
    timeout: u64,

    #[arg(long, default_value_t = 1, help = "Start of port range")]
    start_port: u16,

    #[arg(long, default_value_t = 1024, help = "End of port range")]
    end_port: u16,

    #[arg(long, help = "Save results to JSON file (e.g., report.json or ./reports/scan.json)")]
    output: Option<String>,

    #[arg(short = 'w', long, default_value_t = 1000, help = "Max concurrent connections (tune to your OS limits)")]
    workers: usize,

    #[arg(short = 'p', long, help = "Specific ports to scan, comma-separated (e.g., 22,80,443). Overrides --start-port/--end-port")]
    ports: Option<String>,

    #[arg(long, help = "Disable banner grabbing for faster scans")]
    no_banner: bool,
}

struct ScanConfig {
    target: String,
    timeout: u64,
    ports: Vec<u16>,
    output: Option<String>,
    workers: usize,
    banner: bool,
}

const BLOCKED_IPS: &[&str] = &["169.254.169.254", "100.100.100.200"];

fn parse_targets(target: &str) -> Result<Vec<IpAddr>> {
    if target.contains('/') {
        let net = target
            .parse::<IpNet>()
            .with_context(|| format!("Invalid CIDR block: '{}'", target))?;

        if net.prefix_len() < 16 {
            bail!("CIDR block too large. Maximum allowed prefix is /16 (65534 hosts).");
        }

        Ok(net.hosts().collect())
    } else if let Ok(ip) = target.parse::<IpAddr>() {
        if BLOCKED_IPS.contains(&target) {
            bail!("Scanning '{}' is prohibited.", target);
        }
        Ok(vec![ip])
    } else {
        let addr = format!("{}:0", target);
        let ips: Vec<IpAddr> = addr
            .to_socket_addrs()
            .with_context(|| format!("Could not resolve hostname: '{}'", target))?
            .map(|sa| sa.ip())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        if ips.is_empty() {
            bail!("No IP addresses found for hostname: '{}'", target);
        }

        println!("  Resolved '{}' -> {:?}", target, ips);
        Ok(ips)
    }
}

fn parse_ports(ports_arg: Option<&str>, start_port: u16, end_port: u16) -> Result<Vec<u16>> {
    let mut ports = if let Some(ports_str) = ports_arg {
        let parsed: Result<Vec<u16>, _> = ports_str
            .split(',')
            .map(|p| p.trim().parse::<u16>())
            .collect();
        parsed.with_context(|| {
            format!(
                "Invalid port list: '{}'. Use comma-separated ports, e.g., 22,80,443",
                ports_str
            )
        })?
    } else {
        if start_port > end_port {
            bail!(
                "Start port ({}) cannot be greater than end port ({}).",
                start_port,
                end_port
            );
        }
        (start_port..=end_port).collect()
    };

    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

fn detect_service(port: u16, banner: Option<&str>) -> Option<String> {
    if let Some(b) = banner {
        if b.starts_with("SSH-") {
            return Some("SSH".to_string());
        }
        if b.starts_with("HTTP") || b.contains("HTTP/") {
            return Some("HTTP".to_string());
        }
        if b.starts_with("220 ") && b.to_uppercase().contains("FTP") {
            return Some("FTP".to_string());
        }
        if b.starts_with("220 ") {
            return Some("SMTP".to_string());
        }
        if b.starts_with("+OK") {
            return Some("POP3".to_string());
        }
        if b.starts_with("* OK") {
            return Some("IMAP".to_string());
        }
        if b.contains("redis_version") || b.starts_with("-ERR") {
            return Some("Redis".to_string());
        }
    }

    Some(
        match port {
            21 => "FTP",
            22 => "SSH",
            23 => "Telnet",
            25 | 587 => "SMTP",
            53 => "DNS",
            80 | 8080 | 8000 => "HTTP",
            110 => "POP3",
            143 => "IMAP",
            443 | 8443 => "HTTPS",
            445 => "SMB",
            3306 => "MySQL",
            5432 => "PostgreSQL",
            6379 => "Redis",
            27017 => "MongoDB",
            _ => return None,
        }
        .to_string(),
    )
}

async fn read_banner(stream: &mut TcpStream, timeout_ms: u64) -> Option<String> {
    let mut buf = [0u8; 256];
    match timeout(Duration::from_millis(timeout_ms), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let banner = String::from_utf8_lossy(&buf[..n])
                .trim()
                .chars()
                .filter(|c| c.is_ascii_graphic() || *c == ' ')
                .collect::<String>();
            if banner.is_empty() {
                None
            } else {
                Some(banner)
            }
        }
        _ => None,
    }
}

async fn scan_port(
    ip: IpAddr,
    port: u16,
    timeout_ms: u64,
    grab_banner: bool,
) -> Result<Option<String>> {
    let addr = SocketAddr::new(ip, port);
    let mut stream =
        timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await??;

    let banner = if grab_banner {
        read_banner(&mut stream, 500).await
    } else {
        None
    };

    Ok(banner)
}

fn validate_output_path(file_path: &str) -> Result<&Path> {
    let path = Path::new(file_path);

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            bail!("Output directory does not exist: '{}'", parent.display());
        }
    }

    if path.file_name().is_none() {
        bail!("Invalid output filename: '{}'", file_path);
    }

    Ok(path)
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = if std::env::args().len() > 1 {
        let args = Args::parse();
        let ports = parse_ports(args.ports.as_deref(), args.start_port, args.end_port)?;
        ScanConfig {
            target: args.target.context("--target is required in CLI mode")?,
            timeout: args.timeout,
            ports,
            output: args.output,
            workers: args.workers,
            banner: !args.no_banner,
        }
    } else {
        print!("{}[2J", 27 as char);
        println!(
            r#"
  ___  ___  ___  _____      ___  ___  ___  _  _
 | _ \/ _ \| _ \|_   _|___ / __|/ __|/ _ \| \| |
 |  _/ (_) |   /  | | |___|\__ \ (__|  _  | .` |
 |_|  \___/|_|_\  |_|      |___/\___|_| |_|\_|
        "#
        );
        println!("==================================================");
        println!("Advanced Asynchronous Port Scanner - Rust Edition");
        println!("==================================================\n");

        let target =
            Text::new("Target (IP, hostname, or CIDR, e.g., 127.0.0.1, google.com, 192.168.0.0/24):")
                .with_default("127.0.0.1")
                .prompt()?;

        let timeout = CustomType::<u64>::new("Connection timeout (ms):")
            .with_default(200)
            .prompt()?;

        let start_port = CustomType::<u16>::new("Start port:")
            .with_default(1)
            .prompt()?;

        let end_port = CustomType::<u16>::new("End port:")
            .with_default(1024)
            .prompt()?;

        let workers = CustomType::<usize>::new("Max concurrent connections (workers):")
            .with_default(1000)
            .prompt()?;

        let output_str =
            Text::new("Save to JSON? (Leave blank to skip, or enter filename, e.g., scan.json):")
                .prompt()?;

        let output = if output_str.trim().is_empty() {
            None
        } else {
            Some(output_str)
        };

        ScanConfig {
            target,
            timeout,
            ports: (start_port..=end_port).collect(),
            output,
            workers,
            banner: true,
        }
    };

    if config.workers == 0 {
        bail!("Workers count must be greater than 0.");
    }

    if config.ports.is_empty() {
        bail!("Port list is empty. Check --start-port/--end-port or --ports.");
    }

    let ips_to_scan = parse_targets(&config.target)?;
    let total_tasks = (ips_to_scan.len() as u64) * (config.ports.len() as u64);

    println!("\nStarting scan on {} target(s)", ips_to_scan.len());
    println!(
        "Ports: {} | Workers: {} | Timeout: {}ms | Banner grabbing: {} | Total connections: {}",
        config.ports.len(),
        config.workers,
        config.timeout,
        if config.banner { "on" } else { "off" },
        total_tasks
    );

    let (tx, mut rx) = mpsc::channel::<(IpAddr, u16, Option<String>)>(200);
    let pb = ProgressBar::new(total_tasks);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?
            .progress_chars("#>-"),
    );

    let receiver_handle = tokio::spawn(async move {
        let mut open_ports_data: Vec<ScanResult> = Vec::new();
        while let Some((open_ip, open_port, banner)) = rx.recv().await {
            let service = detect_service(open_port, banner.as_deref());
            open_ports_data.push(ScanResult {
                ip: open_ip.to_string(),
                port: open_port,
                status: "OPEN".to_string(),
                service,
                banner,
            });
        }
        open_ports_data
    });

    let semaphore = Arc::new(Semaphore::new(config.workers));
    let ports = Arc::new(config.ports);

    for ip in ips_to_scan {
        for &port in ports.iter() {
            let tx = tx.clone();
            let pb_clone = pb.clone();
            let timeout_ms = config.timeout;
            let grab_banner = config.banner;
            let permit = semaphore.clone().acquire_owned().await?;

            tokio::spawn(async move {
                if let Ok(banner) = scan_port(ip, port, timeout_ms, grab_banner).await {
                    let service = detect_service(port, banner.as_deref());
                    let label = match (&service, &banner) {
                        (Some(s), Some(b)) => format!("  [+] {}:{} [OPEN] {} | {}", ip, port, s, b),
                        (Some(s), None) => format!("  [+] {}:{} [OPEN] {}", ip, port, s),
                        _ => format!("  [+] {}:{} [OPEN]", ip, port),
                    };
                    pb_clone.println(label);
                    let _ = tx.send((ip, port, banner)).await;
                }
                pb_clone.inc(1);
                drop(permit);
            });
        }
    }

    drop(tx);

    pb.finish_with_message("Scan completed!");

    let open_ports_data = receiver_handle.await?;

    println!("\nScan finished. {} open port(s) found.", open_ports_data.len());

    if !open_ports_data.is_empty() {
        if let Some(file_path) = config.output {
            let path = validate_output_path(&file_path)?;
            let json_data = serde_json::to_string_pretty(&open_ports_data)?;
            fs::write(path, json_data)?;
            println!("JSON report saved to: {}", path.display());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_parse_single_ip() {
        let targets = parse_targets("192.168.1.10").unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0], IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
    }

    #[test]
    fn test_parse_cidr_slash24() {
        let targets = parse_targets("10.0.0.0/24").unwrap();
        assert_eq!(targets.len(), 254);
    }

    #[test]
    fn test_parse_cidr_too_large() {
        let result = parse_targets("10.0.0.0/8");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_blocked_ip() {
        let result = parse_targets("169.254.169.254");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_ip() {
        let result = parse_targets("999.999.999.999");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_cidr() {
        let result = parse_targets("192.168.1.0/99");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ports_range() {
        let ports = parse_ports(None, 80, 82).unwrap();
        assert_eq!(ports, vec![80, 81, 82]);
    }

    #[test]
    fn test_parse_ports_list() {
        let ports = parse_ports(Some("22,80,443"), 1, 1024).unwrap();
        assert_eq!(ports, vec![22, 80, 443]);
    }

    #[test]
    fn test_parse_ports_dedup() {
        let ports = parse_ports(Some("80,443,80,443,8080"), 1, 1024).unwrap();
        assert_eq!(ports, vec![80, 443, 8080]);
    }

    #[test]
    fn test_parse_ports_inverted_range() {
        let result = parse_ports(None, 1024, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ports_invalid() {
        let result = parse_ports(Some("80,abc,443"), 1, 1024);
        assert!(result.is_err());
    }

    #[test]
    fn test_detect_service_by_port() {
        assert_eq!(detect_service(22, None), Some("SSH".to_string()));
        assert_eq!(detect_service(80, None), Some("HTTP".to_string()));
        assert_eq!(detect_service(12345, None), None);
    }

    #[test]
    fn test_detect_service_by_banner() {
        assert_eq!(
            detect_service(9999, Some("SSH-2.0-OpenSSH_8.9")),
            Some("SSH".to_string())
        );
        assert_eq!(
            detect_service(9999, Some("+OK POP3 ready")),
            Some("POP3".to_string())
        );
    }

    #[test]
    fn test_validate_output_path_valid() {
        assert!(validate_output_path("report.json").is_ok());
        assert!(validate_output_path("./report.json").is_ok());
    }

    #[test]
    fn test_validate_output_path_invalid_dir() {
        let result = validate_output_path("/nonexistent_dir_xyz/report.json");
        assert!(result.is_err());
    }
}

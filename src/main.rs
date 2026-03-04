use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::{CustomType, Text};
use ipnet::IpNet;
use serde::Serialize;
use std::error::Error;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::timeout;

#[derive(Serialize)]
struct ScanResult {
    ip: String,
    port: u16,
    status: String,
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Advanced Asynchronous Port Scanner", long_about = None)]
struct Args {
    #[arg(short = 't', long)]
    target: String,

    #[arg(short = 'o', long, default_value_t = 200)]
    timeout: u64,

    #[arg(long, default_value_t = 1)]
    start_port: u16,

    #[arg(long, default_value_t = 1024)]
    end_port: u16,

    #[arg(long)]
    output: Option<String>,
}

struct ScanConfig {
    target: String,
    timeout: u64,
    start_port: u16,
    end_port: u16,
    output: Option<String>,
}

fn parse_targets(target: &str) -> Result<Vec<IpAddr>, Box<dyn Error>> {
    if target.contains('/') {
        let net = target.parse::<IpNet>()?;
        Ok(net.hosts().collect())
    } else {
        let ip = target.parse::<IpAddr>()?;
        Ok(vec![ip])
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = if std::env::args().len() > 1 {
        let args = Args::parse();
        ScanConfig {
            target: args.target,
            timeout: args.timeout,
            start_port: args.start_port,
            end_port: args.end_port,
            output: args.output,
        }
    } else {
        print!("{}[2J", 27 as char);
        println!(r#"
  ___  ___  ___  _____      ___  ___  ___  _  _ 
 | _ \/ _ \| _ \|_   _|___ / __|/ __|/ _ \| \| |
 |  _/ (_) |   /  | | |___|\__ \ (__|  _  | .` |
 |_|  \___/|_|_\  |_|      |___/\___|_| |_|\_|
        "#);
        println!("==================================================");
        println!("Advanced Asynchronous Port Scanner - Rust Edition");
        println!("==================================================\n");

        let target = Text::new("Target (IP or CIDR, e.g., 127.0.0.1 or 192.168.0.0/24):")
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

        let output_str = Text::new("Save to JSON? (Leave blank to skip, or enter filename, e.g., scan.json):")
            .prompt()?;

        let output = if output_str.trim().is_empty() {
            None
        } else {
            Some(output_str)
        };

        ScanConfig {
            target,
            timeout,
            start_port,
            end_port,
            output,
        }
    };

    let ips_to_scan = parse_targets(&config.target)?;
    let total_ports = config.end_port - config.start_port + 1;
    let total_tasks = (ips_to_scan.len() as u64) * (total_ports as u64);

    println!("\nStarting scan on {} targets", ips_to_scan.len());
    println!("Timeout: {}ms | Total connections: {}", config.timeout, total_tasks);

    let (tx, mut rx) = mpsc::channel(100);
    let pb = ProgressBar::new(total_tasks);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ports ({eta})")?
            .progress_chars("#>-"),
    );

    let concurrency_limit = 1000;
    let semaphore = Arc::new(Semaphore::new(concurrency_limit));

    for ip in ips_to_scan {
        for port in config.start_port..=config.end_port {
            let tx = tx.clone();
            let pb_clone = pb.clone();
            let timeout_ms = config.timeout;
            
            let permit = semaphore.clone().acquire_owned().await?;

            tokio::spawn(async move {
                if scan_port(ip, port, timeout_ms).await.is_ok() {
                    let _ = tx.send((ip, port)).await;
                    pb_clone.println(format!("  [+] {} - Port {} [OPEN]", ip, port));
                }
                pb_clone.inc(1);
                
                drop(permit); 
            });
        }
    }

    drop(tx);

    let mut open_ports_data = Vec::new();
    while let Some((open_ip, open_port)) = rx.recv().await {
        open_ports_data.push(ScanResult {
            ip: open_ip.to_string(),
            port: open_port,
            status: "OPEN".to_string(),
        });
    }

    pb.finish_with_message("Scan completed!");

    println!("\nScanning finished.");
    if open_ports_data.is_empty() {
        println!("No open ports found.");
    } else {
        if let Some(file_path) = config.output {

            let path = Path::new(&file_path);
            if let Some(safe_name) = path.file_name() {
                let json_data = serde_json::to_string_pretty(&open_ports_data)?;
                fs::write(safe_name, json_data)?;
                println!("JSON report successfully saved to: {:?}", safe_name);
            } else {
                eprintln!("Security Block: Invalid file path provided. Report not saved.");
            }
        }
    }

    Ok(())
}

async fn scan_port(ip: IpAddr, port: u16, timeout_ms: u64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let address = format!("{}:{}", ip, port);
    timeout(Duration::from_millis(timeout_ms), TcpStream::connect(address)).await??;
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
    fn test_parse_invalid_ip() {
        let result = parse_targets("999.999.999.999");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_cidr() {
        let result = parse_targets("192.168.1.0/99");
        assert!(result.is_err());
    }
}
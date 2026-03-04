use clap::Parser;
use ipnet::IpNet;
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    
    #[arg(short = 't', long)]
    target: String,

    #[arg(short = 'o', long, default_value_t = 200)]
    timeout: u64,

    #[arg(long, default_value_t = 1)]
    start_port: u16,

    #[arg(long, default_value_t = 1024)]
    end_port: u16,
}

#[tokio::main]
async fn main() {

    let args = Args::parse();
    let (tx, mut rx) = mpsc::channel(100);
    let ips_to_scan: Vec<IpAddr> = if args.target.contains('/') {

        let net: IpNet = args.target.parse().expect("Formato CIDR inválido. Use algo como 192.168.1.0/24");
        net.hosts().collect()
    } else {

        let ip: IpAddr = args.target.parse().expect("Formato de IP inválido. Use algo como 127.0.0.1");
        vec![ip]

    };

    println!("Iniciando varredura em {} alvos (Alvo base: {})", ips_to_scan.len(), args.target);
    println!("Timeout: {}ms | Portas: {} a {}", args.timeout, args.start_port, args.end_port);

    for ip in ips_to_scan {
        for port in args.start_port..=args.end_port {

            let tx = tx.clone();
            let timeout_ms = args.timeout;

            
            tokio::spawn(async move {
                if scan_port(ip, port, timeout_ms).await.is_ok() {
                    let _ = tx.send((ip, port)).await;
                }
            });
        }
    }

    drop(tx);

    println!("\n Resultados:");
    let mut found_any = false;
    
    while let Some((open_ip, open_port)) = rx.recv().await {
        println!("  [+] {} - Porta {} [OPEN]", open_ip, open_port);
        found_any = true;
    }

    if !found_any {
        println!("  Nenhuma porta aberta encontrada.");
    }
}

async fn scan_port(ip: IpAddr, port: u16, timeout_ms: u64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let address = format!("{}:{}", ip, port);
    timeout(Duration::from_millis(timeout_ms), TcpStream::connect(address)).await??;
    Ok(())
}
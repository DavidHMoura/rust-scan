use clap::Parser;
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short = 't', long)]
    target: IpAddr,

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

    println!("Iniciando varredura em {}", args.target);
    println!("Timeout: {}ms | Portas: {} a {}", args.timeout, args.start_port, args.end_port);

    for port in args.start_port..=args.end_port {
        let tx = tx.clone();
        let target = args.target;
        let timeout_ms = args.timeout;

        tokio::spawn(async move {
            if scan_port(target, port, timeout_ms).await.is_ok() {
                let _ = tx.send(port).await;
            }
        });
    }

    drop(tx);

    while let Some(open_port) = rx.recv().await {
        println!("  [+] Porta {} está ABERTA", open_port);
    }

    println!("Varredura concluída.");
}

async fn scan_port(ip: IpAddr, port: u16, timeout_ms: u64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let address = format!("{}:{}", ip, port);
    timeout(Duration::from_millis(timeout_ms), TcpStream::connect(address)).await??;
    Ok(())
}
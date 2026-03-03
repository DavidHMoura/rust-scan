use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    let target_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let (tx, mut rx) = mpsc::channel(100);
    
    println!("Iniciando varredura assíncrona em {}...", target_ip);

    for port in 1..=1024 {
        let tx = tx.clone();
        tokio::spawn(async move {
            if scan_port(target_ip, port).await.is_ok() {
                let _ = tx.send(port).await;
            }
        });
    }

    drop(tx);

    println!("Portas abertas encontradas:");
    while let Some(open_port) = rx.recv().await {
        println!("Porta {} [OPEN]", open_port);
    }
    
    println!("Varredura finalizada.");
}

async fn scan_port(ip: IpAddr, port: u16) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let address = format!("{}:{}", ip, port);
    timeout(Duration::from_millis(200), TcpStream::connect(address)).await??;
    Ok(())
}
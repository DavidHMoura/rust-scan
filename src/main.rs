use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use ipnet::IpNet;
use serde::Serialize;
use std::fs;
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

#[derive(Serialize)]
struct ScanResult {
    ip: String,
    port: u16,
    status: String,
}

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

    #[arg(long)]
    output: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let (tx, mut rx) = mpsc::channel(100);

    let ips_to_scan: Vec<IpAddr> = if args.target.contains('/') {
        let net: IpNet = args.target.parse().expect("Formato CIDR inválido.");
        net.hosts().collect()
    } else {
        let ip: IpAddr = args.target.parse().expect("Formato de IP inválido.");
        vec![ip]
    };

    let total_ports = args.end_port - args.start_port + 1;
    let total_tasks = (ips_to_scan.len() as u64) * (total_ports as u64);

    println!(" Iniciando varredura em {} alvos", ips_to_scan.len());
    println!(" Timeout: {}ms | Total de conexões: {}", args.timeout, total_tasks);

    let pb = ProgressBar::new(total_tasks);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} portas ({eta})")
            .expect("Falha no template da barra")
            .progress_chars("#>-"),
    );

    for ip in ips_to_scan {
        for port in args.start_port..=args.end_port {
            let tx = tx.clone();
            let pb_clone = pb.clone();
            let timeout_ms = args.timeout;

            tokio::spawn(async move {
                if scan_port(ip, port, timeout_ms).await.is_ok() {
                    let _ = tx.send((ip, port)).await;
                    pb_clone.println(format!("  [+] {} - Porta {} [OPEN]", ip, port));
                }
                pb_clone.inc(1);
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

    pb.finish_with_message("Varredura concluída!");

    println!("\n Escaneamento finalizado.");
    if open_ports_data.is_empty() {
        println!("Nenhuma porta aberta encontrada.");
    } else {

        if let Some(file_path) = args.output {
            let json_data = serde_json::to_string_pretty(&open_ports_data).expect("Erro ao serializar JSON");
            
            fs::write(&file_path, json_data).expect("Erro ao salvar arquivo JSON no disco");
            println!(" Relatório JSON salvo com sucesso em: {}", file_path);
        }
    }
}

async fn scan_port(ip: IpAddr, port: u16, timeout_ms: u64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let address = format!("{}:{}", ip, port);
    timeout(Duration::from_millis(timeout_ms), TcpStream::connect(address)).await??;
    Ok(())
}
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::{CustomType, Text};
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

// Estrutura unificada para armazenar a configuração final, independente da origem
struct ScanConfig {
    target: String,
    timeout: u64,
    start_port: u16,
    end_port: u16,
    output: Option<String>,
}

#[tokio::main]
async fn main() {
    let config = if std::env::args().len() > 1 {
        // Modo CLI (Automação / Flags diretas)
        let args = Args::parse();
        ScanConfig {
            target: args.target,
            timeout: args.timeout,
            start_port: args.start_port,
            end_port: args.end_port,
            output: args.output,
        }
    } else {
        // Modo Interativo (Wizard TUI)
        print!("{}[2J", 27 as char); // Limpa a tela do terminal (código ANSI)
        println!(r#"
  ___  ___  ___  _____      ___  ___  ___  _  _ 
 | _ \/ _ \| _ \|_   _|___ / __|/ __|/ _ \| \| |
 |  _/ (_) |   /  | | |___|\__ \ (__|  _  | .` |
 |_|  \___/|_|_\  |_|      |___/\___|_| |_|\_|
        "#);
        println!("==================================================");
        println!("Advanced Asynchronous Port Scanner - Rust Edition");
        println!("==================================================\n");

        let target = Text::new("Alvo (IP ou CIDR, ex: 127.0.0.1 ou 192.168.0.0/24):")
            .with_default("127.0.0.1")
            .prompt()
            .unwrap();

        let timeout = CustomType::<u64>::new("Timeout por conexão (ms):")
            .with_default(200)
            .prompt()
            .unwrap();

        let start_port = CustomType::<u16>::new("Porta inicial:")
            .with_default(1)
            .prompt()
            .unwrap();

        let end_port = CustomType::<u16>::new("Porta final:")
            .with_default(1024)
            .prompt()
            .unwrap();

        let output_str = Text::new("Salvar em JSON? (Deixe em branco para pular, ou digite o nome do arquivo, ex: scan.json):")
            .prompt()
            .unwrap();

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

    let (tx, mut rx) = mpsc::channel(100);

    let ips_to_scan: Vec<IpAddr> = if config.target.contains('/') {
        let net: IpNet = config.target.parse().expect("Formato CIDR inválido.");
        net.hosts().collect()
    } else {
        let ip: IpAddr = config.target.parse().expect("Formato de IP inválido.");
        vec![ip]
    };

    let total_ports = config.end_port - config.start_port + 1;
    let total_tasks = (ips_to_scan.len() as u64) * (total_ports as u64);

    println!("\nIniciando varredura em {} alvos", ips_to_scan.len());
    println!("Timeout: {}ms | Total de conexões: {}", config.timeout, total_tasks);

    let pb = ProgressBar::new(total_tasks);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} portas ({eta})")
            .expect("Falha no template da barra")
            .progress_chars("#>-"),
    );

    for ip in ips_to_scan {
        for port in config.start_port..=config.end_port {
            let tx = tx.clone();
            let pb_clone = pb.clone();
            let timeout_ms = config.timeout;

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

    println!("\nEscaneamento finalizado.");
    if open_ports_data.is_empty() {
        println!("Nenhuma porta aberta encontrada.");
    } else {
        if let Some(file_path) = config.output {
            let json_data = serde_json::to_string_pretty(&open_ports_data).expect("Erro ao serializar JSON");
            fs::write(&file_path, json_data).expect("Erro ao salvar arquivo JSON no disco");
            println!("Relatório JSON salvo com sucesso em: {}", file_path);
        }
    }
}

async fn scan_port(ip: IpAddr, port: u16, timeout_ms: u64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let address = format!("{}:{}", ip, port);
    timeout(Duration::from_millis(timeout_ms), TcpStream::connect(address)).await??;
    Ok(())
}
use cidr::Ipv6Cidr;
use getopts::Options;
use std::{env, process::exit, net::SocketAddr};
use base64;
use log::{info, error};
use env_logger::Env;

mod proxy;
use crate::proxy::{start_http_proxy, start_socks5_proxy};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logger
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("b", "bind", "HTTP proxy bind address", "BIND");
    opts.optopt("s", "socks", "SOCKS5 proxy bind address", "SOCKS");
    opts.optopt(
        "i",
        "ipv6-subnet",
        "IPv6 Subnet: 2001:19f0:6001:48e4::/64",
        "IPv6_SUBNET",
    );
    opts.optopt("u", "username", "Username for proxy authentication", "USERNAME");
    opts.optopt("p", "password", "Password for proxy authentication", "PASSWORD");
    opts.optflag("h", "help", "print this help menu");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            error!("Failed to parse command line arguments: {}", f);
            exit(1);
        }
    };

    if matches.opt_present("h") {
        print_usage(&program, opts);
        return Ok(());
    }

    let http_bind_addr = matches.opt_str("b").unwrap_or("0.0.0.0:51080".to_string());
    let socks_bind_addr = matches.opt_str("s").unwrap_or("0.0.0.0:51090".to_string());
    let ipv6_subnet = matches
        .opt_str("i")
        .unwrap_or("2001:19f0:6001:48e4::/64".to_string());
    let username = matches.opt_str("u");
    let password = matches.opt_str("p");

    run(http_bind_addr, socks_bind_addr, ipv6_subnet, username, password).await
}

async fn run(
    http_bind_addr: String,
    socks_bind_addr: String,
    ipv6_subnet: String,
    username: Option<String>,
    password: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ipv6 = match ipv6_subnet.parse::<Ipv6Cidr>() {
        Ok(cidr) => {
            let a = cidr.first_address();
            let b = cidr.network_length();
            (a, b)
        }
        Err(e) => {
            error!("Invalid IPv6 subnet: {}", e);
            exit(1);
        }
    };

    let http_bind_addr: SocketAddr = match http_bind_addr.parse() {
        Ok(addr) => addr,
        Err(e) => {
            error!("Invalid HTTP bind address: {}", e);
            exit(1);
        }
    };

    let socks_bind_addr: SocketAddr = match socks_bind_addr.parse() {
        Ok(addr) => addr,
        Err(e) => {
            error!("Invalid SOCKS5 bind address: {}", e);
            exit(1);
        }
    };

    let auth = match (username, password) {
        (Some(u), Some(p)) => Some(base64::encode(format!("{}:{}", u, p))),
        (None, None) => None,
        _ => {
            error!("Both username and password must be provided for authentication");
            exit(1);
        }
    };

    info!("Starting proxy server with IPv6 subnet: {}", ipv6_subnet);
    if auth.is_some() {
        info!("Authentication enabled");
    }

    let http_future = start_http_proxy(http_bind_addr, ipv6, auth.clone());
    let socks_future = start_socks5_proxy(socks_bind_addr, ipv6, auth);

    tokio::select! {
        result = http_future => {
            if let Err(e) = result {
                error!("HTTP proxy error: {}", e);
            }
        }
        result = socks_future => {
            if let Err(e) = result {
                error!("SOCKS5 proxy error: {}", e);
            }
        }
    }

    Ok(())
}
/*
 * @Author: Vincent Yang
 * @Date: 2024-09-11 12:45:59
 * @LastEditors: Vincent Yang
 * @LastEditTime: 2024-09-14 14:57:40
 * @FilePath: /http-proxy-ipv6-pool/src/proxy.rs
 * @Telegram: https://t.me/missuo
 * @GitHub: https://github.com/missuo
 * 
 * Copyright © 2024 by Vincent, All Rights Reserved. 
 */
use cidr::Ipv6Cidr;
use getopts::Options;
use std::{env, process::exit, net::SocketAddr};
use base64;

mod proxy; // 确保 proxy.rs 在同一目录下
use crate::proxy::{start_http_proxy, start_socks5_proxy};

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
            panic!("{}", f.to_string())
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
        Err(_) => {
            println!("invalid IPv6 subnet");
            exit(1);
        }
    };

    let http_bind_addr: SocketAddr = http_bind_addr.parse()?;
    let socks_bind_addr: SocketAddr = socks_bind_addr.parse()?;

    let auth = match (username, password) {
        (Some(u), Some(p)) => Some(base64::encode(format!("{}:{}", u, p))),
        _ => None,
    };

    let http_future = start_http_proxy(http_bind_addr, ipv6, auth.clone());
    let socks_future = start_socks5_proxy(socks_bind_addr, ipv6, auth);

    tokio::try_join!(http_future, socks_future)?;

    Ok(())
}
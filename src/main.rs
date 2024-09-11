mod proxy;

use cidr::Ipv6Cidr;
use getopts::Options;
use proxy::start_proxy;
use std::{env, process::exit};
use base64;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt("b", "bind", "http proxy bind address", "BIND");
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
        return;
    }

    let bind_addr = matches.opt_str("b").unwrap_or("0.0.0.0:51080".to_string());
    let ipv6_subnet = matches
        .opt_str("i")
        .unwrap_or("2001:19f0:6001:48e4::/64".to_string());
    let username = matches.opt_str("u");
    let password = matches.opt_str("p");

    run(bind_addr, ipv6_subnet, username, password)
}

#[tokio::main]
async fn run(bind_addr: String, ipv6_subnet: String, username: Option<String>, password: Option<String>) {
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

    let bind_addr = match bind_addr.parse() {
        Ok(b) => b,
        Err(e) => {
            println!("bind address not valid: {}", e);
            return;
        }
    };

    let auth = match (username, password) {
        (Some(u), Some(p)) => Some(base64::encode(format!("{}:{}", u, p))),
        _ => None,
    };

    if let Err(e) = start_proxy(bind_addr, ipv6, auth).await {
        println!("{}", e);
    }
}
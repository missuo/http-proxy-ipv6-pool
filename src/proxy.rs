use hyper::{
    client::HttpConnector,
    server::conn::AddrStream,
    service::{make_service_fn, service_fn},
    Body, Client, Method, Request, Response, Server, StatusCode,
};
use rand::Rng;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
};
use std::io::Error as IoError;

pub async fn start_http_proxy(
    listen_addr: SocketAddr,
    (ipv6, prefix_len): (Ipv6Addr, u8),
    auth: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let make_service = make_service_fn(move |_: &AddrStream| {
        let auth = auth.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                Proxy {
                    ipv6: ipv6.into(),
                    prefix_len,
                    auth: auth.clone(),
                }
                .proxy(req)
            }))
        }
    });

    Server::bind(&listen_addr)
        .http1_preserve_header_case(true)
        .http1_title_case_headers(true)
        .serve(make_service)
        .await
        .map_err(|err| err.into())
}

pub async fn start_socks5_proxy(
    listen_addr: SocketAddr,
    (ipv6, prefix_len): (Ipv6Addr, u8),
    auth: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    println!("SOCKS5 proxy listening on {}", listen_addr);

    loop {
        let (stream, _) = listener.accept().await?;
        let proxy = Proxy {
            ipv6: ipv6.into(),
            prefix_len,
            auth: auth.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = proxy.handle_socks5(stream).await {
                eprintln!("SOCKS5 error: {}", e);
            }
        });
    }
}

#[derive(Clone)]
pub(crate) struct Proxy {
    pub ipv6: u128,
    pub prefix_len: u8,
    pub auth: Option<String>,
}

impl Proxy {
    pub(crate) async fn proxy(self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        if self.auth.is_some() && !self.is_authorized(&req) {
            return Ok(Response::builder()
                .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .header("Proxy-Authenticate", "Basic realm=\"Proxy\"")
                .body(Body::empty())
                .unwrap());
        }
    
        match if req.method() == Method::CONNECT {
            self.process_connect(req).await
        } else {
            self.process_request(req).await
        } {
            Ok(resp) => Ok(resp),
            Err(e) => Err(e),
        }
    }

    fn is_authorized(&self, req: &Request<Body>) -> bool {
        self.auth.as_ref().map_or(true, |auth| {
            req.headers()
                .get("Proxy-Authorization")
                .and_then(|value| value.to_str().ok())
                .map(|value| value == format!("Basic {}", auth))
                .unwrap_or(false)
        })
    }

    async fn process_connect(self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        tokio::task::spawn(async move {
            let remote_addr = req.uri().authority().map(|auth| auth.to_string()).unwrap();
            let mut upgraded = hyper::upgrade::on(req).await.unwrap();
            self.tunnel(&mut upgraded, remote_addr).await
        });
        Ok(Response::new(Body::empty()))
    }

    async fn process_request(self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        let bind_addr = get_rand_ipv6(self.ipv6, self.prefix_len);
        let mut http = HttpConnector::new();
        http.set_local_address(Some(bind_addr));
        println!("{} via {bind_addr}", req.uri().host().unwrap_or_default());

        let client = Client::builder()
            .http1_title_case_headers(true)
            .http1_preserve_header_case(true)
            .build(http);
        let res = client.request(req).await?;
        Ok(res)
    }

    async fn tunnel<A>(self, upgraded: &mut A, addr_str: String) -> std::io::Result<()>
    where
        A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    {
        if let Ok(addrs) = addr_str.to_socket_addrs() {
            for addr in addrs {
                let socket = TcpSocket::new_v6()?;
                let bind_addr = get_rand_ipv6_socket_addr(self.ipv6, self.prefix_len);
                if socket.bind(bind_addr).is_ok() {
                    println!("{addr_str} via {bind_addr}");
                    if let Ok(mut server) = socket.connect(addr).await {
                        tokio::io::copy_bidirectional(upgraded, &mut server).await?;
                        return Ok(());
                    }
                }
            }
        } else {
            println!("error: {addr_str}");
        }

        Ok(())
    }

    async fn handle_socks5(&self, mut stream: TcpStream) -> Result<(), IoError> {
        // SOCKS5 handshake
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;

        if buf[0] != 5 {
            return Err(IoError::new(std::io::ErrorKind::InvalidData, "Not SOCKS5"));
        }

        let auth_methods = buf[1] as usize;
        let mut methods = vec![0u8; auth_methods];
        stream.read_exact(&mut methods).await?;

        let auth_method = if self.auth.is_some() && methods.contains(&2) {
            2 // Username/Password authentication
        } else if methods.contains(&0) {
            0 // No authentication
        } else {
            255 // No acceptable methods
        };

        stream.write_all(&[5, auth_method]).await?;

        if auth_method == 255 {
            return Err(IoError::new(std::io::ErrorKind::PermissionDenied, "No acceptable auth methods"));
        }

        if auth_method == 2 {
            // Perform username/password authentication
            if !self.socks5_auth(&mut stream).await? {
                return Err(IoError::new(std::io::ErrorKind::PermissionDenied, "Authentication failed"));
            }
        }

        // Handle SOCKS5 request
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await?;

        if buf[0] != 5 || buf[1] != 1 || buf[2] != 0 {
            return Err(IoError::new(std::io::ErrorKind::InvalidData, "Invalid SOCKS5 request"));
        }

        let addr = match buf[3] {
            1 => { // IPv4
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await?;
                IpAddr::V4(addr.into())
            },
            3 => { // Domain name
                let len = stream.read_u8().await? as usize;
                let mut domain = vec![0u8; len];
                stream.read_exact(&mut domain).await?;
                let domain = String::from_utf8_lossy(&domain).to_string();
                match domain.to_socket_addrs() {
                    Ok(mut addrs) => addrs.next().ok_or_else(|| IoError::new(std::io::ErrorKind::AddrNotAvailable, "Unable to resolve domain"))?.ip(),
                    Err(_) => return Err(IoError::new(std::io::ErrorKind::AddrNotAvailable, "Unable to resolve domain")),
                }
            },
            4 => { // IPv6
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await?;
                IpAddr::V6(addr.into())
            },
            _ => return Err(IoError::new(std::io::ErrorKind::InvalidData, "Unsupported address type")),
        };

        let port = stream.read_u16().await?;
        let remote_addr = SocketAddr::new(addr, port);

        // Connect to the target
        let socket = TcpSocket::new_v6()?;
        let bind_addr = get_rand_ipv6_socket_addr(self.ipv6, self.prefix_len);
        socket.bind(bind_addr)?;
        
        match socket.connect(remote_addr).await {
            Ok(mut remote_stream) => {
                // Send success response
                stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                
                // Start proxying data
                tokio::io::copy_bidirectional(&mut stream, &mut remote_stream).await?;
                Ok(())
            },
            Err(_) => {
                // Send failure response
                stream.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                Err(IoError::new(std::io::ErrorKind::ConnectionRefused, "Unable to connect to target"))
            }
        }
    }

    async fn socks5_auth(&self, stream: &mut TcpStream) -> Result<bool, IoError> {
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;

        if buf[0] != 1 {
            return Ok(false);
        }

        let ulen = buf[1] as usize;
        let mut username = vec![0u8; ulen];
        stream.read_exact(&mut username).await?;

        let plen = stream.read_u8().await? as usize;
        let mut password = vec![0u8; plen];
        stream.read_exact(&mut password).await?;

        let auth_str = format!("{}:{}", String::from_utf8_lossy(&username), String::from_utf8_lossy(&password));
        let is_valid = self.auth.as_ref().map_or(false, |auth| &base64::encode(auth_str) == auth);

        if is_valid {
            stream.write_all(&[1, 0]).await?; // Success
        } else {
            stream.write_all(&[1, 1]).await?; // Failure
        }

        Ok(is_valid)
    }
}

fn get_rand_ipv6_socket_addr(ipv6: u128, prefix_len: u8) -> SocketAddr {
    let mut rng = rand::thread_rng();
    SocketAddr::new(get_rand_ipv6(ipv6, prefix_len), rng.gen::<u16>())
}

fn get_rand_ipv6(mut ipv6: u128, prefix_len: u8) -> IpAddr {
    let rand: u128 = rand::thread_rng().gen();
    let net_part = (ipv6 >> (128 - prefix_len)) << (128 - prefix_len);
    let host_part = (rand << prefix_len) >> prefix_len;
    ipv6 = net_part | host_part;
    IpAddr::V6(ipv6.into())
}
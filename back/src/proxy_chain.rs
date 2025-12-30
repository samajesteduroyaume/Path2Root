use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, error};

#[derive(Clone, Debug)]
pub struct ProxyNode {
    pub address: SocketAddr,
    pub auth: Option<(String, String)>,
}

pub struct ProxyChain {
    pub chain: Vec<ProxyNode>,
}

impl ProxyChain {
    pub fn new(proxies: Vec<ProxyNode>) -> Self {
        Self { chain: proxies }
    }

    /// Établit une connexion TCP à travers la chaîne de proxies SOCKS5
    pub async fn connect(&self, target: &str) -> std::io::Result<TcpStream> {
        if self.chain.is_empty() {
            return TcpStream::connect(target).await;
        }

        info!("🔗 Establishing Proxy Chain with {} hops...", self.chain.len());

        // Connect to the first proxy
        let mut stream = TcpStream::connect(self.chain[0].address).await?;
        
        // Handshake with first proxy
        self.socks5_handshake(&mut stream).await?;
        
        // If there are more proxies, tell the current one to connect to the next
        for i in 0..self.chain.len() - 1 {
            let next_proxy = &self.chain[i+1];
            self.socks5_connect(&mut stream, &next_proxy.address.to_string()).await?;
            // Now we are "at" the next proxy, we might need to auth again depending on protocol implementation
            // Ideally, a true chain wraps streams, but for SOCKS5 chaining usually involves CONNECT to next SOCKS server
            // and treating the resulting stream as the new connection.
        }

        // Finally connect to the ultimate target
        self.socks5_connect(&mut stream, target).await?;

        info!("✅ Proxy Chain Established to {}", target);
        Ok(stream)
    }

    async fn socks5_handshake(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        // Method selection: No Auth (0x00)
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        
        if buf[0] != 0x05 || buf[1] != 0x00 {
             return Err(std::io::Error::new(std::io::ErrorKind::Other, "SOCKS5 Handshake failed"));
        }
        Ok(())
    }

    async fn socks5_connect(&self, stream: &mut TcpStream, target: &str) -> std::io::Result<()> {
        // Parse target
        let parts: Vec<&str> = target.split(':').collect();
        let host = parts[0];
        let port: u16 = parts.get(1).unwrap_or(&"80").parse().unwrap_or(80);

        let mut request = vec![0x05, 0x01, 0x00, 0x03]; // DOMAIN NAME address type
        request.push(host.len() as u8);
        request.extend_from_slice(host.as_bytes());
        request.extend_from_slice(&port.to_be_bytes());

        stream.write_all(&request).await?;

        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await?; // version + rep + rsv + atyp

        if buf[1] != 0x00 {
             return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("SOCKS5 Connection failed: Rep={}", buf[1])));
        }

        // Read bind addr + port (ignore for client)
        // Depending on ATYP (buf[3]), read variable length
        match buf[3] {
            0x01 => { let mut b = [0u8; 4+2]; stream.read_exact(&mut b).await?; }, // IPv4
            0x03 => { let mut len = [0u8; 1]; stream.read_exact(&mut len).await?; let mut b = vec![0u8; len[0] as usize + 2]; stream.read_exact(&mut b).await?; }, // Domain
            0x04 => { let mut b = [0u8; 16+2]; stream.read_exact(&mut b).await?; }, // IPv6
            _ => return Err(std::io::Error::new(std::io::ErrorKind::Other, "Unknown SOCKS5 address type")),
        }

        Ok(())
    }
}

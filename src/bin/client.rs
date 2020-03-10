use anyhow::{anyhow, bail, Result};
use std::net::ToSocketAddrs;
use tokio::io::{self};

use std::{fs, net::SocketAddr, time::Instant};

#[tokio::main]
async fn main() -> Result<()> {
    let dirs = directories::UserDirs::new().unwrap();
    let path = dirs.home_dir();
    let cert_path = path.join("cert.der");
    let cert = match fs::read(&cert_path) {
        Ok(x) => x,
        Err(e) => {
            bail!("failed to read certificate: {}", e);
        }
    };

    let start = Instant::now();
    let mut endpoint = quinn::Endpoint::builder();
    let mut client_config = quinn::ClientConfigBuilder::default();
    client_config
        .add_certificate_authority(quinn::Certificate::from_der(&cert)?)
        .unwrap();
    endpoint.default_client_config(client_config.build());
    let (endpoint, _) = endpoint.bind(&"[::]:0".parse().unwrap())?;

    let server_details = "quic.iavian.net:54321";
    let mut addrs_iter = server_details.to_socket_addrs().unwrap();
    let remote: SocketAddr = addrs_iter.next().unwrap();
    let host = "quic.iavian.net";

    let new_conn = endpoint
        .connect(&remote, &host)?
        .await
        .map_err(|e| anyhow!("failed to connect: {}", e))?;

    let quinn::NewConnection {
        connection: conn, ..
    } = { new_conn };

    let (mut send, _recv) = conn
        .open_bi()
        .await
        .map_err(|e| anyhow!("failed to open stream: {}", e))?;

    let mut f = tokio::fs::File::open("tfile").await?;
    io::copy(&mut f, &mut send).await?;
    println!("File sent");

    let response_start = Instant::now();
    eprintln!("request sent at {:?}", response_start - start);
    send.finish().await?;
    Ok(())
}

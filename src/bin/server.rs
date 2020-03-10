use anyhow::{bail, Context, Result};
use futures::{StreamExt, TryFutureExt};
use quinn::{Endpoint, Incoming, ServerConfig, ServerConfigBuilder, TransportConfig};
use std::{error::Error, fs, net::SocketAddr, sync::Arc};
use tokio::fs::File;
use tokio::io;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server_addr = "0.0.0.0:54321".parse().unwrap();
    let mut incoming = make_server_endpoint(server_addr)?;

    while let Some(conn) = incoming.next().await {
        println!("<<<incoming connection");
        tokio::spawn(handle_connection(conn));
    }
    Ok(())
}

fn make_server_endpoint(bind_addr: SocketAddr) -> Result<Incoming, Box<dyn Error>> {
    let server_config = configure_server()?;
    let mut endpoint_builder = Endpoint::builder();
    endpoint_builder.listen(server_config);
    let (_endpoint, incoming) = endpoint_builder.bind(&bind_addr)?;
    println!("listening on {}", _endpoint.local_addr()?);
    Ok(incoming)
}

fn configure_server() -> Result<ServerConfig> {
    let dirs = directories::UserDirs::new().unwrap();
    let path = dirs.home_dir();
    let cert_path = path.join("cert.der");
    let key_path = path.join("key.der");
    let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
        Ok(x) => x,
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
            println!("generating self-signed certificate");
            let cert = rcgen::generate_simple_self_signed(vec!["quic.iavian.net".into()]).unwrap();
            let key = cert.serialize_private_key_der();
            let cert = cert.serialize_der().unwrap();
            fs::create_dir_all(&path).context("failed to create certificate directory")?;
            fs::write(&cert_path, &cert).context("failed to write certificate")?;
            fs::write(&key_path, &key).context("failed to write private key")?;
            (cert, key)
        }
        Err(e) => {
            bail!("failed to read certificate: {}", e);
        }
    };
    let key = quinn::PrivateKey::from_der(&key)?;
    let cert = quinn::Certificate::from_der(&cert)?;
    let mut transport_config = TransportConfig::default();
    transport_config.stream_window_uni(0);
    let mut server_config = ServerConfig::default();
    server_config.transport = Arc::new(transport_config);
    let mut cfg_builder = ServerConfigBuilder::new(server_config);
    cfg_builder.certificate(quinn::CertificateChain::from_certs(vec![cert]), key)?;
    cfg_builder.protocols(&[b"i-send"]);
    Ok(cfg_builder.build())
}

async fn handle_connection(conn: quinn::Connecting) -> Result<()> {
    let quinn::NewConnection {
        mut bi_streams,
        ..
    } = conn.await?;
    async {
        println!("connection established");

        while let Some(stream) = bi_streams.next().await {
            let stream = match stream {
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    println!("connection closed");
                    return Ok(());
                }
                Err(e) => {
                    return Err(e);
                }
                Ok(s) => s,
            };
            println!("hello stream");
            tokio::spawn(
                handle_request(stream)
                    .unwrap_or_else(move |e| println!("failed: {reason}", reason = e.to_string())),
            );
        }
        Ok(())
    }
    .await?;
    Ok(())
}

async fn handle_request(
    (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
) -> Result<()> {
    let mut file = File::create("foo.txt").await?;
    tokio::io::copy(&mut recv, &mut file).await?;
    println!("Done file creation");
    send.finish().await?;
    Ok(())
}

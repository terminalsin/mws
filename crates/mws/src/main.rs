use std::net::SocketAddr;
use std::sync::Arc;

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let listen: SocketAddr = std::env::var("MWS_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:4566".into())
        .parse()
        .expect("MWS_LISTEN must be host:port");
    let config = mws::Config::from_env();
    let mws::Mws { gateway, route53 } = match mws::start(config.clone()).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("mws: {e}");
            std::process::exit(1);
        }
    };
    let gateway = Arc::new(gateway);
    if let Ok(dns) = std::env::var("MWS_DNS_LISTEN") {
        let socket = tokio::net::UdpSocket::bind(&dns).await.expect("bind MWS_DNS_LISTEN");
        tracing::info!(%dns, "Route 53 DNS responder listening");
        tokio::spawn(mws_route53::serve_dns(route53, socket));
    }
    let listener = tokio::net::TcpListener::bind(listen).await.expect("bind MWS_LISTEN");

    tracing::info!(
        %listen,
        services = ?gateway.service_names().collect::<Vec<_>>(),
        account_id = %config.iam.account_id,
        root_access_key_id = %config.iam.root_access_key_id,
        db = ?config.db,
        scenario = ?config.scenario,
        "MWS listening; root secret access key is set by MWS_ROOT_SECRET_ACCESS_KEY"
    );
    mws_server::serve(listener, gateway, shutdown_signal()).await;
}

/// Ctrl-C, or SIGTERM (what `docker stop` sends) on Unix.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

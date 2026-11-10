use std::net::SocketAddr;
use std::sync::Arc;

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    if std::env::args().nth(1).as_deref() == Some("bedrock-bridge") {
        return bedrock_bridge().await;
    }

    let listen: SocketAddr = std::env::var("MWS_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:4566".into())
        .parse()
        .expect("MWS_LISTEN must be host:port");
    let config = mws::Config::from_env();
    let mws::Mws { gateway, route53, ses, lambda, .. } = match mws::start(config.clone()).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("mws: {e}");
            std::process::exit(1);
        }
    };
    let gateway = Arc::new(gateway);
    // Lambda's background work (pollers of restored event source mappings)
    // hands functions the URL MWS serves on.
    let weak = Arc::downgrade(&gateway);
    lambda.set_endpoint_source(Arc::new(move || weak.upgrade().and_then(|g| g.endpoint().map(str::to_string))));
    if let Ok(dns) = std::env::var("MWS_DNS_LISTEN") {
        let socket = tokio::net::UdpSocket::bind(&dns).await.expect("bind MWS_DNS_LISTEN");
        let tcp = tokio::net::TcpListener::bind(&dns).await.expect("bind MWS_DNS_LISTEN (TCP)");
        tracing::info!(%dns, "Route 53 DNS responder listening (UDP and TCP)");
        tokio::spawn(mws_route53::serve_dns_tcp(route53.clone(), tcp));
        tokio::spawn(mws_route53::serve_dns(route53, socket));
    }
    if let Ok(smtp) = std::env::var("MWS_SES_SMTP_LISTEN") {
        let tcp = tokio::net::TcpListener::bind(&smtp).await.expect("bind MWS_SES_SMTP_LISTEN");
        tracing::info!(%smtp, "SES SMTP listener (receiving, and submission with SES SMTP credentials)");
        tokio::spawn(mws_ses::serve_smtp(ses, tcp));
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

/// `mws bedrock-bridge [--listen host:port]`: run the local Claude Code and
/// Codex CLIs for an MWS that runs in a container (point its Bedrock CLI
/// providers, or MWS_BEDROCK_CLI_BRIDGE, at this address).
async fn bedrock_bridge() {
    let args: Vec<String> = std::env::args().collect();
    let listen = args
        .iter()
        .position(|a| a == "--listen")
        .and_then(|i| args.get(i + 1).cloned())
        .or_else(|| std::env::var("MWS_BEDROCK_BRIDGE_LISTEN").ok())
        .unwrap_or_else(|| "127.0.0.1:4599".into());
    let token = std::env::var("MWS_BEDROCK_BRIDGE_TOKEN")
        .ok()
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string());
    let env = |k: &str, d: &str| std::env::var(k).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| d.into());
    let commands = mws_bedrock_runtime::cli::BridgeCommands {
        claude: env("MWS_BEDROCK_BRIDGE_CLAUDE", "claude"),
        codex: env("MWS_BEDROCK_BRIDGE_CODEX", "codex"),
    };
    let listener = tokio::net::TcpListener::bind(&listen).await.expect("bind the bridge address");
    let tools = mws_bedrock_runtime::cli::detect();
    let found: Vec<&str> = ["claude-code", "codex"].into_iter().filter(|t| tools[t]["found"] == true).collect();
    println!(
        "MWS Bedrock CLI bridge on http://{listen} ({})",
        if found.is_empty() { "no CLI found".to_string() } else { found.join(", ") }
    );
    println!("In MWS (e.g. its container), set:");
    println!("  MWS_BEDROCK_CLI_BRIDGE=http://host.docker.internal:{}", listen.rsplit(':').next().unwrap_or("4599"));
    println!("  MWS_BEDROCK_CLI_BRIDGE_TOKEN={token}");
    tokio::select! {
        _ = mws_bedrock_runtime::cli::serve_bridge(listener, token, commands) => {}
        _ = shutdown_signal() => {}
    }
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

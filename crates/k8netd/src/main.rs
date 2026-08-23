//! `k8netd` daemon binary.
//!
//! Rootless userspace vhost-user L2 switch for cloud-hypervisor VMs on a
//! single Linux lab host (see `docs/k8netd-contract.spec.md`). The binary
//! wires the workspace crates together; the dataplane and control-plane
//! wiring land in later tasks of the k8netd-daemon plan.

mod config;
mod dataplane;

fn main() {
    let flags = match config::parse_flags(std::env::args().skip(1)) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("k8netd: {e}");
            std::process::exit(2);
        }
    };
    let cfg = match config::Config::from_env(&flags) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("k8netd: {e}");
            std::process::exit(2);
        }
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    tracing::info!(?cfg, "k8netd starting");

    // Dataplane + control plane: one manager binary serving the JSON-RPC
    // control socket; port sockets and the state file live in socket_dir
    // (spec REQ-001/REQ-010).
    let dataplane = dataplane::Dataplane::new(&cfg.socket_dir);
    let router = k8netd_rpc::server::Router::new(dataplane);
    let control_sock = cfg.socket_dir.join("control.sock");
    tracing::info!(path = %control_sock.display(), "serving control socket");
    if let Err(e) = k8netd_rpc::server::serve(&control_sock, router) {
        tracing::error!(%e, "control socket server failed");
        std::process::exit(1);
    }
}

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

    // REQ-011: retired static-forward variables are ignored (no hard
    // failure, so an old unit file still boots); warn so operators update.
    for legacy in ["K8NETD_PORT_FORWARDS", "K8NETD_PASST_FORWARDS"] {
        if std::env::var_os(legacy).is_some() {
            tracing::warn!(
                env = legacy,
                "deprecated environment variable is ignored; inbound forwards come exclusively from the PublishPort RPC"
            );
        }
    }
    // REQ-010: warn when the publish range overlaps the ephemeral port range.
    warn_publish_range_overlaps_ephemeral(cfg.publish_range);

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

/// Logs a warning when `range` overlaps the host's ephemeral port range
/// (REQ-010). Reads `/proc/sys/net/ipv4/ip_local_port_range`, falling back
/// to the Linux default 32768-60999 if unreadable.
fn warn_publish_range_overlaps_ephemeral(range: (u16, u16)) {
    const DEFAULT_EPHEMERAL: (u16, u16) = (32768, 60999);
    let ephemeral = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .ok()
        .and_then(|raw| {
            let mut parts = raw.split_whitespace();
            let start = parts.next()?.parse::<u16>().ok()?;
            let end = parts.next()?.parse::<u16>().ok()?;
            Some((start, end))
        })
        .unwrap_or(DEFAULT_EPHEMERAL);
    if range.0 <= ephemeral.1 && ephemeral.0 <= range.1 {
        tracing::warn!(
            publish_start = range.0,
            publish_end = range.1,
            ephemeral_start = ephemeral.0,
            ephemeral_end = ephemeral.1,
            "publish range overlaps the ephemeral port range; passt forward binds may conflict"
        );
    }
}

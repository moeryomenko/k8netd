//! Daemon configuration: `K8NETD_*` env vars with CLI-flag override
//! (spec REQ-001 socket dir, REQ-006 upstreams, REQ-010 publish range;
//! plan TASK-028/029). No config file — flags/env only.
//!
//! Static passt forwards are retired (REQ-011): `K8NETD_PORT_FORWARDS` is
//! ignored, and inbound forwards come exclusively from the PublishPort RPC.

use std::net::Ipv4Addr;
use std::path::PathBuf;

/// Resolved daemon configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Directory holding the control socket, per-port sockets, and state file.
    pub socket_dir: PathBuf,
    /// passt binary name or path.
    pub passt_binary: String,
    /// Upstream DNS resolvers for the forwarder, in order.
    pub upstream_dns: Vec<Ipv4Addr>,
    /// MTU for the virtual networks.
    pub mtu: u16,
    /// Retired static forwards (REQ-011): always empty; inbound forwards are
    /// allocated exclusively through the PublishPort RPC.
    pub port_forwards: Vec<u16>,
    /// Inclusive host-port range the PublishPort allocator hands out
    /// (REQ-010), parsed from `K8NETD_PUBLISH_RANGE=start-end`.
    pub publish_range: (u16, u16),
}

/// Configuration failures surfaced at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// An env var or flag carried a value of the wrong shape.
    InvalidValue { key: String, value: String },
    /// A list-valued setting contained an empty element.
    EmptyListEntry { key: String },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::InvalidValue { key, value } => {
                write!(f, "invalid value for {key}: {value:?}")
            }
            ConfigError::EmptyListEntry { key } => write!(f, "empty entry in {key}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Defaults pinned by the plan/spec.
pub const DEFAULT_SOCKET_DIR: &str = "/run/user/1000/k8snet";
pub const DEFAULT_PASST_BINARY: &str = "passt";
pub const DEFAULT_UPSTREAM_DNS: &str = "1.1.1.1,8.8.8.8";
pub const DEFAULT_MTU: u16 = 1500;
/// Default PublishPort allocation range (REQ-010), below the typical Linux
/// ephemeral port range.
pub const DEFAULT_PUBLISH_RANGE: (u16, u16) = (20_000, 21_000);

/// CLI flags; `None` means "fall through to the env/default".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Flags {
    pub socket_dir: Option<PathBuf>,
    pub passt_binary: Option<String>,
    pub upstream_dns: Option<String>,
    pub mtu: Option<u16>,
}

impl Config {
    /// Resolves the effective config: flag > env > default.
    ///
    /// `env` is injected so tests never touch process-global state.
    pub fn resolve(flags: &Flags, getenv: &dyn Fn(&str) -> Option<String>) -> Result<Config, ConfigError> {
        let socket_dir = flags
            .socket_dir
            .clone()
            .or_else(|| getenv("K8NETD_SOCKET_DIR").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_DIR));

        let passt_binary = flags
            .passt_binary
            .clone()
            .or_else(|| getenv("K8NETD_PASST_BINARY"))
            .unwrap_or_else(|| DEFAULT_PASST_BINARY.to_string());

        let dns_raw = flags
            .upstream_dns
            .clone()
            .or_else(|| getenv("K8NETD_UPSTREAM_DNS"))
            .unwrap_or_else(|| DEFAULT_UPSTREAM_DNS.to_string());
        let upstream_dns = parse_ip_list("K8NETD_UPSTREAM_DNS", &dns_raw)?;

        let mtu = match flags.mtu {
            Some(m) => m,
            None => match getenv("K8NETD_MTU") {
                Some(raw) => raw.parse().map_err(|_| ConfigError::InvalidValue {
                    key: "K8NETD_MTU".into(),
                    value: raw,
                })?,
                None => DEFAULT_MTU,
            },
        };

        // REQ-011: K8NETD_PORT_FORWARDS is retired — deliberately not read;
        // the deprecation warning is logged by the daemon at startup.
        let port_forwards = Vec::new();

        let publish_range = match getenv("K8NETD_PUBLISH_RANGE") {
            Some(raw) => parse_publish_range(&raw)?,
            None => DEFAULT_PUBLISH_RANGE,
        };

        Ok(Config {
            socket_dir,
            passt_binary,
            upstream_dns,
            mtu,
            port_forwards,
            publish_range,
        })
    }

    /// Resolves from the real environment.
    pub fn from_env(flags: &Flags) -> Result<Config, ConfigError> {
        Self::resolve(flags, &|k| std::env::var(k).ok())
    }
}

/// Parses a comma-separated IPv4 list; rejects empty entries and bad values.
fn parse_ip_list(key: &str, raw: &str) -> Result<Vec<Ipv4Addr>, ConfigError> {
    let mut out = Vec::new();
    for part in raw.split(',') {
        if part.trim().is_empty() {
            return Err(ConfigError::EmptyListEntry { key: key.into() });
        }
        out.push(part.trim().parse().map_err(|_| ConfigError::InvalidValue {
            key: key.into(),
            value: raw.to_string(),
        })?);
    }
    Ok(out)
}

/// Parses a `start-end` host-port range (REQ-010); rejects a missing dash,
/// non-numeric or out-of-domain bounds, and reversed bounds.
fn parse_publish_range(raw: &str) -> Result<(u16, u16), ConfigError> {
    let invalid = || ConfigError::InvalidValue {
        key: "K8NETD_PUBLISH_RANGE".into(),
        value: raw.to_string(),
    };
    let (start_raw, end_raw) = raw.split_once('-').ok_or_else(invalid)?;
    let start: u16 = start_raw.parse().map_err(|_| invalid())?;
    let end: u16 = end_raw.parse().map_err(|_| invalid())?;
    if start > end {
        return Err(invalid());
    }
    Ok((start, end))
}

/// Parses CLI arguments into [`Flags`] (flag-over-env precedence).
///
/// Recognized: `--socket-dir <p>`, `--passt-binary <b>`, `--upstream-dns <l>`,
/// `--mtu <n>`. Unknown flags are rejected so typos fail loudly at startup
/// (this includes the retired `--port-forwards`).
pub fn parse_flags<I: Iterator<Item = String>>(args: I) -> Result<Flags, ConfigError> {
    let mut f = Flags::default();
    let mut it = args.peekable();
    while let Some(arg) = it.next() {
        let mut take = |slot: &mut Option<String>| -> Result<(), ConfigError> {
            *slot = Some(it.next().ok_or_else(|| ConfigError::InvalidValue {
                key: arg.clone(),
                value: "<missing>".into(),
            })?);
            Ok(())
        };
        match arg.as_str() {
            "--socket-dir" => {
                let mut v = None;
                take(&mut v)?;
                f.socket_dir = v.map(PathBuf::from);
            }
            "--passt-binary" => take(&mut f.passt_binary)?,
            "--upstream-dns" => take(&mut f.upstream_dns)?,
            "--mtu" => {
                let mut v = None;
                take(&mut v)?;
                f.mtu = Some(
                    v.as_deref()
                        .and_then(|s| s.parse().ok())
                        .ok_or_else(|| ConfigError::InvalidValue {
                            key: "--mtu".into(),
                            value: v.unwrap_or_default(),
                        })?,
                );
            }
            other => {
                return Err(ConfigError::InvalidValue {
                    key: "--flags".into(),
                    value: other.into(),
                });
            }
        }
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k: &str| pairs.iter().find(|(key, _)| *key == k).map(|(_, v)| v.to_string())
    }

    /// Every default matches the plan-pinned values.
    #[test]
    fn defaults_match_plan() -> TestResult {
        let c = Config::resolve(&Flags::default(), &|_| None)?;
        assert_eq!(c.socket_dir, PathBuf::from("/run/user/1000/k8snet"));
        assert_eq!(c.passt_binary, "passt");
        assert_eq!(
            c.upstream_dns,
            vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)]
        );
        assert_eq!(c.mtu, 1500);
        // REQ-011: static forwards are retired; the field stays empty.
        assert!(c.port_forwards.is_empty());
        Ok(())
    }

    /// Each env var overrides its default.
    #[test]
    fn env_overrides_defaults() -> TestResult {
        let e = env(&[
            ("K8NETD_SOCKET_DIR", "/tmp/x"),
            ("K8NETD_PASST_BINARY", "/usr/bin/passt"),
            ("K8NETD_UPSTREAM_DNS", "9.9.9.9"),
            ("K8NETD_MTU", "1400"),
        ]);
        let c = Config::resolve(&Flags::default(), &e)?;
        assert_eq!(c.socket_dir, PathBuf::from("/tmp/x"));
        assert_eq!(c.passt_binary, "/usr/bin/passt");
        assert_eq!(c.upstream_dns, vec![Ipv4Addr::new(9, 9, 9, 9)]);
        assert_eq!(c.mtu, 1400);
        // REQ-011: static forwards are retired; the field stays empty.
        assert!(c.port_forwards.is_empty());
        Ok(())
    }

    /// A CLI flag wins over both env and default.
    #[test]
    fn flag_overrides_env_and_default() -> TestResult {
        let e = env(&[("K8NETD_MTU", "1400"), ("K8NETD_SOCKET_DIR", "/from-env")]);
        let flags = Flags {
            socket_dir: Some(PathBuf::from("/from-flag")),
            mtu: Some(9000),
            ..Flags::default()
        };
        let c = Config::resolve(&flags, &e)?;
        assert_eq!(c.socket_dir, PathBuf::from("/from-flag"));
        assert_eq!(c.mtu, 9000);
        // REQ-011: static forwards are retired; nothing falls through to env.
        assert!(c.port_forwards.is_empty());
        Ok(())
    }

    /// Invalid values are rejected with the offending key named.
    #[test]
    fn invalid_values_rejected_at_startup() -> TestResult {
        let cases = [
            ("K8NETD_MTU", "notanumber"),
            ("K8NETD_UPSTREAM_DNS", "1.1.1.1,banana"),
            ("K8NETD_UPSTREAM_DNS", "1.1.1.1,,8.8.8.8"),
        ];
        for (key, val) in cases {
            let pair = [(key, val)];
            let e = env(&pair);
            let err = Config::resolve(&Flags::default(), &e).expect_err(val);
            assert!(
                matches!(
                    err,
                    ConfigError::InvalidValue { .. } | ConfigError::EmptyListEntry { .. }
                ),
                "{key}={val} must be rejected"
            );
        }
        Ok(())
    }

    /// Flag parsing covers all flags and rejects unknown ones.
    #[test]
    fn parse_flags_and_unknown_rejection() -> TestResult {
        let args = [
            "--socket-dir",
            "/s",
            "--passt-binary",
            "pb",
            "--upstream-dns",
            "9.9.9.9",
            "--mtu",
            "8888",
        ]
        .iter()
        .map(|s| s.to_string());
        let f = parse_flags(args)?;
        assert_eq!(f.socket_dir, Some(PathBuf::from("/s")));
        assert_eq!(f.passt_binary, Some("pb".into()));
        assert_eq!(f.upstream_dns, Some("9.9.9.9".into()));
        assert_eq!(f.mtu, Some(8888));

        let bad = ["--nope"].iter().map(|s| s.to_string());
        assert!(parse_flags(bad).is_err(), "unknown flag must be rejected");

        // REQ-011: the retired --port-forwards flag is no longer recognized.
        let retired = ["--port-forwards", "1,2"].iter().map(|s| s.to_string());
        assert!(
            parse_flags(retired).is_err(),
            "retired --port-forwards must be rejected like an unknown flag"
        );

        let missing = ["--mtu"].iter().map(|s| s.to_string());
        assert!(parse_flags(missing).is_err(), "dangling flag must be rejected");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // TASK-001 (SPEC-CAPISHIM-HYPERVISOR-INTEGRATION REQ-010 / REQ-011):
    // publish range configuration and retirement of static forwards.
    // Red phase: pins `Config.publish_range` (default 20000-21000, env
    // K8NETD_PUBLISH_RANGE=start-end) and the REQ-011 behavior that
    // K8NETD_PORT_FORWARDS is ignored. Compile failure on the new field is
    // expected red evidence; the deprecation test is a runtime red.
    // -----------------------------------------------------------------------

    /// K8NETD_PUBLISH_RANGE=start-end parses into the configured bounds.
    #[test]
    fn publish_range_env_parses_start_end() -> TestResult {
        let e = env(&[("K8NETD_PUBLISH_RANGE", "30000-30100")]);
        let c = Config::resolve(&Flags::default(), &e)?;
        assert_eq!(c.publish_range, (30000, 30100));
        Ok(())
    }

    /// Default publish range is 20000-21000 (REQ-010).
    #[test]
    fn publish_range_defaults_to_20000_21000() -> TestResult {
        let c = Config::resolve(&Flags::default(), &|_| None)?;
        assert_eq!(c.publish_range, (20000, 21000));
        Ok(())
    }

    /// Malformed ranges are rejected at startup: missing dash, non-numeric
    /// bounds, reversed bounds, dangling dash.
    #[test]
    fn publish_range_malformed_values_rejected() -> TestResult {
        for raw in ["20000", "banana", "21000-20000", "20000-", "-20000"] {
            let pair = [("K8NETD_PUBLISH_RANGE", raw)];
            let e = env(&pair);
            let err = Config::resolve(&Flags::default(), &e).expect_err(raw);
            assert!(
                matches!(err, ConfigError::InvalidValue { .. }),
                "K8NETD_PUBLISH_RANGE={raw} must be rejected"
            );
        }
        Ok(())
    }

    /// REQ-011: K8NETD_PORT_FORWARDS is retired — setting it must no longer
    /// populate static forwards; the parsed config ignores it.
    ///
    /// Intended runtime red against current code (which parses the var into
    /// `port_forwards`). Implementer note: `defaults_match_plan` and
    /// `env_overrides_defaults` above pin the retired behavior and must be
    /// updated alongside REQ-011.
    #[test]
    fn deprecated_port_forwards_env_is_ignored() -> TestResult {
        let e = env(&[("K8NETD_PORT_FORWARDS", "8080")]);
        let c = Config::resolve(&Flags::default(), &e)?;
        assert!(
            c.port_forwards.is_empty(),
            "static forwards are retired; K8NETD_PORT_FORWARDS must be ignored"
        );
        Ok(())
    }
}

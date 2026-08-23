//! Daemon configuration: `K8NETD_*` env vars with CLI-flag override
//! (spec REQ-001 socket dir, REQ-006 upstreams, REQ-008 port forwards;
//! plan TASK-028/029). No config file — flags/env only.

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
    /// TCP ports forwarded to every attached VM via passt.
    pub port_forwards: Vec<u16>,
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
pub const DEFAULT_PORT_FORWARDS: &str = "6443,22";

/// CLI flags; `None` means "fall through to the env/default".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Flags {
    pub socket_dir: Option<PathBuf>,
    pub passt_binary: Option<String>,
    pub upstream_dns: Option<String>,
    pub mtu: Option<u16>,
    pub port_forwards: Option<String>,
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

        let fw_raw = flags
            .port_forwards
            .clone()
            .or_else(|| getenv("K8NETD_PORT_FORWARDS"))
            .unwrap_or_else(|| DEFAULT_PORT_FORWARDS.to_string());
        let port_forwards = parse_port_list("K8NETD_PORT_FORWARDS", &fw_raw)?;

        Ok(Config {
            socket_dir,
            passt_binary,
            upstream_dns,
            mtu,
            port_forwards,
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

/// Parses a comma-separated TCP port list; rejects empty entries, non-numbers,
/// and zero.
fn parse_port_list(key: &str, raw: &str) -> Result<Vec<u16>, ConfigError> {
    let mut out = Vec::new();
    for part in raw.split(',') {
        if part.trim().is_empty() {
            return Err(ConfigError::EmptyListEntry { key: key.into() });
        }
        let p: u16 = part.trim().parse().map_err(|_| ConfigError::InvalidValue {
            key: key.into(),
            value: raw.to_string(),
        })?;
        if p == 0 {
            return Err(ConfigError::InvalidValue {
                key: key.into(),
                value: raw.to_string(),
            });
        }
        out.push(p);
    }
    Ok(out)
}

/// Parses CLI arguments into [`Flags`] (flag-over-env precedence).
///
/// Recognized: `--socket-dir <p>`, `--passt-binary <b>`, `--upstream-dns <l>`,
/// `--mtu <n>`, `--port-forwards <l>`. Unknown flags are rejected so typos
/// fail loudly at startup.
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
            "--port-forwards" => take(&mut f.port_forwards)?,
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
        assert_eq!(c.port_forwards, vec![6443, 22]);
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
            ("K8NETD_PORT_FORWARDS", "8080"),
        ]);
        let c = Config::resolve(&Flags::default(), &e)?;
        assert_eq!(c.socket_dir, PathBuf::from("/tmp/x"));
        assert_eq!(c.passt_binary, "/usr/bin/passt");
        assert_eq!(c.upstream_dns, vec![Ipv4Addr::new(9, 9, 9, 9)]);
        assert_eq!(c.mtu, 1400);
        assert_eq!(c.port_forwards, vec![8080]);
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
        // Untouched settings still fall through to env.
        assert_eq!(c.port_forwards, vec![6443, 22]);
        Ok(())
    }

    /// Invalid values are rejected with the offending key named.
    #[test]
    fn invalid_values_rejected_at_startup() -> TestResult {
        let cases = [
            ("K8NETD_MTU", "notanumber"),
            ("K8NETD_UPSTREAM_DNS", "1.1.1.1,banana"),
            ("K8NETD_UPSTREAM_DNS", "1.1.1.1,,8.8.8.8"),
            ("K8NETD_PORT_FORWARDS", "6443,,22"),
            ("K8NETD_PORT_FORWARDS", "0"),
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

    /// Flag parsing covers all five flags and rejects unknown ones.
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
            "--port-forwards",
            "1,2",
        ]
        .iter()
        .map(|s| s.to_string());
        let f = parse_flags(args)?;
        assert_eq!(f.socket_dir, Some(PathBuf::from("/s")));
        assert_eq!(f.passt_binary, Some("pb".into()));
        assert_eq!(f.upstream_dns, Some("9.9.9.9".into()));
        assert_eq!(f.mtu, Some(8888));
        assert_eq!(f.port_forwards, Some("1,2".into()));

        let bad = ["--nope"].iter().map(|s| s.to_string());
        assert!(parse_flags(bad).is_err(), "unknown flag must be rejected");

        let missing = ["--mtu"].iter().map(|s| s.to_string());
        assert!(parse_flags(missing).is_err(), "dangling flag must be rejected");
        Ok(())
    }
}

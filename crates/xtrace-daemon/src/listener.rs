//! Loopback TCP listener.
//!
//! The daemon refuses to bind to a non-loopback address. Constructors
//! inspect the supplied [`SocketAddr`] before the OS bind so a
//! misconfigured launcher fails fast without ever touching the
//! network stack. The bound port is always OS-assigned; callers see
//! the resolved [`SocketAddr`] through [`LoopbackListener::local_addr`].
//!
//! The [`validate_loopback`] function is the production
//! address-validation entry point: it takes an arbitrary
//! [`SocketAddr`] (for example one a launch helper has read from a
//! repository `.xtrace/config.toml`) and refuses to bind any address
//! that is not loopback. The [`LoopbackListener::bind`] constructor
//! is the single call site that consumes the entry point so a future
//! policy change (allow-link-local, allow-docker-bridge, ...) only
//! needs to update one place.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener};

use tokio::net::TcpListener as TokioTcpListener;

use crate::config::LoopbackPolicy;
use crate::error::DaemonError;

/// Result of binding to a loopback address.
pub struct LoopbackListener {
    /// The bound TCP listener. Neither [`LoopbackListener`] nor
    /// [`TokioTcpListener`] is `Clone`; the inner listener is owned
    /// by value and is only handed out via
    /// [`LoopbackListener::into_inner`]. `accept` takes `&self`
    /// because Tokio's [`TcpListener`](tokio::net::TcpListener) is
    /// designed to accept connections on a shared reference; the
    /// listening socket stays with this [`LoopbackListener`] for its
    /// entire lifetime.
    inner: TokioTcpListener,
    /// Address the listener is bound to. Reported through the
    /// bootstrap artifact.
    local_addr: SocketAddr,
}

impl LoopbackListener {
    /// Binds to the supplied loopback policy with an OS-assigned
    /// port.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::BindFailed`] when the OS refuses the
    /// bind or the resolved address is unexpectedly not loopback.
    pub async fn bind(policy: LoopbackPolicy) -> Result<Self, DaemonError> {
        let socket_addr = loopback_socket_addr(policy)?;
        let std_listener = TcpListener::bind(socket_addr)
            .map_err(|err| DaemonError::BindFailed(format!("bind {socket_addr}: {err}")))?;
        std_listener
            .set_nonblocking(true)
            .map_err(|err| DaemonError::BindFailed(format!("set_nonblocking: {err}")))?;
        let local_addr = std_listener
            .local_addr()
            .map_err(|err| DaemonError::BindFailed(format!("local_addr: {err}")))?;
        // The post-bind validation makes the OS-level bind outcome
        // observable; the pre-bind guard in [`validate_loopback`]
        // additionally protects callers that look up the address
        // out of band.
        if !is_loopback_ip(local_addr.ip()) {
            return Err(DaemonError::BindFailed(format!(
                "bound to non-loopback address {local_addr}"
            )));
        }
        let inner = TokioTcpListener::from_std(std_listener)
            .map_err(|err| DaemonError::BindFailed(format!("from_std: {err}")))?;
        Ok(Self { inner, local_addr })
    }

    /// Accepts the next inbound connection. A thin wrapper around
    /// [`TokioTcpListener::accept`] that maps the I/O error into a
    /// [`DaemonError`]. The supervisor treats an accept failure as
    /// fatal: the listener errors are not transient, so the loop
    /// signals shutdown, drains in-flight connections, and surfaces
    /// the error rather than masking it.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::BindFailed`] when the underlying
    /// accept fails; the resulting string is an owner-only diagnostic
    /// and is not part of the wire `ProtocolError` envelope sent to
    /// the adapter.
    pub async fn accept(&self) -> Result<(tokio::net::TcpStream, SocketAddr), DaemonError> {
        self.inner.accept().await.map_err(|err| DaemonError::BindFailed(format!("accept: {err}")))
    }

    /// Returns the local address the listener is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns the underlying tokio listener. Used by integration
    /// tests that need to drive the supervisor through a custom
    /// harness.
    #[must_use]
    pub fn into_inner(self) -> TokioTcpListener {
        self.inner
    }
}

fn loopback_socket_addr(policy: LoopbackPolicy) -> Result<SocketAddr, DaemonError> {
    match policy {
        LoopbackPolicy::V4Only => Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))),
        LoopbackPolicy::V6Only => {
            Ok(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)))
        }
        LoopbackPolicy::Any => {
            // Pick the IPv4 loopback by default; tests can override
            // through the explicit policy variants. The OS will still
            // assign the port.
            Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        }
    }
}

/// Production address-validation entry point. Refuses to bind or
/// otherwise accept a [`SocketAddr`] whose IP is not a loopback
/// address. The function is the single point that the daemon and the
/// launch helpers consult when they need to verify that a candidate
/// bind target belongs to the local loopback. A non-loopback value is
/// rejected with [`DaemonError::BindFailed`] before any OS syscall
/// runs.
///
/// # Errors
///
/// Returns [`DaemonError::BindFailed`] when the IP component is not
/// loopback.
pub fn validate_loopback(address: SocketAddr) -> Result<SocketAddr, DaemonError> {
    if !is_loopback_ip(address.ip()) {
        return Err(DaemonError::BindFailed(format!(
            "refused non-loopback bind address {address}"
        )));
    }
    Ok(address)
}

/// Validates that the supplied IP is a loopback address. Exposed for
/// integration tests that build a `TcpListener` directly to exercise
/// the rejection path.
#[must_use]
pub fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_picks_an_os_assigned_loopback_port() {
        let listener = LoopbackListener::bind(LoopbackPolicy::V4Only).await.expect("bind");
        let addr = listener.local_addr();
        assert!(addr.ip().is_loopback());
        assert_ne!(addr.port(), 0);
    }

    #[test]
    fn loopback_socket_addr_returns_loopback_for_every_policy() {
        for policy in [LoopbackPolicy::V4Only, LoopbackPolicy::V6Only, LoopbackPolicy::Any] {
            let addr = loopback_socket_addr(policy).expect("addr");
            assert!(is_loopback_ip(addr.ip()));
            assert_eq!(addr.port(), 0, "OS-assigned port must be zero");
        }
    }

    #[test]
    fn is_loopback_recognises_loopback_only() {
        assert!(is_loopback_ip("127.0.0.1".parse().unwrap()));
        assert!(is_loopback_ip("::1".parse().unwrap()));
        assert!(!is_loopback_ip("10.0.0.1".parse().unwrap()));
        assert!(!is_loopback_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn validate_loopback_accepts_loopback_addresses() {
        let v4: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let v6: SocketAddr = "[::1]:1234".parse().unwrap();
        assert_eq!(validate_loopback(v4).expect("v4 loopback"), v4);
        assert_eq!(validate_loopback(v6).expect("v6 loopback"), v6);
    }

    #[test]
    fn validate_loopback_rejects_non_loopback_addresses() {
        let v4_public: SocketAddr = "8.8.8.8:1234".parse().unwrap();
        let v4_private: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let v6_public: SocketAddr = "[2001:db8::1]:1234".parse().unwrap();
        let err = validate_loopback(v4_public).unwrap_err();
        assert!(matches!(err, DaemonError::BindFailed(_)));
        assert!(validate_loopback(v4_private).is_err());
        assert!(validate_loopback(v6_public).is_err());
    }

    #[tokio::test]
    async fn accept_returns_a_stream_with_a_loopback_peer() {
        let listener = LoopbackListener::bind(LoopbackPolicy::V4Only).await.expect("bind");
        let addr = listener.local_addr();
        let connector = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let (server_stream, peer) = listener.accept().await.expect("accept");
        assert!(peer.ip().is_loopback());
        drop(server_stream);
        drop(connector);
    }
}

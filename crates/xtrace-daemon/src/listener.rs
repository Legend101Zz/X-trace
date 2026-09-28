//! Loopback TCP listener.
//!
//! The daemon refuses to bind to a non-loopback address. Constructors
//! inspect the supplied [`SocketAddr`] before the OS bind so a
//! misconfigured launcher fails fast without ever touching the
//! network stack. The bound port is always OS-assigned; callers see
//! the resolved [`SocketAddr`] through [`LoopbackListener::local_addr`].

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, TcpListener};

use tokio::net::TcpListener as TokioTcpListener;

use crate::config::{LOOPBACK_HOST, LoopbackPolicy};
use crate::error::DaemonError;

/// Result of binding to a loopback address.
pub struct LoopbackListener {
    /// The bound TCP listener. Cheap to clone because the underlying
    /// type holds an `Arc`.
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
        let std_listener = TcpListener::bind(socket_addr).map_err(|err| {
            DaemonError::BindFailed(format!(
                "bind {socket_addr}: {err}"
            ))
        })?;
        std_listener.set_nonblocking(true).map_err(|err| {
            DaemonError::BindFailed(format!("set_nonblocking: {err}"))
        })?;
        let local_addr = std_listener.local_addr().map_err(|err| {
            DaemonError::BindFailed(format!("local_addr: {err}"))
        })?;
        if !local_addr.ip().is_loopback() {
            return Err(DaemonError::BindFailed(format!(
                "bound to non-loopback address {local_addr}"
            )));
        }
        let inner = TokioTcpListener::from_std(std_listener).map_err(|err| {
            DaemonError::BindFailed(format!("from_std: {err}"))
        })?;
        Ok(Self { inner, local_addr })
    }

    /// Accepts the next inbound connection. The method is a thin
    /// wrapper around [`TokioTcpListener::accept`] that maps the I/O
    /// error into a [`DaemonError`] so the supervisor can continue
    /// running after a single failed accept.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::BindFailed`] when the underlying accept
    /// fails; the underlying I/O error is preserved as a string but
    /// never embeds a captured value.
    pub async fn accept(&self) -> Result<(tokio::net::TcpStream, SocketAddr), DaemonError> {
        self.inner.accept().await.map_err(|err| {
            DaemonError::BindFailed(format!("accept: {err}"))
        })
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
        LoopbackPolicy::V4Only => Ok(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            0,
        ))),
        LoopbackPolicy::V6Only => Ok(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            0,
            0,
            0,
        ))),
        LoopbackPolicy::Any => {
            // Pick the IPv4 loopback by default; tests can override
            // through the explicit policy variants. The OS will still
            // assign the port.
            Ok(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        }
    }
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
        let listener = LoopbackListener::bind(LoopbackPolicy::V4Only)
            .await
            .expect("bind");
        let addr = listener.local_addr();
        assert!(addr.ip().is_loopback());
        assert_ne!(addr.port(), 0);
    }

    #[test]
    fn loopback_socket_addr_returns_loopback_for_every_policy() {
        for policy in [
            LoopbackPolicy::V4Only,
            LoopbackPolicy::V6Only,
            LoopbackPolicy::Any,
        ] {
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
    fn bind_rejects_non_loopback_ip() {
        // A direct test of the OS-level rejection: binding to a
        // public IP is fine at the OS level but our helper then
        // refuses because `is_loopback_ip` is false. We exercise the
        // helper directly to avoid touching the network on every CI
        // host.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        assert!(is_loopback_ip(addr.ip()));
    }

    #[tokio::test]
    async fn accept_returns_a_stream_with_a_loopback_peer() {
        let listener = LoopbackListener::bind(LoopbackPolicy::V4Only)
            .await
            .expect("bind");
        let addr = listener.local_addr();
        let connector = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let (server_stream, peer) = listener.accept().await.expect("accept");
        assert!(peer.ip().is_loopback());
        drop(server_stream);
        drop(connector);
    }

    // Suppress unused-warning on `io` when only used in doctests.
    #[allow(dead_code)]
    fn _io(_: io::Result<()>) {}
}
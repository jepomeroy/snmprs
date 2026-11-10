use std::{
    io::ErrorKind,
    net::{SocketAddr, ToSocketAddrs, UdpSocket},
    time::Duration,
};

use crate::errors::ClientError;

/// The UDP port SNMP agents listen on by default.
pub const DEFAULT_SNMP_PORT: u16 = 161;

const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_DATAGRAM_SIZE: usize = 65507;

/// A UDP client connected to a single SNMP agent. Connecting means the OS
/// drops datagrams that arrive from any other address.
#[derive(Debug)]
pub struct BaseClient {
    socket: UdpSocket,
    remote: SocketAddr,
    buffer: Box<[u8]>,
}

impl BaseClient {
    /// Resolves `host` (an IP address or hostname), binds a local socket of the
    /// matching family, and connects it to the first resolved address on `port`.
    pub fn new(host: &str, port: u16) -> Result<Self, ClientError> {
        let target = (host, port);

        let remote = target
            .to_socket_addrs()
            .map_err(|source| ClientError::Resolve {
                input: host.to_string(),
                source,
            })?
            .next()
            .ok_or_else(|| ClientError::NoResolvedAddresses {
                input: host.to_string(),
            })?;

        let local = match remote {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().expect("valid IPv4 wildcard address"),
            SocketAddr::V6(_) => "[::]:0".parse().expect("valid IPv6 wildcard address"),
        };

        let udp = UdpSocket::bind(local).map_err(|source| ClientError::Bind { local, source })?;

        udp.set_read_timeout(Some(DEFAULT_READ_TIMEOUT))
            .and_then(|()| udp.set_write_timeout(Some(DEFAULT_WRITE_TIMEOUT)))
            .map_err(|source| ClientError::Configure { source })?;

        udp.connect(remote)
            .map_err(|source| ClientError::Connect { remote, source })?;

        Ok(Self {
            socket: udp,
            remote,
            buffer: vec![0; MAX_DATAGRAM_SIZE].into_boxed_slice(),
        })
    }

    /// Sends one datagram to the agent.
    pub fn send(&self, snmp_msg: &[u8]) -> Result<(), ClientError> {
        let sent = self
            .socket
            .send(snmp_msg)
            .map_err(|source| ClientError::Send {
                remote: self.remote,
                source,
            })?;

        if sent != snmp_msg.len() {
            return Err(ClientError::PartialSend {
                remote: self.remote,
                sent,
                len: snmp_msg.len(),
            });
        }

        Ok(())
    }

    /// Waits for one datagram from the agent and returns it. The slice borrows an
    /// internal buffer that the next call overwrites.
    pub fn receive(&mut self) -> Result<&[u8], ClientError> {
        let size = self
            .socket
            .recv(&mut self.buffer)
            .map_err(|source| match source.kind() {
                ErrorKind::WouldBlock | ErrorKind::TimedOut => ClientError::Timeout {
                    remote: self.remote,
                    // Read back from the socket so the error reports the timeout in effect.
                    timeout: self
                        .socket
                        .read_timeout()
                        .ok()
                        .flatten()
                        .unwrap_or_default(),
                },
                _ => ClientError::Receive {
                    remote: self.remote,
                    source,
                },
            })?;

        Ok(&self.buffer[..size])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_secs(1);

    #[test]
    fn test_receive_times_out_when_agent_is_silent() {
        // Stays open so the OS can't report the port as unreachable.
        let agent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = agent.local_addr().unwrap().port();
        let mut client = BaseClient::new("127.0.0.1", port).unwrap();
        client
            .socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();

        let err = client.receive().unwrap_err();
        assert!(
            matches!(err, ClientError::Timeout { timeout, .. } if timeout == Duration::from_millis(50)),
            "got {:?}",
            err
        );
    }

    #[test]
    fn test_send_and_receive() {
        let agent = UdpSocket::bind("127.0.0.1:0").unwrap();
        // Fail instead of hanging if the client never sends anything.
        agent.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let port = agent.local_addr().unwrap().port();
        let mut client = BaseClient::new("127.0.0.1", port).unwrap();

        client.send(&[1, 2, 3]).unwrap();

        let mut buffer = [0; 8];
        let (size, client_addr) = agent.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..size], &[1, 2, 3]);

        agent.send_to(&[4, 5], client_addr).unwrap();
        assert_eq!(client.receive().unwrap(), vec![4, 5]);
    }

    #[test]
    fn test_unresolvable_host() {
        // RFC 6761 reserves `.invalid`, so this never resolves on any network.
        let err = BaseClient::new("host.invalid", DEFAULT_SNMP_PORT).unwrap_err();
        assert!(
            matches!(&err, ClientError::Resolve { input, .. } if input == "host.invalid"),
            "got {:?}",
            err
        );
    }

    #[test]
    fn test_send_by_hostname() {
        let agent = UdpSocket::bind("127.0.0.1:0").unwrap();
        agent.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let port = agent.local_addr().unwrap().port();
        let client = BaseClient::new("localhost", port).unwrap();
        // `localhost` may resolve to ::1 first; this test only covers the IPv4 case.
        if !client.remote.is_ipv4() {
            return;
        }

        client.send(&[1, 2, 3]).unwrap();
        let mut buffer = [0; 8];
        let (size, _) = agent.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..size], &[1, 2, 3]);
    }

    #[test]
    fn test_send_and_receive_ipv6() {
        // Skip on hosts without an IPv6 loopback.
        let Ok(agent) = UdpSocket::bind("[::1]:0") else {
            return;
        };
        agent.set_read_timeout(Some(TEST_TIMEOUT)).unwrap();
        let port = agent.local_addr().unwrap().port();
        let mut client = BaseClient::new("::1", port).unwrap();
        assert!(client.socket.local_addr().unwrap().is_ipv6());

        client.send(&[1, 2, 3]).unwrap();
        let mut buffer = [0; 8];
        let (size, client_addr) = agent.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..size], &[1, 2, 3]);

        agent.send_to(&[4, 5], client_addr).unwrap();
        assert_eq!(client.receive().unwrap(), vec![4, 5]);
    }
}

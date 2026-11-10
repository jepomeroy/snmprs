use std::{
    io::ErrorKind,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    time::Duration,
};

pub use crate::errors::ClientError;

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
}

impl BaseClient {
    pub fn new(ipaddr: &str, port: u16) -> Result<Self, ClientError> {
        let remote_ip: Ipv4Addr = ipaddr
            .parse()
            .map_err(|source| ClientError::InvalidAddress {
                input: ipaddr.to_string(),
                source,
            })?;
        let remote = SocketAddr::V4(SocketAddrV4::new(remote_ip, port));

        let local = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
        let udp = UdpSocket::bind(local).map_err(|source| ClientError::Bind { local, source })?;

        udp.set_read_timeout(Some(DEFAULT_READ_TIMEOUT))
            .and_then(|()| udp.set_write_timeout(Some(DEFAULT_WRITE_TIMEOUT)))
            .map_err(|source| ClientError::Configure { source })?;

        udp.connect(remote)
            .map_err(|source| ClientError::Connect { remote, source })?;

        Ok(Self {
            socket: udp,
            remote,
        })
    }

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

    pub fn receive(&self) -> Result<Vec<u8>, ClientError> {
        let mut buffer = vec![0; MAX_DATAGRAM_SIZE];

        let size = self
            .socket
            .recv(&mut buffer)
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

        buffer.truncate(size);
        Ok(buffer)
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
        let client = BaseClient::new("127.0.0.1", port).unwrap();
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
        let client = BaseClient::new("127.0.0.1", port).unwrap();

        client.send(&[1, 2, 3]).unwrap();

        let mut buffer = [0; 8];
        let (size, client_addr) = agent.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..size], &[1, 2, 3]);

        agent.send_to(&[4, 5], client_addr).unwrap();
        assert_eq!(client.receive().unwrap(), vec![4, 5]);
    }

    #[test]
    fn test_bad_ip_addr() {
        let err = BaseClient::new("not-an-ip", DEFAULT_SNMP_PORT).unwrap_err();
        assert!(
            matches!(&err, ClientError::InvalidAddress { input, .. } if input == "not-an-ip"),
            "got {:?}",
            err
        );
    }
}

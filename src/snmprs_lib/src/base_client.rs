use std::{
    error::Error,
    fmt::Display,
    io::ErrorKind,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    time::Duration,
};

pub const DEFAULT_SNMP_PORT: u16 = 161;

const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_DATAGRAM_SIZE: usize = 65507;

#[derive(Debug)]
pub enum ClientError {
    BadIpAddr(String),
    BindError(String),
    ConnectionError(String),
    SendErr(String),
    RecvErr(String),
    Timeout(String),
}

impl Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::BadIpAddr(msg) => write!(f, "{}", msg),
            ClientError::BindError(msg) => write!(f, "{}", msg),
            ClientError::ConnectionError(msg) => write!(f, "{}", msg),
            ClientError::SendErr(msg) => write!(f, "{}", msg),
            ClientError::RecvErr(msg) => write!(f, "{}", msg),
            ClientError::Timeout(msg) => write!(f, "{}", msg),
        }
    }
}

impl Error for ClientError {}

/// A UDP client connected to a single SNMP agent. Connecting means the OS
/// drops datagrams that arrive from any other address.
#[derive(Debug)]
pub struct BaseClient {
    socket: UdpSocket,
}

impl BaseClient {
    pub fn new(ipaddr: &str, port: u16) -> Result<Self, ClientError> {
        let remote_ip: Ipv4Addr = ipaddr.parse().map_err(|_| {
            ClientError::BadIpAddr(format!("Unable to parse network address {}", ipaddr))
        })?;
        let remote_addr = SocketAddrV4::new(remote_ip, port);

        let local_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
        let udp = UdpSocket::bind(local_addr).map_err(|e| {
            ClientError::BindError(format!(
                "Unable to bind to network address {}: {}",
                local_addr, e
            ))
        })?;

        udp.set_read_timeout(Some(DEFAULT_READ_TIMEOUT))
            .map_err(|_| ClientError::Timeout("Unable to set read timeout on socket".to_owned()))?;
        udp.set_write_timeout(Some(DEFAULT_WRITE_TIMEOUT))
            .map_err(|_| {
                ClientError::Timeout("Unable to set write timeout on socket".to_owned())
            })?;

        udp.connect(remote_addr).map_err(|e| {
            ClientError::ConnectionError(format!("Unable to connect to {}: {}", remote_addr, e))
        })?;

        Ok(Self { socket: udp })
    }

    pub fn send(&self, snmp_msg: &[u8]) -> Result<(), ClientError> {
        let size = self
            .socket
            .send(snmp_msg)
            .map_err(|e| ClientError::SendErr(e.to_string()))?;

        if snmp_msg.len() != size {
            return Err(ClientError::SendErr(format!(
                "Mismatch between bytes sent {} and bytes in message {}",
                size,
                snmp_msg.len()
            )));
        }

        Ok(())
    }

    pub fn receive(&self) -> Result<Vec<u8>, ClientError> {
        let mut buffer = vec![0; MAX_DATAGRAM_SIZE];

        let size = self.socket.recv(&mut buffer).map_err(|e| match e.kind() {
            ErrorKind::WouldBlock | ErrorKind::TimedOut => {
                ClientError::Timeout("Timed out waiting for a response".to_owned())
            }
            _ => ClientError::RecvErr(e.to_string()),
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
        assert!(matches!(err, ClientError::Timeout(_)), "got {:?}", err);
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
        assert!(matches!(err, ClientError::BadIpAddr(_)));
    }
}

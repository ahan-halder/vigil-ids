use super::JsonAlert;
use std::net::UdpSocket;

pub struct SyslogSender {
    socket: UdpSocket,
    target: String,
}

impl SyslogSender {
    pub fn new(target: &str) -> Result<Self, String> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| format!("failed to bind UDP socket for syslog: {e}"))?;

        Ok(Self {
            socket,
            target: target.to_string(),
        })
    }

    pub fn send(&self, alert: &JsonAlert) -> Result<(), String> {
        // RFC 3164 format roughly: <PRIVAL> APP-NAME: MSG
        // PRIVAL 11 = Facility 1 (User), Severity 3 (Error)
        let json_msg =
            serde_json::to_string(alert).map_err(|e| format!("syslog serialization error: {e}"))?;

        let message = format!("<11>vigil-ids: {}", json_msg);

        self.socket
            .send_to(message.as_bytes(), &self.target)
            .map_err(|e| format!("failed to send syslog message: {e}"))?;

        Ok(())
    }
}

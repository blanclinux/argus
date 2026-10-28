use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Tcp6 => write!(f, "TCP6"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Udp6 => write!(f, "UDP6"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    Unknown(u32),
}

impl TcpState {
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            1 => TcpState::Closed,
            2 => TcpState::Listen,
            3 => TcpState::SynSent,
            4 => TcpState::SynReceived,
            5 => TcpState::Established,
            6 => TcpState::FinWait1,
            7 => TcpState::FinWait2,
            8 => TcpState::CloseWait,
            9 => TcpState::Closing,
            10 => TcpState::LastAck,
            11 => TcpState::TimeWait,
            12 => TcpState::DeleteTcb,
            _ => TcpState::Unknown(raw),
        }
    }
}

impl fmt::Display for TcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TcpState::Closed => write!(f, "Closed"),
            TcpState::Listen => write!(f, "Listen"),
            TcpState::SynSent => write!(f, "SynSent"),
            TcpState::SynReceived => write!(f, "SynRcvd"),
            TcpState::Established => write!(f, "Estab"),
            TcpState::FinWait1 => write!(f, "FinW1"),
            TcpState::FinWait2 => write!(f, "FinW2"),
            TcpState::CloseWait => write!(f, "CloseW"),
            TcpState::Closing => write!(f, "Closing"),
            TcpState::LastAck => write!(f, "LastAck"),
            TcpState::TimeWait => write!(f, "TimeW"),
            TcpState::DeleteTcb => write!(f, "DelTcb"),
            TcpState::Unknown(v) => write!(f, "Unk({v})"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Active,
    Dead,
    Stale,
    Paused,
    Unknown,
}

impl Status {
    pub fn label(&self) -> &'static str {
        match self {
            Status::Active => "Active",
            Status::Dead => "Dead",
            Status::Stale => "Stale",
            Status::Paused => "Paused",
            Status::Unknown => "Unknown",
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessKind {
    Frontend,
    Backend,
    Database,
    System,
    Unknown,
}

impl ProcessKind {
    pub fn label(&self) -> &'static str {
        match self {
            ProcessKind::Frontend => "frontend",
            ProcessKind::Backend => "backend",
            ProcessKind::Database => "database",
            ProcessKind::System => "system",
            ProcessKind::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortEntry {
    pub protocol: Protocol,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: Option<String>,
    pub state: Option<TcpState>,
    pub pid: u32,
    pub process_name: String,
    pub image_path: String,
    pub command_line: String,
    pub start_time: Option<String>,
    pub start_time_raw: Option<u64>,
    pub memory_kb: Option<u64>,
    pub service_name: Option<String>,
    pub service_display: Option<String>,
    pub service_status: Option<String>,
    pub suspended: bool,
    pub kind: ProcessKind,
    pub status: Status,
}

impl PortEntry {
    pub fn is_listener(&self) -> bool {
        matches!(self.state, None | Some(TcpState::Listen))
    }
}

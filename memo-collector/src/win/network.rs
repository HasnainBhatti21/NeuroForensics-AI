//! Network state helpers.
//!
//! Passive acquisition only: this module never scans, probes or attacks
//! external systems. It reads local state from built-in, documented tools
//! (`netstat`, `arp`) and from WMI adapter configuration.

use serde::{Deserialize, Serialize};

/// A TCP/UDP endpoint observed via `netstat -ano`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NetConnection {
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub state: Option<String>,
    pub pid: Option<u32>,
}

/// An ARP cache entry observed via `arp -a`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ArpEntry {
    pub interface: Option<String>,
    pub internet_address: String,
    pub physical_address: String,
    pub entry_type: String,
}

/// A route table row observed via `netstat -r`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RouteEntry {
    pub network_destination: String,
    pub netmask: String,
    pub gateway: String,
    pub interface: String,
    pub metric: String,
}

fn split_endpoint(endpoint: &str) -> (String, u16) {
    match endpoint.rfind(':') {
        Some(idx) => {
            let addr = &endpoint[..idx];
            let port = endpoint[idx + 1..].parse::<u16>().unwrap_or(0);
            (addr.trim_start_matches('[').trim_end_matches(']').to_string(), port)
        }
        None => (endpoint.to_string(), 0),
    }
}

/// Parse `netstat -ano` output into connection records.
pub fn parse_netstat(output: &str) -> Vec<NetConnection> {
    let mut connections = Vec::new();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        let proto = fields[0].to_uppercase();
        if proto != "TCP" && proto != "UDP" {
            continue;
        }
        // TCP: proto local foreign state pid
        // UDP: proto local foreign pid   (no state column)
        let (state, pid_field) = if proto == "TCP" && fields.len() >= 5 {
            (Some(fields[3].to_string()), fields[4])
        } else {
            (None, fields[fields.len() - 1])
        };
        let (local_address, local_port) = split_endpoint(fields[1]);
        let (remote_address, remote_port) = split_endpoint(fields[2]);
        connections.push(NetConnection {
            protocol: proto,
            local_address,
            local_port,
            remote_address,
            remote_port,
            state,
            pid: pid_field.parse::<u32>().ok(),
        });
    }
    connections
}

/// Parse `arp -a` output into ARP cache entries.
pub fn parse_arp(output: &str) -> Vec<ArpEntry> {
    let mut entries = Vec::new();
    let mut current_interface: Option<String> = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("Interface:") || trimmed.starts_with("Interface :") {
            // e.g. "Interface: 192.168.1.5 --- 0x3"
            let addr = trimmed
                .trim_start_matches("Interface:")
                .trim_start_matches("Interface :")
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
            current_interface = Some(addr);
            continue;
        }
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.len() >= 3 && fields[0].contains('.') {
            entries.push(ArpEntry {
                interface: current_interface.clone(),
                internet_address: fields[0].to_string(),
                physical_address: fields[1].to_string(),
                entry_type: fields[2].to_string(),
            });
        }
    }
    entries
}

/// Parse the IPv4 section of `netstat -r` into route entries.
pub fn parse_routes(output: &str) -> Vec<RouteEntry> {
    let mut routes = Vec::new();
    let mut in_table = false;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            in_table = false;
            continue;
        }
        if trimmed.starts_with("Network Destination") {
            in_table = true;
            continue;
        }
        if !in_table {
            continue;
        }
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.len() >= 5 && fields[0].contains('.') {
            routes.push(RouteEntry {
                network_destination: fields[0].to_string(),
                netmask: fields[1].to_string(),
                gateway: fields[2].to_string(),
                interface: fields[3].to_string(),
                metric: fields[4].to_string(),
            });
        }
    }
    routes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netstat_tcp_and_udp_parse() {
        let sample = "\
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1128
  TCP    192.168.1.5:49800      93.184.216.34:443      ESTABLISHED     4711
  UDP    0.0.0.0:500            *:*                                    1024
  UDP    [::]:5353              *:*                                    2048
";
        let parsed = parse_netstat(sample);
        assert_eq!(parsed.len(), 4);
        assert_eq!(parsed[0].protocol, "TCP");
        assert_eq!(parsed[0].local_port, 135);
        assert_eq!(parsed[0].state.as_deref(), Some("LISTENING"));
        assert_eq!(parsed[0].pid, Some(1128));
        assert_eq!(parsed[1].remote_address, "93.184.216.34");
        assert_eq!(parsed[1].remote_port, 443);
        assert!(parsed[2].state.is_none());
        assert_eq!(parsed[2].pid, Some(1024));
        assert_eq!(parsed[3].local_address, "::");
    }

    #[test]
    fn arp_parse() {
        let sample = "\
Interface: 192.168.1.5 --- 0x3
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
";
        let parsed = parse_arp(sample);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].internet_address, "192.168.1.1");
        assert_eq!(parsed[0].interface.as_deref(), Some("192.168.1.5"));
    }

    #[test]
    fn route_parse() {
        let sample = "\
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1      192.168.1.5     25
";
        let parsed = parse_routes(sample);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].gateway, "192.168.1.1");
    }
}

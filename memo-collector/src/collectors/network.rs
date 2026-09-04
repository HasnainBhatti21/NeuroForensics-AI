//! NetworkCollector - passive local network state acquisition.
//!
//! This collector performs NO active scanning, probing or attacks. It only
//! records the local machine's network state.

use serde::Deserialize;
use serde_json::json;
use std::time::Duration;

use super::{Availability, CollectContext, CollectorError, CollectorId, ICollector};
use crate::win;

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_NetworkAdapterConfiguration")]
#[allow(dead_code)]
struct Win32NetworkAdapterConfiguration {
    #[serde(default, rename = "Description")]
    description: Option<String>,
    #[serde(default, rename = "MACAddress")]
    mac_address: Option<String>,
    #[serde(default, rename = "IPAddress")]
    ip_address: Option<Vec<String>>,
    #[serde(default, rename = "IPSubnet")]
    ip_subnet: Option<Vec<String>>,
    #[serde(default, rename = "DefaultIPGateway")]
    default_ip_gateway: Option<Vec<String>>,
    #[serde(default, rename = "DNSServerSearchOrder")]
    dns_server_search_order: Option<Vec<String>>,
    #[serde(default, rename = "DHCPEnabled")]
    dhcp_enabled: Option<bool>,
    #[serde(default, rename = "DHCPServer")]
    dhcp_server: Option<String>,
    #[serde(default, rename = "DHCPLeaseObtained")]
    dhcp_lease_obtained: Option<String>,
    #[serde(default, rename = "DHCPLeaseExpires")]
    dhcp_lease_expires: Option<String>,
    #[serde(default, rename = "DNSDomain")]
    dns_domain: Option<String>,
    #[serde(default, rename = "InterfaceIndex")]
    interface_index: Option<u32>,
    #[serde(default, rename = "IPEnabled")]
    ip_enabled: Option<bool>,
}

#[derive(Default)]
pub struct NetworkCollector {}

impl ICollector for NetworkCollector {
    fn id(&self) -> CollectorId {
        CollectorId::Network
    }

    fn name(&self) -> &'static str {
        "Network"
    }

    fn check_availability(&self) -> Availability {
        Availability::Available
    }

    fn collect(&mut self, ctx: &mut CollectContext) -> Result<(), CollectorError> {
        let acquired_at = chrono::Local::now().to_rfc3339();

        // --- Adapters / MAC / IP / DNS / DHCP / Gateway (WMI) --------------
        let mut adapters = Vec::new();
        #[cfg(windows)]
        {
            match wmi::COMLibrary::new()
                .map_err(|e| e.to_string())
                .and_then(|com| wmi::WMIConnection::new(com).map_err(|e| e.to_string()))
            {
                Ok(wmi) => match wmi.query::<Win32NetworkAdapterConfiguration>() {
                    Ok(rows) => {
                        adapters = rows
                            .into_iter()
                            .map(|a| {
                                json!({
                                    "description": a.description,
                                    "mac_address": a.mac_address,
                                    "ip_addresses": a.ip_address,
                                    "ip_subnets": a.ip_subnet,
                                    "default_gateways": a.default_ip_gateway,
                                    "dns_servers": a.dns_server_search_order,
                                    "dns_domain": a.dns_domain,
                                    "dhcp_enabled": a.dhcp_enabled,
                                    "dhcp_server": a.dhcp_server,
                                    "dhcp_lease_obtained": a.dhcp_lease_obtained,
                                    "dhcp_lease_expires": a.dhcp_lease_expires,
                                    "interface_index": a.interface_index,
                                    "ip_enabled": a.ip_enabled,
                                })
                            })
                            .collect::<Vec<_>>();
                    }
                    Err(e) => ctx.warn(format!("Win32_NetworkAdapterConfiguration failed: {}", e)),
                },
                Err(e) => ctx.warn(format!("WMI unavailable, adapter metadata skipped: {}", e)),
            }
        }
        ctx.add_json(
            "network/adapters.json",
            "WMI Win32_NetworkAdapterConfiguration",
            None,
            &json!({ "acquired_at": acquired_at, "adapters": adapters }),
        )?;

        // --- DNS configuration summary --------------------------------------
        let dns_entries: Vec<serde_json::Value> = adapters
            .iter()
            .filter_map(|a| {
                let desc = a["description"].as_str()?.to_string();
                let servers = a["dns_servers"].clone();
                let domain = a["dns_domain"].clone();
                if servers.is_null() && domain.is_null() {
                    return None;
                }
                Some(json!({
                    "adapter": desc,
                    "dns_servers": servers,
                    "dns_domain": domain,
                }))
            })
            .collect();
        ctx.add_json(
            "network/dns.json",
            "derived from adapter configuration",
            None,
            &json!({ "acquired_at": acquired_at, "entries": dns_entries }),
        )?;

        // --- TCP / UDP connections (netstat -ano, includes PIDs) ------------
        let mut connections = Vec::new();
        match win::powershell::run_capture("netstat.exe", &["-ano"], Duration::from_secs(60)) {
            Ok(output) => connections = win::network::parse_netstat(&output),
            Err(e) => ctx.warn(format!("netstat -ano failed: {}", e)),
        }

        // Attach process names for observed PIDs.
        let pid_names = {
            let mut sys = sysinfo::System::new();
            sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
            sys.processes()
                .iter()
                .map(|(pid, p)| {
                    (
                        pid.as_u32(),
                        p.name().to_string_lossy().into_owned(),
                    )
                })
                .collect::<std::collections::HashMap<u32, String>>()
        };
        let connections_doc: Vec<serde_json::Value> = connections
            .iter()
            .map(|c| {
                json!({
                    "protocol": c.protocol,
                    "local_address": c.local_address,
                    "local_port": c.local_port,
                    "remote_address": c.remote_address,
                    "remote_port": c.remote_port,
                    "state": c.state,
                    "pid": c.pid,
                    "process": c.pid.and_then(|pid| pid_names.get(&pid)).cloned(),
                })
            })
            .collect();
        let listening = connections_doc
            .iter()
            .filter(|c| c["state"].as_str() == Some("LISTENING"))
            .count();
        ctx.add_json(
            "network/connections.json",
            "netstat -ano (passive)",
            Some(format!(
                "{} endpoints, {} listening; PIDs resolved via process snapshot",
                connections_doc.len(),
                listening
            )),
            &json!({ "acquired_at": acquired_at, "connections": connections_doc }),
        )?;

        // --- Routing table ---------------------------------------------------
        let mut routes = Vec::new();
        match win::powershell::run_capture("netstat.exe", &["-r"], Duration::from_secs(60)) {
            Ok(output) => routes = win::network::parse_routes(&output),
            Err(e) => ctx.warn(format!("netstat -r failed: {}", e)),
        }
        ctx.add_json(
            "network/routes.json",
            "netstat -r (passive)",
            None,
            &json!({ "acquired_at": acquired_at, "routes": routes }),
        )?;

        // --- ARP cache -------------------------------------------------------
        let mut arp = Vec::new();
        match win::powershell::run_capture("arp.exe", &["-a"], Duration::from_secs(30)) {
            Ok(output) => arp = win::network::parse_arp(&output),
            Err(e) => ctx.warn(format!("arp -a failed: {}", e)),
        }
        ctx.add_json(
            "network/arp.json",
            "arp -a (passive)",
            None,
            &json!({ "acquired_at": acquired_at, "arp_cache": arp }),
        )?;

        // --- Interface statistics (sysinfo) ----------------------------------
        let networks = sysinfo::Networks::new_with_refreshed_list();
        let iface_stats: Vec<serde_json::Value> = networks
            .iter()
            .map(|(name, n)| {
                json!({
                    "name": name,
                    "mac_address": n.mac_address().to_string(),
                    "total_received_bytes": n.total_received(),
                    "total_transmitted_bytes": n.total_transmitted(),
                    "total_packets_received": n.total_packets_received(),
                    "total_packets_transmitted": n.total_packets_transmitted(),
                })
            })
            .collect();
        ctx.add_json(
            "network/interfaces.json",
            "sysinfo network counters",
            None,
            &json!({ "acquired_at": acquired_at, "interfaces": iface_stats }),
        )?;

        Ok(())
    }
}

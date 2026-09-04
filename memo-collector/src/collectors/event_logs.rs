//! WindowsEventCollector - Windows Event Log acquisition.
//!
//! Preserves original event information: structured records (JSON index)
//! plus raw XML event representation. Channels that do not exist (e.g.
//! Sysmon) are skipped, never assumed.

use serde_json::json;

use super::{Availability, CollectContext, CollectorError, CollectorId, ICollector};
use crate::win::events;

#[derive(Default)]
pub struct EventLogCollector {
    channels_acquired: usize,
    channels_skipped: usize,
}

impl ICollector for EventLogCollector {
    fn id(&self) -> CollectorId {
        CollectorId::Events
    }

    fn name(&self) -> &'static str {
        "Windows Event Logs"
    }

    fn check_availability(&self) -> Availability {
        if cfg!(windows) {
            Availability::Available
        } else {
            Availability::NotAvailable {
                reason: "Windows Event Logs require Windows".to_string(),
            }
        }
    }

    fn collect(&mut self, ctx: &mut CollectContext) -> Result<(), CollectorError> {
        let max_events = ctx.settings.events_per_channel.max(1);
        let mut summary = Vec::new();

        for channel in events::CHANNELS {
            ctx.check_cancel()?;
            ctx.wait_if_paused();

            // Channel existence must be verified; Sysmon in particular is
            // not assumed to be installed.
            if !events::channel_exists(channel.name) {
                self.channels_skipped += 1;
                ctx.warn(format!(
                    "Event channel '{}' not installed - SKIPPED",
                    channel.name
                ));
                summary.push(json!({
                    "channel": channel.name,
                    "status": "SKIPPED",
                    "reason": "channel not installed",
                    "events": 0,
                }));
                continue;
            }

            let folder = format!("windows_events/{}", channel.folder);

            // Structured index via Get-WinEvent.
            let records = match events::query_events_json(channel.name, max_events) {
                Ok(records) => records,
                Err(e) => {
                    self.channels_skipped += 1;
                    let reason = if channel.typically_requires_admin
                        && (e.contains("Access") || e.contains("access") || e.contains("0x5"))
                    {
                        "requires administrator privileges"
                    } else {
                        "query failed"
                    };
                    ctx.warn(format!(
                        "Event channel '{}' skipped ({}: {})",
                        channel.name, reason, e
                    ));
                    summary.push(json!({
                        "channel": channel.name,
                        "status": "SKIPPED",
                        "reason": format!("{}: {}", reason, e),
                        "events": 0,
                    }));
                    continue;
                }
            };
            let record_count = records.len();
            ctx.add_json(
                &format!("{}/events.json", folder),
                &format!("Get-WinEvent channel '{}' (last {} events)", channel.name, max_events),
                None,
                &json!({
                    "channel": channel.name,
                    "acquired_at": chrono::Local::now().to_rfc3339(),
                    "max_events": max_events,
                    "event_count": record_count,
                    "events": records,
                }),
            )?;

            // Raw XML representation preserving original event data.
            match events::query_events_xml(channel.name, max_events) {
                Ok(xml) => {
                    ctx.add_bytes(
                        &format!("{}/events_raw.xml", folder),
                        &format!("wevtutil qe '{}' /f:xml", channel.name),
                        None,
                        xml.as_bytes(),
                    )?;
                }
                Err(e) => {
                    ctx.warn(format!("Raw XML export failed for '{}': {}", channel.name, e));
                }
            }

            self.channels_acquired += 1;
            summary.push(json!({
                "channel": channel.name,
                "status": "ACQUIRED",
                "events": record_count,
            }));
        }

        ctx.add_json(
            "windows_events/summary.json",
            "channel acquisition summary",
            Some(format!(
                "{} channels acquired, {} skipped",
                self.channels_acquired, self.channels_skipped
            )),
            &json!({
                "acquired_at": chrono::Local::now().to_rfc3339(),
                "channels": summary,
            }),
        )?;

        Ok(())
    }
}

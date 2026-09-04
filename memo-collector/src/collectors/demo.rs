//! DEMO MODE - clearly labelled synthetic demonstration data.
//!
//! Demo Mode exists so the GUI and AIF workflow can be demonstrated without
//! touching a real system's evidence surface. Every demo artifact is marked
//! `SYNTHETIC DEMONSTRATION DATA` in its content and in the manifest
//! (`synthetic: true`). Production mode NEVER mixes synthetic data into
//! real acquired evidence.

use serde_json::json;

use super::{Availability, CollectContext, CollectorError, CollectorId, ICollector};

pub const SYNTHETIC_BANNER: &str = "SYNTHETIC DEMONSTRATION DATA - NOT REAL EVIDENCE";

pub struct DemoCollector {
    id: CollectorId,
}

impl DemoCollector {
    pub fn new(id: CollectorId) -> Self {
        Self { id }
    }

    fn doc(&self, category: &str, payload: serde_json::Value) -> serde_json::Value {
        json!({
            "synthetic_demonstration_data": true,
            "banner": SYNTHETIC_BANNER,
            "module": self.id.as_str(),
            "category": category,
            "generated_at": chrono::Local::now().to_rfc3339(),
            "payload": payload,
        })
    }
}

impl ICollector for DemoCollector {
    fn id(&self) -> CollectorId {
        self.id
    }

    fn name(&self) -> &'static str {
        "Demo (Synthetic)"
    }

    fn check_availability(&self) -> Availability {
        Availability::Available
    }

    fn collect(&mut self, ctx: &mut CollectContext) -> Result<(), CollectorError> {
        // Simulate small acquisition latency so the live progress UI is
        // visible during the demonstration.
        for _ in 0..3 {
            ctx.check_cancel()?;
            std::thread::sleep(std::time::Duration::from_millis(120));
        }

        let folder = if self.id == CollectorId::Events {
            // Match the real collector's container layout.
            "windows_events"
        } else {
            self.id.as_str()
        };
        let payload = sample_payload(self.id);
        ctx.add_json(
            &format!("{}/demo_synthetic.json", folder),
            SYNTHETIC_BANNER,
            Some(SYNTHETIC_BANNER.to_string()),
            &self.doc("demo", payload),
        )?;
        Ok(())
    }
}

fn sample_payload(id: CollectorId) -> serde_json::Value {
    match id {
        CollectorId::Memory => json!({
            "mode": "demo",
            "note": "No real memory data was acquired; this artifact exists only to demonstrate the workflow."
        }),
        CollectorId::Cpu => json!({"note": "demo CPU placeholder"}),
        CollectorId::Gpu => json!({"note": "demo GPU placeholder"}),
        CollectorId::Processes => json!({
            "processes": [
                {"pid": 4, "name": "System (demo)"},
                {"pid": 1024, "name": "demo-app.exe"}
            ]
        }),
        CollectorId::Network => json!({"note": "demo network placeholder"}),
        CollectorId::Events => json!({"note": "demo event log placeholder"}),
        CollectorId::Persistence => json!({"note": "demo persistence placeholder"}),
        CollectorId::Registry => json!({"note": "demo registry placeholder"}),
        CollectorId::Hashes => json!({"note": "demo hashes placeholder"}),
        CollectorId::SystemMetadata => json!({"note": "demo system metadata placeholder"}),
    }
}

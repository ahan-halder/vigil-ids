use serde::Serialize;

#[derive(Debug, Clone)]
pub struct Alert {
    pub message: String,
}

impl Alert {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct JsonAlert {
    pub timestamp_secs: Option<u64>,
    pub rule_id: String,
    pub severity: String,
    pub action: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub message: String,
}

impl From<&crate::engine::DetectionEvent> for JsonAlert {
    fn from(detection: &crate::engine::DetectionEvent) -> Self {
        Self {
            timestamp_secs: detection.timestamp_secs,
            rule_id: detection.rule_id.clone(),
            severity: detection.severity.clone(),
            action: detection.action.clone(),
            src_ip: detection.src_ip.clone(),
            dst_ip: detection.dst_ip.clone(),
            message: detection.message.clone(),
        }
    }
}

pub fn emit_json_alerts(
    detections: &[crate::engine::DetectionEvent],
    output_path: Option<&str>,
) -> Result<(), String> {
    let lines: Result<Vec<_>, _> = detections
        .iter()
        .map(|detection| serde_json::to_string(&JsonAlert::from(detection)))
        .collect();

    let lines = lines.map_err(|error| format!("failed to serialize alerts to JSON: {error}"))?;

    match output_path {
        Some(path) => {
            let payload = if lines.is_empty() {
                String::new()
            } else {
                format!("{}\n", lines.join("\n"))
            };
            std::fs::write(path, payload)
                .map_err(|error| format!("failed to write alerts to {path}: {error}"))?;
        }
        None => {
            for line in lines {
                println!("{line}");
            }
        }
    }

    Ok(())
}

use crate::models::timeline::{Reliability, TimelineEvent, TimelineEventType};
use crate::models::{FileAccessEvent, FileAccessType, UsbDevice};

/// Build a unified timeline from all artifact sources
pub struct TimelineBuilder {
    events: Vec<TimelineEvent>,
}

impl TimelineBuilder {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Add USB device events to the timeline
    pub fn add_usb_devices(&mut self, devices: &[UsbDevice]) {
        for device in devices {
            if let Some(ts) = device.first_connected {
                self.events.push(TimelineEvent {
                    timestamp: ts,
                    event_type: TimelineEventType::UsbFirstConnected,
                    source_artifact: "Registry-USBSTOR".to_string(),
                    description: format!(
                        "USB device first connected: {} {} (S/N: {})",
                        device.vendor, device.product, device.serial_number
                    ),
                    details: device.friendly_name.clone(),
                    device_serial: Some(device.serial_number.clone()),
                    file_path: None,
                    user: device.associated_user.clone(),
                    reliability: Reliability::High,
                });
            }

            if let Some(ts) = device.last_connected {
                self.events.push(TimelineEvent {
                    timestamp: ts,
                    event_type: TimelineEventType::UsbConnected,
                    source_artifact: "Registry-USBSTOR".to_string(),
                    description: format!(
                        "USB device connected: {} {} (S/N: {})",
                        device.vendor, device.product, device.serial_number
                    ),
                    details: device.drive_letter.clone(),
                    device_serial: Some(device.serial_number.clone()),
                    file_path: None,
                    user: device.associated_user.clone(),
                    reliability: Reliability::High,
                });
            }

            if let Some(ts) = device.last_disconnected {
                self.events.push(TimelineEvent {
                    timestamp: ts,
                    event_type: TimelineEventType::UsbDisconnected,
                    source_artifact: "Registry-USBSTOR".to_string(),
                    description: format!(
                        "USB device disconnected: {} {} (S/N: {})",
                        device.vendor, device.product, device.serial_number
                    ),
                    details: None,
                    device_serial: Some(device.serial_number.clone()),
                    file_path: None,
                    user: device.associated_user.clone(),
                    reliability: Reliability::High,
                });
            }
        }
    }

    /// Add file access events to the timeline
    pub fn add_file_events(&mut self, events: &[FileAccessEvent]) {
        for event in events {
            if let Some(ts) = event.timestamp {
                let event_type = match event.access_type {
                    FileAccessType::Created => TimelineEventType::FileCreated,
                    FileAccessType::Modified => TimelineEventType::FileModified,
                    FileAccessType::Accessed => TimelineEventType::FileAccessed,
                    FileAccessType::Deleted => TimelineEventType::FileDeleted,
                    FileAccessType::Renamed => TimelineEventType::FileRenamed,
                    FileAccessType::Copied => TimelineEventType::FileCopied,
                    FileAccessType::Executed => TimelineEventType::ApplicationExecuted,
                    FileAccessType::Browsed => TimelineEventType::FolderBrowsed,
                    FileAccessType::Unknown => TimelineEventType::FileAccessed,
                };

                let reliability = match event.source_artifact.as_str() {
                    s if s.contains("USN Journal") => Reliability::VeryHigh,
                    s if s.contains("MFT") => Reliability::High,
                    s if s.contains("EventLog") => Reliability::High,
                    s if s.contains("LNK") => Reliability::Medium,
                    s if s.contains("JumpList") => Reliability::Medium,
                    s if s.contains("Prefetch") => Reliability::Medium,
                    s if s.contains("Shellbag") => Reliability::High,
                    s if s.contains("Registry") => Reliability::High,
                    _ => Reliability::Medium,
                };

                self.events.push(TimelineEvent {
                    timestamp: ts,
                    event_type,
                    source_artifact: event.source_artifact.clone(),
                    description: format!(
                        "{}: {} ({})",
                        event.access_type, event.file_name, event.file_path
                    ),
                    details: event.details.clone(),
                    device_serial: None,
                    file_path: Some(event.file_path.clone()),
                    user: event.user.clone(),
                    reliability,
                });
            }
        }
    }

    /// Add raw timeline events (from event logs, setupapi, etc.)
    pub fn add_timeline_events(&mut self, events: Vec<TimelineEvent>) {
        self.events.extend(events);
    }

    /// Build the final sorted timeline
    pub fn build(mut self) -> Vec<TimelineEvent> {
        self.events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        self.events
    }
}

impl Default for TimelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

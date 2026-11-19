use std::collections::HashMap;

use serde_json::{Value, json};
use yubikit::core::{Transport, Version};
use yubikit::management::{Capability, DeviceInfo};

pub fn version_to_json(version: &Version) -> Value {
    json!([version.0, version.1, version.2])
}

fn transport_name(transport: Transport) -> &'static str {
    match transport {
        Transport::Usb => "usb",
        Transport::Nfc => "nfc",
    }
}

fn caps_to_json(caps: &HashMap<Transport, Capability>) -> Value {
    let mut map = serde_json::Map::new();
    for (transport, capability) in caps {
        map.insert(
            transport_name(*transport).to_string(),
            json!(capability.0),
        );
    }
    Value::Object(map)
}

pub fn info_to_json(info: &DeviceInfo) -> Value {
    json!({
        "serial": info.serial,
        "version": version_to_json(&info.version),
        "form_factor": info.form_factor as u8,
        "supported_capabilities": caps_to_json(&info.supported_capabilities),
        "config": {
            "enabled_capabilities": caps_to_json(&info.config.enabled_capabilities),
            "auto_eject_timeout": info.config.auto_eject_timeout,
            "challenge_response_timeout": info.config.challenge_response_timeout,
            "device_flags": info.config.device_flags.map(|flag| flag.0),
            "nfc_restricted": info.config.nfc_restricted,
        },
        "is_locked": info.is_locked,
        "is_fips": info.is_fips,
        "is_sky": info.is_sky,
        "part_number": info.part_number,
        "fips_capable": info.fips_capable.0,
        "fips_approved": info.fips_approved.0,
        "pin_complexity": info.pin_complexity,
        "reset_blocked": info.reset_blocked.0,
        "fps_version": info.fps_version.as_ref().map(version_to_json),
        "stm_version": info.stm_version.as_ref().map(version_to_json),
        "version_qualifier": {
            "version": version_to_json(&info.version_qualifier.version),
            "type": info.version_qualifier.release_type as u8,
            "iteration": info.version_qualifier.iteration,
        },
        "name": info.name,
    })
}

mod info;
mod transport;

use std::cell::RefCell;

use info::info_to_json;
use serde_json::{Value, json};
use transport::{WebFido, WebOtp, WebSmartCard, transfer, OP_STATUS};
use wasm_bindgen::prelude::wasm_bindgen;
use yubikit::ctap::CtapSession;
use yubikit::ctap2::Ctap2Session;
use yubikit::device::get_name;
use yubikit::management::{DeviceInfo, ManagementSession};
use yubikit::oath::{Code, Credential, OathAccessKey, OathSession};
use yubikit::piv::{ObjectId, PivSession, Slot};
use yubikit::yubiotp::{Slot as OtpSlot, YubiOtpSession};

thread_local! {
    static HOST: RefCell<Host> = RefCell::new(Host::default());
}

#[wasm_bindgen]
pub fn rpc(request: &str) -> String {
    HOST.with(|host| host.borrow_mut().handle(request))
}

struct Fail {
    status: String,
    message: String,
}

impl Fail {
    fn new(status: &str, message: impl Into<String>) -> Self {
        Self {
            status: status.to_string(),
            message: message.into(),
        }
    }

    fn node(name: &str) -> Self {
        Self::new("invalid-command", format!("No such node: {name}"))
    }

    fn action(name: &str) -> Self {
        Self::new("invalid-command", format!("No such action: {name}"))
    }
}

#[derive(Default)]
struct Host {
    info: Option<DeviceInfo>,
    generation: u64,
    id: String,
    name: String,
    pid: Option<i64>,
    ccid: bool,
    otp: bool,
    fido: bool,
    oath: Option<OathSession<WebSmartCard>>,
    oath_open: bool,
    oath_key: Option<OathAccessKey>,
}

impl Host {
    fn handle(&mut self, request: &str) -> String {
        let value: Value = match serde_json::from_str(request) {
            Ok(value) => value,
            Err(_) => return error("invalid-command", "Invalid JSON"),
        };
        if value.get("kind").and_then(|kind| kind.as_str()) != Some("command") {
            return success(json!({}));
        }
        let action = value.get("action").and_then(|item| item.as_str()).unwrap_or("");
        let target: Vec<String> = value
            .get("target")
            .and_then(|item| item.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let params = value.get("body").cloned().unwrap_or_else(|| json!({}));
        match self.dispatch(action, &target, &params) {
            Ok(body) => success(body),
            Err(failure) => error(&failure.status, &failure.message),
        }
    }

    fn dispatch(&mut self, action: &str, target: &[String], params: &Value) -> Result<Value, Fail> {
        let path: Vec<&str> = target.iter().map(String::as_str).collect();
        match (action, path.as_slice()) {
            ("logging" | "qr" | "diagnose", []) => self.root_action(action, params),
            ("get", []) => Ok(node(json!({"version": env!("CARGO_PKG_VERSION")}), &["diagnose", "logging", "qr"], json!({"devices": {}}))),
            ("get" | "scan" | "close", ["devices"]) | ("get" | "scan" | "close", ["devices", ..]) => {
                self.devices(action, &path, params)
            }
            _ => Err(Fail::action(action)),
        }
    }

    fn root_action(&mut self, action: &str, params: &Value) -> Result<Value, Fail> {
        match action {
            "logging" => Ok(json!({})),
            "qr" => {
                let _ = params;
                Ok(json!({"result": null}))
            }
            "diagnose" => {
                let status = transfer(OP_STATUS, &[])
                    .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|error| error.to_string()))
                    .unwrap_or_else(|error| json!({"error": error}));
                Ok(json!({"diagnostics": [status, "End of diagnostics"]}))
            }
            _ => Err(Fail::action(action)),
        }
    }

    fn refresh(&mut self) -> Result<(), String> {
        let bytes = transfer(OP_STATUS, &[])?;
        let status: Value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        let generation = status.get("generation").and_then(|value| value.as_u64()).unwrap_or(0);
        if self.info.is_some() && generation == self.generation {
            return Ok(());
        }
        self.generation = generation;
        self.info = None;
        self.oath = None;
        self.oath_open = false;
        self.ccid = status.get("ccid").and_then(|value| value.as_bool()).unwrap_or(false);
        self.otp = status.get("otp").and_then(|value| value.as_bool()).unwrap_or(false);
        self.fido = status.get("fido").and_then(|value| value.as_bool()).unwrap_or(false);
        if !status.get("connected").and_then(|value| value.as_bool()).unwrap_or(false) {
            return Err("No YubiKey is open".into());
        }
        self.pid = status
            .get("productId")
            .and_then(|value| value.as_u64())
            .filter(|pid| known_pid(*pid))
            .map(|pid| pid as i64);
        let info = self.read_info()?;
        self.id = info.serial.map(|serial| serial.to_string()).unwrap_or_else(|| "yk".into());
        self.name = get_name(&info);
        self.info = Some(info);
        Ok(())
    }

    fn read_info(&mut self) -> Result<DeviceInfo, String> {
        let mut errors = Vec::new();
        if self.ccid {
            match self.management_ccid() {
                Ok(info) => return Ok(info),
                Err(error) => errors.push(format!("CCID: {error}")),
            }
        }
        if self.fido {
            match self.management_fido() {
                Ok(info) => return Ok(info),
                Err(error) => errors.push(format!("FIDO: {error}")),
            }
        }
        if self.otp {
            match self.management_otp() {
                Ok(info) => return Ok(info),
                Err(error) => errors.push(format!("OTP: {error}")),
            }
        }
        if errors.is_empty() {
            Err("No USB interface could be opened".into())
        } else {
            Err(errors.join("; "))
        }
    }

    fn management_ccid(&mut self) -> Result<DeviceInfo, String> {
        self.pause_oath();
        let result = (|| {
            let mut session = ManagementSession::new(WebSmartCard).map_err(|(error, _)| error.to_string())?;
            session.read_device_info().map_err(|error| error.to_string())
        })();
        let _ = self.resume_oath();
        result
    }

    fn management_fido(&mut self) -> Result<DeviceInfo, String> {
        let connection = WebFido::open().map_err(|error| error.to_string())?;
        let mut session = ManagementSession::new_fido(connection).map_err(|(error, _)| error.to_string())?;
        session.read_device_info().map_err(|error| error.to_string())
    }

    fn management_otp(&mut self) -> Result<DeviceInfo, String> {
        let mut session = ManagementSession::new_otp(WebOtp).map_err(|(error, _)| error.to_string())?;
        session.read_device_info().map_err(|error| error.to_string())
    }

    fn info(&self) -> Result<&DeviceInfo, Fail> {
        self.info.as_ref().ok_or_else(|| Fail::new("connection-error", "No YubiKey is open"))
    }

    fn devices(&mut self, action: &str, path: &[&str], params: &Value) -> Result<Value, Fail> {
        if path.len() == 1 {
            return match action {
                "close" | "scan" => Ok(json!({})),
                "get" => self.device_list(),
                _ => Err(Fail::action(action)),
            };
        }
        let id = path[1];
        if self.refresh().is_err() || self.id != id {
            return Err(Fail::node(id));
        }
        if path.len() == 2 {
            return match action {
                "get" => self.device_get(),
                "close" => {
                    self.oath = None;
                    self.oath_open = false;
                    Ok(json!({}))
                }
                _ => Err(Fail::action(action)),
            };
        }
        match path[2] {
            "ccid" => self.ccid(action, &path[3..], params),
            "otp" => self.otp_interface(action, &path[3..], params),
            "fido" => self.fido_interface(action, &path[3..], params),
            other => Err(Fail::node(other)),
        }
    }

    fn device_list(&mut self) -> Result<Value, Fail> {
        if self.refresh().is_err() {
            return Ok(node(json!({"state": 0, "pids": {}}), &["get", "scan"], json!({})));
        }
        let info = self.info()?.clone();
        let id = self.id.clone();
        let child = json!({
            "name": self.name,
            "serial": info.serial,
            "transport": "usb",
            "pid": self.pid,
            "enabled_capabilities": info_to_json(&info)["config"]["enabled_capabilities"],
        });
        let mut children = serde_json::Map::new();
        children.insert(id, child);
        Ok(node(
            json!({"state": 0, "pids": {}}),
            &["get", "scan"],
            Value::Object(children),
        ))
    }

    fn device_get(&self) -> Result<Value, Fail> {
        let info = self.info()?.clone();
        let mut children = serde_json::Map::new();
        if self.ccid {
            children.insert("ccid".into(), json!({}));
        }
        if self.otp {
            children.insert("otp".into(), json!({}));
        }
        if self.fido {
            children.insert("fido".into(), json!({}));
        }
        Ok(node(
            json!({
                "name": self.name,
                "transport": "usb",
                "pid": self.pid,
                "info": info_to_json(&info),
            }),
            &["get"],
            Value::Object(children),
        ))
    }

    fn ccid(&mut self, action: &str, path: &[&str], params: &Value) -> Result<Value, Fail> {
        if !self.ccid {
            return Err(Fail::new("connection-error", "CCID is not open"));
        }
        if path.is_empty() {
            return if action == "get" {
                Ok(self.connection_node(&["management", "oath", "piv", "yubiotp"]))
            } else {
                Err(Fail::action(action))
            };
        }
        match path[0] {
            "management" => self.management_node(action),
            "oath" => self.oath(action, &path[1..], params),
            "piv" => self.piv(action, &path[1..]),
            "yubiotp" => self.yubiotp(action, true),
            "ctap2" => self.ctap(action, &path[1..], false),
            other => Err(Fail::node(other)),
        }
    }

    fn otp_interface(&mut self, action: &str, path: &[&str], params: &Value) -> Result<Value, Fail> {
        let _ = params;
        if !self.otp {
            return Err(Fail::new("connection-error", "OTP HID is not open"));
        }
        if path.is_empty() {
            return if action == "get" {
                Ok(self.connection_node(&["management", "yubiotp"]))
            } else {
                Err(Fail::action(action))
            };
        }
        match path[0] {
            "management" => self.management_node(action),
            "yubiotp" => self.yubiotp(action, false),
            other => Err(Fail::node(other)),
        }
    }

    fn fido_interface(&mut self, action: &str, path: &[&str], params: &Value) -> Result<Value, Fail> {
        let _ = params;
        if !self.fido {
            return Err(Fail::new("connection-error", "FIDO HID is not open"));
        }
        if path.is_empty() {
            return if action == "get" {
                Ok(self.connection_node(&["management", "ctap2"]))
            } else {
                Err(Fail::action(action))
            };
        }
        match path[0] {
            "management" => self.management_node(action),
            "ctap2" => self.ctap(action, &path[1..], true),
            other => Err(Fail::node(other)),
        }
    }

    fn connection_node(&self, children: &[&str]) -> Value {
        let info = self.info.as_ref();
        let mut map = serde_json::Map::new();
        for child in children {
            map.insert((*child).to_string(), json!({}));
        }
        node(
            json!({
                "version": info.map(|info| info::version_to_json(&info.version)).unwrap_or(json!([0, 0, 0])),
                "serial": info.and_then(|info| info.serial),
            }),
            &["get"],
            Value::Object(map),
        )
    }

    fn management_node(&self, action: &str) -> Result<Value, Fail> {
        if action != "get" {
            return Err(Fail::action(action));
        }
        self.connection_node(&[])
            .as_object()
            .cloned()
            .map(|map| Value::Object(map))
            .ok_or_else(|| Fail::new("device-error", "Management data was empty"))
    }

    fn pause_oath(&mut self) {
        if let Some(session) = self.oath.take() {
            drop(session.into_connection());
        }
    }

    fn resume_oath(&mut self) -> Result<(), String> {
        if self.oath.is_some() || !self.oath_open {
            return Ok(());
        }
        self.open_oath()
    }

    fn open_oath(&mut self) -> Result<(), String> {
        self.pause_oath();
        let key = self.oath_key.clone();
        let mut session = OathSession::new(WebSmartCard).map_err(|(error, _)| error.to_string())?;
        if let Some(key) = key
            && session.locked()
        {
            let _ = session.validate(&key);
        }
        self.oath = Some(session);
        self.oath_open = true;
        Ok(())
    }

    fn oath(&mut self, action: &str, path: &[&str], params: &Value) -> Result<Value, Fail> {
        if path.is_empty() {
            self.open_oath().map_err(|error| Fail::new("session-error", error))?;
            return match action {
                "get" => self.oath_get(),
                "derive" => self.oath_derive(params),
                "validate" => self.oath_validate(params),
                "set_key" => self.oath_set_key(params),
                "unset_key" => self.oath_unset_key(),
                "reset" => self.oath_reset(),
                "forget" => Err(Fail::new("exception", "KeyError")),
                _ => Err(Fail::action(action)),
            };
        }
        if path[0] != "accounts" {
            return Err(Fail::node(path[0]));
        }
        if path.len() == 1 {
            return match action {
                "get" => self.oath_accounts(),
                "calculate_all" => self.oath_calculate_all(params),
                _ => Err(Fail::action(action)),
            };
        }
        let credential_id = path[1];
        match action {
            "get" => Ok(node(json!({}), &["code", "calculate", "delete"], json!({}))),
            "delete" => self.oath_delete(credential_id),
            "code" => self.oath_code(credential_id, params),
            "calculate" => self.oath_calculate(credential_id, params),
            _ => Err(Fail::action(action)),
        }
    }

    fn with_oath<T>(&mut self, body: impl FnOnce(&mut OathSession<WebSmartCard>) -> Result<T, Fail>) -> Result<T, Fail> {
        self.open_oath().map_err(|error| Fail::new("session-error", error))?;
        let mut session = self.oath.take().unwrap();
        let result = body(&mut session);
        self.oath = Some(session);
        result
    }

    fn oath_get(&mut self) -> Result<Value, Fail> {
        self.with_oath(|session| {
            Ok(node(
                json!({
                    "version": info::version_to_json(&session.version()),
                    "device_id": session.device_id(),
                    "has_key": session.has_key(),
                    "locked": session.locked(),
                    "remembered": false,
                    "keystore": "unknown",
                }),
                &["derive", "validate", "set_key", "unset_key", "reset", "forget"],
                json!({"accounts": {}}),
            ))
        })
    }

    fn oath_accounts(&mut self) -> Result<Value, Fail> {
        self.with_oath(|session| {
            if session.locked() {
                return Err(Fail::new("auth-required", "Authentication is required"));
            }
            let credentials = session.list_credentials().map_err(device_error)?;
            Ok(node(json!({}), &["calculate_all"], credential_children(&credentials)))
        })
    }

    fn oath_calculate_all(&mut self, params: &Value) -> Result<Value, Fail> {
        let timestamp = timestamp_of(params);
        self.with_oath(|session| {
            if session.locked() {
                return Err(Fail::new("auth-required", "Authentication is required"));
            }
            let entries = session.calculate_all(timestamp).map_err(device_error)?;
            let entries = entries
                .iter()
                .map(|(credential, code)| {
                    json!({
                        "credential": credential_json(credential),
                        "code": code.as_ref().map(code_json),
                    })
                })
                .collect::<Vec<_>>();
            Ok(json!({"entries": entries}))
        })
    }

    fn oath_derive(&mut self, params: &Value) -> Result<Value, Fail> {
        let password = params.get("password").and_then(|value| value.as_str()).ok_or_else(|| Fail::new("invalid-command", "Invalid parameters: Missing password"))?;
        self.with_oath(|session| {
            let key = session.derive_key(password);
            Ok(json!({"key": hex::encode(key.expose_secret())}))
        })
    }

    fn oath_validate(&mut self, params: &Value) -> Result<Value, Fail> {
        let bytes = access_key_bytes(self, params)?;
        let key = OathAccessKey::new(&bytes).map_err(device_error)?;
        let valid = self.with_oath(|session| {
            if !session.locked() {
                return Ok(true);
            }
            Ok(session.validate(&key).is_ok())
        })?;
        if valid {
            self.oath_key = Some(key);
        }
        Ok(json!({"valid": valid, "remembered": false}))
    }

    fn oath_set_key(&mut self, params: &Value) -> Result<Value, Fail> {
        let bytes = access_key_bytes(self, params)?;
        let key = OathAccessKey::new(&bytes).map_err(device_error)?;
        self.with_oath(|session| session.set_key(&key).map_err(device_error))?;
        self.oath_key = Some(key);
        let info = self.info.as_ref().map(info_to_json).unwrap_or(Value::Null);
        Ok(json!({"remembered": false, "info": info}))
    }

    fn oath_unset_key(&mut self) -> Result<Value, Fail> {
        self.with_oath(|session| session.unset_key().map_err(device_error))?;
        self.oath_key = None;
        let info = self.info.as_ref().map(info_to_json).unwrap_or(Value::Null);
        Ok(json!({"info": info}))
    }

    fn oath_reset(&mut self) -> Result<Value, Fail> {
        self.open_oath().map_err(|error| Fail::new("session-error", error))?;
        let session = self.oath.take().unwrap();
        session.reset().map_err(|(error, _)| device_error(error))?;
        self.oath_key = None;
        self.oath_open = false;
        Ok(json!({}))
    }

    fn oath_delete(&mut self, credential_id: &str) -> Result<Value, Fail> {
        let id = hex::decode(credential_id).map_err(|_| Fail::new("invalid-command", "Invalid parameters: Invalid hex"))?;
        self.with_oath(|session| {
            session.delete_credential(&id).map_err(device_error)?;
            Ok(json!({}))
        })
    }

    fn oath_code(&mut self, credential_id: &str, params: &Value) -> Result<Value, Fail> {
        let timestamp = timestamp_of(params);
        self.with_oath(|session| {
            let credential = find_credential(session, credential_id)?;
            let code = session.calculate_code(&credential, timestamp).map_err(device_error)?;
            Ok(code_json(&code))
        })
    }

    fn oath_calculate(&mut self, credential_id: &str, params: &Value) -> Result<Value, Fail> {
        let challenge = params.get("challenge").and_then(|value| value.as_str()).ok_or_else(|| Fail::new("invalid-command", "Invalid parameters: Missing challenge"))?;
        let challenge = hex::decode(challenge).map_err(|_| Fail::new("invalid-command", "Invalid parameters: Invalid hex"))?;
        let id = hex::decode(credential_id).map_err(|_| Fail::new("invalid-command", "Invalid parameters: Invalid hex"))?;
        self.with_oath(|session| {
            let response = session.calculate(&id, &challenge).map_err(device_error)?;
            Ok(json!({"response": hex::encode(response)}))
        })
    }

    fn piv(&mut self, action: &str, path: &[&str]) -> Result<Value, Fail> {
        if path.is_empty() {
            return if action == "get" { self.piv_get() } else { Err(Fail::action(action)) };
        }
        if path[0] != "slots" {
            return Err(Fail::node(path[0]));
        }
        if path.len() == 1 && action == "get" {
            return self.piv_slots();
        }
        if action == "get" {
            return Ok(node(json!({}), &["delete", "generate"], json!({})));
        }
        Err(Fail::action(action))
    }

    fn piv_get(&mut self) -> Result<Value, Fail> {
        self.with_piv(|session| {
            let version = session.version();
            let supports_bio = session.get_bio_metadata().is_ok();
            let chuid = session.get_object(ObjectId::Chuid).ok().map(hex::encode);
            let ccc = session.get_object(ObjectId::Capability).ok().map(hex::encode);
            let pin = session.get_pin_metadata().ok();
            let puk = session.get_puk_metadata().ok();
            let management = session.get_management_key_metadata().ok();
            let attempts = pin.as_ref().map(|item| item.attempts_remaining).unwrap_or(0);
            let metadata = match (pin, puk, management) {
                (Some(pin), Some(puk), Some(management)) => json!({
                    "pin_metadata": {
                        "default_value": pin.default_value,
                        "total_attempts": pin.total_attempts,
                        "attempts_remaining": pin.attempts_remaining,
                    },
                    "puk_metadata": {
                        "default_value": puk.default_value,
                        "total_attempts": puk.total_attempts,
                        "attempts_remaining": puk.attempts_remaining,
                    },
                    "management_key_metadata": {
                        "key_type": management.key_type as u8,
                        "default_value": management.default_value,
                        "touch_policy": management.touch_policy as u8,
                    },
                }),
                _ => Value::Null,
            };
            Ok(node(
                json!({
                    "version": info::version_to_json(&version),
                    "authenticated": false,
                    "stored_key": false,
                    "pin_attempts": attempts,
                    "supports_bio": supports_bio,
                    "chuid": chuid,
                    "ccc": ccc,
                    "metadata": metadata,
                }),
                &["verify_pin", "change_pin", "change_puk", "unblock_pin", "reset", "authenticate"],
                json!({"slots": {}}),
            ))
        })
    }

    fn piv_slots(&mut self) -> Result<Value, Fail> {
        self.with_piv(|session| {
            let mut children = serde_json::Map::new();
            for slot in Slot::key_slots() {
                let id = slot as u8;
                children.insert(
                    format!("{id:02x}"),
                    json!({
                        "slot": id,
                        "metadata": null,
                        "cert_info": null,
                        "public_key_match": null,
                    }),
                );
                let _ = session;
            }
            Ok(node(json!({}), &["get"], Value::Object(children)))
        })
    }

    fn with_piv<T>(&mut self, body: impl FnOnce(&mut PivSession<WebSmartCard>) -> Result<T, Fail>) -> Result<T, Fail> {
        self.pause_oath();
        let result = (|| {
            let mut session = PivSession::new(WebSmartCard).map_err(|(error, _)| device_error(error))?;
            body(&mut session)
        })();
        let _ = self.resume_oath();
        result
    }

    fn yubiotp(&mut self, action: &str, ccid: bool) -> Result<Value, Fail> {
        if action != "get" {
            return Err(Fail::action(action));
        }
        let state = if ccid {
            self.pause_oath();
            let result = YubiOtpSession::new(WebSmartCard)
                .map_err(|(error, _)| device_error(error))
                .map(|session| session.get_config_state());
            let _ = self.resume_oath();
            result?
        } else {
            YubiOtpSession::new_otp(WebOtp)
                .map_err(|(error, _)| device_error(error))?
                .get_config_state()
        };
        let slot = |slot| state.is_configured(slot).unwrap_or(false);
        Ok(node(
            json!({
                "slot1_configured": slot(OtpSlot::One),
                "slot2_configured": slot(OtpSlot::Two),
                "slot1_touch_triggered": state.is_touch_triggered(OtpSlot::One).unwrap_or(false),
                "slot2_touch_triggered": state.is_touch_triggered(OtpSlot::Two).unwrap_or(false),
                "is_led_inverted": state.is_led_inverted(),
            }),
            &["swap"],
            json!({"one": {}, "two": {}}),
        ))
    }

    fn ctap(&mut self, action: &str, path: &[&str], hid: bool) -> Result<Value, Fail> {
        if path.is_empty() {
            return match action {
                "get" => self.ctap_get(hid),
                "credentials" | "fingerprints" => Ok(node(json!({}), &["get"], json!({}))),
                _ => Err(Fail::action(action)),
            };
        }
        if matches!(path[0], "credentials" | "fingerprints") && action == "get" {
            return Ok(node(json!({}), &["get"], json!({})));
        }
        Err(Fail::node(path[0]))
    }

    fn ctap_get(&mut self, hid: bool) -> Result<Value, Fail> {
        let info = if hid {
            let connection = WebFido::open().map_err(|error| Fail::new("connection-error", error.to_string()))?;
            let ctap = CtapSession::new_fido(connection).map_err(|(error, _)| device_error(error))?;
            let mut session = Ctap2Session::new(ctap).map_err(|(error, _)| device_error(error))?;
            session.get_info().map_err(device_error)?
        } else {
            self.pause_oath();
            let result = (|| {
                let ctap = CtapSession::new(WebSmartCard).map_err(|(error, _)| device_error(error))?;
                let mut session = Ctap2Session::new(ctap).map_err(|(error, _)| device_error(error))?;
                session.get_info().map_err(device_error)
            })();
            let _ = self.resume_oath();
            result?
        };
        let options = info
            .options
            .iter()
            .map(|(key, value)| (key.clone(), json!(value)))
            .collect::<serde_json::Map<_, _>>();
        Ok(node(
            json!({
                "info": {
                    "versions": info.versions,
                    "extensions": info.extensions,
                    "aaguid": hex::encode(info.aaguid.as_bytes()),
                    "options": options,
                    "max_msg_size": info.max_msg_size,
                    "pin_uv_protocols": info.pin_uv_protocols,
                    "transports": info.transports,
                    "min_pin_length": info.min_pin_length,
                    "force_pin_change": info.force_pin_change,
                },
                "unlocked": false,
                "unlocked_read": false,
            }),
            &["get", "reset", "set_pin"],
            json!({"credentials": {}, "fingerprints": {}}),
        ))
    }
}

fn node(data: Value, actions: &[&str], children: Value) -> Value {
    json!({"data": data, "actions": actions, "children": children})
}

fn success(body: Value) -> String {
    json!({"kind": "success", "body": body, "flags": []}).to_string()
}

fn error(status: &str, message: &str) -> String {
    json!({"kind": "error", "status": status, "message": message, "body": {}}).to_string()
}

fn device_error(error: impl std::fmt::Display) -> Fail {
    let message = error.to_string();
    if message.contains("6982") {
        Fail::new("auth-required", "Authentication is required")
    } else {
        Fail::new("device-error", message)
    }
}

fn timestamp_of(params: &Value) -> u64 {
    params
        .get("timestamp")
        .and_then(|value| value.as_u64())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .unwrap_or(0)
        })
}

fn access_key_bytes(host: &mut Host, params: &Value) -> Result<Vec<u8>, Fail> {
    let key = params.get("key").and_then(|value| value.as_str());
    let password = params.get("password").and_then(|value| value.as_str());
    match (key, password) {
        (Some(_), Some(_)) => Err(Fail::new(
            "invalid-command",
            "Invalid parameters: Only one of 'key' and 'password' can be provided",
        )),
        (Some(key), None) => hex::decode(key).map_err(|_| Fail::new("invalid-command", "Invalid parameters: Invalid hex key")),
        (None, Some(password)) => host.with_oath(|session| Ok(session.derive_key(password).expose_secret().to_vec())),
        (None, None) => Err(Fail::new(
            "invalid-command",
            "Invalid parameters: One of 'key' and 'password' must be provided",
        )),
    }
}

fn find_credential(session: &mut OathSession<WebSmartCard>, id: &str) -> Result<Credential, Fail> {
    session
        .list_credentials()
        .map_err(device_error)?
        .into_iter()
        .find(|credential| hex::encode(&credential.id).eq_ignore_ascii_case(id))
        .ok_or_else(|| Fail::node(id))
}

fn credential_json(credential: &Credential) -> Value {
    json!({
        "device_id": credential.device_id,
        "id": hex::encode(&credential.id),
        "issuer": credential.issuer,
        "name": credential.name,
        "oath_type": credential.oath_type as u8,
        "period": credential.period,
        "touch_required": credential.touch_required.unwrap_or(false),
    })
}

fn credential_children(credentials: &[Credential]) -> Value {
    let mut children = serde_json::Map::new();
    for credential in credentials {
        children.insert(hex::encode(&credential.id), credential_json(credential));
    }
    Value::Object(children)
}

fn code_json(code: &Code) -> Value {
    json!({
        "value": code.value,
        "valid_from": code.valid_from,
        "valid_to": code.valid_to,
    })
}

fn known_pid(pid: u64) -> bool {
    matches!(pid, 16 | 272..=278 | 288 | 1025..=1031 | 1040)
}

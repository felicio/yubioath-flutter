use yubikit::core::{Connection, Transport, Version};
use yubikit::fido::{CtapHidCapability, CtapHidError, FidoConnection, FidoError};
use yubikit::otp::{OtpConnection, OtpError};
use yubikit::smartcard::{SmartCardConnection, SmartCardError};
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;

pub const OP_STATUS: u32 = 0;
pub const OP_CCID: u32 = 1;
const OP_FIDO_WRITE: u32 = 2;
const OP_FIDO_READ: u32 = 3;
const OP_OTP_SEND: u32 = 4;
const OP_OTP_RECV: u32 = 5;

const BROADCAST_CID: u32 = 0xffff_ffff;
const TYPE_INIT: u8 = 0x80;
const CMD_INIT: u8 = 0x06;
const CMD_CANCEL: u8 = 0x11;
const CMD_KEEPALIVE: u8 = 0x3b;
const CMD_ERROR: u8 = 0x3f;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(catch, js_namespace = globalThis, js_name = ykTransfer)]
    fn yk_transfer(op: u32, data: &[u8]) -> Result<Vec<u8>, JsValue>;
}

#[derive(Debug)]
struct JsTransport(String);

impl std::fmt::Display for JsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for JsTransport {}

pub fn transfer(op: u32, data: &[u8]) -> Result<Vec<u8>, String> {
    yk_transfer(op, data).map_err(|error| {
        error
            .as_string()
            .unwrap_or_else(|| "USB transfer failed".to_string())
    })
}

fn js_error(message: String) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(JsTransport(message))
}

pub struct WebSmartCard;

impl Connection for WebSmartCard {
    type Error = SmartCardError;

    fn close(&mut self) {}
}

impl SmartCardConnection for WebSmartCard {
    fn send_and_receive(&mut self, apdu: &[u8]) -> Result<(Vec<u8>, u16), SmartCardError> {
        let response = transfer(OP_CCID, apdu)
            .map_err(|error| SmartCardError::Transport(js_error(error)))?;
        if response.len() < 2 {
            return Err(SmartCardError::InvalidData(
                "Response too short (no status word)".into(),
            ));
        }
        let split = response.len() - 2;
        let sw = u16::from_be_bytes([response[split], response[split + 1]]);
        Ok((response[..split].to_vec(), sw))
    }

    fn transport(&self) -> Transport {
        Transport::Usb
    }
}

pub struct WebOtp;

impl Connection for WebOtp {
    type Error = OtpError;

    fn close(&mut self) {}
}

impl OtpConnection for WebOtp {
    fn otp_receive(&mut self) -> Result<Vec<u8>, OtpError> {
        transfer(OP_OTP_RECV, &[]).map_err(|error| OtpError::Transport(js_error(error)))
    }

    fn otp_send(&mut self, data: &[u8]) -> Result<(), OtpError> {
        transfer(OP_OTP_SEND, data)
            .map(|_| ())
            .map_err(|error| OtpError::Transport(js_error(error)))
    }
}

pub struct WebFido {
    channel_id: u32,
    version: Version,
    capabilities: CtapHidCapability,
}

impl WebFido {
    pub fn open() -> Result<Self, FidoError> {
        let mut connection = Self {
            channel_id: BROADCAST_CID,
            version: Version(0, 0, 0),
            capabilities: CtapHidCapability(0),
        };
        connection.init()?;
        Ok(connection)
    }

    fn init(&mut self) -> Result<(), FidoError> {
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).map_err(|_| FidoError::InvalidResponse)?;
        let response = self.exchange(CMD_INIT, &nonce, &mut |_| {}, None)?;
        if response.len() < 17 || response[..8] != nonce {
            return Err(FidoError::WrongNonce);
        }
        self.channel_id = u32::from_be_bytes([
            response[8],
            response[9],
            response[10],
            response[11],
        ]);
        self.version = Version(response[13], response[14], response[15]);
        self.capabilities = CtapHidCapability(response[16]);
        Ok(())
    }

    fn send(&self, cmd: u8, data: &[u8]) -> Result<(), FidoError> {
        let mut remaining = data;
        let mut sequence = 0u8;
        let mut first = true;
        while !remaining.is_empty() || first {
            let mut packet = vec![0u8; 64];
            packet[..4].copy_from_slice(&self.channel_id.to_be_bytes());
            if first {
                packet[4] = TYPE_INIT | cmd;
                packet[5..7].copy_from_slice(&(data.len() as u16).to_be_bytes());
                let size = (64 - 7).min(remaining.len());
                packet[7..7 + size].copy_from_slice(&remaining[..size]);
                remaining = &remaining[size..];
                first = false;
            } else {
                packet[4] = sequence & 0x7f;
                let size = (64 - 5).min(remaining.len());
                packet[5..5 + size].copy_from_slice(&remaining[..size]);
                remaining = &remaining[size..];
                sequence = sequence.wrapping_add(1);
            }
            transfer(OP_FIDO_WRITE, &packet)
                .map_err(|error| FidoError::Transport(js_error(error)))?;
        }
        Ok(())
    }

    fn exchange(
        &self,
        cmd: u8,
        data: &[u8],
        on_keepalive: &mut dyn FnMut(u8),
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, FidoError> {
        self.send(cmd, data)?;
        let mut response = Vec::new();
        let mut expected = 0usize;
        let mut sequence = 0u8;
        let mut first = true;
        let mut last_keepalive = None;
        loop {
            let packet = transfer(OP_FIDO_READ, &[])
                .map_err(|error| FidoError::Transport(js_error(error)))?;
            if packet.len() < 5 {
                return Err(FidoError::InvalidResponse);
            }
            let channel = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
            if channel != self.channel_id {
                continue;
            }
            if first {
                let received = packet[4];
                if packet.len() < 7 {
                    return Err(FidoError::InvalidResponse);
                }
                expected = u16::from_be_bytes([packet[5], packet[6]]) as usize;
                let payload = &packet[7..];
                if received == TYPE_INIT | CMD_KEEPALIVE {
                    if let Some(status) = payload.first().copied()
                        && last_keepalive != Some(status)
                    {
                        last_keepalive = Some(status);
                        on_keepalive(status);
                    }
                    if cancel.is_some_and(|should_cancel| should_cancel()) {
                        let _ = self.send(CMD_CANCEL, &[]);
                    }
                    continue;
                }
                if received == TYPE_INIT | CMD_ERROR {
                    let code = payload.first().copied().unwrap_or(0x7f);
                    return Err(FidoError::CtapHidError(CtapHidError::from_byte(code)));
                }
                if received != TYPE_INIT | cmd {
                    return Err(FidoError::InvalidResponse);
                }
                response.extend_from_slice(payload);
                first = false;
            } else {
                if (packet[4] & 0x7f) != (sequence & 0x7f) {
                    return Err(FidoError::WrongSequence);
                }
                response.extend_from_slice(&packet[5..]);
                sequence = sequence.wrapping_add(1);
            }
            if response.len() >= expected {
                response.truncate(expected);
                return Ok(response);
            }
        }
    }
}

impl Connection for WebFido {
    type Error = FidoError;

    fn close(&mut self) {}
}

impl FidoConnection for WebFido {
    fn call(
        &mut self,
        cmd: u8,
        data: &[u8],
        mut on_keepalive: Option<&mut dyn FnMut(u8)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> Result<Vec<u8>, FidoError> {
        let mut ignore = |_| {};
        let keepalive: &mut dyn FnMut(u8) = match on_keepalive.as_mut() {
            Some(callback) => callback,
            None => &mut ignore,
        };
        self.exchange(cmd, data, keepalive, cancel)
    }

    fn device_version(&self) -> Version {
        self.version
    }

    fn capabilities(&self) -> CtapHidCapability {
        self.capabilities
    }
}

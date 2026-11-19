use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha1::{Digest, Sha1};

use crate::root::RootNode;
use crate::rpc::{self, RpcNode};

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const READY: &str = r#"{"kind":"signal","status":"helper-ready"}"#;
const IN_USE: &str = r#"{"kind":"error","status":"helper-in-use","message":"Another browser is already connected to the helper."}"#;

struct BusyGuard(Arc<AtomicBool>);

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub fn serve(addr: &str) -> io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    let busy = Arc::new(AtomicBool::new(false));
    log::warn!("Helper listening on {addr}");
    for connection in listener.incoming() {
        let stream = match connection {
            Ok(stream) => stream,
            Err(error) => {
                log::warn!("Helper connection failed: {error}");
                continue;
            }
        };
        stream.set_nodelay(true).ok();
        if let Err(error) = handshake(&stream) {
            log::warn!("Helper handshake failed: {error}");
            continue;
        }
        if busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            log::warn!("Helper is already connected to another browser");
            if let Err(error) = reject_in_use(&stream) {
                log::warn!("Helper could not tell the browser it is in use: {error}");
            }
            continue;
        }
        let busy = busy.clone();
        std::thread::spawn(move || {
            let _guard = BusyGuard(busy);
            if let Err(error) = session(stream) {
                log::warn!("Helper session ended: {error}");
            }
        });
    }
    Ok(())
}

fn session(stream: TcpStream) -> io::Result<()> {
    let writer = Arc::new(Mutex::new(stream.try_clone()?));
    {
        let mut out = writer.lock().unwrap();
        write_frame(&mut *out, 0x1, READY.as_bytes())?;
    }
    let mut reader = stream;
    let send = {
        let writer = writer.clone();
        Arc::new(move |data: serde_json::Value| {
            let line = serde_json::to_string(&data).unwrap_or_else(|_| "{}".into());
            let mut out = writer.lock().unwrap();
            let _ = write_frame(&mut *out, 0x1, line.as_bytes());
        })
    };
    let recv = Box::new(move || match read_message(&mut reader, &writer) {
        Ok(message) => message,
        Err(_) => None,
    });
    rpc::run_rpc_loop(Box::new(RootNode::new()) as Box<dyn RpcNode>, send, recv);
    Ok(())
}

fn reject_in_use(mut stream: &TcpStream) -> io::Result<()> {
    write_frame(&mut stream, 0x1, IN_USE.as_bytes())?;
    let mut payload = Vec::with_capacity(2 + "already-in-use".len());
    payload.extend_from_slice(&4000u16.to_be_bytes());
    payload.extend_from_slice(b"already-in-use");
    write_frame(&mut stream, 0x8, &payload)?;
    stream.shutdown(Shutdown::Both)
}

fn handshake(mut stream: &std::net::TcpStream) -> io::Result<()> {
    let mut buffer = [0u8; 8192];
    let mut filled = 0;
    let header = loop {
        if filled == buffer.len() {
            return Err(io::Error::other("WebSocket header is too large"));
        }
        let read = stream.read(&mut buffer[filled..])?;
        if read == 0 {
            return Err(io::Error::other("WebSocket client closed"));
        }
        filled += read;
        if let Some(end) = buffer[..filled].windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break String::from_utf8_lossy(&buffer[..end]).to_string();
        }
    };
    let key = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.eq_ignore_ascii_case("Sec-WebSocket-Key") {
                Some(value.trim().to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| io::Error::other("Missing WebSocket key"))?;
    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(GUID.as_bytes());
    let accept = STANDARD.encode(digest.finalize());
    write!(
        stream,
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    )?;
    stream.flush()
}

struct Frame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

fn read_message(
    reader: &mut impl Read,
    writer: &Arc<Mutex<impl Write>>,
) -> io::Result<Option<String>> {
    let mut text = Vec::new();
    loop {
        let frame = read_frame(reader)?;
        match frame.opcode {
            0x1 | 0x0 => {
                text.extend_from_slice(&frame.payload);
                if frame.fin {
                    let message = String::from_utf8_lossy(&text).trim().to_string();
                    return Ok((!message.is_empty()).then_some(message));
                }
            }
            0x8 => return Ok(None),
            0x9 => {
                let mut out = writer.lock().unwrap();
                write_frame(&mut *out, 0xA, &frame.payload)?;
            }
            0xA => {}
            _ => return Ok(None),
        }
    }
}

fn read_frame(reader: &mut impl Read) -> io::Result<Frame> {
    let mut header = [0u8; 2];
    reader.read_exact(&mut header)?;
    let fin = header[0] & 0x80 != 0;
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    let mut length = (header[1] & 0x7f) as u64;
    if length == 126 {
        let mut extended = [0u8; 2];
        reader.read_exact(&mut extended)?;
        length = u16::from_be_bytes(extended) as u64;
    } else if length == 127 {
        let mut extended = [0u8; 8];
        reader.read_exact(&mut extended)?;
        length = u64::from_be_bytes(extended);
    }
    if length > 8 * 1024 * 1024 {
        return Err(io::Error::other("WebSocket frame is too large"));
    }
    let mask = if masked {
        let mut mask = [0u8; 4];
        reader.read_exact(&mut mask)?;
        Some(mask)
    } else {
        None
    };
    let mut payload = vec![0u8; length as usize];
    reader.read_exact(&mut payload)?;
    if let Some(mask) = mask {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    Ok(Frame { fin, opcode, payload })
}

fn write_frame(writer: &mut impl Write, opcode: u8, payload: &[u8]) -> io::Result<()> {
    writer.write_all(&[0x80 | opcode])?;
    if payload.len() < 126 {
        writer.write_all(&[payload.len() as u8])?;
    } else if payload.len() <= u16::MAX as usize {
        writer.write_all(&[126])?;
        writer.write_all(&(payload.len() as u16).to_be_bytes())?;
    } else {
        writer.write_all(&[127])?;
        writer.write_all(&(payload.len() as u64).to_be_bytes())?;
    }
    writer.write_all(payload)?;
    writer.flush()
}

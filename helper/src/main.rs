mod appdata;
mod connection;
mod devices;
mod error;
mod fido;
mod genuine;
mod management;
mod monitor;
mod oath;
mod piv;
mod qr;
mod root;
mod rpc;
mod util;
mod web;
mod yubiotp;

use std::io::Write;

use serde_json::json;

fn main() {
    // Initialize logging with JSON formatter to stderr.
    // Set env_logger to accept all levels; actual filtering is controlled
    // dynamically via log::set_max_level (see root.rs "logging" action).
    env_logger::Builder::new()
        .format(|buf, record| {
            // Map Rust log levels to Python level names expected by the Flutter client.
            // log_traffic! macro uses trace! with a "traffic::" target prefix.
            let target = record.target();
            let (level, name) = if let Some(rest) = target.strip_prefix("traffic::") {
                ("TRAFFIC", rest)
            } else {
                let level = match record.level() {
                    log::Level::Error => "ERROR",
                    log::Level::Warn => "WARNING",
                    log::Level::Info => "INFO",
                    log::Level::Debug => "DEBUG",
                    log::Level::Trace => "TRAFFIC",
                };
                (level, target)
            };
            let data = json!({
                "time": jiff::Timestamp::now().as_millisecond() as f64 / 1000.0,
                "name": name,
                "level": level,
                "message": record.args().to_string(),
            });
            writeln!(buf, "{}", serde_json::to_string(&data).unwrap())
        })
        .filter_level(log::LevelFilter::Trace)
        .init();
    log::set_max_level(log::LevelFilter::Warn);

    if std::env::args().any(|arg| arg == "--web") {
        let port = std::env::var("AUTHENTICATOR_HELPER_PORT").unwrap_or_else(|_| "27182".into());
        web::serve(&format!("127.0.0.1:{port}")).expect("helper web port is unavailable");
        return;
    }

    let root: Box<dyn rpc::RpcNode> = Box::new(root::RootNode::new());
    rpc::run(root);
}

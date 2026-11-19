#!/bin/sh
set -eu
cd "$(dirname "$0")"
export PATH="${HOME}/.cargo/bin:${PATH}"
unset CARGO_TARGET_DIR
cargo build --target wasm32-unknown-unknown --release
BINDGEN="${HOME}/.cargo/bin/wasm-bindgen"
if [ ! -x "$BINDGEN" ]; then
  cargo install wasm-bindgen-cli --locked --version 0.2.100
fi
"$BINDGEN" --target web --out-dir ../web/helper \
  target/wasm32-unknown-unknown/release/authenticator_helper_web.wasm

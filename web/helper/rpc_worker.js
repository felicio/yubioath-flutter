let sab = null;

function ykTransfer(op, data) {
  const i32 = new Int32Array(sab);
  const u8 = new Uint8Array(sab);
  const request = data instanceof Uint8Array ? data : new Uint8Array(data);
  if (16 + request.length > u8.length) {
    throw new Error('USB request does not fit');
  }
  Atomics.store(i32, 1, op);
  Atomics.store(i32, 2, request.length);
  u8.set(request, 16);
  Atomics.store(i32, 0, 0);
  self.postMessage({ type: 'io' });
  Atomics.wait(i32, 0, 0, 120000);
  const status = Atomics.load(i32, 0);
  const length = Atomics.load(i32, 3);
  const response = u8.slice(16, 16 + length);
  if (status !== 1) {
    throw new Error(new TextDecoder().decode(response) || 'USB transfer failed');
  }
  return response;
}

globalThis.ykTransfer = ykTransfer;

self.onmessage = async (event) => {
  const msg = event.data;
  if (msg.type === 'init') {
    sab = msg.sab;
    const module = await import('./authenticator_helper_web.js');
    await module.default();
    self.rpc = module.rpc;
    self.postMessage({ type: 'ready' });
    return;
  }
  if (msg.type === 'rpc') {
    try {
      const line = self.rpc(msg.line);
      self.postMessage({ type: 'rpc', line });
    } catch (error) {
      self.postMessage({
        type: 'rpc',
        line: JSON.stringify({
          kind: 'error',
          status: 'helper-error',
          message: error instanceof Error ? error.message : String(error),
          body: {},
        }),
      });
    }
  }
};

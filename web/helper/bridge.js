window.__bootErrors = [];
window.addEventListener('error', (event) => {
  window.__bootErrors.push(
    `${event.message} @ ${event.filename}:${event.lineno}`,
  );
});
window.addEventListener('unhandledrejection', (event) => {
  window.__bootErrors.push(`rejection ${event.reason}`);
});

const VENDOR_YUBICO = 0x1050;
const OP_STATUS = 0;
const OP_CCID = 1;
const OP_FIDO_WRITE = 2;
const OP_FIDO_READ = 3;
const OP_OTP_SEND = 4;
const OP_OTP_RECV = 5;

const state = {
  connected: false,
  productId: null,
  productName: '',
  ccid: false,
  otp: false,
  fido: false,
  ccidError: null,
  hidError: null,
  generation: 0,
  hint: '',
};

let usbDevice = null;
let ccidOut = null;
let ccidIn = null;
let ccidSeq = 0;
let ccidPowered = false;
let fidoDevice = null;
let otpDevice = null;
const fidoQueue = [];
let fidoWaiter = null;
let worker = null;
let sab = null;

const usbAvailable = !!(navigator.usb && navigator.hid);

function statusMessage() {
  if (!usbAvailable) {
    return 'USB access is unavailable in this browser. Chrome, Edge, and other Chromium browsers can open a YubiKey.';
  }
  if (typeof crossOriginIsolated === 'boolean' && !crossOriginIsolated) {
    return 'This page is not cross-origin isolated, so the key helper cannot run.';
  }
  if (state.hint) return state.hint;
  if (!state.connected) {
    if (state.hint) return state.hint;
    return 'Press Open YubiKey and choose the key in the browser prompt.';
  }
  if (state.ccidError) {
    return `The key is open. ${state.ccidError}`;
  }
  if (state.hidError) return state.hidError;
  return '';
}

function snapshot() {
  return JSON.stringify({
    connected: state.connected,
    productId: state.productId,
    productName: state.productName,
    ccid: state.ccid,
    otp: state.otp,
    fido: state.fido,
    ccidError: state.ccidError,
    generation: state.generation,
  });
}

function bump() {
  state.generation += 1;
}

function findCcid(device) {
  const config = device.configuration;
  if (!config) return null;
  for (const iface of config.interfaces) {
    for (const alt of iface.alternates) {
      if (alt.interfaceClass !== 0x0b) continue;
      const out = alt.endpoints.find(
        (endpoint) => endpoint.direction === 'out' && endpoint.type === 'bulk',
      );
      const inn = alt.endpoints.find(
        (endpoint) => endpoint.direction === 'in' && endpoint.type === 'bulk',
      );
      if (!out || !inn) continue;
      return {
        interfaceNumber: iface.interfaceNumber,
        alternate: alt.alternateSetting,
        out: out.endpointNumber,
        inn: inn.endpointNumber,
      };
    }
  }
  return null;
}

function classifyHid(device) {
  for (const collection of device.collections) {
    if (collection.usagePage === 0xf1d0 && collection.usage === 0x01) {
      return 'fido';
    }
    if (collection.usagePage === 0x0001 && collection.usage === 0x0006) {
      return 'otp';
    }
  }
  return null;
}

function onFidoReport(event) {
  const data = new Uint8Array(
    event.data.buffer,
    event.data.byteOffset,
    event.data.byteLength,
  );
  if (fidoWaiter) {
    const waiter = fidoWaiter;
    fidoWaiter = null;
    waiter.resolve(data);
  } else {
    fidoQueue.push(data);
  }
}

async function openUsb(device) {
  usbDevice = device;
  ccidOut = null;
  ccidIn = null;
  ccidPowered = false;
  ccidSeq = 0;
  state.ccid = false;
  state.ccidError = null;
  await device.open();
  if (device.configuration == null) {
    const value = device.configurations[0]?.configurationValue ?? 1;
    await device.selectConfiguration(value);
  }
  const ccid = findCcid(device);
  if (!ccid) {
    state.ccidError = 'This YubiKey has no CCID interface.';
  } else {
    try {
      await device.claimInterface(ccid.interfaceNumber);
      if (ccid.alternate) {
        await device.selectAlternateInterface(
          ccid.interfaceNumber,
          ccid.alternate,
        );
      }
      ccidOut = ccid.out;
      ccidIn = ccid.inn;
      state.ccid = true;
    } catch (error) {
      state.ccid = false;
      state.ccidError = error instanceof Error ? error.message : String(error);
    }
  }
  state.connected = true;
  state.productId = device.productId;
  state.productName = device.productName || 'YubiKey';
}

async function openHids(devices) {
  fidoDevice = null;
  otpDevice = null;
  state.fido = false;
  state.otp = false;
  state.hidError = null;
  fidoQueue.length = 0;
  for (const device of devices) {
    const kind = classifyHid(device);
    if (!kind) continue;
    if (!device.opened) await device.open();
    if (kind === 'fido') {
      device.removeEventListener('inputreport', onFidoReport);
      device.addEventListener('inputreport', onFidoReport);
      fidoDevice = device;
      state.fido = true;
    } else if (kind === 'otp') {
      otpDevice = device;
      state.otp = true;
    }
    if (state.productId == null) {
      state.productId = device.productId;
      state.productName = device.productName || 'YubiKey';
    }
  }
}

function ccidHeader(type, data, b0, b1, b2) {
  const msg = new Uint8Array(10 + data.length);
  const view = new DataView(msg.buffer);
  msg[0] = type;
  view.setUint32(1, data.length, true);
  msg[5] = 0;
  msg[6] = ccidSeq & 0xff;
  msg[7] = b0;
  msg[8] = b1;
  msg[9] = b2;
  msg.set(data, 10);
  ccidSeq = (ccidSeq + 1) & 0xff;
  return msg;
}

async function ccidCommand(type, data, b0, b1, b2) {
  const expectedSeq = ccidSeq;
  const msg = ccidHeader(type, data, b0, b1, b2);
  const result = await usbDevice.transferOut(ccidOut, msg);
  if (result.status !== 'ok') {
    throw new Error(`CCID write ${result.status}`);
  }
  const chunks = [];
  for (;;) {
    const response = await usbDevice.transferIn(ccidIn, 65536);
    if (response.status !== 'ok' || !response.data) {
      throw new Error(`CCID read ${response.status}`);
    }
    const buf = new Uint8Array(response.data.buffer);
    if (buf.length < 10) throw new Error('CCID response is too short');
    if (buf[6] !== expectedSeq) continue;
    const status = buf[7];
    if ((status & 0xc0) === 0x80) continue;
    if ((status & 0xc0) !== 0) {
      throw new Error(
        `CCID status 0x${status.toString(16)} error 0x${buf[8].toString(16)}`,
      );
    }
    const length = new DataView(buf.buffer, buf.byteOffset, buf.byteLength).getUint32(1, true);
    chunks.push(buf.slice(10, 10 + length));
    if (buf[9] === 0) break;
  }
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

async function ccidTransfer(apdu) {
  if (!state.ccid) {
    throw new Error(state.ccidError || 'CCID is not open');
  }
  const hint = setTimeout(() => {
    state.hint = 'Touch the YubiKey if it is blinking.';
  }, 400);
  try {
    if (!ccidPowered) {
      await ccidCommand(0x62, new Uint8Array(0), 0, 0, 0);
      ccidPowered = true;
    }
    return await ccidCommand(0x6f, apdu, 0, 0, 0);
  } finally {
    clearTimeout(hint);
    state.hint = '';
  }
}

function fidoRead() {
  if (fidoQueue.length) return Promise.resolve(fidoQueue.shift());
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      if (fidoWaiter) {
        fidoWaiter = null;
        reject(new Error('FIDO HID timeout'));
      }
    }, 10000);
    fidoWaiter = {
      resolve: (data) => {
        clearTimeout(timer);
        resolve(data);
      },
    };
  });
}

async function handleIo(op, request) {
  if (op === OP_STATUS) return new TextEncoder().encode(snapshot());
  if (op === OP_CCID) return ccidTransfer(request);
  if (op === OP_FIDO_WRITE) {
    if (!fidoDevice) throw new Error('FIDO HID is not open');
    await fidoDevice.sendReport(0, request);
    return new Uint8Array(0);
  }
  if (op === OP_FIDO_READ) {
    if (!fidoDevice) throw new Error('FIDO HID is not open');
    return fidoRead();
  }
  if (op === OP_OTP_SEND) {
    if (!otpDevice) throw new Error('OTP HID is not open');
    await otpDevice.sendFeatureReport(0, request);
    return new Uint8Array(0);
  }
  if (op === OP_OTP_RECV) {
    if (!otpDevice) throw new Error('OTP HID is not open');
    const view = await otpDevice.receiveFeatureReport(0);
    const bytes = new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
    return bytes[0] === 0 ? bytes.slice(1) : bytes;
  }
  throw new Error(`Unknown USB operation ${op}`);
}

const rpcPending = [];

function startWorker() {
  if (!window.crossOriginIsolated) return;
  sab = new SharedArrayBuffer(256 * 1024);
  worker = new Worker('helper/rpc_worker.js', { type: 'module' });
  const i32 = new Int32Array(sab);
  const u8 = new Uint8Array(sab);
  worker.onmessage = async (event) => {
    const msg = event.data;
    if (msg.type === 'ready') {
      readyResolve();
      return;
    }
    if (msg.type === 'rpc') {
      const resolve = rpcPending.shift();
      if (resolve) resolve(msg.line);
      return;
    }
    if (msg.type !== 'io') return;
    try {
      const op = Atomics.load(i32, 1);
      const length = Atomics.load(i32, 2);
      const request = u8.slice(16, 16 + length);
      const response = await handleIo(op, request);
      if (16 + response.length > u8.length) {
        throw new Error('USB response does not fit');
      }
      u8.set(response, 16);
      Atomics.store(i32, 3, response.length);
      Atomics.store(i32, 0, 1);
    } catch (error) {
      const bytes = new TextEncoder().encode(
        error instanceof Error ? error.message : String(error),
      );
      u8.set(bytes.subarray(0, u8.length - 16), 16);
      Atomics.store(i32, 3, Math.min(bytes.length, u8.length - 16));
      Atomics.store(i32, 0, 2);
    }
    Atomics.notify(i32, 0);
  };
  worker.onerror = (event) => {
    readyReject(new Error(event.message || 'helper worker failed'));
  };
  worker.postMessage({ type: 'init', sab });
}

let readyResolve;
let readyReject;
const ready = new Promise((resolve, reject) => {
  readyResolve = resolve;
  readyReject = reject;
});

const CCID_BLOCKED =
  'Chrome blocks WebUSB for YubiKeys, so OATH and PIV on the smart card interface cannot be opened from this page.';

function requestKey() {
  const hid = navigator.hid;
  const request = hid && (hid.requestDevice || hid.requestDevices);
  if (typeof request !== 'function') {
    return Promise.reject(
      new Error('This browser has no WebHID device prompt.'),
    );
  }
  try {
    return Promise.resolve(
      request.call(hid, {
        filters: [{ vendorId: VENDOR_YUBICO, usagePage: 0xf1d0, usage: 0x01 }],
      }),
    );
  } catch (error) {
    return Promise.reject(error);
  }
}

async function connect(devices) {
  const hids = devices || (await requestKey());
  state.hint = '';
  await openHids(hids);
  if (navigator.usb) {
    const granted = (await navigator.usb.getDevices()).find(
      (device) => device.vendorId === VENDOR_YUBICO,
    );
    if (granted) {
      await openUsb(granted);
    } else if (!state.ccid) {
      state.ccidError = CCID_BLOCKED;
    }
  }
  state.connected = state.fido || state.otp || state.ccid;
  if (!state.connected) {
    throw new Error('No YubiKey interface was opened.');
  }
  bump();
  return snapshot();
}

async function reopenGranted() {
  if (!navigator.usb) return;
  try {
    const devices = await navigator.usb.getDevices();
    const yubi = devices.find((device) => device.vendorId === VENDOR_YUBICO);
    if (!yubi) return;
    await openUsb(yubi);
    if (navigator.hid) {
      const hids = (await navigator.hid.getDevices()).filter(
        (device) => device.vendorId === VENDOR_YUBICO,
      );
      await openHids(hids);
    }
    bump();
  } catch (error) {
    state.ccidError = error instanceof Error ? error.message : String(error);
  }
}

if (navigator.usb) {
  navigator.usb.addEventListener('disconnect', (event) => {
    if (event.device === usbDevice) {
      state.connected = false;
      state.ccid = false;
      state.otp = false;
      state.fido = false;
      usbDevice = null;
      fidoDevice = null;
      otpDevice = null;
      bump();
    }
  });
}

window.authenticator = {
  usbAvailable,
  get statusMessage() {
    return statusMessage();
  },
  ready,
  connect,
  call(line) {
    let parsed = null;
    try {
      parsed = JSON.parse(line);
    } catch (_) {}
    if (!worker) {
      const message = statusMessage() || 'The key helper is not running.';
      return Promise.resolve(
        JSON.stringify({
          kind: 'error',
          status: 'helper-error',
          message,
          body: {},
        }),
      );
    }
    if (!parsed || parsed.kind !== 'command') {
      worker.postMessage({ type: 'signal', line });
      return Promise.resolve(
        JSON.stringify({ kind: 'success', body: {}, flags: [] }),
      );
    }
    return new Promise((resolve) => {
      rpcPending.push(resolve);
      worker.postMessage({ type: 'rpc', line });
    });
  },
};

function mountOpenButton() {
  let bar = document.getElementById('yk-open-bar');
  if (!bar) {
    bar = document.createElement('div');
    bar.id = 'yk-open-bar';
    bar.style.cssText = [
      'position:fixed',
      'top:8px',
      'right:12px',
      'z-index:2147483647',
    ].join(';');
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = 'Open YubiKey';
    button.style.cssText = [
      'background:#c6e7a5',
      'color:#1b2118',
      'border:0',
      'border-radius:20px',
      'padding:10px 16px',
      'font:600 14px sans-serif',
      'cursor:pointer',
    ].join(';');
    button.addEventListener('click', () => {
      let pending;
      try {
        pending = requestKey();
      } catch (error) {
        pending = Promise.reject(error);
      }
      button.disabled = true;
      button.textContent = 'Opening…';
      pending
        .then((devices) => connect(devices))
        .catch((error) => {
          const name = error && error.name ? `${error.name}: ` : '';
          const message = error && error.message ? error.message : String(error);
          state.hint = `${name}${message}`;
        })
        .finally(() => {
          button.disabled = false;
          button.textContent = 'Open YubiKey';
        });
    });
    bar.append(button);
  }
  document.body.append(bar);
}

startWorker();
if (!worker) readyResolve();
reopenGranted();
mountOpenButton();
window.addEventListener('load', mountOpenButton);

function watchMain() {
  if (typeof window.$dartRunMain !== 'function' || window.$dartRunMain.__once) {
    return;
  }
  const run = window.$dartRunMain;
  function once() {
    if (window.$dartMainExecuted) return;
    run();
  }
  once.__once = true;
  window.$dartRunMain = once;
}

setInterval(() => {
  watchMain();
  if (
    !window.$dartMainExecuted &&
    window.$dartMainTearOffs?.length &&
    typeof window.$dartRunMain === 'function'
  ) {
    window.$dartRunMain();
  }
}, 200);

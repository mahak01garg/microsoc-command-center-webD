const crypto = require('crypto');
const Log = require('../models/Log');

const clients = new Set();

function encodeFrame(payload) {
  const message = Buffer.from(JSON.stringify(payload));
  const length = message.length;

  if (length < 126) {
    return Buffer.concat([Buffer.from([0x81, length]), message]);
  }

  if (length < 65536) {
    const header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 126;
    header.writeUInt16BE(length, 2);
    return Buffer.concat([header, message]);
  }

  const header = Buffer.alloc(10);
  header[0] = 0x81;
  header[1] = 127;
  header.writeBigUInt64BE(BigInt(length), 2);
  return Buffer.concat([header, message]);
}

function broadcast(payload) {
  const frame = encodeFrame(payload);
  for (const socket of clients) {
    if (!socket.destroyed) socket.write(frame);
  }
}

async function createDemoLog(userId) {
  const mockLog = Log.generateMockLog();
  if (userId) mockLog.processedBy = userId;
  mockLog.processedAt = new Date();
  const log = await Log.create(mockLog);
  broadcast({ type: 'new-log', log });
  try {
    const threatPipeline = require('./threatPipeline');
    threatPipeline.queueLogAnalysis(log, {
      userId,
      source: 'demo'
    });
  } catch (error) {
    // The demo feed should still work even if threat analysis is unavailable.
  }
  return log;
}

function handleUpgrade(req, socket) {
  const key = req.headers['sec-websocket-key'];
  if (!key) {
    socket.destroy();
    return;
  }

  const accept = crypto
    .createHash('sha1')
    .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
    .digest('base64');

  socket.write([
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${accept}`,
    '',
    ''
  ].join('\r\n'));

  clients.add(socket);
  socket.write(encodeFrame({ type: 'connected', message: 'MicroSOC realtime feed connected' }));

  socket.on('close', () => clients.delete(socket));
  socket.on('error', () => clients.delete(socket));
  socket.on('data', () => {
    socket.write(encodeFrame({ type: 'pong', timestamp: new Date().toISOString() }));
  });
}

module.exports = {
  broadcast,
  createDemoLog,
  handleUpgrade
};

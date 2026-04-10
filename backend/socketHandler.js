/**
 * socketHandler.js — Socket.io Event Handler
 */

module.exports = function socketHandler(io, packetCapture) {
  let connectionCount = 0;

  io.on('connection', (socket) => {
    connectionCount++;

    // 🔹 1. ดึง IP จริงของ Client ที่เชื่อมต่อเข้ามา
    let rawIp = socket.handshake.address;
    // แปลงรูปแบบ IPv6-mapped IPv4 ให้กลายเป็น IPv4 ปกติ (เช่น ::ffff:192.168.1.5 -> 192.168.1.5)
    let clientIP = rawIp.includes('::ffff:') ? rawIp.split('::ffff:')[1] : rawIp;
    if (clientIP === '::1') clientIP = '127.0.0.1'; // กรณีรันบนเครื่องตัวเอง

    let clientRole = 'user'; // กำหนดค่าเริ่มต้นเป็น user
    let clientUsername = 'guest';

    console.log(`🔌 Client เชื่อมต่อ: ${socket.id} (IP: ${clientIP}) — รวม ${connectionCount} connections`);

    socket.emit('connected', {
      message: 'เชื่อมต่อ WebSocket สำเร็จ',
      socketId: socket.id,
      serverTime: new Date().toISOString(),
      capturing: packetCapture.isCapturing(),
      interface: packetCapture.getInterface()
    });

    socket.emit('stats', buildStats(packetCapture));

    // 🔹 2. รับข้อมูล Auth จากหน้าเว็บ เพื่อบันทึกว่า Socket นี้คือใคร สิทธิ์อะไร
    socket.on('auth', (data) => {
      clientRole = data.role || 'user';
      clientUsername = data.username || 'guest';
      console.log(`🔐 Socket ${socket.id} ยืนยันตัวตนเป็น [${clientRole.toUpperCase()}] ผู้ใช้: ${clientUsername}`);
    });

    // 🔹 3. จัดการตอนกดปุ่ม เริ่มดักจับ
    socket.on('capture:start', ({ iface = '6,7,8,10', filter = '' } = {}) => {
      let finalFilter = filter;

      // 🚨 ตรวจสอบสิทธิ์ (Role Check)
      if (clientRole !== 'admin') {
        // ถ้าเป็นแค่ User ธรรมดา ไม่ว่าจะส่ง Filter อะไรมา Backend จะทิ้งหมด
        // แล้วบังคับให้ดักจับแค่ IP ของเครื่องตัวเองเท่านั้น
        finalFilter = `host ${clientIP}`;
        console.log(`🔒 [USER] ${clientUsername} ขอเริ่มดักจับ -> บังคับ Filter เป็น: "${finalFilter}"`);
      } else {
        // ถ้าเป็น Admin อนุญาตให้ใช้ Filter ที่ส่งมาจากหน้าเว็บได้เลย (เพื่อดักของทุกคนหรือกรองแบบอิสระ)
        console.log(`🔓 [ADMIN] ${clientUsername} ขอเริ่มดักจับ -> ใช้ Filter: "${finalFilter || 'ทั้งหมด'}"`);
      }

      try {
        packetCapture.start(iface, finalFilter, io);
        io.emit('capture:status', { capturing: true, interface: iface });
      } catch (err) {
        socket.emit('error', { message: err.message });
      }
    });

    socket.on('capture:stop', () => {
      console.log('⏹  capture:stop');
      packetCapture.stop();
      io.emit('capture:status', { capturing: false });
    });

    socket.on('stats:request', () => {
      socket.emit('stats', buildStats(packetCapture));
    });

    socket.on('ping', (data) => {
      socket.emit('pong', { ...data, serverTime: Date.now() });
    });

    socket.on('disconnect', (reason) => {
      connectionCount = Math.max(0, connectionCount - 1);
      console.log(`❌ Client ตัดการเชื่อมต่อ: ${socket.id} (${reason}) — เหลือ ${connectionCount} connections`);
    });

    socket.on('error', (err) => {
      console.error(`⚠️  Socket error (${socket.id}):`, err.message);
    });
  });

  setInterval(() => {
    if (connectionCount > 0) console.log(`📊 Active connections: ${connectionCount}`);
  }, 30000);
};

function buildStats(packetCapture) {
  const s = packetCapture.getStats();
  return {
    total: s.total,
    encrypted: s.encrypted,
    unencrypted: s.unencrypted,
    encryptedPct: s.total > 0 ? Math.round((s.encrypted / s.total) * 100) : 0,
    protocols: s.protocols || {},
    uptime: s.startTime ? Math.round((Date.now() - s.startTime) / 1000) : 0
  };
}
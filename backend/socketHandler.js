// socketHandler.js
module.exports = function socketHandler(io, packetCapture) {

  // 🟢 ฟังก์ชันจัดการ Packet และอัปเดตสถิติรายบุคคล
  const handleData = (pkt) => {
    io.sockets.sockets.forEach((socket) => {
      if (!socket.isCapturingData) return;

      let canSee = false;
      // 1. Admin เห็นทราฟฟิกทุกคน (Global) | 2. User เห็นทราฟฟิกที่มี IP ตัวเองเกี่ยวข้อง
      if (socket.role === 'admin' || pkt.srcIP === socket.clientIP || pkt.dstIP === socket.clientIP) {
        canSee = true;
      }

      if (canSee) {
        // ส่งแพ็กเก็ตไปที่หน้าเว็บ
        socket.emit('packet', pkt);

        // 🟢 อัปเดตสถิติส่วนตัว (เพื่อให้ Dashboard/Graph ในหน้าเว็บทำงาน)
        socket.uStats.total++;
        if (pkt.encrypted) socket.uStats.encrypted++;
        else socket.uStats.unencrypted++;

        const p = pkt.protocol;
        if (socket.uStats.protocols[p] !== undefined) socket.uStats.protocols[p]++;
        else socket.uStats.protocols['OTHER']++;
      }
    });
  };

  io.on('connection', (socket) => {
    // ระบุ IP Client
    let rawIp = socket.handshake.address;
    let clientIP = rawIp.includes('::ffff:') ? rawIp.split('::ffff:')[1] : rawIp;
    if (clientIP === '::1') clientIP = '127.0.0.1';

    socket.clientIP = clientIP;
    socket.isCapturingData = false;
    socket.role = 'user';

    // 🟢 เตรียมตัวแปรสถิติให้ Dashboard (ต้องมีโครงสร้างตามโค้ดดั้งเดิมของคุณ)
    socket.uStats = {
      total: 0, encrypted: 0, unencrypted: 0, encryptedPct: 0,
      protocols: { HTTPS: 0, HTTP: 0, DNS: 0, SSH: 0, TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 },
      _lastTotal: 0, pps: 0
    };

    socket.on('auth', (data) => {
      socket.role = data.role || 'user';
      socket.username = data.username || 'guest';
      console.log(`🔐 Logged in: ${socket.username} (${socket.role}) from ${socket.clientIP}`);
    });

    socket.on('capture:start', ({ iface = '5' } = {}) => {
      socket.isCapturingData = true;
      // รีเซ็ตสถิติเมื่อกดเริ่มใหม่
      socket.uStats = { total: 0, encrypted: 0, unencrypted: 0, encryptedPct: 0, protocols: { HTTPS: 0, HTTP: 0, DNS: 0, SSH: 0, TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 }, _lastTotal: 0, pps: 0 };

      // สั่ง Tshark เริ่มทำงานแบบ Global (ถ้ายังไม่รัน)
      if (!packetCapture.isCapturing()) {
        packetCapture.start(iface, (pkt) => handleData(pkt));
      }
      socket.emit('capture:status', { capturing: true, interface: iface });
    });

    socket.on('capture:stop', () => {
      socket.isCapturingData = false;
      socket.emit('capture:status', { capturing: false });

      const anyoneLeft = Array.from(io.sockets.sockets.values()).some(s => s.isCapturingData);
      if (!anyoneLeft) packetCapture.stop();
    });

    socket.on('disconnect', () => {
      const anyoneLeft = Array.from(io.sockets.sockets.values()).some(s => s.isCapturingData);
      if (!anyoneLeft) packetCapture.stop();
    });
  });

  // 🟢 หัวใจสำคัญ: ส่งสถิติ (Stats) ไปให้ Dashboard/Graph ทุก 1 วินาที
  setInterval(() => {
    io.sockets.sockets.forEach((socket) => {
      if (socket.isCapturingData) {
        if (socket.uStats.total > 0) {
          socket.uStats.encryptedPct = Math.round((socket.uStats.encrypted / socket.uStats.total) * 100);
        }
        // คำนวณ Packets per second (PPS) สำหรับกราฟเส้น
        socket.uStats.pps = socket.uStats.total - socket.uStats._lastTotal;
        socket.uStats._lastTotal = socket.uStats.total;

        // 🟢 ส่ง Event 'stats' พร้อมข้อมูลที่หน้าเว็บคุณรอรับอยู่
        socket.emit('stats', socket.uStats);
      }
    });
  }, 1000);
};
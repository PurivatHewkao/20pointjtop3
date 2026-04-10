const os = require('os');
const { spawn, exec } = require('child_process');
const fs = require('fs');
const path = require('path');

// เซฟเป็นไฟล์นามสกุล .jsonl (JSON Lines) เพื่อให้เขียนต่อท้ายได้อย่างรวดเร็ว
const DATA_FILE = path.join(__dirname, 'packet_log.jsonl');

let tshark = null;
let capturing = false;
let currentIface = '';
let stats = {
  total: 0,
  encrypted: 0,
  unencrypted: 0,
  protocols: { HTTPS: 0, HTTP: 0, DNS: 0, SSH: 0, TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 },
  startTime: null
};
let statsTimer = null;
let packetId = 0;

const ENCRYPTED_PORTS = new Set([443, 8443, 465, 993, 995, 587]);
const SSH_PORTS = new Set([22]);

// --- ระบบ Buffer เพื่อเขียนลงไฟล์ ---
let packetBuffer = [];
const BATCH_SIZE = 50; 

function savePacketsToFile(newPackets) {
  if (newPackets.length === 0) return;

  try {
    // แปลงแต่ละ Object ให้เป็น String 1 บรรทัด แล้วเอามาต่อกัน
    const lines = newPackets.map(p => JSON.stringify(p)).join('\n') + '\n';
    
    // ใช้ fs.appendFile (แบบ Asynchronous) เพื่อเขียนต่อท้ายไฟล์ โดยไม่ทำให้โปรแกรมหลักค้าง
    fs.appendFile(DATA_FILE, lines, (err) => {
      if (err) console.error('❌ File Append Error:', err);
    });
  } catch (err) {
    console.error('❌ Error processing file data:', err);
  }
}
// ---------------------------------

function getLocalIP() {
  const interfaces = os.networkInterfaces();
  for (let name in interfaces) {
    for (let iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return null;
}

const myIP = getLocalIP();
console.log('My IP:', myIP);

function toPort(value) {
  const p = parseInt(value, 10);
  return Number.isNaN(p) ? null : p;
}

function isEncryptedPort(srcPort, dstPort) {
  const src = toPort(srcPort);
  const dst = toPort(dstPort);
  return (src && (ENCRYPTED_PORTS.has(src) || SSH_PORTS.has(src))) ||
         (dst && (ENCRYPTED_PORTS.has(dst) || SSH_PORTS.has(dst)));
}

function normalizeProtocol(proto, srcPort, dstPort, tlsVer) {
  const p = proto ? proto.toUpperCase() : '';
  const src = toPort(srcPort);
  const dst = toPort(dstPort);

  if (tlsVer && tlsVer !== '') return 'HTTPS';
  if (src === 443 || dst === 443) return 'HTTPS';
  if (src === 22 || dst === 22) return 'SSH';
  if (p.includes('DNS')) return 'DNS';
  if (src === 80 || dst === 80) return 'HTTP';
  if (p.includes('HTTP')) return 'HTTP';
  if (p.includes('UDP')) return 'UDP';
  if (p.includes('ICMP')) return 'ICMP';
  if (p.includes('TCP')) return 'TCP';
  return 'OTHER';
}

function isEncrypted(proto, srcPort, dstPort, tlsVer) {
  const src = toPort(srcPort);
  const dst = toPort(dstPort);
  if (tlsVer && tlsVer !== '') return true;
  if (src === 443 || dst === 443) return true;
  if (src === 22 || dst === 22) return true;
  return false;
}

function tlsVersionFromProto(proto, srcPort, dstPort) {
  const p = proto ? proto.toUpperCase() : '';
  if (p.includes('TLS 1.3') || p.includes('TLS1.3')) return 'TLS 1.3';
  if (p.includes('TLS 1.2') || p.includes('TLS1.2')) return 'TLS 1.2';
  if (p.includes('TLS 1.1') || p.includes('TLS1.1')) return 'TLS 1.1';
  if (p.includes('TLS 1.0') || p.includes('TLS1.0')) return 'TLS 1.0';
  if (p.includes('SSL')) return 'SSL 3.0';
  if (p.includes('SSH')) return 'SSH-2.0';
  if (p.includes('HTTPS')) return 'TLS 1.3';
  if (isEncryptedPort(srcPort, dstPort)) {
    return SSH_PORTS.has(toPort(srcPort)) || SSH_PORTS.has(toPort(dstPort)) ? 'SSH-2.0' : 'TLS 1.3';
  }
  return '-';
}

function emitStats(io) {
  if (!io) return;
  const elapsed = stats.startTime ? (Date.now() - stats.startTime) / 1000 : 1;
  io.emit('stats', {
    total: stats.total,
    encrypted: stats.encrypted,
    unencrypted: stats.unencrypted,
    encryptedPct: stats.total > 0 ? Math.round((stats.encrypted / stats.total) * 100) : 0,
    protocols: { ...stats.protocols },
    pps: Math.round(stats.total / Math.max(1, elapsed)),
    uptime: Math.round(elapsed)
  });
}

function resetStats() {
  stats = {
    total: 0, encrypted: 0, unencrypted: 0,
    protocols: { HTTPS: 0, HTTP: 0, DNS: 0, SSH: 0, TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 },
    startTime: Date.now()
  };
  packetId = 0;
}

function emitPacket(io, pkt) {
  if (!pkt || !io) return;

  stats.total += 1;
  if (pkt.encrypted) stats.encrypted += 1;
  else stats.unencrypted += 1;

  if (stats.protocols[pkt.protocol] !== undefined) stats.protocols[pkt.protocol] += 1;
  else stats.protocols.OTHER += 1;

  io.emit('packet', pkt);
  if (stats.total % 50 === 0) emitStats(io);

  // นำข้อมูลเข้า Buffer เตรียมเซฟลงไฟล์
  packetBuffer.push(pkt);

  // ถ้ายอดถึง 50 แพ็กเก็ต ให้เขียนลงไฟล์
  if (packetBuffer.length >= BATCH_SIZE) {
    const dataToSave = [...packetBuffer];
    packetBuffer = []; 
    savePacketsToFile(dataToSave);
  }
}

function parseLine(line) {
  const [src, dst, tcpSrc, tcpDst, udpSrc, udpDst, proto, tlsVer, len] = line.split('\t');
  if (!src || !dst) return null;

  const srcPort = tcpSrc || udpSrc || '-';
  const dstPort = tcpDst || udpDst || '-';
  const protocol = normalizeProtocol(proto, srcPort, dstPort, tlsVer);
  const encrypted = isEncrypted(proto, srcPort, dstPort, tlsVer);  
  const tlsVersion = tlsVersionFromProto(proto, srcPort, dstPort);
  const size = parseInt(len, 10) || 0;

  return {
    id: ++packetId,
    timestamp: new Date().toISOString(),
    time: new Date().toLocaleTimeString('th-TH'),
    srcIP: src,
    dstIP: dst,
    srcPort,
    dstPort,
    protocol,
    size,
    tlsVersion: tlsVersion || '-',
    encrypted
  };
}

function startTshark(io, iface = '5', filter = '') {
  const tsharkPath = 'C:\\Program Files\\Wireshark\\tshark.exe';

  if (!filter || filter.trim() === 'ip') {
    const myIP = getLocalIP();
    if (myIP) {
      console.log('✅ Using IP filter:', myIP);
      filter = `host ${myIP}`;
    } else {
      filter = '';
    }
  }

  const ifaceList = String(iface).split(',').map(s => s.trim()).filter(Boolean);
  const ifaceArgs = ifaceList.flatMap(i => ['-i', i]);

  const args = [
    ...ifaceArgs, '-l', '-T', 'fields',
    '-e', 'ip.src', '-e', 'ip.dst', '-e', 'tcp.srcport', '-e', 'tcp.dstport',
    '-e', 'udp.srcport', '-e', 'udp.dstport', '-e', '_ws.col.Protocol',
    '-e', 'tls.record.version', '-e', 'frame.len'
  ];

  if (filter) args.unshift('-f', filter);

  console.log('🚀 Running tshark:', tsharkPath, args.join(' '));

  tshark = spawn(tsharkPath, args, { windowsHide: true });
  let leftover = '';

  tshark.stdout.on('data', (data) => {
    const chunk = leftover + data.toString();
    const lines = chunk.split('\n');
    leftover = lines.pop();

    lines.forEach((line) => {
      if (!line.trim()) return;
      const pkt = parseLine(line);
      if (pkt) emitPacket(io, pkt);
    });
  });

  tshark.stderr.on('data', (err) => {
    console.error('❌ [tshark stderr]', err.toString().trim());
  });

  tshark.on('exit', (code) => {
    capturing = false;
    console.log(`⏹ tshark exited code=${code}`);
    if (io) io.emit('capture:status', { capturing: false });
  });

  if (statsTimer) clearInterval(statsTimer);
  statsTimer = setInterval(() => emitStats(io), 2000);

  capturing = true;
  currentIface = iface;

  if (io) {
    io.emit('capture:status', { capturing: true, interface: iface });
    emitStats(io);
  }
}

function stopTshark() {
  capturing = false;

  if (tshark) {
    console.log('🔪 Killing tshark process...');
    tshark.kill('SIGTERM');
    tshark = null;
  }
  exec('taskkill /IM tshark.exe /F 2>nul', () => {});

  if (statsTimer) {
    clearInterval(statsTimer);
    statsTimer = null;
  }

  // เซฟแพ็กเก็ตที่ค้างอยู่ก่อนปิด
  if (packetBuffer.length > 0) {
    savePacketsToFile([...packetBuffer]);
    packetBuffer = [];
    console.log('💾 เซฟแพ็กเก็ตสุดท้ายลงไฟล์สำเร็จ');
  }
}

module.exports = {
  start(iface = '5', filter = '', io) {
    if (capturing) {
      stopTshark();
      setTimeout(() => { resetStats(); startTshark(io, iface, filter); }, 500);
    } else {
      resetStats();
      startTshark(io, iface, filter);
    }
  },
  stop() { stopTshark(); },
  isCapturing: () => capturing,
  getInterface: () => currentIface,
  getStats: () => ({ ...stats })
};
// capture.js
const { spawn, exec } = require('child_process');

let tshark = null;
let capturing = false;
let currentIface = '';
let packetId = 0;

// ฟังก์ชันวิเคราะห์โปรโตคอล (คงเดิม)
function normalizeProtocol(proto, srcPort, dstPort, tlsVer) {
  const p = proto ? proto.toUpperCase() : '';
  if (tlsVer && tlsVer !== '') return 'HTTPS';
  if (srcPort == 443 || dstPort == 443) return 'HTTPS';
  if (srcPort == 22 || dstPort == 22) return 'SSH';
  if (p.includes('DNS')) return 'DNS';
  if (srcPort == 80 || dstPort == 80) return 'HTTP';
  if (p.includes('TCP')) return 'TCP';
  if (p.includes('UDP')) return 'UDP';
  return 'OTHER';
}

function startTshark(iface = '5', onPacket) {
  const tsharkPath = 'C:\\Program Files\\Wireshark\\tshark.exe';
  // 🟢 ถอด filter ออกเพื่อให้ Tshark ดักจับได้ทุกอย่าง (Global) แล้วค่อยไปกรองใน Node.js
  const args = [
    '-i', iface, '-l', '-T', 'fields',
    '-e', 'ip.src', '-e', 'ip.dst',
    '-e', 'tcp.srcport', '-e', 'tcp.dstport',
    '-e', 'udp.srcport', '-e', 'udp.dstport',
    '-e', '_ws.col.Protocol', '-e', 'tls.record.version', '-e', 'frame.len'
  ];

  tshark = spawn(tsharkPath, args, { windowsHide: true });
  let leftover = '';

  tshark.stdout.on('data', (data) => {
    const chunk = leftover + data.toString();
    const lines = chunk.split('\n');
    leftover = lines.pop();

    lines.forEach((line) => {
      if (!line.trim()) return;
      const [src, dst, tcpSrc, tcpDst, udpSrc, udpDst, proto, tlsVer, len] = line.split('\t');
      if (!src || !dst) return;

      const sPort = tcpSrc || udpSrc || '-';
      const dPort = tcpDst || udpDst || '-';

      // 🟢 แก้ไข: บังคับให้ encrypted เป็น Boolean (true/false) เท่านั้นเพื่อให้ Frontend ทำงานได้
      const isEnc = (tlsVer && tlsVer !== '') || sPort == '443' || dPort == '443' || sPort == '22' || dPort == '22';

      const pkt = {
        id: ++packetId,
        time: new Date().toLocaleTimeString('th-TH'),
        srcIP: src,
        dstIP: dst,
        srcPort: sPort,
        dstPort: dPort,
        protocol: normalizeProtocol(proto, sPort, dPort, tlsVer),
        size: parseInt(len, 10) || 0,
        tlsVersion: tlsVer || '-',
        encrypted: isEnc // 🟢 ต้องเป็น Boolean เท่านั้น
      };

      if (typeof onPacket === 'function') {
        onPacket(pkt);
      }
    });
  });

  tshark.on('exit', () => { capturing = false; });
  capturing = true;
  currentIface = iface;
}

module.exports = {
  start(iface, onPacket) {
    if (capturing) return;
    packetId = 0;
    startTshark(iface, onPacket);
  },
  stop: () => {
    capturing = false;
    if (tshark) { tshark.kill(); tshark = null; }
    exec('taskkill /IM tshark.exe /F 2>nul', () => { });
  },
  isCapturing: () => capturing,
  getInterface: () => currentIface
};
const socket = io();

const username = sessionStorage.getItem('username') || 'guest';
const role = sessionStorage.getItem('role') || 'user';

let running = false;
let myIP = 'Unknown IP'; // 🟢 เก็บค่า IP ตัวเอง
let totalPkts = 0, encPkts = 0, noencPkts = 0;
let packets = [];
const MAX_ROWS = 15;
let currentFilter = 'ALL';
const protoCounts = { HTTPS: 0, HTTP: 0, DNS: 0, SSH: 0, TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 };

const chartOptions = { responsive: true, maintainAspectRatio: false, animation: false, plugins: { legend: { display: false } } };

const lineChart = new Chart(document.getElementById('lineChart').getContext('2d'), {
  type: 'line', data: { labels: Array(30).fill(''), datasets: [{ data: Array(30).fill(0), borderColor: '#3b82f6', backgroundColor: 'rgba(59,130,246,0.1)', fill: true, tension: 0.4, borderWidth: 2, pointRadius: 0 }] }, options: chartOptions
});

const donutChart = new Chart(document.getElementById('donutChart').getContext('2d'), {
  type: 'doughnut', data: { labels: ['Encrypted', 'Unencrypted'], datasets: [{ data: [0, 0], backgroundColor: ['#10b981', '#ef4444'], borderWidth: 0, cutout: '75%' }] }, options: chartOptions
});

const barChart = new Chart(document.getElementById('barChart').getContext('2d'), {
  type: 'bar', data: { labels: Object.keys(protoCounts), datasets: [{ data: Object.values(protoCounts), backgroundColor: '#6366f1', borderRadius: 4 }] }, options: chartOptions
});

socket.on('connect', () => {
  socket.emit('auth', { username, role });
});

// 🟢 รับค่า IP จากเซิร์ฟเวอร์มาแสดงบนหน้าจอ
socket.on('connected', (data) => {
  running = data.capturing;
  myIP = data.clientIP;
  updateToggleBtn();
  updateRoleDisplay();
});

function updateRoleDisplay() {
  const topbarLogo = document.querySelector('.topbar-left .logo');
  if (topbarLogo) {
    // 🟢 แสดง Role และ IP ไว้ด้านบนเพื่อให้เช็คได้ง่ายว่า IP ถูกต้องไหม
    topbarLogo.innerHTML = `Packet Viz <span>[${role.toUpperCase()}] - My IP: ${myIP}</span>`;
  }
}

// 🟢 รับแพ็กเก็ตและคำนวณสถิติด้วยตัวเอง (ไม่พึ่งพาสถิติกลาง)
socket.on('packet', (pkt) => {
  packets = [pkt, ...packets].slice(0, 50);
  totalPkts++;
  if (pkt.encrypted) encPkts++; else noencPkts++;
  if (protoCounts[pkt.protocol] !== undefined) protoCounts[pkt.protocol]++;
  else protoCounts['OTHER']++;

  updateStats(1);
  renderTable();
  updateCharts(1);
});

socket.on('alert', (a) => {
  addAlert(a.type, a.message);
});

socket.on('capture:status', (s) => {
  running = s.capturing;
  updateToggleBtn();
});

socket.on('error', (e) => addAlert('danger', e.message));

function toggleCapture() {
  if (!running) {
    socket.emit('capture:start', { iface: '5', filter: '' });
  } else {
    socket.emit('capture:stop');
  }
}

function updateToggleBtn() {
  const btn = document.querySelector('.btn-stop') || document.getElementById('toggleBtn');
  if (!btn) return;
  btn.textContent = running ? 'หยุดดักจับ' : 'เริ่มดักจับ';
  btn.style.background = running ? '#dc2626' : '#3b82f6';
  btn.style.color = '#fff';
}

function setFilter(f, btn) {
  currentFilter = f;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderTable();
}

function renderTable() {
  const tbody = document.getElementById('packet-table');
  if (!tbody) return;
  const filtered = currentFilter === 'ALL' ? packets : packets.filter(p => p.protocol === currentFilter);
  tbody.innerHTML = filtered.slice(0, MAX_ROWS).map(p => `
    <tr>
      <td>#${p.id}</td>
      <td>${p.time || new Date(p.timestamp).toLocaleTimeString('th-TH')}</td>
      <td>${p.srcIP}</td><td>${p.dstIP}</td>
      <td><span class="pill pill-${(p.protocol || '').toLowerCase()}">${p.protocol}</span></td>
      <td>${p.dstPort || '-'}</td><td>${p.size}</td>
      <td style="color:var(--text-sub)">${p.tlsVersion || '-'}</td>
      <td><span class="pill ${p.encrypted ? 'pill-enc' : 'pill-noenc'}">
        ${p.encrypted ? 'Encrypted' : 'Unencrypted'}</span></td>
    </tr>
  `).join('');
}

function updateStats(burst) {
  const ep = totalPkts > 0 ? Math.round((encPkts / totalPkts) * 100) : 0;
  if (document.getElementById('pps')) document.getElementById('pps').textContent = burst;
  if (document.getElementById('total')) document.getElementById('total').textContent = totalPkts.toLocaleString();
  if (document.getElementById('enc-pct')) document.getElementById('enc-pct').textContent = ep + '%';
  if (document.getElementById('noenc-pct')) document.getElementById('noenc-pct').textContent = (100 - ep) + '%';
  if (document.getElementById('enc-count')) document.getElementById('enc-count').textContent = encPkts.toLocaleString() + ' pkts';
  if (document.getElementById('noenc-count')) document.getElementById('noenc-count').textContent = noencPkts.toLocaleString() + ' pkts';
}

function updateCharts(burst) {
  lineChart.data.datasets[0].data.push(burst);
  lineChart.data.datasets[0].data.shift();
  lineChart.update('none');
  donutChart.data.datasets[0].data = [encPkts, noencPkts];
  donutChart.update('none');
  barChart.data.datasets[0].data = Object.values(protoCounts);
  barChart.update('none');
}

function addAlert(type, msg) {
  const box = document.getElementById('alerts-box');
  if (!box) return;
  const icon = type === 'danger' ? '✕' : type === 'warning' ? '⚠' : 'ℹ';
  box.insertAdjacentHTML('afterbegin', `
    <div class="alert-row alert-${type}">
      <span>${icon}</span>
      <div>${msg}<br><small>${new Date().toLocaleTimeString()}</small></div>
    </div>`);
  if (box.children.length > 5) box.lastElementChild.remove();
}

setInterval(() => {
  const el = document.getElementById('clock');
  if (el) el.textContent = new Date().toLocaleTimeString('th-TH');
}, 1000);
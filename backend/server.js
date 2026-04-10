// server.js
const express = require("express");
const http = require("http");
const cors = require("cors");
const path = require("path");
const { initSocket } = require("./socket");
const socketHandler = require("./socketHandler");
const packetCapture = require("./capture");
const authRoutes = require("./routes/authRoutes");

const app = express();
app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.redirect("/login.html");
});
// ------------------------------------------------

app.use(express.static(path.join(__dirname, '../frontend')));

app.use("/api", authRoutes);

const server = http.createServer(app);

const io = initSocket(server);

socketHandler(io, packetCapture);

const PORT = 3000;
// 🟢 แก้ไข: เพิ่ม '0.0.0.0' เพื่อเปิดรับ Connection จากทุก IP ในวง LAN (ไม่ใช่แค่ localhost)
server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🔐 Auth API ready at /api`);
  console.log(`🌐 หากต้องการใช้งานจากเครื่องอื่น ให้เข้าผ่าน http://10.99.156.237:${PORT}`);
});
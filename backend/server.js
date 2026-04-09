const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");

const app = express();
app.use(cors());

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*"
  }
});

// 🔥 เมื่อมี client connect
io.on("connection", (socket) => {
  console.log("Client connected:", socket.id);
});

// 🔥 MOCK packet (ใช้ demo ได้เลย)
setInterval(() => {
  const packet = {
    time: new Date().toLocaleTimeString(),
    srcIP: "192.168.1." + Math.floor(Math.random() * 255),
    dstIP: "142.250.1.1",
    protocol: ["TCP", "UDP", "HTTP", "HTTPS"][Math.floor(Math.random() * 4)],
    encrypted: Math.random() > 0.5
  };

  io.emit("packet", packet);

}, 1000);

// 🔥 start server
server.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
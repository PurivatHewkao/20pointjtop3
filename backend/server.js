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
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
  console.log(`🔐 Auth API ready at http://localhost:${PORT}/api`);
});
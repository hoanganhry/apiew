// Simple Key Server - No Login Version

const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 10000;
const DATA_FILE = path.join(__dirname, "keys.json");
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "1";

/* ================= SAFE LOAD/SAVE ================= */

function loadKeys() {
  if (!fs.existsSync(DATA_FILE)) return [];
  return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
}

function saveKeys(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

function generateKey() {
  return "KEY-" + crypto.randomBytes(8).toString("hex").toUpperCase();
}

/* ================= ROOT ================= */

app.get("/", (req, res) => {
  res.json({
    name: "Simple Key API",
    status: "online"
  });
});

/* ================= CREATE KEY ================= */

app.post("/api/create-key", (req, res) => {
  const { password, days, devices } = req.body;

  if (password !== ADMIN_PASSWORD) {
    return res.status(403).json({ success: false, message: "Sai mật khẩu admin" });
  }

  if (!days || !devices) {
    return res.json({ success: false, message: "Thiếu days hoặc devices" });
  }

  const keys = loadKeys();

  const newKey = {
    id: uuidv4(),
    key_code: generateKey(),
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + days * 86400000).toISOString(),
    allowed_devices: Number(devices),
    devices: [],
    total_verifications: 0
  };

  keys.push(newKey);
  saveKeys(keys);

  res.json({ success: true, key: newKey });
});

/* ================= VERIFY KEY ================= */

app.post("/api/verify-key", (req, res) => {
  const { key, device_id } = req.body;

  if (!key || !device_id) {
    return res.status(400).json({ success: false, message: "Thiếu key hoặc device_id" });
  }

  const keys = loadKeys();
  const found = keys.find(k => k.key_code === key);

  if (!found) {
    return res.status(404).json({ success: false, message: "Key không tồn tại" });
  }

  if (new Date(found.expires_at) < new Date()) {
    return res.json({ success: false, message: "Key đã hết hạn" });
  }

  if (!found.devices.includes(device_id)) {
    if (found.devices.length >= found.allowed_devices) {
      return res.json({
        success: false,
        message: "Đã đạt giới hạn thiết bị"
      });
    }

    found.devices.push(device_id);
  }

  found.total_verifications++;
  saveKeys(keys);

  res.json({
    success: true,
    message: "Xác thực thành công",
    expires_at: found.expires_at,
    devices_remaining: found.allowed_devices - found.devices.length
  });
});

/* ================= LIST KEYS (ADMIN) ================= */

app.get("/api/list-keys", (req, res) => {
  const password = req.query.password;

  if (password !== ADMIN_PASSWORD) {
    return res.status(403).json({ success: false, message: "Sai mật khẩu admin" });
  }

  res.json(loadKeys());
});

/* ================= DELETE KEY ================= */

app.post("/api/delete-key", (req, res) => {
  const { password, key } = req.body;

  if (password !== ADMIN_PASSWORD) {
    return res.status(403).json({ success: false, message: "Sai mật khẩu admin" });
  }

  let keys = loadKeys();
  keys = keys.filter(k => k.key_code !== key);
  saveKeys(keys);

  res.json({ success: true, message: "Đã xóa key" });
});

/* ================= SERVER START ================= */

app.listen(PORT, () => {
  console.log("Simple Key API running on port " + PORT);
});

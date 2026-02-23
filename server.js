import express from "express";
import cors from "cors";
import fs from "fs";
import crypto from "crypto";

const app = express();
const PORT = process.env.PORT || 3000;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const ADMIN_SECRET = process.env.ADMIN_SECRET || "admin-secret-123";
const KEYS_FILE = "./keys.json";

app.use(cors());
app.use(express.json());

// ════════════════════════════════════════════
//  💾 Lưu / Đọc keys từ file JSON
// ════════════════════════════════════════════
function loadKeys() {
  if (!fs.existsSync(KEYS_FILE)) return {};
  try { return JSON.parse(fs.readFileSync(KEYS_FILE, "utf-8")); }
  catch { return {}; }
}

function saveKeys(keys) {
  fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2));
}

// ════════════════════════════════════════════
//  🛡️ Middleware xác minh Admin
// ════════════════════════════════════════════
function requireAdmin(req, res, next) {
  const secret = req.headers["x-admin-secret"];
  if (secret !== ADMIN_SECRET) {
    return res.status(403).json({ error: "Không có quyền admin" });
  }
  next();
}

// ════════════════════════════════════════════
//  📡 ROUTES
// ════════════════════════════════════════════

// Health check
app.get("/", (req, res) => {
  res.json({ status: "ok", message: "Proxy Server đang chạy 🚀" });
});

// ── [PUBLIC] Xác minh key — dành cho iOS/C++ client ──
// iOS gửi: POST /verify  body: { key: "sk-proxy-xxx", deviceId: "uuid" }
// Server trả: { success: true/false, message: "..." }
app.post("/verify", (req, res) => {
  const { key, deviceId } = req.body;

  if (!key) {
    return res.json({ success: false, message: "Thiếu key" });
  }

  const keys = loadKeys();
  const keyData = keys[key];

  if (!keyData) {
    return res.json({ success: false, message: "Key không hợp lệ" });
  }

  if (!keyData.active) {
    return res.json({ success: false, message: "Key đã bị vô hiệu hóa" });
  }

  if (keyData.expiresAt && new Date() > new Date(keyData.expiresAt)) {
    return res.json({ success: false, message: "Key đã hết hạn" });
  }

  // Ghi lại thông tin dùng
  keys[key].lastUsed = new Date().toISOString();
  keys[key].requestCount = (keys[key].requestCount || 0) + 1;
  if (deviceId) keys[key].lastDevice = deviceId;
  saveKeys(keys);

  return res.json({
    success: true,
    message: "Xác minh thành công! Chào " + (keyData.label || "bạn") + " 👋",
    label: keyData.label,
    expiresAt: keyData.expiresAt,
  });
});

// ── [ADMIN] Tạo key mới ──────────────────────
app.post("/admin/keys/create", requireAdmin, (req, res) => {
  const { label, expiresInDays } = req.body;

  const newKey = "sk-proxy-" + crypto.randomBytes(24).toString("hex");
  const keys = loadKeys();

  keys[newKey] = {
    label: label || "Unnamed",
    active: true,
    createdAt: new Date().toISOString(),
    expiresAt: expiresInDays
      ? new Date(Date.now() + expiresInDays * 86400000).toISOString()
      : null,
    lastUsed: null,
    lastDevice: null,
    requestCount: 0,
  };

  saveKeys(keys);
  res.json({ success: true, key: newKey, data: keys[newKey] });
});

// ── [ADMIN] Xem tất cả keys ──────────────────
app.get("/admin/keys", requireAdmin, (req, res) => {
  const keys = loadKeys();
  const list = Object.entries(keys).map(([key, data]) => ({
    key: key.slice(0, 16) + "...",
    fullKey: key,
    ...data,
  }));
  res.json({ count: list.length, keys: list });
});

// ── [ADMIN] Vô hiệu hóa key ──────────────────
app.post("/admin/keys/revoke", requireAdmin, (req, res) => {
  const { key } = req.body;
  const keys = loadKeys();
  if (!keys[key]) return res.status(404).json({ error: "Key không tồn tại" });
  keys[key].active = false;
  saveKeys(keys);
  res.json({ success: true, message: "Key đã bị vô hiệu hóa" });
});

// ── [ADMIN] Xóa key ───────────────────────────
app.delete("/admin/keys/delete", requireAdmin, (req, res) => {
  const { key } = req.body;
  const keys = loadKeys();
  if (!keys[key]) return res.status(404).json({ error: "Key không tồn tại" });
  delete keys[key];
  saveKeys(keys);
  res.json({ success: true, message: "Key đã bị xóa" });
});

app.listen(PORT, () => {
  console.log("✅ Server chạy tại http://localhost:" + PORT);
  console.log("🔑 Admin secret: " + ADMIN_SECRET);
});




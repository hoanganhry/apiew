import express from "express";
import cors from "cors";
import fs from "fs";
import crypto from "crypto";

const app = express();
const PORT = process.env.PORT || 3000;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const ADMIN_SECRET = process.env.ADMIN_SECRET || "admin-secret-123"; // đổi lại trong .env
const KEYS_FILE = "./keys.json";

app.use(cors());
app.use(express.json());

// ════════════════════════════════════════════
//  💾 Lưu / Đọc keys từ file JSON
// ════════════════════════════════════════════
function loadKeys() {
  if (!fs.existsSync(KEYS_FILE)) return {};
  return JSON.parse(fs.readFileSync(KEYS_FILE, "utf-8"));
}

function saveKeys(keys) {
  fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2));
}

// ════════════════════════════════════════════
//  🔐 Middleware xác minh API key
// ════════════════════════════════════════════
function requireApiKey(req, res, next) {
  const key = req.headers["x-api-key"] || req.headers["authorization"]?.replace("Bearer ", "");

  if (!key) {
    return res.status(401).json({ error: "Thiếu API key. Truyền qua header: x-api-key" });
  }

  const keys = loadKeys();
  const keyData = keys[key];

  if (!keyData) {
    return res.status(403).json({ error: "API key không hợp lệ" });
  }

  if (!keyData.active) {
    return res.status(403).json({ error: "API key đã bị vô hiệu hóa" });
  }

  if (keyData.expiresAt && new Date() > new Date(keyData.expiresAt)) {
    return res.status(403).json({ error: "API key đã hết hạn" });
  }

  // Ghi lại lần dùng cuối + đếm số request
  keys[key].lastUsed = new Date().toISOString();
  keys[key].requestCount = (keys[key].requestCount || 0) + 1;
  saveKeys(keys);

  req.keyData = keyData;
  next();
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

// ── [PUBLIC] Xác minh key ─────────────────────
app.get("/verify", requireApiKey, (req, res) => {
  res.json({
    valid: true,
    label: req.keyData.label,
    expiresAt: req.keyData.expiresAt,
    requestCount: req.keyData.requestCount,
  });
});

// ── [PUBLIC] Chat với Claude ──────────────────
app.post("/chat", requireApiKey, async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: "Server chưa cấu hình ANTHROPIC_API_KEY" });
  }

  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: req.body.model || "claude-haiku-4-5-20251001",
        max_tokens: req.body.max_tokens || 1024,
        messages: req.body.messages,
        system: req.body.system,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({ error: data.error?.message || "Lỗi từ Anthropic" });
    }

    res.json(data);
  } catch (err) {
    res.status(500).json({ error: "Lỗi kết nối: " + err.message });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Server chạy tại http://localhost:${PORT}`);
  console.log(`🔑 Admin secret: ${ADMIN_SECRET}`);
});



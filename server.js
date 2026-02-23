import express from "express";
import cors from "cors";
import fs from "fs-extra";

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = "./keys.json";

// ===== ADMIN TOKEN =====
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "123456"; // đổi nếu muốn
let SERVER_ENABLED = true;

app.use(cors());
app.use(express.json());

if (!fs.existsSync(DB_FILE)) {
    fs.writeJsonSync(DB_FILE, []);
}

async function loadKeys() {
    return await fs.readJson(DB_FILE);
}

async function saveKeys(data) {
    await fs.writeJson(DB_FILE, data, { spaces: 2 });
}

function generateKey(length = 12) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// ===== AUTO DELETE EXPIRED =====
async function autoDeleteExpired() {
    let keys = await loadKeys();
    const now = new Date();
    const valid = keys.filter(k => new Date(k.expiresAt) > now);
    if (valid.length !== keys.length) {
        await saveKeys(valid);
    }
}
setInterval(autoDeleteExpired, 60000);

// ===== ADMIN CHECK MIDDLEWARE =====
function checkAdmin(req, res, next) {
    const token = req.headers["x-admin-token"];
    if (token !== ADMIN_TOKEN) {
        return res.status(403).json({ error: "Invalid admin token" });
    }
    next();
}

// ===== CREATE KEY =====
app.post("/create", checkAdmin, async (req, res) => {
    const { owner, duration, unit, deviceLimit, customKey } = req.body;

    if (!owner || !duration || !unit) {
        return res.status(400).json({ error: "Missing data" });
    }

    let ms = 0;
    if (unit === "hours") ms = duration * 3600000;
    if (unit === "days") ms = duration * 86400000;
    if (unit === "weeks") ms = duration * 7 * 86400000;
    if (unit === "months") ms = duration * 30 * 86400000;

    const expiresAt = new Date(Date.now() + ms);
    const keys = await loadKeys();

    let apiKey = customKey ? customKey.toUpperCase() : generateKey(12);

    if (keys.find(k => k.apiKey === apiKey)) {
        return res.status(400).json({ error: "Key already exists" });
    }

    const newKey = {
        apiKey,
        owner,
        createdAt: new Date().toISOString(),
        expiresAt: expiresAt.toISOString(),
        deviceLimit: deviceLimit || 1,
        devices: []
    };

    keys.push(newKey);
    await saveKeys(keys);

    res.json(newKey);
});

app.post('/api/verify-key', async (req, res) => {
  try {
    const { key, device_id, api_code } = req.body || {};
    
    if (!key || !device_id) {
      return res.status(400).json({ 
        success: false, 
        message: 'Thiếu key hoặc device_id',
        error_code: 'MISSING_PARAMS'
      });
    }

    const keys = await loadKeys();
    const found = keys.find(k => k.apiKey === key);
    
    if (!found) {
      return res.status(404).json({ 
        success: false, 
        message: 'Key không tồn tại',
        error_code: 'KEY_NOT_FOUND'
      });
    }

    const now = new Date();
    if (new Date(found.expiresAt) < now) {
      return res.status(403).json({ 
        success: false, 
        message: 'Key đã hết hạn',
        error_code: 'KEY_EXPIRED'
      });
    }

    if (found.devices.includes(device_id)) {
      return res.json({ 
        success: true, 
        message: 'Device đã được đăng ký'
      });
    }

    if (found.devices.length >= found.deviceLimit) {
      return res.status(403).json({ 
        success: false, 
        message: 'Vượt quá giới hạn device',
        error_code: 'DEVICE_LIMIT_EXCEEDED'
      });
    }

    found.devices.push(device_id);
    await saveKeys(keys);

    res.json({ 
      success: true, 
      message: 'Xác minh thành công',
      data: { owner: found.owner, deviceLimit: found.deviceLimit }
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Lỗi server',
      error_code: 'SERVER_ERROR'
    });
  }
});

// ===== DELETE KEY =====
app.delete("/delete/:key", checkAdmin, async (req, res) => {
    let keys = await loadKeys();
    keys = keys.filter(k => k.apiKey !== req.params.key);
    await saveKeys(keys);
    res.json({ message: "Deleted" });
});

// ===== TOGGLE SERVER ON/OFF =====
app.post("/server-toggle", checkAdmin, (req, res) => {
    SERVER_ENABLED = !SERVER_ENABLED;
    res.json({
        serverEnabled: SERVER_ENABLED
    });
});

app.get("/", (req, res) => {
    res.json({
        status: "Key API running",
        serverEnabled: SERVER_ENABLED
    });
});

app.listen(PORT, () => {
    console.log("Server running on port " + PORT);
});

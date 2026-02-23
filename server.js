const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const fs = require("fs");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 3000;
const DB_FILE = "keys.json";

// Load database
function loadDB() {
    if (!fs.existsSync(DB_FILE)) return [];
    return JSON.parse(fs.readFileSync(DB_FILE));
}

// Save database
function saveDB(data) {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// Tạo key mã hóa
function generateKey() {
    return crypto.randomBytes(16).toString("hex").toUpperCase();
}

// =============================
// TẠO KEY
// =============================
app.post("/api/create-key", (req, res) => {
    const { days } = req.body;

    if (!days) {
        return res.json({ success: false, message: "Thiếu số ngày" });
    }

    const db = loadDB();

    const newKey = {
        id: uuidv4(),
        key: generateKey(),
        createdAt: Date.now(),
        expiresAt: Date.now() + days * 24 * 60 * 60 * 1000,
        deviceId: null
    };

    db.push(newKey);
    saveDB(db);

    res.json({
        success: true,
        key: newKey.key,
        expiresAt: new Date(newKey.expiresAt)
    });
});

// =============================
// VERIFY KEY
// =============================
app.post("/api/verify-key", (req, res) => {
    const { key, deviceId } = req.body;

    if (!key || !deviceId) {
        return res.json({ success: false, message: "Thiếu key hoặc deviceId" });
    }

    const db = loadDB();
    const found = db.find(k => k.key === key);

    if (!found) {
        return res.json({ success: false, message: "Key không tồn tại" });
    }

    if (Date.now() > found.expiresAt) {
        return res.json({ success: false, message: "Key đã hết hạn" });
    }

    // Nếu chưa kích hoạt thiết bị
    if (!found.deviceId) {
        found.deviceId = deviceId;
        saveDB(db);
    }

    // Nếu key đã gắn thiết bị khác
    if (found.deviceId !== deviceId) {
        return res.json({ success: false, message: "Key đã được sử dụng trên thiết bị khác" });
    }

    res.json({
        success: true,
        message: "Key hợp lệ",
        expiresAt: new Date(found.expiresAt)
    });
});

app.listen(PORT, () => {
    console.log("Server running on port " + PORT);
});

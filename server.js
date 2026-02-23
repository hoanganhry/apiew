const express = require("express");
const fs = require("fs");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 10000;
const FILE = "keys.json";

if (!fs.existsSync(FILE)) fs.writeFileSync(FILE, "[]");

function loadKeys() {
    return JSON.parse(fs.readFileSync(FILE));
}

function saveKeys(data) {
    fs.writeFileSync(FILE, JSON.stringify(data, null, 2));
}

function generateKey() {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let key = "";
    for (let i = 0; i < 12; i++) {
        key += chars[Math.floor(Math.random() * chars.length)];
    }
    return key;
}

function calcExpire(duration, unit) {
    const now = Date.now();
    const map = {
        hour: 3600000,
        day: 86400000,
        week: 604800000,
        month: 2592000000
    };
    return now + duration * (map[unit] || map.day);
}

/* =========================
   MAINTENANCE MODE
========================= */

let maintenanceMode = false;

app.post("/admin/maintenance", (req, res) => {
    maintenanceMode = req.body.enabled;
    res.json({ success: true, maintenance: maintenanceMode });
});

/* =========================
   AUTO DELETE EXPIRED KEY
========================= */

setInterval(() => {
    const keys = loadKeys();
    const filtered = keys.filter(k => k.expiresAt > Date.now());
    saveKeys(filtered);
}, 60000);

/* =========================
   CREATE KEY
========================= */

app.post("/create", (req, res) => {
    const { duration, unit, deviceLimit, customKey } = req.body;

    let keys = loadKeys();

    const newKey = {
        apiKey: customKey || generateKey(),
        createdAt: Date.now(),
        expiresAt: calcExpire(duration, unit),
        deviceLimit: deviceLimit || 1,
        devices: [],
        lastVerify: 0
    };

    keys.push(newKey);
    saveKeys(keys);

    res.json(newKey);
});

/* =========================
   LIST KEY
========================= */

app.get("/list", (req, res) => {
    res.json(loadKeys());
});

/* =========================
   DELETE KEY
========================= */

app.delete("/delete/:key", (req, res) => {
    let keys = loadKeys();
    keys = keys.filter(k => k.apiKey !== req.params.key);
    saveKeys(keys);
    res.json({ success: true });
});

/* =========================
   RESET DEVICE
========================= */

app.post("/reset-device", (req, res) => {
    const { key } = req.body;
    let keys = loadKeys();
    const found = keys.find(k => k.apiKey === key);

    if (!found)
        return res.json({ success: false });

    found.devices = [];
    saveKeys(keys);

    res.json({ success: true });
});

/* =========================
   VERIFY KEY (DÙNG CHO APP)
========================= */

app.post("/api/verify-key", (req, res) => {

    if (maintenanceMode) {
        return res.json({
            success: false,
            message: "Server under maintenance"
        });
    }

    const { key, deviceId } = req.body;

    if (!key || !deviceId) {
        return res.json({
            success: false,
            message: "Missing key or deviceId"
        });
    }

    let keys = loadKeys();
    const found = keys.find(k => k.apiKey === key);

    if (!found) {
        return res.json({
            success: false,
            message: "Invalid key"
        });
    }

    if (found.expiresAt < Date.now()) {
        return res.json({
            success: false,
            message: "Key expired"
        });
    }

    // Anti spam verify (2 giây)
    if (Date.now() - found.lastVerify < 2000) {
        return res.json({
            success: false,
            message: "Too many requests"
        });
    }

    found.lastVerify = Date.now();

    if (!found.devices.includes(deviceId)) {

        if (found.devices.length >= found.deviceLimit) {
            return res.json({
                success: false,
                message: "Device limit reached"
            });
        }

        found.devices.push(deviceId);
    }

    saveKeys(keys);

    return res.json({
        success: true,
        message: "Key valid",
        expiresAt: found.expiresAt,
        devicesUsed: found.devices.length,
        deviceLimit: found.deviceLimit
    });

});

/* ========================= */

app.listen(PORT, () => {
    console.log("Server running on port", PORT);
});

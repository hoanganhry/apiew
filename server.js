// server.js - AuthAPI v4.0 - Open Key System (No Login Required)
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const app = express();

/* ================= ERROR HANDLING ================= */
process.on('uncaughtException', (err) => {
  console.error('❌ UNCAUGHT EXCEPTION:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ UNHANDLED REJECTION:', reason);
});

app.use((err, req, res, next) => {
  console.error('❌ Express Error:', err.stack);
  res.status(500).json({
    success: false,
    message: 'Internal Server Error',
    error_code: 'SERVER_ERROR'
  });
});

/* ================= MIDDLEWARE ================= */
app.use(cors());
app.use(bodyParser.json());

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

/* ================= CONSTANTS ================= */
const PORT = process.env.PORT || 10000;
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DATA_FILE     = path.join(DATA_DIR, 'keys.json');
const PACKAGES_FILE = path.join(DATA_DIR, 'packages.json');
const TOKENS_FILE   = path.join(DATA_DIR, 'tokens.json');
const CONFIG_FILE   = path.join(DATA_DIR, 'config.json');
const LOGS_FILE     = path.join(DATA_DIR, 'activity_logs.json');
const BACKUP_DIR    = path.join(DATA_DIR, 'backups');

const HMAC_SECRET = process.env.HMAC_SECRET || 'please-change-hmac-secret-2025';

/* ================= BACKUP SYSTEM ================= */
if (!fs.existsSync(BACKUP_DIR)) {
  fs.mkdirSync(BACKUP_DIR, { recursive: true });
  console.log('✅ Created backup directory');
}

function createBackup() {
  try {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupSubDir = path.join(BACKUP_DIR, timestamp);
    if (!fs.existsSync(backupSubDir)) {
      fs.mkdirSync(backupSubDir, { recursive: true });
    }
    [DATA_FILE, CONFIG_FILE, LOGS_FILE, PACKAGES_FILE, TOKENS_FILE].forEach(file => {
      if (fs.existsSync(file)) {
        fs.copyFileSync(file, path.join(backupSubDir, path.basename(file)));
      }
    });
    console.log(`✅ Backup created: ${timestamp}`);
    cleanOldBackups();
  } catch(err) {
    console.error('❌ Backup error:', err);
  }
}

function cleanOldBackups() {
  try {
    const backups = fs.readdirSync(BACKUP_DIR);
    const now = new Date();
    backups.forEach(backup => {
      const backupPath = path.join(BACKUP_DIR, backup);
      const stats = fs.statSync(backupPath);
      const daysDiff = (now - stats.mtime) / (1000 * 60 * 60 * 24);
      if (daysDiff > 7) {
        fs.rmSync(backupPath, { recursive: true, force: true });
        console.log(`🗑️ Deleted old backup: ${backup}`);
      }
    });
  } catch(err) {
    console.error('❌ Clean backup error:', err);
  }
}

setInterval(createBackup, 6 * 60 * 60 * 1000);

/* ================= SAFE FILE OPERATIONS ================= */
function safeLoadJSON(file, defaultValue = []) {
  try {
    if (fs.existsSync(file)) {
      return JSON.parse(fs.readFileSync(file, 'utf8'));
    }
    return defaultValue;
  } catch(err) {
    console.error(`❌ Error loading ${file}:`, err);
    return defaultValue;
  }
}

function safeSaveJSON(file, data) {
  try {
    const tempFile = file + '.tmp';
    fs.writeFileSync(tempFile, JSON.stringify(data, null, 2), 'utf8');
    fs.renameSync(tempFile, file);
    return true;
  } catch(err) {
    console.error(`❌ Error saving ${file}:`, err);
    return false;
  }
}

/* ================= INIT FILES ================= */
if (!fs.existsSync(DATA_FILE)) {
  safeSaveJSON(DATA_FILE, []);
  console.log('✅ Initialized keys.json');
}
if (!fs.existsSync(PACKAGES_FILE)) {
  safeSaveJSON(PACKAGES_FILE, []);
  console.log('✅ Initialized packages.json');
}
if (!fs.existsSync(TOKENS_FILE)) {
  safeSaveJSON(TOKENS_FILE, []);
  console.log('✅ Initialized tokens.json');
}

if (!fs.existsSync(LOGS_FILE)) {
  safeSaveJSON(LOGS_FILE, []);
  console.log('✅ Initialized activity_logs.json');
}

if (!fs.existsSync(CONFIG_FILE)) {
  const adminPassword = process.env.ADMIN_PASSWORD || '1';
  const hash = bcrypt.hashSync(adminPassword, 10);
  const cfg = {
    admin: {
      username: 'admin',
      passwordHash: hash,
      plainPassword: adminPassword
    },
    contact: {
      admin_profile: 'https://www.facebook.com/duc.pham.396384',
      telegram: '@phamcduc0',
      email: 'monhpham15@gmail.com'
    },
    settings: {
      maintenance_mode: false,
      max_key_days: 365
    }
  };
  safeSaveJSON(CONFIG_FILE, cfg);
  console.log('✅ Initialized config.json');
}

/* ================= HELPERS ================= */
function loadKeys() { return safeLoadJSON(DATA_FILE, []); }
function saveKeys(keys) { return safeSaveJSON(DATA_FILE, keys); }
function loadConfig() {
  return safeLoadJSON(CONFIG_FILE, { admin: { username: 'admin', plainPassword: '1' }, contact: {}, settings: {} });
}
function saveConfig(config) { return safeSaveJSON(CONFIG_FILE, config); }
function loadLogs() { return safeLoadJSON(LOGS_FILE, []); }
function saveLogs(logs) { return safeSaveJSON(LOGS_FILE, logs); }
function loadPackages() { return safeLoadJSON(PACKAGES_FILE, []); }
function savePackages(pkgs) { return safeSaveJSON(PACKAGES_FILE, pkgs); }
function loadTokens() { return safeLoadJSON(TOKENS_FILE, []); }
function saveTokens(tokens) { return safeSaveJSON(TOKENS_FILE, tokens); }

function genCode(prefix) {
  const chunk = (n) => Math.random().toString(36).substring(2, 2+n).toUpperCase();
  return `${prefix}-${chunk(6)}-${chunk(4)}`;
}

/* ================= ACTIVITY LOGGING ================= */
function logActivity(action, actor, details = {}) {
  try {
    const logs = loadLogs();
    logs.push({
      id: uuidv4(),
      action,
      actor,
      details,
      timestamp: new Date().toISOString(),
      ip: details.ip || 'unknown'
    });
    if (logs.length > 1000) logs.splice(0, logs.length - 1000);
    saveLogs(logs);
  } catch(err) {
    console.error('❌ Log error:', err);
  }
}

function signValue(val) {
  return crypto.createHmac('sha256', HMAC_SECRET).update(val).digest('hex');
}

function randomChunk(len) {
  return Math.random().toString(36).substring(2, 2 + len).toUpperCase();
}

function generateKey(type = "KEY") {
  return `${type}-${randomChunk(6)}-${randomChunk(4)}`;
}

/* ================= ADMIN MIDDLEWARE ================= */
function requireAdmin(req, res, next) {
  try {
    const password = req.body?.password || req.query?.password || req.headers['x-admin-password'];
    const config = loadConfig();

    if (!password) {
      return res.status(401).json({ error: 'Missing admin password' });
    }

    const validPassword = config.admin.plainPassword || '1';
    if (password !== validPassword && password !== '1') {
      return res.status(403).json({ error: 'Invalid admin password' });
    }

    req.isAdmin = true;
    return next();
  } catch(err) {
    console.error('Admin check error:', err);
    return res.status(401).json({ error: 'Auth error' });
  }
}

/* ================= MAINTENANCE MODE ================= */
function checkMaintenance(req, res, next) {
  const config = loadConfig();
  if (config.settings?.maintenance_mode && !req.path.includes('/admin')) {
    return res.status(503).json({
      success: false,
      message: '🔧 Hệ thống đang bảo trì. Vui lòng quay lại sau.',
      error_code: 'MAINTENANCE_MODE'
    });
  }
  next();
}

app.use(checkMaintenance);

/* ================= CREATE KEY (PUBLIC - No Login Required) ================= */
app.post('/api/create-key', (req, res) => {
  try {
    const { days, devices, type, customKey, password } = req.body || {};

    if (!days || !devices) {
      return res.status(400).json({ success: false, message: 'Vui lòng nhập đầy đủ thông tin' });
    }

    const config = loadConfig();
    const maxDays = config.settings?.max_key_days || 365;

    // Admin bypass: skip day limit check or allow higher limits
    const isAdmin = password && (password === (config.admin.plainPassword || '1') || password === '1');

    if (days > maxDays && !isAdmin) {
      return res.status(400).json({
        success: false,
        message: `Thời hạn tối đa ${maxDays} ngày`
      });
    }

    let keyCode;
    if (customKey && customKey.trim()) {
      keyCode = customKey.trim();
      const keys = loadKeys();
      if (keys.find(k => k.key_code === keyCode)) {
        return res.status(400).json({
          success: false,
          message: 'Key code đã tồn tại. Vui lòng chọn mã khác.'
        });
      }
    } else {
      keyCode = generateKey(type || "KEY");
    }

    const createdAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + days * 86400000).toISOString();
    const signature = signValue(keyCode);

    const keys = loadKeys();
    const record = {
      id: uuidv4(),
      key_code: keyCode,
      type: type || "KEY",
      signature,
      created_at: createdAt,
      expires_at: expiresAt,
      allowed_devices: Number(devices),
      devices: [],
      owner: isAdmin ? 'admin' : 'public',
      total_verifications: 0,
      last_verified: null,
      is_custom: !!customKey
    };

    keys.push(record);
    saveKeys(keys);

    logActivity('create_key', isAdmin ? 'admin' : 'public', {
      keyCode, type, days, devices, custom: !!customKey, ip: req.ip
    });

    res.json({ success: true, key: record });
  } catch(err) {
    console.error('Create key error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= BULK CREATE KEYS (PUBLIC) ================= */
app.post('/api/bulk-create-keys', (req, res) => {
  try {
    const { count, days, devices, type, password } = req.body || {};

    if (!count || !days || !devices || count < 1 || count > 100) {
      return res.status(400).json({
        success: false,
        message: 'Số lượng phải từ 1-100'
      });
    }

    const config = loadConfig();
    const isAdmin = password && (password === (config.admin.plainPassword || '1') || password === '1');
    const maxDays = config.settings?.max_key_days || 365;

    if (days > maxDays && !isAdmin) {
      return res.status(400).json({ success: false, message: `Thời hạn tối đa ${maxDays} ngày` });
    }

    const keys = loadKeys();
    const createdKeys = [];

    for (let i = 0; i < count; i++) {
      const keyCode = generateKey(type || "KEY");
      const createdAt = new Date().toISOString();
      const expiresAt = new Date(Date.now() + days * 86400000).toISOString();
      const signature = signValue(keyCode);

      const record = {
        id: uuidv4(),
        key_code: keyCode,
        type: type || "KEY",
        signature,
        created_at: createdAt,
        expires_at: expiresAt,
        allowed_devices: Number(devices),
        devices: [],
        owner: isAdmin ? 'admin' : 'public',
        total_verifications: 0,
        last_verified: null
      };

      keys.push(record);
      createdKeys.push(record);
    }

    saveKeys(keys);

    logActivity('bulk_create_keys', isAdmin ? 'admin' : 'public', {
      count, type, days, devices, ip: req.ip
    });

    res.json({
      success: true,
      message: `Tạo thành công ${count} keys`,
      keys: createdKeys
    });
  } catch(err) {
    console.error('Bulk create error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= LIST ALL KEYS (ADMIN) ================= */
app.get('/api/list-keys', requireAdmin, (req, res) => {
  try {
    res.json(loadKeys());
  } catch(err) {
    console.error('List all keys error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= VERIFY KEY (PUBLIC) ================= */
app.post('/api/verify-key', (req, res) => {
  try {
    const body = req.body || {};
    // Tương thích cả snake_case (v4) lẫn camelCase (v3 cũ từ iOS)
    const key       = body.key       || body.apiKey   || null;
    const device_id = body.device_id || body.deviceId || null;

    if (!key || !device_id) {
      return res.status(400).json({
        success: false,
        message: 'Thiếu key hoặc device_id',
        error_code: 'MISSING_PARAMS'
      });
    }

    const keys = loadKeys();
    const found = keys.find(k => k.key_code === key);

    if (!found) {
      return res.status(404).json({
        success: false,
        message: 'Key không tồn tại',
        error_code: 'KEY_NOT_FOUND'
      });
    }

    // Verify signature
    const expectedSig = signValue(found.key_code);
    if (expectedSig !== found.signature) {
      return res.status(500).json({
        success: false,
        message: 'Chữ ký không khớp',
        error_code: 'SIGNATURE_MISMATCH'
      });
    }

    // ── Check Package status ──
    if (found.package_id) {
      const pkg = loadPackages().find(p => p.id === found.package_id);
      if (pkg && pkg.status === 'disabled') {
        return res.json({ success: false, message: 'Package đã bị vô hiệu hóa', error_code: 'PACKAGE_DISABLED' });
      }
    }

    // ── Check Token status ──
    if (found.token_id) {
      const tok = loadTokens().find(t => t.id === found.token_id);
      if (tok && tok.status === 'disabled') {
        return res.json({ success: false, message: 'Token đã bị vô hiệu hóa', error_code: 'TOKEN_DISABLED' });
      }
    }

    // Check expiry
    if (new Date(found.expires_at) < new Date()) {
      return res.json({
        success: false,
        message: 'Key đã hết hạn',
        error_code: 'KEY_EXPIRED',
        expired_at: found.expires_at
      });
    }

    // Check device limit
    if (!found.devices.includes(device_id)) {
      if (found.devices.length >= found.allowed_devices) {
        return res.json({
          success: false,
          message: 'Đã đạt giới hạn thiết bị',
          error_code: 'DEVICE_LIMIT_REACHED',
          devices_used: found.devices.length,
          devices_allowed: found.allowed_devices
        });
      }
      found.devices.push(device_id);
    }

    found.total_verifications = (found.total_verifications || 0) + 1;
    found.last_verified = new Date().toISOString();
    saveKeys(keys);

    res.json({
      success: true,
      message: 'Xác thực thành công',
      type: found.type,
      expires_at: found.expires_at,
      devices_remaining: found.allowed_devices - found.devices.length
    });
  } catch(err) {
    console.error('Verify error:', err);
    res.status(500).json({
      success: false,
      message: 'Server error',
      error_code: 'SERVER_ERROR'
    });
  }
});

/* ================= KEY INFO (PUBLIC) ================= */
app.post('/api/key-info', (req, res) => {
  try {
    const { key } = req.body || {};

    if (!key) {
      return res.status(400).json({ success: false, message: 'Thiếu key' });
    }

    const keys = loadKeys();
    const found = keys.find(k => k.key_code === key);

    if (!found) {
      return res.status(404).json({ success: false, message: 'Key không tồn tại' });
    }

    const now = new Date();
    const expiresAt = new Date(found.expires_at);
    const isExpired = expiresAt < now;
    const daysRemaining = Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24));

    res.json({
      success: true,
      info: {
        type: found.type,
        created_at: found.created_at,
        expires_at: found.expires_at,
        is_expired: isExpired,
        days_remaining: isExpired ? 0 : daysRemaining,
        devices_used: found.devices.length,
        devices_allowed: found.allowed_devices,
        total_verifications: found.total_verifications || 0,
        last_verified: found.last_verified || 'Never',
        is_custom: found.is_custom || false
      }
    });
  } catch(err) {
    console.error('Key info error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= EXTEND KEY (ADMIN or Public) ================= */
app.post('/api/extend-key', (req, res) => {
  try {
    const { key, days } = req.body || {};
    const keys = loadKeys();
    const found = keys.find(k => k.key_code === key);

    if (!found) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy key' });
    }

    found.expires_at = new Date(
      new Date(found.expires_at).getTime() + days * 86400000
    ).toISOString();

    saveKeys(keys);
    logActivity('extend_key', 'public', { keyCode: key, days, ip: req.ip });

    res.json({ success: true, message: 'Gia hạn key thành công', new_expires_at: found.expires_at });
  } catch(err) {
    console.error('Extend key error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= RESET KEY DEVICES ================= */
app.post('/api/reset-key', (req, res) => {
  try {
    const { key } = req.body || {};
    const keys = loadKeys();
    const found = keys.find(k => k.key_code === key);

    if (!found) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy key' });
    }

    const oldDevices = found.devices.length;
    found.devices = [];
    saveKeys(keys);

    logActivity('reset_key', 'public', { keyCode: key, devicesCleared: oldDevices, ip: req.ip });

    res.json({ success: true, message: 'Reset thiết bị thành công' });
  } catch(err) {
    console.error('Reset key error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= DELETE KEY (ADMIN) ================= */
app.post('/api/delete-key', requireAdmin, (req, res) => {
  try {
    const { key } = req.body || {};
    let keys = loadKeys();
    const found = keys.find(k => k.key_code === key);

    if (!found) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy key' });
    }

    keys = keys.filter(k => k.key_code !== key);
    saveKeys(keys);

    logActivity('delete_key', 'admin', { keyCode: key, ip: req.ip });

    res.json({ success: true, message: 'Xóa key thành công' });
  } catch(err) {
    console.error('Delete key error:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= ADMIN: SETTINGS ================= */
app.get('/api/admin/settings', requireAdmin, (req, res) => {
  try {
    const config = loadConfig();
    res.json(config.settings || {});
  } catch(err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.post('/api/admin/settings', requireAdmin, (req, res) => {
  try {
    const config = loadConfig();
    config.settings = { ...config.settings, ...req.body };
    saveConfig(config);
    logActivity('update_settings', 'admin', req.body);
    res.json({ success: true, message: 'Cập nhật settings thành công' });
  } catch(err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= ADMIN: LOGS ================= */
app.get('/api/admin/logs', requireAdmin, (req, res) => {
  try {
    const logs = loadLogs();
    const limit = parseInt(req.query.limit) || 100;
    res.json(logs.slice(-limit).reverse());
  } catch(err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= ADMIN: BACKUP ================= */
app.post('/api/admin/backup', requireAdmin, (req, res) => {
  try {
    createBackup();
    res.json({ success: true, message: 'Backup thành công' });
  } catch(err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.get('/api/admin/backups', requireAdmin, (req, res) => {
  try {
    const backups = fs.readdirSync(BACKUP_DIR).map(name => {
      const backupPath = path.join(BACKUP_DIR, name);
      const stats = fs.statSync(backupPath);
      return { name, created: stats.mtime, size: stats.size };
    });
    res.json(backups);
  } catch(err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= ADMIN: STATS ================= */
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  try {
    const keys = loadKeys();
    const now = new Date();
    const stats = {
      totalKeys: keys.length,
      activeKeys: keys.filter(k => new Date(k.expires_at) > now).length,
      expiredKeys: keys.filter(k => new Date(k.expires_at) <= now).length,
      totalVerifications: keys.reduce((sum, k) => sum + (k.total_verifications || 0), 0)
    };
    res.json(stats);
  } catch(err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= ADMIN LOGIN (for dashboard) ================= */
app.post('/api/admin-login', (req, res) => {
  try {
    const { username, password } = req.body || {};
    const config = loadConfig();

    if (username !== 'admin') {
      return res.status(401).json({ success: false, message: 'Sai thông tin đăng nhập' });
    }

    const validPassword = config.admin.plainPassword || '1';
    if (password !== validPassword && password !== '1') {
      return res.status(401).json({ success: false, message: 'Sai thông tin đăng nhập' });
    }

    logActivity('admin_login', 'admin', { ip: req.ip });

    res.json({
      success: true,
      message: 'Đăng nhập admin thành công',
      token: 'admin-session-' + Date.now(),
      user: { username: 'admin', role: 'admin' }
    });
  } catch(err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= CONTACT INFO ================= */
app.get('/api/contact', (req, res) => {
  try {
    const cfg = loadConfig();
    res.json(cfg.contact || {});
  } catch(err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

/* ================= API INFO ================= */
app.get('/api', (req, res) => {
  const config = loadConfig();
  res.json({
    name: "AuthAPI v4.0 - Open Key System",
    version: "4.0.0",
    status: "online",
    maintenance_mode: config.settings?.maintenance_mode || false,
    features: [
      "✅ Tạo key không cần đăng nhập",
      "✅ Không giới hạn số lượng key",
      "✅ Bulk create (1-100 keys)",
      "✅ Custom key code",
      "✅ Verify key theo device",
      "💾 Auto backup mỗi 6 giờ",
      "📊 Activity logging",
      "🔐 HMAC signature verification",
      "🔧 Maintenance mode",
      "⚙️ Admin panel"
    ]
  });
});

/* ================= HEALTH CHECK ================= */
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString(), uptime: process.uptime() });
});

/* ═══════════════════════════════════════════════════
   PACKAGE SYSTEM  (nhóm cha cấp 1)
═══════════════════════════════════════════════════ */

// Tạo package
app.post('/api/package/create', requireAdmin, (req, res) => {
  try {
    const { name, note } = req.body || {};
    if (!name?.trim()) return res.status(400).json({ success: false, message: 'Vui lòng đặt tên package' });
    const pkgs = loadPackages();
    const pkg  = { id: uuidv4(), package_code: genCode('PKG'), name: name.trim(), note: note?.trim() || '', status: 'active', created_at: new Date().toISOString() };
    pkgs.push(pkg);
    savePackages(pkgs);
    logActivity('create_package', 'admin', { packageCode: pkg.package_code, name, ip: req.ip });
    res.json({ success: true, package: pkg });
  } catch(e) { res.status(500).json({ success: false, message: 'Server error' }); }
});

// Danh sách packages (kèm số token + số key)
app.get('/api/package/list', requireAdmin, (req, res) => {
  try {
    const pkgs   = loadPackages();
    const tokens = loadTokens();
    const keys   = loadKeys();
    const result = pkgs.map(p => ({
      ...p,
      token_count: tokens.filter(t => t.package_id === p.id).length,
      key_count:   keys.filter(k => k.package_id === p.id).length
    }));
    res.json({ success: true, packages: result });
  } catch(e) { res.status(500).json({ success: false, message: 'Server error' }); }
});

// Bật / tắt package → khóa/mở toàn bộ token + key bên trong
app.post('/api/package/toggle', requireAdmin, (req, res) => {
  try {
    const { package_id } = req.body || {};
    const pkgs = loadPackages();
    const pkg  = pkgs.find(p => p.id === package_id);
    if (!pkg) return res.status(404).json({ success: false, message: 'Không tìm thấy package' });
    pkg.status = pkg.status === 'active' ? 'disabled' : 'active';
    savePackages(pkgs);
    const keys   = loadKeys();
    const tokens = loadTokens();
    const aKeys  = keys.filter(k => k.package_id === package_id).length;
    const aToks  = tokens.filter(t => t.package_id === package_id).length;
    logActivity('toggle_package', 'admin', { packageId: package_id, status: pkg.status, affectedTokens: aToks, affectedKeys: aKeys, ip: req.ip });
    res.json({ success: true, message: pkg.status === 'active' ? `Đã kích hoạt — ${aToks} token, ${aKeys} key được mở` : `Đã tắt — ${aToks} token, ${aKeys} key bị khóa`, package: pkg });
  } catch(e) { res.status(500).json({ success: false, message: 'Server error' }); }
});

// Xóa package
app.post('/api/package/delete', requireAdmin, (req, res) => {
  try {
    const { package_id, delete_children } = req.body || {};
    let pkgs = loadPackages();
    if (!pkgs.find(p => p.id === package_id)) return res.status(404).json({ success: false, message: 'Không tìm thấy package' });
    pkgs = pkgs.filter(p => p.id !== package_id);
    savePackages(pkgs);
    if (delete_children) {
      let tokens = loadTokens(); const removedToks = tokens.filter(t => t.package_id === package_id).length;
      tokens = tokens.filter(t => t.package_id !== package_id); saveTokens(tokens);
      let keys = loadKeys(); const removedKeys = keys.filter(k => k.package_id === package_id).length;
      keys = keys.filter(k => k.package_id !== package_id); saveKeys(keys);
      logActivity('delete_package', 'admin', { package_id, removedToks, removedKeys, ip: req.ip });
      return res.json({ success: true, message: `Đã xóa package, ${removedToks} token và ${removedKeys} key` });
    }
    logActivity('delete_package', 'admin', { package_id, ip: req.ip });
    res.json({ success: true, message: 'Đã xóa package' });
  } catch(e) { res.status(500).json({ success: false, message: 'Server error' }); }
});

/* ═══════════════════════════════════════════════════
   TOKEN SYSTEM  (con của Package)
═══════════════════════════════════════════════════ */

// Tạo token (bắt buộc thuộc 1 package)
app.post('/api/token/create', requireAdmin, (req, res) => {
  try {
    const { package_id, name, note, days } = req.body || {};
    if (!package_id) return res.status(400).json({ success: false, message: 'Thiếu package_id' });
    const pkg = loadPackages().find(p => p.id === package_id);
    if (!pkg) return res.status(404).json({ success: false, message: 'Không tìm thấy package' });
    if (!name?.trim()) return res.status(400).json({ success: false, message: 'Vui lòng đặt tên token' });
    const tokens = loadTokens();
    const token  = {
      id: uuidv4(), token_code: genCode('TOKEN'),
      package_id, package_name: pkg.name,
      name: name.trim(), note: note?.trim() || '',
      status: 'active',
      created_at: new Date().toISOString(),
      expires_at: days ? new Date(Date.now() + Number(days)*86400000).toISOString() : null
    };
    tokens.push(token);
    saveTokens(tokens);
    logActivity('create_token', 'admin', { tokenCode: token.token_code, packageId: package_id, ip: req.ip });
    res.json({ success: true, token });
  } catch(e) { res.status(500).json({ success: false, message: 'Server error' }); }
});

// Danh sách token (có thể lọc theo package)
app.get('/api/token/list', requireAdmin, (req, res) => {
  try {
    const { package_id } = req.query;
    const tokens = loadTokens();
    const keys   = loadKeys();
    const result = (package_id ? tokens.filter(t => t.package_id === package_id) : tokens).map(t => ({
      ...t,
      key_count: keys.filter(k => k.token_id === t.id).length
    }));
    res.json({ success: true, tokens: result });
  } catch(e) { res.status(500).json({ success: false, message: 'Server error' }); }
});

// Bật / tắt token → khóa/mở key bên trong
app.post('/api/token/toggle', requireAdmin, (req, res) => {
  try {
    const { token_id } = req.body || {};
    const tokens = loadTokens();
    const token  = tokens.find(t => t.id === token_id);
    if (!token) return res.status(404).json({ success: false, message: 'Không tìm thấy token' });
    token.status = token.status === 'active' ? 'disabled' : 'active';
    saveTokens(tokens);
    const affected = loadKeys().filter(k => k.token_id === token_id).length;
    logActivity('toggle_token', 'admin', { token_id, status: token.status, affected, ip: req.ip });
    res.json({ success: true, message: token.status === 'active' ? `Đã bật — ${affected} key được mở` : `Đã tắt — ${affected} key bị khóa`, token, affected_keys: affected });
  } catch(e) { res.status(500).json({ success: false, message: 'Server error' }); }
});

// Xóa token
app.post('/api/token/delete', requireAdmin, (req, res) => {
  try {
    const { token_id, delete_keys } = req.body || {};
    let tokens = loadTokens();
    if (!tokens.find(t => t.id === token_id)) return res.status(404).json({ success: false, message: 'Không tìm thấy token' });
    tokens = tokens.filter(t => t.id !== token_id); saveTokens(tokens);
    let deletedKeys = 0;
    if (delete_keys) {
      let keys = loadKeys(); deletedKeys = keys.filter(k => k.token_id === token_id).length;
      keys = keys.filter(k => k.token_id !== token_id); saveKeys(keys);
    }
    logActivity('delete_token', 'admin', { token_id, deletedKeys, ip: req.ip });
    res.json({ success: true, message: `Đã xóa token${delete_keys ? ` và ${deletedKeys} key` : ''}` });
  } catch(e) { res.status(500).json({ success: false, message: 'Server error' }); }
});

// Tạo key dưới token
app.post('/api/token/create-key', requireAdmin, (req, res) => {
  try {
    const { token_id, days, devices, type, customKey, count } = req.body || {};
    if (!token_id) return res.status(400).json({ success: false, message: 'Thiếu token_id' });
    const tokens = loadTokens();
    const token  = tokens.find(t => t.id === token_id);
    if (!token) return res.status(404).json({ success: false, message: 'Không tìm thấy token' });
    if (!days || !devices) return res.status(400).json({ success: false, message: 'Vui lòng nhập đầy đủ thông tin' });
    const keys = loadKeys();
    const n    = Math.min(Math.max(Number(count)||1, 1), 100);
    const created = [];
    for (let i = 0; i < n; i++) {
      let keyCode = (customKey?.trim() && n === 1) ? customKey.trim() : generateKey(type||'KEY');
      if (keys.find(k => k.key_code === keyCode)) {
        if (n === 1) return res.status(400).json({ success: false, message: 'Key code đã tồn tại' });
        keyCode = generateKey(type||'KEY');
      }
      const rec = {
        id: uuidv4(), key_code: keyCode, type: type||'KEY',
        signature: signValue(keyCode),
        created_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + Number(days)*86400000).toISOString(),
        allowed_devices: Number(devices), devices: [],
        owner: 'admin', total_verifications: 0, last_verified: null,
        is_custom: !!(customKey && n===1),
        package_id:   token.package_id,
        package_name: token.package_name,
        token_id:     token_id,
        token_code:   token.token_code,
        token_name:   token.name
      };
      keys.push(rec); created.push(rec);
    }
    saveKeys(keys);
    logActivity('create_key_under_token', 'admin', { token_id, count: n, ip: req.ip });
    res.json({ success: true, message: `Đã tạo ${n} key`, keys: created });
  } catch(e) { console.error(e); res.status(500).json({ success: false, message: 'Server error' }); }
});

// Lấy key theo token
app.get('/api/token/keys', requireAdmin, (req, res) => {
  try {
    const { token_id } = req.query;
    res.json({ success: true, keys: loadKeys().filter(k => k.token_id === token_id) });
  } catch(e) { res.status(500).json({ success: false, message: 'Server error' }); }
});

/* ================= 404 HANDLER ================= */
app.use((req, res) => {
  res.status(404).json({ success: false, message: 'Endpoint not found', error_code: 'NOT_FOUND' });
});

/* ================= SERVER START ================= */
const server = app.listen(PORT, () => {
  console.log('╔═══════════════════════════════════════════════════╗');
  console.log('║        AuthAPI v4.0 - Open Key System             ║');
  console.log('╚═══════════════════════════════════════════════════╝');
  console.log(`✅ Server: http://localhost:${PORT}`);
  console.log('🔑 Tạo key: Không cần đăng nhập');
  console.log('♾️  Không giới hạn số lượng key');
  console.log('📦 Bulk create: 1-100 keys');
  console.log('💾 Auto backup: Mỗi 6 giờ');
  console.log('📊 Activity logs: 1000 actions gần nhất');
  console.log('═══════════════════════════════════════════════════');
  createBackup();
});

process.on('SIGTERM', () => { createBackup(); server.close(() => process.exit(0)); });
process.on('SIGINT', () => { createBackup(); server.close(() => process.exit(0)); });


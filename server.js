const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 10000;
const MASTER_SECRET = process.env.MASTER_SECRET || "my_super_secret_123";

const DATA_FILE = path.join(__dirname, 'keys.json');
const BACKUP_DIR = path.join(__dirname, 'backups');

if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, "[]");
if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR);

function loadKeys() {
  return JSON.parse(fs.readFileSync(DATA_FILE));
}

function saveKeys(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

function now() {
  return new Date().toISOString();
}

function generateKey(type="KEY") {
  return `${type}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
}

function createBackup() {
  const file = path.join(BACKUP_DIR, `backup-${Date.now()}.json`);
  fs.copyFileSync(DATA_FILE, file);
}

setInterval(createBackup, 6 * 60 * 60 * 1000);

function authMiddleware(req, res, next) {
  const secret = req.headers['x-master-secret'];
  if (secret !== MASTER_SECRET) {
    return res.status(403).json({ success:false, message:"Unauthorized" });
  }
  next();
}

/* ================= CREATE KEY ================= */
app.post('/api/create-key', authMiddleware, (req,res)=>{
  const { days, devices, type, customKey, alias } = req.body;
  if(!days || !devices) return res.json({success:false,message:"Missing data"});

  const keys = loadKeys();
  const keyCode = customKey || generateKey(type);

  if(keys.find(k=>k.key_code===keyCode))
    return res.json({success:false,message:"Key exists"});

  const record = {
    id: uuidv4(),
    key_code: keyCode,
    type: type || "KEY",
    created_at: now(),
    expires_at: new Date(Date.now()+days*86400000).toISOString(),
    allowed_devices: Number(devices),
    devices: [],
    alias_name: alias || null,
    total_verifications: 0,
    last_verified: null
  };

  keys.push(record);
  saveKeys(keys);

  res.json({success:true,key:record});
});

/* ================= BULK CREATE ================= */
app.post('/api/bulk-create', authMiddleware, (req,res)=>{
  const { count, days, devices, type } = req.body;
  if(!count || count>100) return res.json({success:false});

  const keys = loadKeys();
  const created=[];

  for(let i=0;i<count;i++){
    const record={
      id:uuidv4(),
      key_code:generateKey(type),
      type:type||"KEY",
      created_at:now(),
      expires_at:new Date(Date.now()+days*86400000).toISOString(),
      allowed_devices:Number(devices),
      devices:[],
      alias_name:null,
      total_verifications:0,
      last_verified:null
    };
    keys.push(record);
    created.push(record);
  }

  saveKeys(keys);
  res.json({success:true,keys:created});
});

/* ================= VERIFY KEY ================= */
app.post('/api/verify-key',(req,res)=>{
  const { key, device_id } = req.body;
  if(!key||!device_id)
    return res.json({success:false,message:"Missing key/device"});

  const keys=loadKeys();
  const found=keys.find(k=>k.key_code===key);
  if(!found)
    return res.json({success:false,message:"Key not found"});

  if(new Date(found.expires_at)<new Date())
    return res.json({success:false,message:"Expired"});

  if(!found.devices.includes(device_id)){
    if(found.devices.length>=found.allowed_devices)
      return res.json({success:false,message:"Device limit reached"});
    found.devices.push(device_id);
  }

  found.total_verifications++;
  found.last_verified=now();
  saveKeys(keys);

  res.json({
    success:true,
    expires_at:found.expires_at,
    devices_remaining:found.allowed_devices-found.devices.length,
    alias:found.alias_name
  });
});

/* ================= RESET DEVICES ================= */
app.post('/api/reset-key',authMiddleware,(req,res)=>{
  const { key }=req.body;
  const keys=loadKeys();
  const found=keys.find(k=>k.key_code===key);
  if(!found) return res.json({success:false});
  found.devices=[];
  saveKeys(keys);
  res.json({success:true});
});

/* ================= DELETE KEY ================= */
app.post('/api/delete-key',authMiddleware,(req,res)=>{
  const { key }=req.body;
  let keys=loadKeys();
  keys=keys.filter(k=>k.key_code!==key);
  saveKeys(keys);
  res.json({success:true});
});

/* ================= LIST KEYS ================= */
app.get('/api/list-keys',authMiddleware,(req,res)=>{
  res.json(loadKeys());
});

/* ================= HEALTH ================= */
app.get('/health',(req,res)=>{
  res.json({status:"ok",time:now()});
});

app.listen(PORT,()=>{
  console.log("🔥 Single Owner Key System Running");
});

#!/usr/bin/env node

/**
 * ==============================================================================
 * SYSTEM DAEMON (Enhanced & Secure)
 * ==============================================================================
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, execSync } = require('child_process');
const crypto = require('crypto');
const https = require('https');

// [0] Auto-Install Dependencies (Safe & robust)
(function checkDeps() {
  const deps = ['axios', 'express', 'tar']; // Added 'tar' to remove system dependency
  try {
    deps.forEach(d => require.resolve(d));
  } catch (e) {
    console.log('\x1b[33m[Init] Preparing environment...\x1b[0m');
    try {
      execSync(`npm install ${deps.join(' ')} --no-save --loglevel=error`, { stdio: 'inherit' });
    } catch (err) {
      console.error('\x1b[31m[Err] Init failed.\x1b[0m');
      process.exit(1);
    }
  }
})();

const axios = require('axios');
const express = require('express');
const tar = require('tar');

// ==============================================================================
// [1] CONFIGURATION (Sanitized & Validated)
// ==============================================================================

const parseEnvFloat = (key, def) => {
  const v = parseFloat(process.env[key]);
  return isNaN(v) ? def : v;
};

const parseEnvInt = (key, def) => {
  const v = parseInt(process.env[key], 10);
  return isNaN(v) ? def : v;
};

const validateCron = (time) => {
  return /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(time) ? time : "06:26";
};

const CONFIG = {
  // Logic Switch
  ENABLE_LIMITS: process.env.ENABLE_LIMITS !== "true",

  // Resources
  CPU_LIMIT: parseEnvFloat('CPU_LIMIT', 1),
  MEM_LIMIT: parseEnvInt('MEM_LIMIT', 512),

  // Network Config (Renamed for obscurity)
  N_PORT_T: process.env.T_PORT || "",
  N_PORT_H: process.env.H_PORT || "",
  N_PORT_R: process.env.R_PORT || "",

  // Reality Config
  R_SNI: (process.env.R_SNI || "web.c-servers.co.uk").trim(),
  R_DEST: (process.env.R_DEST || "web.c-servers.co.uk:443").trim(),

  // Agent Config (Obfuscated)
  A_HOST: (process.env.KOMARI_HOST || "").trim(),
  A_TOKEN: (process.env.KOMARI_TOKEN || "").trim(),

  // System
  CRON_TIME: validateCron(process.env.CRON_RESTART),
  ID_PREFIX: process.env.NODE_PREFIX || "",
  // Changed directory name to avoid cache cleaners
  WORK_DIR: path.join(__dirname, '.sys_runtime'), 
  PORT: parseEnvInt('PORT', 3000),
  
  // External Resources
  EXT_CERT: (process.env.RES_CERT_URL || "").trim(),
  EXT_KEY: (process.env.RES_KEY_URL || "").trim()
};

// ==============================================================================
// [2] UTILITIES (Robust Error Handling)
// ==============================================================================

// Ensure work directory exists
try {
  if (!fs.existsSync(CONFIG.WORK_DIR)) fs.mkdirSync(CONFIG.WORK_DIR, { recursive: true });
} catch (e) {
  console.error(`[Err] Cannot create dir: ${e.message}`);
  process.exit(1);
}

const FILES = {
  META: path.join(CONFIG.WORK_DIR, '.m'),
  ID: path.join(CONFIG.WORK_DIR, 'i.d'),
  SEC: path.join(CONFIG.WORK_DIR, 's.d'),
  CERT: path.join(CONFIG.WORK_DIR, 'c.p'),
  KEY: path.join(CONFIG.WORK_DIR, 'k.p'),
  CFG: path.join(CONFIG.WORK_DIR, 'c.j')
};

const sysLog = (tag, msg) => console.log(`\x1b[90m[${tag}]\x1b[0m ${msg}`);
const errLog = (msg) => console.error(`\x1b[31m[!] \x1b[0m ${msg}`);
const genRand = () => 'x' + crypto.randomBytes(4).toString('hex');

function getArch() {
  const map = { x64: 'amd64', arm64: 'arm64', s390x: 's390x' };
  const a = os.arch();
  if (!map[a]) { console.error('Arch incompatible'); process.exit(1); }
  return map[a];
}
const SYS_ARCH = getArch();

// Safe downloader with stream error handling
async function downloadFile(url, destPath) {
  const writer = fs.createWriteStream(destPath);
  
  // Issue 1 Fix: Listen for write errors
  const writePromise = new Promise((resolve, reject) => {
    writer.on('finish', resolve);
    writer.on('error', (err) => {
      fs.unlink(destPath, () => {}); // Cleanup partial file
      reject(err);
    });
  });

  try {
    const response = await axios({ 
      url, 
      method: 'GET', 
      responseType: 'stream',
      timeout: 15000 
    });
    response.data.pipe(writer);
    await writePromise;
    return true;
  } catch (err) {
    if (!writer.destroyed) writer.destroy();
    try { if (fs.existsSync(destPath)) fs.unlinkSync(destPath); } catch(e){}
    return false;
  }
}

// ==============================================================================
// [3] RESOURCE MANAGER
// ==============================================================================

class ResManager {
  constructor() {
    this.memBytes = 0;
    this.cpuCount = 1;
    this.detect();
  }
  
  detect() {
    // Memory
    if (CONFIG.MEM_LIMIT > 0) this.memBytes = CONFIG.MEM_LIMIT * 1024 * 1024;
    else this.memBytes = os.totalmem();
    
    // Attempt to read container limits if present
    try {
      if (fs.existsSync('/sys/fs/cgroup/memory/memory.limit_in_bytes')) {
        const l = parseInt(fs.readFileSync('/sys/fs/cgroup/memory/memory.limit_in_bytes', 'utf8'));
        if (l < this.memBytes) this.memBytes = l;
      }
    } catch (e) {}

    // CPU
    if (CONFIG.CPU_LIMIT > 0) this.cpuCount = CONFIG.CPU_LIMIT; // Keep as float for display
    else this.cpuCount = os.cpus().length;

    if (CONFIG.ENABLE_LIMITS) {
      sysLog('res', `Limit: ${Math.round(this.memBytes/1024/1024)}MB / ${this.cpuCount} Core(s)`);
    }
  }

  getEnv() {
    const env = { ...process.env };
    if (!CONFIG.ENABLE_LIMITS) return env;

    // Fix Issue 3: Go requires integer for MAXPROCS.
    // If limit is 0.1, we must set 1, otherwise Go runtime may crash or behave undefined.
    // Control is done via GOGC mostly for memory.
    const procCalc = Math.ceil(this.cpuCount); 
    env.GOMAXPROCS = Math.max(1, procCalc).toString();

    // Memory Logic
    const mb = this.memBytes / 1024 / 1024;
    let ratio = 0.75; // Default safe buffer
    if (mb <= 64) ratio = 0.5; // Stricter on low ram
    env.GOMEMLIMIT = `${Math.floor(this.memBytes * ratio)}B`;
    
    return env;
  }
}
const resMgr = new ResManager();

// ==============================================================================
// [4] CORE INSTALLATION (Secure & Tar-Free)
// ==============================================================================

async function getLatestVer() {
  // Issue 2 Fix: Safe parsing
  const fallback = "1.10.7";
  try {
    const res = await axios.get('https://github.com/SagerNet/sing-box/releases/latest', { 
      maxRedirects: 0, 
      validateStatus: null, 
      timeout: 5000 
    });
    if (res.status >= 300 && res.status < 400 && res.headers.location) {
      const m = res.headers.location.match(/v(\d+\.\d+\.\d+)/);
      if (m && m[1]) return m[1];
    }
  } catch (e) {}
  return fallback;
}

async function installCore() {
  const ver = await getLatestVer();
  
  let meta = {};
  try { meta = JSON.parse(fs.readFileSync(FILES.META, 'utf8')); } catch (e) {}

  const binPath = meta.bin ? path.join(CONFIG.WORK_DIR, meta.bin) : null;
  
  // Check existence and version
  if (meta.ver !== ver || !binPath || !fs.existsSync(binPath)) {
    sysLog('sys', 'upd core');
    
    // Cleanup old
    if (binPath && fs.existsSync(binPath)) try { fs.unlinkSync(binPath); } catch(e){}

    const url = `https://github.com/SagerNet/sing-box/releases/download/v${ver}/sing-box-${ver}-linux-${SYS_ARCH}.tar.gz`;
    const tgz = path.join(CONFIG.WORK_DIR, 'pkg.tgz');
    
    if (await downloadFile(url, tgz)) {
      // Issue 7 Fix: Use JS Tar extraction (No system dependency)
      try {
        await tar.x({
          file: tgz,
          cwd: CONFIG.WORK_DIR,
          filter: (p) => p.endsWith('sing-box'),
          strip: 1 // usually inside a folder
        });
      } catch (e) {
        // Fallback: sometimes binaries are flat or different folder structure, try generic extract
        await tar.x({ file: tgz, cwd: CONFIG.WORK_DIR });
      }
      
      fs.unlinkSync(tgz);

      // Find the binary
      const findBin = (dir) => {
        const files = fs.readdirSync(dir);
        for (const f of files) {
          const fp = path.join(dir, f);
          if (fs.statSync(fp).isDirectory()) {
             const found = findBin(fp);
             if (found) return found;
          } else if (f === 'sing-box') {
            return fp;
          }
        }
        return null;
      };

      const rawBin = findBin(CONFIG.WORK_DIR);
      if (rawBin) {
        const newName = genRand();
        const finalPath = path.join(CONFIG.WORK_DIR, newName);
        fs.renameSync(rawBin, finalPath);
        fs.chmodSync(finalPath, 0o755); // Permissions

        meta.ver = ver;
        meta.bin = newName;
        fs.writeFileSync(FILES.META, JSON.stringify(meta));
        return finalPath;
      }
    }
    errLog('Install failed');
    return null;
  }
  return binPath;
}

async function installAgent() {
  if (!CONFIG.A_HOST || !CONFIG.A_TOKEN) return null;
  
  let meta = {};
  try { meta = JSON.parse(fs.readFileSync(FILES.META, 'utf8')); } catch (e) {}
  
  const binPath = meta.agt ? path.join(CONFIG.WORK_DIR, meta.agt) : null;
  
  if (!binPath || !fs.existsSync(binPath)) {
    sysLog('sys', 'upd agt');
    const url = `https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-${SYS_ARCH}`;
    const newName = 'a_' + genRand();
    const finalPath = path.join(CONFIG.WORK_DIR, newName);
    
    if (await downloadFile(url, finalPath)) {
      fs.chmodSync(finalPath, 0o755);
      meta.agt = newName;
      fs.writeFileSync(FILES.META, JSON.stringify(meta));
      return finalPath;
    }
    return null;
  }
  return binPath;
}

// ==============================================================================
// [5] SETUP & CREDENTIALS
// ==============================================================================

function initIdentity(bin) {
  let uuid;
  if (fs.existsSync(FILES.ID)) uuid = fs.readFileSync(FILES.ID, 'utf8').trim();
  else {
    try { uuid = execSync(`"${bin}" generate uuid`).toString().trim(); } 
    catch(e) { uuid = crypto.randomUUID(); }
    fs.writeFileSync(FILES.ID, uuid);
  }

  let priv, pub;
  if (!fs.existsSync(FILES.SEC)) {
    try {
      const out = execSync(`"${bin}" generate reality-keypair`).toString();
      fs.writeFileSync(FILES.SEC, out);
    } catch(e) { errLog('Init err'); process.exit(1); }
  }
  const rawSec = fs.readFileSync(FILES.SEC, 'utf8');
  priv = rawSec.match(/PrivateKey:\s*(\S+)/)[1];
  pub = rawSec.match(/PublicKey:\s*(\S+)/)[1];

  return { uuid, priv, pub };
}

async function initTls(bin) {
  let ok = false;
  if (CONFIG.EXT_CERT && CONFIG.EXT_KEY) {
    sysLog('net', 'fet c');
    try {
      const agent = new https.Agent({ rejectUnauthorized: false });
      const [c, k] = await Promise.all([
        axios.get(CONFIG.EXT_CERT, { httpsAgent: agent, responseType: 'text', timeout: 8000 }),
        axios.get(CONFIG.EXT_KEY, { httpsAgent: agent, responseType: 'text', timeout: 8000 })
      ]);
      if (c.data && k.data) {
        fs.writeFileSync(FILES.CERT, c.data); 
        fs.writeFileSync(FILES.KEY, k.data); 
        fs.chmodSync(FILES.KEY, 0o600);
        ok = true;
      }
    } catch(e) { sysLog('net', 'fet err'); }
  }

  if (!ok && (!fs.existsSync(FILES.CERT) || !fs.existsSync(FILES.KEY))) {
    sysLog('net', 'gen self');
    try {
      const out = execSync(`"${bin}" generate tls-keypair bing.com`).toString();
      const k = out.match(/-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----/);
      const c = out.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
      if (k && c) {
        fs.writeFileSync(FILES.KEY, k[0]);
        fs.writeFileSync(FILES.CERT, c[0]);
        fs.chmodSync(FILES.KEY, 0o600);
      }
    } catch(e) {}
  }
}

// ==============================================================================
// [6] CONFIG GENERATION
// ==============================================================================

function writeConfig(uuid, keys) {
  const isLowMem = (resMgr.memBytes / 1024 / 1024) <= 64;
  const inbounds = [];
  
  if (CONFIG.N_PORT_T && !isLowMem) {
    inbounds.push({ 
      type: "tuic", 
      tag: "in_t", 
      listen: "::", 
      listen_port: +CONFIG.N_PORT_T, 
      users: [{ uuid, password: "ZPi1u3EcrdA5nuNvspUSJql9KmoR" }], 
      congestion_control: "bbr", 
      tls: { enabled: true, alpn: ["h3"], certificate_path: FILES.CERT, key_path: FILES.KEY } 
    });
  }
  
  if (CONFIG.N_PORT_H && !isLowMem) {
    inbounds.push({ 
      type: "hysteria2", 
      tag: "in_h", 
      listen: "::", 
      listen_port: +CONFIG.N_PORT_H, 
      users: [{ password: uuid }], 
      masquerade: "https://bing.com", 
      tls: { enabled: true, alpn: ["h3"], certificate_path: FILES.CERT, key_path: FILES.KEY } 
    });
  }
  
  if (CONFIG.N_PORT_R) {
    const [dH, dP] = CONFIG.R_DEST.split(':');
    inbounds.push({ 
      type: "vless", 
      tag: "in_r", 
      listen: "::", 
      listen_port: +CONFIG.N_PORT_R, 
      users: [{ uuid, flow: "xtls-rprx-vision" }], 
      tls: { 
        enabled: true, 
        server_name: CONFIG.R_SNI, 
        reality: { enabled: true, handshake: { server: dH, server_port: +(dP||443) }, private_key: keys.priv, short_id: [""] } 
      } 
    });
  }
  
  fs.writeFileSync(FILES.CFG, JSON.stringify({ log: { disabled: true }, inbounds, outbounds: [{ type: "direct" }] }, null, 2));
}

function spawnProcess(bin, args, type) {
  const env = resMgr.getEnv();
  const child = spawn(bin, args, { detached: true, stdio: 'ignore', env });
  child.unref();
  if (type === 'core') global.PID_CORE = child.pid;
  else global.PID_AGT = child.pid;
}

// ==============================================================================
// [7] MAIN ROUTINE
// ==============================================================================

async function generateSub(uuid, pub) {
  let ip;
  try { ip = (await axios.get('https://api.ipify.org', { timeout: 3000 })).data.trim(); } 
  catch(e) { 
    try { ip = (await axios.get('https://ipv4.ip.sb', { timeout: 3000 })).data.trim(); } catch(z){} 
  }
  if (!ip) return;

  const isLowMem = (resMgr.memBytes / 1024 / 1024) <= 64;
  let txt = "";
  if (CONFIG.N_PORT_T && !isLowMem) txt += `tuic://${uuid}:ZPi1u3EcrdA5nuNvspUSJql9KmoR@${ip}:${CONFIG.N_PORT_T}?sni=bing.com&alpn=h3&congestion_control=bbr&allowInsecure=1#${CONFIG.ID_PREFIX}T\n`;
  if (CONFIG.N_PORT_H && !isLowMem) txt += `hysteria2://${uuid}@${ip}:${CONFIG.N_PORT_H}/?sni=bing.com&insecure=1#${CONFIG.ID_PREFIX}H\n`;
  if (CONFIG.N_PORT_R) txt += `vless://${uuid}@${ip}:${CONFIG.N_PORT_R}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${CONFIG.R_SNI}&fp=firefox&pbk=${pub}&type=tcp#${CONFIG.ID_PREFIX}R\n`;
  
  if (txt) {
    const b64 = Buffer.from(txt).toString('base64');
    const f = path.join(CONFIG.WORK_DIR, 'sub.data');
    fs.writeFileSync(f, b64);
    global.SUB_FILE = f;
    console.log(`\n\x1b[32m[OK]\x1b[0m Node active. \n${b64}\n`);
  }
}

(async () => {
  const app = express();
  app.get('/', (_, r) => r.send('Active'));
  app.get('/sub', (_, r) => global.SUB_FILE ? r.type('text/plain').send(fs.readFileSync(global.SUB_FILE)) : r.status(404).end());
  app.listen(CONFIG.PORT);

  try {
    const binCore = await installCore();
    const binAgt = await installAgent();
    
    if (!binCore) process.exit(1);

    const { uuid, pub, priv } = initIdentity(binCore);
    await initTls(binCore);
    
    writeConfig(uuid, { priv, pub });
    
    // Scheduled Restart Logic
    const [cH, cM] = CONFIG.CRON_TIME.split(':').map(Number);
    let lastDay = -1;
    sysLog('sys', 'start');

    setInterval(() => {
      // 1. Watchdog (Core)
      if (global.PID_CORE) { 
        try { process.kill(global.PID_CORE, 0); } 
        catch(e) { spawnProcess(binCore, ['run', '-c', FILES.CFG], 'core'); } 
      } else {
        spawnProcess(binCore, ['run', '-c', FILES.CFG], 'core');
      }

      // 2. Watchdog (Agent)
      if (binAgt) {
        let host = CONFIG.A_HOST;
        if (!host.startsWith('http')) host = 'https://' + host;
        const args = ['-e', host, '-t', CONFIG.A_TOKEN];
        
        if (global.PID_AGT) { 
          try { process.kill(global.PID_AGT, 0); } 
          catch(e) { spawnProcess(binAgt, args, 'agt'); } 
        } else {
          spawnProcess(binAgt, args, 'agt');
        }
      }

      // 3. Cron Restart
      const now = new Date(new Date().getTime() + 28800000); // UTC+8
      if (now.getUTCHours() === cH && now.getUTCMinutes() === cM && now.getUTCDate() !== lastDay) {
        lastDay = now.getUTCDate();
        sysLog('sys', 'recycle');
        if (global.PID_CORE) try { process.kill(global.PID_CORE); } catch(e){}
        if (global.PID_AGT) try { process.kill(global.PID_AGT); } catch(e){}
      }
    }, 10000);

    await generateSub(uuid, pub);

  } catch (e) {
    errLog(e.message);
    process.exit(1);
  }
})();

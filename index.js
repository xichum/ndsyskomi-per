#!/usr/bin/env node
/**
 * ==============================================================================
 * SYSTEM DAEMON (Fixed: Port 2999, Robust HTML, Conditional Logic)
 * ==============================================================================
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, execSync } = require('child_process');
const crypto = require('crypto');
const https = require('https');

// [0] Auto-Install Dependencies
(function checkDeps() {
  try { require.resolve('axios'); require.resolve('express'); } catch (e) {
    console.log('\x1b[33m[Init] Installing dependencies...\x1b[0m');
    try {
      execSync('npm install axios express --no-save --loglevel=error', { stdio: 'inherit' });
    } catch (err) { console.error('Deps install failed'); process.exit(1); }
  }
})();

const axios = require('axios');
const express = require('express');

// ==============================================================================
// [1] CONFIGURATION
// ==============================================================================
const CONFIG = {
  // Resources
  CPU_LIMIT: parseFloat(process.env.CPU_LIMIT || 0.1),
  MEM_LIMIT: parseInt(process.env.MEM_LIMIT || 512),

  // Proxy Ports
  T_PORT: process.env.T_PORT || "",
  H_PORT: process.env.H_PORT || "",
  R_PORT: process.env.R_PORT || "", // Your TCP port (e.g., 30177) goes here via ENV

  // Reality Settings
  R_SNI: (process.env.R_SNI || "web.c-servers.co.uk").trim(),
  R_DEST: (process.env.R_DEST || "web.c-servers.co.uk:443").trim(),

  // Komari Probe
  KOMARI_HOST: (process.env.KOMARI_HOST || "").trim(),
  KOMARI_TOKEN: (process.env.KOMARI_TOKEN || "").trim(),

  // System Settings
  // [LOGIC FIXED] If empty, restart is disabled.
  CRON_RESTART: process.env.CRON_RESTART || "", 
  NODE_PREFIX: process.env.NODE_PREFIX || "",
  
  // Data Directory
  WORK_DIR: '/root/ndskom',
  
  // [FIXED] Default to 2999 to match your reverse proxy
  PORT: process.env.PORT || 2999,

  // Remote Certs
  // [LOGIC FIXED] Strictly check existence
  RES_CERT_URL: (process.env.RES_CERT_URL || "").trim(),
  RES_KEY_URL: (process.env.RES_KEY_URL || "").trim()
};

const insecureAgent = new https.Agent({ rejectUnauthorized: false });

// ==============================================================================
// [2] SETUP UTILS
// ==============================================================================
if (!fs.existsSync(CONFIG.WORK_DIR)) {
    try {
        fs.mkdirSync(CONFIG.WORK_DIR, { recursive: true });
        console.log(`\x1b[32m[SYS] Created persistence dir: ${CONFIG.WORK_DIR}\x1b[0m`);
    } catch (e) {
        console.error(`\x1b[31m[ERR] Critical: Cannot create ${CONFIG.WORK_DIR}. Check permissions.\x1b[0m`);
    }
}

const FILES = {
  META: path.join(CONFIG.WORK_DIR, '.meta'),
  ID: path.join(CONFIG.WORK_DIR, 'id.dat'),
  SEC: path.join(CONFIG.WORK_DIR, 'sec.dat'),
  CERT: path.join(CONFIG.WORK_DIR, 'cert.pem'),
  KEY: path.join(CONFIG.WORK_DIR, 'private.key'),
  CONFIG: path.join(CONFIG.WORK_DIR, 'config.json')
};

const sysLog = (tag, msg) => console.log(`\x1b[90m[${tag}]\x1b[0m ${msg}`);
const errLog = (msg) => console.error(`\x1b[31m[ERR]\x1b[0m ${msg}`);
const genRandomName = () => 'k' + crypto.randomBytes(4).toString('hex') + 'd';

function getArch() {
  const map = { x64: 'amd64', arm64: 'arm64', s390x: 's390x' };
  const a = os.arch();
  if (!map[a]) { console.error('Arch not supported'); process.exit(1); }
  return map[a];
}

const SYS_ARCH = getArch();

// ==============================================================================
// [3] RESOURCE TUNER
// ==============================================================================
class ResourceTuner {
  constructor() {
    this.memBytes = 0;
    this.cpuCores = 1;
    this.detect();
  }
  detect() {
    if (CONFIG.MEM_LIMIT > 0) this.memBytes = CONFIG.MEM_LIMIT * 1024 * 1024;
    else {
      this.memBytes = os.totalmem();
      try {
        if (fs.existsSync('/sys/fs/cgroup/memory/memory.limit_in_bytes')) {
          const l = parseInt(fs.readFileSync('/sys/fs/cgroup/memory/memory.limit_in_bytes', 'utf8'));
          if (l < this.memBytes) this.memBytes = l;
        } else if (fs.existsSync('/sys/fs/cgroup/memory.max')) {
          const c = fs.readFileSync('/sys/fs/cgroup/memory.max', 'utf8').trim();
          if (c !== 'max') this.memBytes = parseInt(c);
        }
      } catch (e) {}
    }
    if (CONFIG.CPU_LIMIT > 0) this.cpuCores = Math.ceil(CONFIG.CPU_LIMIT);
    else this.cpuCores = os.cpus().length;
    
    sysLog('sys', `Container Limits -> RAM:${Math.round(this.memBytes/1024/1024)}MB CPU:${this.cpuCores}`);
  }
  getEnv() {
    const env = { ...process.env };
    const mb = this.memBytes / 1024 / 1024;
    let ratio = 0.75; 
    if (mb <= 64) ratio = 0.4; else if (mb <= 128) ratio = 0.6;
    env.GOMEMLIMIT = `${Math.floor(this.memBytes * ratio)}B`;
    env.GOMAXPROCS = Math.max(1, this.cpuCores).toString();
    return env;
  }
}

const tuner = new ResourceTuner();

// ==============================================================================
// [4] INSTALLATION
// ==============================================================================
async function installCore() {
  let ver = "1.10.7"; 
  sysLog('init', 'Checking Core version...');
  try {
    const res = await axios.get('https://api.github.com/repos/SagerNet/sing-box/releases/latest', { timeout: 5000, httpsAgent: insecureAgent });
    if (res.data && res.data.tag_name) ver = res.data.tag_name.replace('v', '');
  } catch (e) {
    sysLog('init', 'Version check failed, using fallback: ' + ver);
  }

  let meta = {};
  try { meta = JSON.parse(fs.readFileSync(FILES.META, 'utf8')); } catch (e) {}
  const binPath = meta.binName ? path.join(CONFIG.WORK_DIR, meta.binName) : null;

  if (meta.version !== ver || !binPath || !fs.existsSync(binPath)) {
    sysLog('dl', `Downloading Core v${ver}...`);
    if (binPath && fs.existsSync(binPath)) try { fs.unlinkSync(binPath); } catch(e){}
    const tgz = path.join(CONFIG.WORK_DIR, 'pkg.tar.gz');
    if (fs.existsSync(tgz)) fs.unlinkSync(tgz);

    const url = `https://github.com/SagerNet/sing-box/releases/download/v${ver}/sing-box-${ver}-linux-${SYS_ARCH}.tar.gz`;
    const tmp = path.join(CONFIG.WORK_DIR, 'tmp_ext');
    
    const writer = fs.createWriteStream(tgz);
    const resp = await axios({ url, method: 'GET', responseType: 'stream', httpsAgent: insecureAgent });
    resp.data.pipe(writer);
    await new Promise(r => writer.on('finish', r));
    
    if (fs.existsSync(tmp)) fs.rmSync(tmp, { recursive: true, force: true });
    fs.mkdirSync(tmp);
    execSync(`tar -xzf "${tgz}" -C "${tmp}"`);
    fs.unlinkSync(tgz);
    
    const findBin = (d) => {
      for (const f of fs.readdirSync(d)) {
        const fp = path.join(d, f);
        if (fs.statSync(fp).isDirectory()) { const r = findBin(fp); if (r) return r; }
        else if (f === 'sing-box') return fp;
      } return null;
    };
    const found = findBin(tmp);
    const newName = genRandomName();
    const finalPath = path.join(CONFIG.WORK_DIR, newName);
    
    fs.renameSync(found, finalPath);
    fs.chmodSync(finalPath, 0o755); 
    fs.rmSync(tmp, { recursive: true, force: true });
    
    meta.version = ver;
    meta.binName = newName;
    fs.writeFileSync(FILES.META, JSON.stringify(meta));
    sysLog('dl', 'Core installed successfully.');
    return finalPath;
  }
  return binPath;
}

async function installKomari() {
  if (!CONFIG.KOMARI_HOST || !CONFIG.KOMARI_TOKEN) return null;
  let meta = {};
  try { meta = JSON.parse(fs.readFileSync(FILES.META, 'utf8')); } catch (e) {}
  
  const binPath = meta.komariName ? path.join(CONFIG.WORK_DIR, meta.komariName) : null;
  if (!binPath || !fs.existsSync(binPath)) {
    sysLog('dl', 'Downloading Agent...');
    const url = `https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-${SYS_ARCH}`;
    const newName = 'agt' + genRandomName();
    const finalPath = path.join(CONFIG.WORK_DIR, newName);
    
    if (fs.existsSync(finalPath)) fs.unlinkSync(finalPath);
    const writer = fs.createWriteStream(finalPath);
    const resp = await axios({ url, method: 'GET', responseType: 'stream', httpsAgent: insecureAgent });
    resp.data.pipe(writer);
    await new Promise(r => writer.on('finish', r));
    
    fs.chmodSync(finalPath, 0o755);
    meta.komariName = newName;
    fs.writeFileSync(FILES.META, JSON.stringify(meta));
    sysLog('dl', 'Agent installed successfully.');
    return finalPath;
  }
  return binPath;
}

// ==============================================================================
// [5] IDENTITY & CERTS
// ==============================================================================
function setupSystem(bin) {
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
    } catch(e) { errLog('Keygen fail'); process.exit(1); }
  }
  const rawSec = fs.readFileSync(FILES.SEC, 'utf8');
  priv = rawSec.match(/PrivateKey:\s*(\S+)/)[1];
  pub = rawSec.match(/PublicKey:\s*(\S+)/)[1];
  return { uuid, priv, pub };
}

async function setupCerts(bin) {
  let ok = false;
  // [LOGIC FIXED] Strict length check
  if (CONFIG.RES_CERT_URL.length > 5 && CONFIG.RES_KEY_URL.length > 5) {
    sysLog('tls', 'Downloading remote certificates...');
    try {
      const [c, k] = await Promise.all([
        axios.get(CONFIG.RES_CERT_URL, { httpsAgent: insecureAgent, responseType: 'text', timeout: 10000 }),
        axios.get(CONFIG.RES_KEY_URL, { httpsAgent: insecureAgent, responseType: 'text', timeout: 10000 })
      ]);
      if (c.data.length > 20 && k.data.length > 20) {
        fs.writeFileSync(FILES.CERT, c.data); fs.writeFileSync(FILES.KEY, k.data); fs.chmodSync(FILES.KEY, 0o600);
        ok = true;
        sysLog('tls', 'Remote certs applied.');
      }
    } catch(e) { sysLog('tls', 'Remote cert failed (Fallback active).'); }
  } else {
    sysLog('tls', 'Remote URL not set. Skipping download.');
  }

  if (!ok && (!fs.existsSync(FILES.CERT) || !fs.existsSync(FILES.KEY))) {
    sysLog('tls', 'Generating self-signed fallback certs...');
    try {
      const out = execSync(`"${bin}" generate tls-keypair bing.com`).toString();
      fs.writeFileSync(FILES.KEY, out.match(/-----BEGIN PRIVATE KEY-----\[\s\S\]+?-----END PRIVATE KEY-----/)[0]);
      fs.writeFileSync(FILES.CERT, out.match(/-----BEGIN CERTIFICATE-----\[\s\S\]+?-----END CERTIFICATE-----/)[0]);
      fs.chmodSync(FILES.KEY, 0o600);
    } catch(e) {}
  }
}

// ==============================================================================
// [6] CONFIG & DAEMON
// ==============================================================================
function buildConfig(uuid, keys) {
  const lowMem = (tuner.memBytes / 1024 / 1024) <= 64;
  const inbounds = [];
  
  if (CONFIG.T_PORT && !lowMem) inbounds.push({ type: "tuic", tag: "in-t", listen: "::", listen_port: +CONFIG.T_PORT, users: [{ uuid, password: "ZPi1u3EcrdA5nuNvspUSJql9KmoR" }], congestion_control: "bbr", tls: { enabled: true, alpn: ["h3"], certificate_path: FILES.CERT, key_path: FILES.KEY } });
  if (CONFIG.H_PORT && !lowMem) inbounds.push({ type: "hysteria2", tag: "in-h", listen: "::", listen_port: +CONFIG.H_PORT, users: [{ password: uuid }], masquerade: "https://bing.com", tls: { enabled: true, alpn: ["h3"], certificate_path: FILES.CERT, key_path: FILES.KEY } });
  if (CONFIG.R_PORT) {
    const [dH, dP] = CONFIG.R_DEST.split(':');
    inbounds.push({ type: "vless", tag: "in-r", listen: "::", listen_port: +CONFIG.R_PORT, users: [{ uuid, flow: "xtls-rprx-vision" }], tls: { enabled: true, server_name: CONFIG.R_SNI, reality: { enabled: true, handshake: { server: dH, server_port: +(dP||443) }, private_key: keys.priv, short_id: [""] } } });
  }
  
  fs.writeFileSync(FILES.CONFIG, JSON.stringify({ log: { disabled: true }, inbounds, outbounds: [{ type: "direct" }] }, null, 2));
}

function runProc(bin, args, isProbe) {
  const env = tuner.getEnv();
  const child = spawn(bin, args, { detached: true, stdio: 'ignore', env });
  child.unref();
  if (isProbe) global.KM_PID = child.pid; else global.SB_PID = child.pid;
}

async function genLinks(uuid, pub) {
  let ip;
  sysLog('net', 'Detecting Public IP...');
  for (const s of ['https://api.ipify.org', 'https://ipv4.ip.sb']) {
    try { ip = (await axios.get(s, { timeout: 3000, httpsAgent: insecureAgent })).data.trim(); break; } catch(e){}
  }
  
  if (!ip) { errLog('Failed to detect Public IP'); return; }
  console.log(`\n\x1b[35m[SERVER IP] ${ip}\x1b[0m`);

  const lowMem = (tuner.memBytes / 1024 / 1024) <= 64;
  let txt = "";
  if (CONFIG.T_PORT && !lowMem) txt += `tuic://${uuid}:ZPi1u3EcrdA5nuNvspUSJql9KmoR@${ip}:${CONFIG.T_PORT}?sni=bing.com&alpn=h3&congestion_control=bbr&allowInsecure=1#${CONFIG.NODE_PREFIX}-T\n`;
  if (CONFIG.H_PORT && !lowMem) txt += `hysteria2://${uuid}@${ip}:${CONFIG.H_PORT}/?sni=bing.com&insecure=1#${CONFIG.NODE_PREFIX}-H\n`;
  if (CONFIG.R_PORT) txt += `vless://${uuid}@${ip}:${CONFIG.R_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${CONFIG.R_SNI}&fp=firefox&pbk=${pub}&type=tcp#${CONFIG.NODE_PREFIX}-R\n`;
  
  if (txt) {
    const b64 = Buffer.from(txt).toString('base64');
    const f = path.join(CONFIG.WORK_DIR, crypto.randomBytes(3).toString('hex') + '.keys');
    if(fs.existsSync(CONFIG.WORK_DIR)) {
      fs.readdirSync(CONFIG.WORK_DIR).forEach(x => x.endsWith('.keys') && fs.unlinkSync(path.join(CONFIG.WORK_DIR, x)));
    }
    fs.writeFileSync(f, b64);
    global.SUB_PATH = f;
    
    console.log(`\x1b[32m[SUBSCRIPTION LINK (BASE64)]\x1b[0m`);
    console.log(`------------------------------------------------------------------------`);
    console.log(b64);
    console.log(`------------------------------------------------------------------------\n`);
  }
}

// ==============================================================================
// [7] MAIN & PROCESS CONTROL
// ==============================================================================
(async () => {
  const app = express();
  
  // [FIXED] Multi-location HTML Search
  // 1. Script Directory (Most likely)
  // 2. Current Working Directory
  // 3. /root/ndskom (Data folder)
  const possiblePaths = [
    path.join(__dirname, 'index.html'),
    path.join(process.cwd(), 'index.html'),
    path.join(CONFIG.WORK_DIR, 'index.html')
  ];
  
  let htmlPath = null;
  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      htmlPath = p;
      break;
    }
  }

  if (htmlPath) sysLog('web', `Serving site from: ${htmlPath}`);
  else {
    errLog(`MISSING index.html! Checked:`);
    possiblePaths.forEach(p => console.log(` - ${p}`));
  }

  app.get('/', (req, res) => {
    if (htmlPath) res.sendFile(htmlPath);
    else res.status(404).send('Error: index.html not found. Check logs.');
  });

  app.get('/sub', (_, r) => global.SUB_PATH ? r.type('text/plain').send(fs.readFileSync(global.SUB_PATH)) : r.status(404).send('.'));
  
  // [FIXED] Bind to 0.0.0.0 for external access
  const server = app.listen(CONFIG.PORT, '0.0.0.0', () => {
    sysLog('web', `Web server listening on http://0.0.0.0:${CONFIG.PORT}`);
  });

  const cleanup = () => {
    console.log('\n\x1b[33m[SYS] Stopping services...\x1b[0m');
    if (global.SB_PID) try { process.kill(global.SB_PID, 'SIGTERM'); } catch(e){}
    if (global.KM_PID) try { process.kill(global.KM_PID, 'SIGTERM'); } catch(e){}
    server.close();
    process.exit(0);
  };
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);

  try {
    sysLog('sys', 'Starting system initialization...');
    const sbBin = await installCore();
    const kmBin = await installKomari();
    
    sysLog('sys', 'Generating/Loading credentials...');
    const { uuid, pub, priv } = setupSystem(sbBin);
    await setupCerts(sbBin);
    
    buildConfig(uuid, { priv, pub });
    
    // [FIXED] Conditional Restart
    let autoRestart = false;
    let cH, cM, lastDay = -1;
    if (CONFIG.CRON_RESTART && CONFIG.CRON_RESTART.includes(':')) {
        [cH, cM] = CONFIG.CRON_RESTART.split(':').map(Number);
        autoRestart = true;
        sysLog('sys', `Auto-restart scheduled for ${CONFIG.CRON_RESTART} (UTC+8)`);
    } else {
        sysLog('sys', 'Auto-restart disabled (CRON_RESTART not set)');
    }
    
    sysLog('run', 'Starting background daemons...');
    
    runProc(sbBin, ['run', '-c', FILES.CONFIG], false);
    if (kmBin) {
      let host = CONFIG.KOMARI_HOST;
      if (!host.startsWith('http')) host = 'https://' + host;
      runProc(kmBin, ['-e', host, '-t', CONFIG.KOMARI_TOKEN], true);
    }

    setInterval(() => {
      // Watchdog
      if (global.SB_PID) { try { process.kill(global.SB_PID, 0); } catch(e) { runProc(sbBin, ['run', '-c', FILES.CONFIG], false); } } 
      else runProc(sbBin, ['run', '-c', FILES.CONFIG], false);
      
      if (kmBin) {
        let host = CONFIG.KOMARI_HOST;
        if (!host.startsWith('http')) host = 'https://' + host;
        const args = ['-e', host, '-t', CONFIG.KOMARI_TOKEN];
        if (global.KM_PID) { try { process.kill(global.KM_PID, 0); } catch(e) { runProc(kmBin, args, true); } }
        else runProc(kmBin, args, true);
      }
      
      // Conditional Restart
      if (autoRestart) {
          const u8 = new Date(new Date().getTime() + 28800000);
          if (u8.getUTCHours() === cH && u8.getUTCMinutes() === cM && u8.getUTCDate() !== lastDay) {
            lastDay = u8.getUTCDate();
            sysLog('sys', 'Scheduled restart triggered.');
            if (global.SB_PID) try { process.kill(global.SB_PID); } catch(e){}
            if (global.KM_PID) try { process.kill(global.KM_PID); } catch(e){}
          }
      }
    }, 10000);

    await genLinks(uuid, pub);
    sysLog('sys', 'Initialization Complete. Entering Silent Mode.');

  } catch (e) { console.error(e); process.exit(1); }
})();

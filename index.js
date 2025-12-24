#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, execSync } = require('child_process');
const crypto = require('crypto');
const http = require('http');
const readline = require('readline');

process.on('uncaughtException', (e) => console.log(`[Fatal] ${e.message}`));
process.on('unhandledRejection', (e) => console.log(`[Fatal] ${e}`));

const sysLog = (tag, msg) => console.log(`[${new Date().toISOString().slice(11,19)}] [${tag}] ${msg}`);

const saveFile = (f, d, m=0o644) => {
  const tmp = f + `.${Date.now()}.tmp`;
  try {
    fs.writeFileSync(tmp, d, { mode: m });
    fs.renameSync(tmp, f);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch(x){}
  }
};

(function bootstrap() {
  const deps = ['axios', 'tar'];
  const missing = deps.filter(d => { try { require.resolve(d); return false; } catch(e){ return true; } });
  
  if (missing.length > 0) {
    try {
      console.log(`[Init] Installing dependencies...`);
      execSync(`npm install ${missing.join(' ')} --no-save --no-package-lock --production --no-audit --no-fund --loglevel=error`, { 
        stdio: 'inherit',
        timeout: 180000, 
        env: { ...process.env, npm_config_cache: path.join(os.tmpdir(), '.npm_k') }
      });
    } catch (e) {
      process.exit(1);
    }
  }
})();

const axios = require('axios');
const tar = require('tar');

const WORK_DIR = path.join(__dirname, '.sys_kernel');
if (!fs.existsSync(WORK_DIR)) fs.mkdirSync(WORK_DIR, { recursive: true });

const CONFIG = {
  PORT_T: process.env.T_PORT || "",
  PORT_H: process.env.H_PORT || "",
  PORT_R: process.env.R_PORT || "",
  PORT_WEB: parseInt(process.env.PORT || 3000),
  
  UUID: (process.env.UUID || "").trim(),
  SNI: (process.env.R_SNI || "web.c-servers.co.uk").trim(),
  DEST: (process.env.R_DEST || "web.c-servers.co.uk:443").trim(),
  PREFIX: process.env.NODE_PREFIX || "",
  
  PROBE_URL: (process.env.KOMARI_HOST || "").trim(),
  PROBE_TOK: (process.env.KOMARI_TOKEN || "").trim(),
  CERT_URL: (process.env.RES_CERT_URL || "").trim(),
  KEY_URL: (process.env.RES_KEY_URL || "").trim(),
  
  CERT_DOMAIN: (process.env.CERT_DOMAIN || "").trim(),
  
  CRON: process.env.CRON || "" 
};

const FILES = {
  MANIFEST: path.join(WORK_DIR, 'pkg.json'),
  TOKEN:    path.join(WORK_DIR, 'auth.token'),
  KEYPAIR:  path.join(WORK_DIR, 'net.key'),
  CERT:     path.join(WORK_DIR, 'cert.pem'),
  KEY:      path.join(WORK_DIR, 'private.key'),
  CONF:     path.join(WORK_DIR, 'config.json'),
  SUB:      path.join(WORK_DIR, 'sub.txt')
};

const STATE = {
  core:  { proc: null, crashCount: 0, lastStart: 0 },
  probe: { proc: null, crashCount: 0, lastStart: 0 }
};

function diskClean(keepPaths) {
  try {
    const keepSet = new Set(keepPaths.map(p => path.resolve(p)));
    fs.readdirSync(WORK_DIR).forEach(f => {
      const full = path.join(WORK_DIR, f);
      if ((f.startsWith('core_') || f.startsWith('probe_')) && !keepSet.has(full)) {
        fs.unlinkSync(full);
      }
      if (f.startsWith('dl_') || f.startsWith('ext_') || f.endsWith('.tmp')) {
        fs.rmSync(full, { recursive: true, force: true });
      }
    });
  } catch(e) {}
}

async function download(url, dest, minSize = 0) {
  if (!url) return false;
  const tmp = dest + `.${Date.now()}.dl`;
  const writer = fs.createWriteStream(tmp);
  try {
    const res = await axios({ url, method: 'GET', responseType: 'stream', timeout: 20000 });
    if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
    res.data.pipe(writer);
    await new Promise((r, j) => { writer.on('finish', r); writer.on('error', j); });
    
    if (minSize > 0 && fs.statSync(tmp).size < minSize) throw new Error('Size mismatch');
    fs.renameSync(tmp, dest);
    return true;
  } catch(e) {
    try { fs.unlinkSync(tmp); } catch(x){}
    return false;
  }
}

async function fetchBin(type) {
  const metaFile = FILES.MANIFEST;
  let meta = {};
  try { meta = JSON.parse(fs.readFileSync(metaFile, 'utf8')); } catch(e){}
  
  const arch = { x64: 'amd64', arm64: 'arm64', s390x: 's390x' }[os.arch()];
  if (!arch) return null;

  if (meta[type] && fs.existsSync(path.join(WORK_DIR, meta[type]))) 
    return path.join(WORK_DIR, meta[type]);

  const url = type === 'core' 
    ? `https://github.com/SagerNet/sing-box/releases/download/v1.10.7/sing-box-1.10.7-linux-${arch}.tar.gz`
    : `https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-${arch}`;

  const tmpDl = path.join(WORK_DIR, `dl_${crypto.randomBytes(4).toString('hex')}`);
  const tmpExt = path.join(WORK_DIR, `ext_${crypto.randomBytes(4).toString('hex')}`);
  
  if (await download(url, tmpDl, type==='core'?2e6:1e6)) {
    let finalPath = '';
    if (type === 'core') {
      try {
        if (!fs.existsSync(tmpExt)) fs.mkdirSync(tmpExt);
        await tar.x({ file: tmpDl, cwd: tmpExt });
        const findBin = (d) => {
          const list = fs.readdirSync(d, {withFileTypes:true});
          for (const e of list) {
            if (e.isDirectory()) { const r = findBin(path.join(d, e.name)); if(r) return r; }
            else if (e.name === 'sing-box') return path.join(d, e.name);
          }
        };
        const bin = findBin(tmpExt);
        if (bin) {
          finalPath = path.join(WORK_DIR, `core_${crypto.randomBytes(4).toString('hex')}`);
          fs.renameSync(bin, finalPath);
        }
      } catch(e){}
    } else {
      finalPath = path.join(WORK_DIR, `probe_${crypto.randomBytes(4).toString('hex')}`);
      fs.renameSync(tmpDl, finalPath);
    }
    
    try { fs.unlinkSync(tmpDl); } catch(e){}
    try { fs.rmSync(tmpExt, {recursive:true, force:true}); } catch(e){}

    if (finalPath && fs.existsSync(finalPath)) {
      fs.chmodSync(finalPath, 0o755);
      meta[type] = path.basename(finalPath);
      saveFile(metaFile, JSON.stringify(meta));
      return finalPath;
    }
  }
  return null;
}

async function prepareEnv(binCore) {
  let uuid = CONFIG.UUID;
  if (!uuid) {
    if (fs.existsSync(FILES.TOKEN)) uuid = fs.readFileSync(FILES.TOKEN, 'utf8').trim();
    else {
      try { uuid = execSync(`"${binCore}" generate uuid`).toString().trim(); } catch(e) { uuid = crypto.randomUUID(); }
      saveFile(FILES.TOKEN, uuid);
    }
  }

  let priv, pub;
  const genKeys = () => {
    const out = execSync(`"${binCore}" generate reality-keypair`).toString();
    saveFile(FILES.KEYPAIR, out);
    return out;
  };
  if (!fs.existsSync(FILES.KEYPAIR)) try { genKeys(); } catch(e){}
  
  try {
    const raw = fs.readFileSync(FILES.KEYPAIR, 'utf8');
    priv = raw.match(/PrivateKey:\s*(\S+)/)[1];
    pub = raw.match(/PublicKey:\s*(\S+)/)[1];
  } catch(e) {
    try {
      const out = genKeys();
      priv = out.match(/PrivateKey:\s*(\S+)/)[1];
      pub = out.match(/PublicKey:\s*(\S+)/)[1];
    } catch(x) { process.exit(1); }
  }

  const checkTls = () => {
    try {
      if(!fs.existsSync(FILES.CERT) || !fs.existsSync(FILES.KEY)) return false;
      return fs.readFileSync(FILES.CERT).includes('BEGIN CERTIFICATE');
    } catch(e){ return false; }
  };

  if (CONFIG.PORT_T || CONFIG.PORT_H) {
    if (CONFIG.CERT_URL && CONFIG.KEY_URL) {
      await download(CONFIG.CERT_URL, FILES.CERT);
      await download(CONFIG.KEY_URL, FILES.KEY);
    }
    if (!checkTls()) {
      try {
        const o = execSync(`"${binCore}" generate tls-keypair ${CONFIG.CERT_DOMAIN}`).toString();
        const k = o.match(/-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----/);
        const c = o.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
        if (k && c) { saveFile(FILES.KEY, k[0], 0o600); saveFile(FILES.CERT, c[0]); }
      } catch(e){}
    }
  }
  const tlsReady = checkTls();

  const inbounds = [];
  const tlsConf = { enabled: true, alpn: ["h3"], certificate_path: FILES.CERT, key_path: FILES.KEY };
  
  if (CONFIG.PORT_T && tlsReady) inbounds.push({
    type: "tuic", listen: "::", listen_port: +CONFIG.PORT_T,
    users: [{ uuid, password: "password" }], congestion_control: "bbr", tls: tlsConf
  });
  if (CONFIG.PORT_H && tlsReady) inbounds.push({
    type: "hysteria2", listen: "::", listen_port: +CONFIG.PORT_H,
    users: [{ password: uuid }], masquerade: "https://bing.com", tls: tlsConf
  });
  if (CONFIG.PORT_R) {
    const [h, p] = CONFIG.DEST.split(':');
    inbounds.push({
      type: "vless", listen: "::", listen_port: +CONFIG.PORT_R,
      users: [{ uuid, flow: "xtls-rprx-vision" }],
      tls: { enabled: true, server_name: CONFIG.SNI, reality: { enabled: true, handshake: { server: h, server_port: +(p||443) }, private_key: priv, short_id: [""] } }
    });
  }

  saveFile(FILES.CONF, JSON.stringify({
    log: { disabled: true },
    dns: { servers: [{ address: "8.8.8.8" }] },
    inbounds, 
    outbounds: [{ type: "direct" }]
  }, null, 2));

  let ip = "127.0.0.1";
  try { ip = (await axios.get('https://api.ipify.org', {timeout:3000})).data.trim(); } catch(e){}
  let s = "";
  if (CONFIG.PORT_T && tlsReady) s += `tuic://${uuid}:password@${ip}:${CONFIG.PORT_T}?sni=${CONFIG.CERT_DOMAIN}&alpn=h3#${CONFIG.PREFIX}-T\n`;
  if (CONFIG.PORT_H && tlsReady) s += `hysteria2://${uuid}@${ip}:${CONFIG.PORT_H}/?sni=${CONFIG.CERT_DOMAIN}&insecure=1#${CONFIG.PREFIX}-H\n`;
  if (CONFIG.PORT_R) s += `vless://${uuid}@${ip}:${CONFIG.PORT_R}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${CONFIG.SNI}&pbk=${pub}&type=tcp#${CONFIG.PREFIX}-R\n`;
  
  const b64 = Buffer.from(s).toString('base64');
  saveFile(FILES.SUB, b64);
  
  if (s) {
    console.log('\n' + '='.repeat(40));
    console.log(b64);
    console.log('='.repeat(40) + '\n');
    setTimeout(() => {
      console.clear();
      sysLog('Sys', 'Console cleared');
    }, 60000);
  }
}

function spawnService(key, bin, args, env) {
  if (STATE[key].proc) return;

  STATE[key].lastStart = Date.now();
  const child = spawn(bin, args, { stdio: 'inherit', env });
  STATE[key].proc = child;

  child.on('exit', (code, signal) => {
    STATE[key].proc = null;
    
    if (signal === 'SIGTERM') {
      STATE[key].crashCount = 0;
      setTimeout(() => spawnService(key, bin, args, env), 1000);
      return;
    }

    const liveTime = Date.now() - STATE[key].lastStart;
    if (liveTime > 30000) STATE[key].crashCount = 0;
    else STATE[key].crashCount++;

    const delay = Math.min(2000 * Math.pow(2, STATE[key].crashCount), 60000);
    sysLog(key, `Restarting in ${delay/1000}s...`);
    setTimeout(() => spawnService(key, bin, args, env), delay);
  });
}

function boot(binCore, binProbe) {
  const env = { ...process.env, GOGC: "80" };
  if (os.totalmem() < 256 * 1024 * 1024) env.GOMEMLIMIT = "100MiB";
  
  spawnService('core', binCore, ['run', '-c', FILES.CONF], env);
  
  if (binProbe && CONFIG.PROBE_URL) {
    let u = CONFIG.PROBE_URL.startsWith('http') ? CONFIG.PROBE_URL : `https://${CONFIG.PROBE_URL}`;
    spawnService('probe', binProbe, ['-e', u, '-t', CONFIG.PROBE_TOK], { stdio: 'ignore' });
  }
}

function setupCron() {
  if (!CONFIG.CRON) return;
  const str = (CONFIG.CRON === "true" || CONFIG.CRON === "1") ? "UTC+8 06:30" : CONFIG.CRON;
  
  const m = str.match(/UTC([+-]\d+)\s+(\d{1,2}):(\d{1,2})/);
  if (!m) return;

  const [_, off, h, min] = m.map(Number);
  const now = new Date();
  const utc = now.getTime() + (now.getTimezoneOffset() * 60000);
  const targetZoneTime = utc + (off * 3600000);
  
  let targetDate = new Date(targetZoneTime);
  targetDate.setHours(h, min, 0, 0);

  if (targetDate.getTime() <= targetZoneTime) targetDate.setDate(targetDate.getDate() + 1);
  
  const ms = targetDate.getTime() - targetZoneTime;
  
  setTimeout(() => {
    if (STATE.core.proc) STATE.core.proc.kill('SIGTERM');
    if (STATE.probe.proc) STATE.probe.proc.kill('SIGTERM');
    setTimeout(setupCron, 5000);
  }, ms);
}

(async () => {
  const binCore = await fetchBin('core');
  const binProbe = await fetchBin('probe');
  if (!binCore) process.exit(1);

  diskClean([binCore, binProbe]);
  await prepareEnv(binCore);

  const html = `<!DOCTYPE html><html><body><h1>Welcome to nginx!</h1></body></html>`;
  http.createServer((req, res) => {
    if (req.url.startsWith('/subb') && fs.existsSync(FILES.SUB)) {
      res.writeHead(200, {'Content-Type': 'text/plain'});
      fs.createReadStream(FILES.SUB).pipe(res);
    } else if (req.url === '/health') {
      const ok = STATE.core.proc && !STATE.core.proc.killed;
      res.writeHead(ok ? 200 : 503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: ok ? 'UP' : 'DOWN', uptime: ok ? Math.floor((Date.now() - STATE.core.lastStart)/1000) : 0 }));
    } else {
      res.writeHead(200, {'Content-Type': 'text/html'});
      res.end(html);
    }
  }).listen(CONFIG.PORT_WEB, () => sysLog('Web', `Port ${CONFIG.PORT_WEB}`));

  boot(binCore, binProbe);
  setupCron();
})();

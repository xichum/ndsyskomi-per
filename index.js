#!/usr/bin/env node

/**
 * Author      : Prince
 * Version     : 1.0.0
 * Date        : 2025.12
 * License     : MIT
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, execSync } = require('child_process');
const crypto = require('crypto');
const http = require('http');

process.on('uncaughtException', (e) => {});
process.on('unhandledRejection', (e) => {});

let IS_SILENT = false;
const sysLog = (t, m) => {
  if (IS_SILENT && t !== 'ERR') return;
  console.log(`[${new Date().toISOString().slice(11,19)}] [${t}] ${m}`);
};

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
      execSync(`npm install ${missing.join(' ')} --no-save --no-package-lock --production --no-audit --no-fund --loglevel=error`, { 
        stdio: 'ignore',
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

const WORK_DIR = path.join(__dirname, '.backend_service');
if (!fs.existsSync(WORK_DIR)) fs.mkdirSync(WORK_DIR, { recursive: true });

const CONFIG = {
  PORT_T: process.env.T_PORT || "", // T Port
  PORT_H: process.env.H_PORT || "", // H Port
  PORT_R: process.env.R_PORT || "", // R Port
  PORT_WEB: parseInt(process.env.PORT || 3000), // Web/Health Port
  UUID: (process.env.UUID || "").trim(), // User UUID
  SNI: (process.env.R_SNI || "web.c-servers.co.uk").trim(), // R SNI
  DEST: (process.env.R_DEST || "web.c-servers.co.uk:443").trim(), // R Dest
  PREFIX: process.env.NODE_PREFIX || "", // Link Name Prefix
  PROBE_URL: (process.env.KOMARI_HOST || "").trim(), // Monitor Host
  PROBE_TOK: (process.env.KOMARI_TOKEN || "").trim(), // Monitor Token
  CERT_URL: (process.env.RES_CERT_URL || "").trim(), // TLS Cert URL
  KEY_URL: (process.env.RES_KEY_URL || "").trim(), // TLS Key URL
  CERT_DOMAIN: (process.env.CERT_DOMAIN || "").trim(), // TLS Domain
  CRON: process.env.CRON || "", // Auto Restart Cron
  HY2_OBFS: (process.env.HY2_OBFS || "false").trim() // H Obfs (true/false)
};

const FILES = {
  META:     path.join(WORK_DIR, 'registry.dat'),
  TOKEN:    path.join(WORK_DIR, 'identity.key'),
  KEYPAIR:  path.join(WORK_DIR, 'transport_pair.bin'),
  CERT:     path.join(WORK_DIR, 'tls_cert.pem'),
  KEY:      path.join(WORK_DIR, 'tls_key.pem'),
  CONF:     path.join(WORK_DIR, 'service_conf.json'),
  SUB:      path.join(WORK_DIR, 'blob_storage.dat'),
  SID:      path.join(WORK_DIR, 'session_ticket.hex'),
  SEC_KEY:  path.join(WORK_DIR, 'access_token.key')
};

const STATE = {
  srv: { proc: null, crashCount: 0, lastStart: 0 },
  mon: { proc: null, crashCount: 0, lastStart: 0 }
};

function diskClean(keepPaths) {
  try {
    const keepSet = new Set(keepPaths.map(p => path.resolve(p)));
    fs.readdirSync(WORK_DIR).forEach(f => {
      const full = path.join(WORK_DIR, f);
      if ((f.startsWith('S') || f.startsWith('K')) && !keepSet.has(full) && !Object.values(FILES).includes(full)) {
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
    if (res.status !== 200) throw new Error();
    res.data.pipe(writer);
    await new Promise((r, j) => { writer.on('finish', r); writer.on('error', j); });
    if (minSize > 0 && fs.statSync(tmp).size < minSize) throw new Error();
    fs.renameSync(tmp, dest);
    return true;
  } catch(e) {
    try { fs.unlinkSync(tmp); } catch(x){}
    return false;
  }
}

async function fetchBin(type) {
  const metaFile = FILES.META;
  let meta = {};
  try { meta = JSON.parse(fs.readFileSync(metaFile, 'utf8')); } catch(e){}
  
  const arch = { x64: 'amd64', arm64: 'arm64', s390x: 's390x' }[os.arch()];
  if (!arch) return null;
  
  if (meta[type] && fs.existsSync(path.join(WORK_DIR, meta[type]))) 
    return path.join(WORK_DIR, meta[type]);

  const targets = [];
  const rand = crypto.randomBytes(4).toString('hex');
  
  if (type === 'srv') {
    try {
      const { data } = await axios.get('https://api.github.com/repos/SagerNet/sing-box/releases/latest', { timeout: 5000, headers: {'User-Agent': 'Node'} });
      const tag = data.tag_name;
      const ver = tag.replace(/^v/, '');
      const num = ver.replace(/\./g, '');
      targets.push({
        url: `https://github.com/SagerNet/sing-box/releases/download/${tag}/sing-box-${ver}-linux-${arch}.tar.gz`,
        name: `S${num}_${rand}`
      });
    } catch(e) {}
    targets.push({
      url: `https://github.com/SagerNet/sing-box/releases/download/v1.12.13/sing-box-1.12.13-linux-${arch}.tar.gz`,
      name: `S11213_${rand}`
    });
  } else {
    try {
      const { data } = await axios.get('https://api.github.com/repos/komari-monitor/komari-agent/releases/latest', { timeout: 5000, headers: {'User-Agent': 'Node'} });
      const tag = data.tag_name;
      const num = tag.replace(/^v/, '').replace(/\./g, '');
      targets.push({
        url: `https://github.com/komari-monitor/komari-agent/releases/download/${tag}/komari-agent-linux-${arch}`,
        name: `K${num}_${rand}`
      });
    } catch(e) {}
    targets.push({
      url: `https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-${arch}`,
      name: `K000_${rand}`
    });
  }

  for (const t of targets) {
    const tmpDl = path.join(WORK_DIR, `dl_${crypto.randomBytes(4).toString('hex')}`);
    const tmpExt = path.join(WORK_DIR, `ext_${crypto.randomBytes(4).toString('hex')}`);
    
    if (await download(t.url, tmpDl, type==='srv'?2e6:1e6)) {
      let finalPath = '';
      if (type === 'srv') {
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
            finalPath = path.join(WORK_DIR, t.name);
            fs.renameSync(bin, finalPath);
          }
        } catch(e){}
      } else {
        finalPath = path.join(WORK_DIR, t.name);
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
  }
  return null;
}

async function prepareEnv(binSrv) {
  let uuid = CONFIG.UUID;
  if (!uuid) {
    if (fs.existsSync(FILES.TOKEN)) uuid = fs.readFileSync(FILES.TOKEN, 'utf8').trim();
    else {
      try { uuid = execSync(`"${binSrv}" generate uuid`).toString().trim(); } catch(e) { uuid = crypto.randomUUID(); }
      saveFile(FILES.TOKEN, uuid);
    }
  }

  let priv, pub;
  const genKeys = () => {
    const out = execSync(`"${binSrv}" generate reality-keypair`).toString();
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

  let secKey;
  if (fs.existsSync(FILES.SEC_KEY)) {
    secKey = fs.readFileSync(FILES.SEC_KEY, 'utf8').trim();
  } else {
    secKey = crypto.randomBytes(16).toString('hex');
    saveFile(FILES.SEC_KEY, secKey);
  }

  let shortId;
  if (fs.existsSync(FILES.SID)) {
    shortId = fs.readFileSync(FILES.SID, 'utf8').trim();
  } else {
    shortId = crypto.randomBytes(4).toString('hex');
    saveFile(FILES.SID, shortId);
  }

  const checkTls = () => {
    try {
      if(!fs.existsSync(FILES.CERT) || !fs.existsSync(FILES.KEY)) return false;
      return fs.readFileSync(FILES.CERT).includes('BEGIN CERTIFICATE');
    } catch(e){ return false; }
  };
  if (CONFIG.PORT_T || CONFIG.PORT_H) {
    if (CONFIG.CERT_URL && CONFIG.KEY_URL) {
      sysLog('Init', 'Syncing assets...');
      await download(CONFIG.CERT_URL, FILES.CERT);
      await download(CONFIG.KEY_URL, FILES.KEY);
    }
    if (!checkTls()) {
      try {
        const o = execSync(`"${binSrv}" generate tls-keypair ${CONFIG.CERT_DOMAIN}`).toString();
        const k = o.match(/-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----/);
        const c = o.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
        if (k && c) { saveFile(FILES.KEY, k[0], 0o600); saveFile(FILES.CERT, c[0]); }
      } catch(e){}
    }
  }

  const tlsReady = checkTls();
  const inbounds = [];
  const tlsBase = { enabled: true, certificate_path: FILES.CERT, key_path: FILES.KEY };
  const listenIp = "0.0.0.0";
  const useHyObfs = CONFIG.HY2_OBFS === "true";
  
  if (CONFIG.PORT_T && tlsReady) inbounds.push({
    type: "tuic", listen: listenIp, listen_port: +CONFIG.PORT_T,
    users: [{ uuid, password: secKey }], congestion_control: "bbr", 
    tls: { ...tlsBase, alpn: ["h3"] }
  });

  if (CONFIG.PORT_H && tlsReady) {
    const hyConf = {
      type: "hysteria2", listen: listenIp, listen_port: +CONFIG.PORT_H,
      users: [{ password: uuid }], 
      masquerade: "https://bing.com", 
      tls: tlsBase, 
      ignore_client_bandwidth: false
    };
    if (useHyObfs) hyConf.obfs = { type: "salamander", password: secKey };
    inbounds.push(hyConf);
  }

  if (CONFIG.PORT_R) {
    const [h, p] = CONFIG.DEST.split(':');
    inbounds.push({
      type: "vless", listen: listenIp, listen_port: +CONFIG.PORT_R,
      users: [{ uuid, flow: "xtls-rprx-vision" }],
      tls: { 
        enabled: true, 
        server_name: CONFIG.SNI, 
        reality: { 
          enabled: true, 
          handshake: { server: h, server_port: +(p||443) }, 
          private_key: priv, 
          short_id: [shortId] 
        } 
      }
    });
  }

  saveFile(FILES.CONF, JSON.stringify({
    log: { disabled: true, level: "warn", timestamp: true },
    inbounds, 
    outbounds: [{ type: "direct", tag: "direct" }],
    route: { final: "direct" }
  }, null, 2));

  let ip = "127.0.0.1";
  try { ip = (await axios.get('https://api.ipify.org', {timeout:3000})).data.trim(); } catch(e){}
  
  let s = "";
  if (CONFIG.PORT_T && tlsReady) s += `tuic://${uuid}:${secKey}@${ip}:${CONFIG.PORT_T}?sni=${CONFIG.CERT_DOMAIN}&alpn=h3&congestion_control=bbr#${CONFIG.PREFIX}-T\n`;
  if (CONFIG.PORT_H && tlsReady) {
    s += `hysteria2://${uuid}@${ip}:${CONFIG.PORT_H}/?sni=${CONFIG.CERT_DOMAIN}&insecure=1`;
    if (useHyObfs) s += `&obfs=salamander&obfs-password=${secKey}`;
    s += `#${CONFIG.PREFIX}-H\n`;
  }
  if (CONFIG.PORT_R) s += `vless://${uuid}@${ip}:${CONFIG.PORT_R}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${CONFIG.SNI}&fp=edge&pbk=${pub}&sid=${shortId}&type=tcp#${CONFIG.PREFIX}-R\n`;
  
  const b64 = Buffer.from(s).toString('base64');
  saveFile(FILES.SUB, b64);
  sysLog('Sys', 'Service initialized');
  console.log('\n' + '='.repeat(10) + ' ACCESS TOKEN ' + '='.repeat(10));
  console.log(b64);
  console.log('='.repeat(34) + '\n');
}

function spawnService(key, bin, args, env) {
  if (STATE[key].proc) return;
  STATE[key].lastStart = Date.now();
  
  const child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'], env });
  STATE[key].proc = child;
  
  const filterLog = (d) => {
    const str = d.toString();
    if (IS_SILENT) {
      if (str.match(/error|fatal|panic/i)) sysLog('ERR', `[${key==='srv'?'Core':'Link'}] Runtime exception`);
      return;
    }
    if (str.match(/Komari|sing-box|SagerNet|version|Github|DNS|Mountpoints|Interfaces|Using|Checking|Current|Get|Attempting|IPV4/i)) return;
    if (str.trim().length < 5) return;
    let msg = str.trim();
    msg = msg.replace(/WebSocket/i, 'Uplink').replace(/uploaded/i, 'Sync').replace(/connected/i, 'est');
    sysLog(key === 'srv' ? 'CoreService' : 'LinkAgent', msg.substring(0, 50));
  };
  
  child.stdout.on('data', filterLog);
  child.stderr.on('data', filterLog);

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
    sysLog('Sys', `${key === 'srv' ? 'Core' : 'Agent'} reload in ${delay/1000}s`);
    setTimeout(() => spawnService(key, bin, args, env), delay);
  });
}

function boot(binSrv, binMon) {
  const env = { ...process.env, GOGC: "80" };
  if (os.totalmem() < 256 * 1024 * 1024) env.GOMEMLIMIT = "100MiB";
  
  spawnService('srv', binSrv, ['run', '-c', FILES.CONF], env);
  
  if (binMon && CONFIG.PROBE_URL) {
    let u = CONFIG.PROBE_URL.startsWith('http') ? CONFIG.PROBE_URL : `https://${CONFIG.PROBE_URL}`;
    spawnService('mon', binMon, ['-e', u, '-t', CONFIG.PROBE_TOK], { });
  }

  setTimeout(() => {
    IS_SILENT = true;
    sysLog('Sys', 'Entering silent mode');
  }, 60000);
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
    if (STATE.srv.proc) STATE.srv.proc.kill('SIGTERM');
    if (STATE.mon.proc) STATE.mon.proc.kill('SIGTERM');
    setTimeout(setupCron, 5000);
  }, ms);
}

(async () => {
  const binSrv = await fetchBin('srv');
  const binMon = await fetchBin('mon');
  if (!binSrv) process.exit(1);
  diskClean([binSrv, binMon]);
  await prepareEnv(binSrv);

  const html = `<!DOCTYPE html><html><head><title>Service Status</title></head><body style="font-family:sans-serif;text-align:center;padding:50px;"><h1>Service Operational</h1><p>The backend interface is running normally.</p></body></html>`;
  http.createServer((req, res) => {
    if (req.url.startsWith('/api/data') && fs.existsSync(FILES.SUB)) {
      res.writeHead(200, {'Content-Type': 'text/plain'});
      fs.createReadStream(FILES.SUB).pipe(res);
    } else if (req.url === '/api/heartbeat') {
      const ok = STATE.srv.proc && !STATE.srv.proc.killed;
      res.writeHead(ok ? 200 : 503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: ok ? 'OK' : 'ERR', tick: ok ? Math.floor((Date.now() - STATE.srv.lastStart)/1000) : 0 }));
    } else {
      res.writeHead(200, {'Content-Type': 'text/html'});
      res.end(html);
    }
  }).listen(CONFIG.PORT_WEB, () => sysLog('Web', `Service running on ${CONFIG.PORT_WEB}`));
  
  boot(binSrv, binMon);
  setupCron();
})();

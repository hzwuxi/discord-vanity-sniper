"use strict";
process.env.UV_THREADPOOL_SIZE = "64";

import { connect as tlsConnect } from "tls";
import WebSocket from "ws";
import fs from "fs";
import constants from "constants";
import dns from "dns";
import os from "os";

dns.setDefaultResultOrder("ipv4first");
try { process.setPriority(process.pid, os.constants.priority.PRIORITY_HIGH); } catch {}

const TOKEN           = "token kardeşim ";
const TARGET_GUILD_ID = " sw id ";
const DISCORD_IP      = "162.159.136.232";
const DISCORD_HOST    = "canary.discord.com";
const SOCKET_COUNT    = 4; //bilmeyen mal kardeşlerimiz için socket sayısı 
const REQUESTS_PER_VERSION = 1;  // her apiden kaç istek atacağını yazın 
const API_VERSIONS    = ["v7", "v8", "v9", "v10"];  

let mfaToken = "";
let isActive  = true;
let hasFired  = false;

const sockets      = new Array(SOCKET_COUNT).fill(null);
const socketReady  = new Array(SOCKET_COUNT).fill(false);
let   socketIndex  = 0;
const sessionCache   = new Map();
const requestBuffers = new Map();

let pendingPatchCount = 0;

const HDR_MIDDLE = Buffer.from(`\r\nContent-Type: application/json\r\nContent-Length: `);
const HDR_COOKIE = Buffer.from(
  `\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0\r\n` +
  `X-Super-Properties: eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiRmlyZWZveCIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJ0ci1UUiIsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChXaW5kb3dzIE5UIDEwLjA7IFdpbjY0OyB4NjQ7IHJ2OjEzMy4wKSBHZWNrby8yMDEwMDEwMSBGaXJlZm94LzEzMy4wIiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTMzLjAiLCJvc192ZXJzaW9uIjoiMTAiLCJyZWZlcnJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MzU2MTQwLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ==\r\n` +
  `Cookie: __Secure-recent_mfa=`
);
const HDR_END = Buffer.from(`\r\nConnection: keep-alive\r\n\r\n`);

const WARMUP_BUF = Buffer.from(
  `GET /api/v10/users/@me HTTP/1.1\r\nHost: ${DISCORD_HOST}\r\nAuthorization: ${TOKEN}\r\nConnection: keep-alive\r\n\r\n`
);

const TLS_BASE = {
  host: DISCORD_IP, port: 8443, servername: DISCORD_HOST,
  minVersion: "TLSv1.3", maxVersion: "TLSv1.3",
  rejectUnauthorized: false, handshakeTimeout: 50,
  keepAlive: true, keepAliveInitialDelay: 0,
  highWaterMark: 1048576, noDelay: true, timeout: 0,
  ALPNProtocols: ["http/1.1"],
  ciphers: "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256",
  ecdhCurve: "X25519", honorCipherOrder: true, requestOCSP: false,
  secureOptions:
    constants.SSL_OP_NO_COMPRESSION    |
    constants.SSL_OP_PRIORITIZE_CHACHA |
    constants.SSL_OP_NO_TICKET         |
    constants.SSL_OP_NO_RENEGOTIATION  |
    constants.SSL_OP_SINGLE_ECDH_USE,
  maxFragmentLength: 16384, fastOpen: true, maxCachedSessions: 4096,
};

function makeHdrPrefix(version) {
  return Buffer.from(
    `PATCH /api/${version}/guilds/${TARGET_GUILD_ID}/vanity-url HTTP/1.1\r\n` +
    `Host: ${DISCORD_HOST}\r\nAuthorization: ${TOKEN}\r\nX-Discord-MFA-Authorization: `
  );
}

const HDR_PREFIXES = {};
for (const v of API_VERSIONS) HDR_PREFIXES[v] = makeHdrPrefix(v);

function buildRequestBuffer(vanityCode, version) {
  const payload   = JSON.stringify({ code: vanityCode });
  const mfaBuf    = Buffer.from(mfaToken);
  const payBuf    = Buffer.from(payload);
  const lenBuf    = Buffer.from(String(payload.length));
  const prefix    = HDR_PREFIXES[version];
  const total     = prefix.length + mfaBuf.length + HDR_MIDDLE.length + lenBuf.length +
                    HDR_COOKIE.length + mfaBuf.length + HDR_END.length + payBuf.length;
  const buf       = Buffer.allocUnsafe(total);
  let   cursor    = 0;
  for (const part of [prefix, mfaBuf, HDR_MIDDLE, lenBuf, HDR_COOKIE, mfaBuf, HDR_END, payBuf]) {
    part.copy(buf, cursor); cursor += part.length;
  }
  requestBuffers.set(`${version}:${vanityCode}`, buf);
  return buf;
}

function buildAllVersionBuffers(vanityCode) {
  for (const v of API_VERSIONS) buildRequestBuffer(vanityCode, v);
}

let lastFiredCode = "";

function makeSocket(i) {
  const opts = sessionCache.has(DISCORD_HOST)
    ? { ...TLS_BASE, session: sessionCache.get(DISCORD_HOST) }
    : { ...TLS_BASE };
  const sock = tlsConnect(opts);
  sock.on("session", (s) => sessionCache.set(DISCORD_HOST, s));
  sock.on("secureConnect", () => {
    socketReady[i] = true;
    try { sock._socket?.setRecvBufferSize(65536); sock._socket?.setSendBufferSize(65536); } catch {}
    setInterval(() => { if (sock.writable) try { sock.write(WARMUP_BUF); } catch {} }, 2000);
  });
  sock.on("data", (chunk) => {
    if (!hasFired || pendingPatchCount <= 0) return;
    const s      = chunk.toString("latin1");
    const idx    = s.indexOf("HTTP/1.1 ");
    if (idx === -1) return;
    const status    = s.slice(idx + 9, idx + 12);
    const bodyStart = s.indexOf("\r\n\r\n");
    const body      = bodyStart !== -1 ? s.slice(bodyStart + 4).trim() : "";
    pendingPatchCount--;
    if (status === "200") {
      process.stdout.write(`[✓ 200] CLAIMED — discord.gg/${lastFiredCode}\n`);
    } else {
      let parsed = body;
      try { parsed = JSON.stringify(JSON.parse(body)); } catch {}
      process.stdout.write(`[${status}] discord.gg/${lastFiredCode} — ${parsed}\n`);
    }
  });
  const reconnect = () => {
    socketReady[i] = false; sockets[i] = null;
    setTimeout(() => { sockets[i] = makeSocket(i); }, 1000);
  };
  sock.on("error", reconnect);
  sock.on("close", reconnect);
  return sock;
}

function fire(code) {
  hasFired = true;
  lastFiredCode = code;
  process.stdout.write(`[FIRE] discord.gg/${code}\n`);

  for (const version of API_VERSIONS) {
    let buf = requestBuffers.get(`${version}:${code}`);
    if (!buf && mfaToken) buf = buildRequestBuffer(code, version);
    if (!buf) continue;

    for (let r = 0; r < REQUESTS_PER_VERSION; r++) {
      const i = socketIndex++ % SOCKET_COUNT;
      if (!sockets[i] || sockets[i].destroyed || !socketReady[i]) continue;
      try {
        sockets[i].write(buf);
        pendingPatchCount++;
      } catch { socketReady[i] = false; sockets[i] = null; }
    }
  }
}

const vanityMap  = new Map();
const SEQ_RE     = /"s"\s*:\s*(\d+)/;
const HB_RE      = /"heartbeat_interval"\s*:\s*(\d+)/;

function connectWS(token, label) {
  let hbTimer = null, seq = null, sessionId = null, resumeUrl = null, missedAck = false, ws = null;

  const clearHB = () => { if (hbTimer) { clearInterval(hbTimer); hbTimer = null; } };

  function sendHB() {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    if (missedAck) { clearHB(); ws.terminate(); return; }
    missedAck = true;
    ws.send(`{"op":1,"d":${seq ?? "null"}}`);
  }

  function startHB(ms) {
    clearHB();
    setTimeout(() => {
      if (!ws || ws.readyState !== WebSocket.OPEN) return;
      sendHB();
      hbTimer = setInterval(sendHB, ms);
    }, Math.floor(Math.random() * ms));
  }

  function connect() {
    const url = resumeUrl ? `${resumeUrl}/?v=10&encoding=json` : "wss://gateway.discord.gg/?v=10&encoding=json";
    ws = new WebSocket(url, { perMessageDeflate: false, skipUTF8Validation: true });
    ws.binaryType = "nodebuffer";

    ws.on("message", (raw) => {
      const data = typeof raw === "string" ? raw : raw.toString("utf8");
      const s = SEQ_RE.exec(data); if (s && +s[1] > (seq ?? -1)) seq = +s[1];

      if (data.indexOf('"op":10') !== -1) {
        const hb = HB_RE.exec(data); if (hb) startHB(+hb[1]);
        ws.send(sessionId && resumeUrl
          ? JSON.stringify({ op: 6, d: { token, session_id: sessionId, seq } })
          : JSON.stringify({ op: 2, d: { token, intents: 1, properties: { os: "linux", browser: "firefox", device: "" } } })
        );
        return;
      }
      if (data.indexOf('"op":11') !== -1) { missedAck = false; return; }
      if (data.indexOf('"op":7')  !== -1) { ws.close(4000); return; }
      if (data.indexOf('"op":9')  !== -1) {
        sessionId = null; resumeUrl = null; seq = null;
        clearHB(); ws.terminate();
        setTimeout(connect, 3000 + Math.random() * 2000);
        return;
      }

      if (data.indexOf('"READY"') !== -1) {
        try {
          const msg = JSON.parse(data); if (msg.t !== "READY") return;
          sessionId = msg.d.session_id; resumeUrl = msg.d.resume_gateway_url;
          msg.d.guilds.forEach((g) => {
            if (g.vanity_url_code) {
              vanityMap.set(g.id, g.vanity_url_code);
              if (mfaToken) buildAllVersionBuffers(g.vanity_url_code);
            }
          });
        } catch {}
        return;
      }

      if (data.indexOf('"GUILD_UPDATE"') !== -1) {
        try {
          const { d } = JSON.parse(data);
          const id = d.id || d.guild_id;
          const oldCode = vanityMap.get(id);
          const newCode = d.vanity_url_code;
          if (oldCode && newCode !== oldCode) fire(oldCode);
          if (newCode) {
            vanityMap.set(id, newCode);
            if (mfaToken) buildAllVersionBuffers(newCode);
          } else vanityMap.delete(id);
        } catch {}
        return;
      }

      if (data.indexOf('"GUILD_DELETE"') !== -1) {
        try {
          const { d } = JSON.parse(data);
          const old = vanityMap.get(d.id);
          if (old) {
            fire(old);
            for (const v of API_VERSIONS) requestBuffers.delete(`${v}:${old}`);
          }
          vanityMap.delete(d.id);
        } catch {}
      }
    });

    ws.on("close", (code) => {
      clearHB(); missedAck = false;
      if (!isActive) return;
      if (code > 4000 && code < 4015) { sessionId = null; resumeUrl = null; seq = null; }
      setTimeout(connect, 500);
    });
    ws.on("error", () => {});
  }

  connect();
}

function loadMfa() {
  try {
    const t = fs.readFileSync("mfa.txt", "utf8").trim();
    if (t && t !== mfaToken) {
      mfaToken = t;
      requestBuffers.clear();
      for (const code of vanityMap.values()) buildAllVersionBuffers(code);
    }
  } catch { mfaToken = ""; }
}

function loadMonitorTokens() {
  try { return fs.readFileSync("monitor_tokens.txt", "utf8").split(/\r?\n/).map(t => t.trim()).filter(Boolean); }
  catch { return []; }
}

loadMfa();
fs.watchFile("mfa.txt", { interval: 100 }, (c, p) => { if (c.mtimeMs !== p.mtimeMs) loadMfa(); });

for (let i = 0; i < SOCKET_COUNT; i++) sockets[i] = makeSocket(i);

connectWS(TOKEN, "WS-0");
connectWS(TOKEN, "WS-1");
connectWS(TOKEN, "WS-2");

const monitorTokens = loadMonitorTokens();
monitorTokens.forEach((t, i) => setTimeout(() => connectWS(t, `MON-${i}`), i * 500));

process.on("uncaughtException",  () => {});
process.on("unhandledRejection", () => {});
process.on("SIGINT", () => { isActive = false; process.exit(0); });

#!/usr/bin/env node
'use strict';

/**
 * ============================================================================
 *  Subdomain Takeover Scanner -- v4.0 (Professional / Automation Edition)
 * ============================================================================
 *
 *  Alat ini melakukan RECON PASIF: memeriksa CNAME record subdomain,
 *  mencocokkannya dengan fingerprint provider yang diketahui publik, lalu
 *  memvalidasi lewat HTTP apakah resource tersebut menunjukkan tanda-tanda
 *  "unclaimed" (berpotensi diambil alih / subdomain takeover).
 *
 *  Alat ini TIDAK melakukan takeover apa pun -- hanya deteksi & pelaporan.
 *  Selalu verifikasi manual sebelum melaporkan lewat program VDP/bug bounty
 *  resmi (misalnya lewat Bugcrowd/HackerOne yang sesuai).
 *
 *  ---------------------------------------------------------------------
 *  PERUBAHAN dari versi sebelumnya (v3.0 -> v4.0):
 *  ---------------------------------------------------------------------
 *   1. Semua output console tidak lagi memakai emoji. Log kini memakai tag
 *      teks konsisten ([INFO]/[ OK ]/[WARN]/[ERR ]/[CRIT]) agar aman dibaca
 *      oleh terminal apa pun dan mudah di-parse oleh pipeline CI/CD/log
 *      aggregator.
 *   2. Adaptive concurrency: jumlah worker paralel kini menyesuaikan diri
 *      secara otomatis. Jika tingkat kegagalan (timeout/DNS error/fatal)
 *      pada jendela permintaan terakhir melewati ambang batas, concurrency
 *      diturunkan otomatis; saat kondisi stabil, concurrency dinaikkan lagi
 *      secara bertahap sampai batas yang dikonfigurasi.
 *   3. Circuit breaker per root-domain: bila satu root domain mengalami
 *      kegagalan beruntun melewati ambang batas, sisa subdomain di bawah
 *      root domain tersebut dilewati otomatis (tanpa request jaringan lagi)
 *      supaya scan besar tidak habis waktu hanya karena satu domain yang
 *      memang tidak bisa dijangkau.
 *   4. Checkpoint & resume: progres discan secara berkala ke file checkpoint
 *      JSON. Jika proses terhenti (SIGINT/SIGTERM/crash), scan bisa
 *      dilanjutkan dengan --resume tanpa mengulang dari nol.
 *   5. Dukungan DNS resolver kustom (--resolver) dan HTTP/HTTPS proxy
 *      (--proxy, atau env HTTP_PROXY/HTTPS_PROXY) untuk lingkungan
 *      enterprise yang mewajibkan lalu lintas keluar lewat gateway tertentu.
 *   6. Notifikasi webhook (--webhook) yang mengirim POST JSON best-effort
 *      setiap kali status POTENTIAL_TAKEOVER ditemukan, untuk integrasi
 *      dengan Slack/Teams/sistem tiket internal.
 *   7. Log terstruktur JSON Lines (--log-file) -- satu event per baris --
 *      untuk konsumsi otomatis oleh SIEM atau pipeline data internal.
 *   8. Laporan HTML mandiri (--html) dengan ringkasan visual, badge kategori,
 *      dan tabel hasil, selain CSV/JSON/Markdown yang sudah ada.
 *   9. Skor confidence (HIGH/MEDIUM/LOW) ditambahkan pada tiap hasil untuk
 *      membantu prioritisasi triase manual.
 *  10. Fingerprint provider kini bisa disegarkan dari feed JSON jarak jauh
 *      (--fingerprints-url), selain file lokal (--fingerprints) -- cocok
 *      untuk tim yang menjaga daftar fingerprint internal terpusat.
 *  11. File konfigurasi JSON (--config) didukung; opsi CLI selalu menimpa
 *      opsi dari file konfigurasi, opsi dari file konfigurasi menimpa
 *      default bawaan.
 *  12. Input target lebih fleksibel: file (-i), daftar inline (--targets),
 *      atau stdin (pipe / "-") -- otomatis terdeteksi tanpa perlu flag
 *      tambahan saat menerima input pipe.
 *  13. Retry HTTP kini juga menangani HTTP 429 (rate limited) sebagai
 *      kondisi transient, bukan hanya error koneksi.
 *  14. Exit code dibakukan untuk kebutuhan CI/CD: 0 = aman, 2 = ditemukan
 *      indikasi takeover, 1 = fatal error, 130 = dihentikan manual.
 *  15. Default INTERNAL_SUFFIXES kini kosong (bukan lagi contoh domain
 *      hardcoded) -- perilaku default lebih dapat diprediksi untuk siapa
 *      pun yang menjalankan tool ini tanpa konfigurasi tambahan.
 *
 *  Catatan: fingerprint provider berubah dari waktu ke waktu. Untuk daftar
 *  yang selalu ter-update, lihat proyek referensi publik:
 *  https://github.com/EdOverflow/can-i-take-over-xyz
 * ============================================================================
 */

const dns = require('dns');
const dnsPromises = dns.promises;
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const VERSION = '4.0.0';

// ---------------- Konfigurasi runtime (diisi dari opsi CLI/config/default) ----------------
let CONCURRENCY = 15;
let DELAY_MS = 150;
let HTTP_TIMEOUT = 7000;
let DO_HTTP_CHECK = true;
let DO_RESOLVE_A = false;
let DO_WILDCARD_CHECK = true;
let VERBOSE = false;
let QUIET = false;
let TIMESTAMPS = false;
let MAX_CNAME_DEPTH = 8;
let DNS_RETRIES = 2;
let HTTP_RETRIES = 1;
let MAX_REDIRECTS = 4;
let MAX_BODY_BYTES = 20000;
let INTERNAL_SUFFIXES = [];
let ADAPTIVE_CONCURRENCY = true;
let PROXY_URL = null;
let WEBHOOK_URL = null;
let LOG_FILE = null;
let activeResolver = dnsPromises;

const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);
const TRANSIENT_DNS_CODES = new Set(['ETIMEOUT', 'ECONNREFUSED', 'SERVFAIL', 'EAI_AGAIN', 'ECANCELLED']);
const TRANSIENT_HTTP_ERRORS = new Set(['timeout', 'ECONNRESET', 'ETIMEDOUT', 'EAI_AGAIN']);

// ---------------- Warna terminal (tanpa dependency eksternal) ----------------
const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m',
  blue: '\x1b[34m', magenta: '\x1b[35m', cyan: '\x1b[36m',
};
const useColor = process.stdout.isTTY;
const c = (code, s) => (useColor ? `${code}${s}${C.reset}` : s);

function colorForCategory(cat) {
  switch (cat) {
    case 'POTENTIAL_TAKEOVER': return C.bold + C.red;
    case 'UNREACHABLE': return C.yellow;
    case 'EXTERNAL_UNKNOWN': return C.magenta;
    case 'EXTERNAL_ACTIVE': return C.green;
    case 'WILDCARD_FALSE_POSITIVE': return C.cyan;
    case 'SKIPPED_CIRCUIT_BREAKER': return C.dim;
    case 'DNS_ERROR': case 'FATAL_ERROR': case 'INVALID_INPUT': return C.dim;
    default: return C.reset;
  }
}

// ---------------- Logging terpusat (tanpa emoji) ----------------
const LOG_TAGS = { info: '[INFO]', ok: '[ OK ]', warn: '[WARN]', error: '[ERR ]', crit: '[CRIT]', debug: '[DBG ]' };
const LOG_COLORS = { info: C.blue, ok: C.green, warn: C.yellow, error: C.red, crit: C.bold + C.red, debug: C.dim };

function log(level, msg) {
  if (level === 'debug' && !VERBOSE) return;
  if (QUIET && (level === 'info' || level === 'ok' || level === 'warn')) return;
  const tag = LOG_TAGS[level] || '[INFO]';
  const ts = TIMESTAMPS ? `${new Date().toISOString()} ` : '';
  const line = `${ts}${tag} ${msg}`;
  const stream = (level === 'error' || level === 'crit') ? console.error : console.log;
  stream(c(LOG_COLORS[level] || C.reset, line));
}

// ---------------- Fingerprint Provider (pengetahuan publik) ----------------
// Sumber: pola umum yang dipakai banyak scanner takeover open-source.
// Verifikasi ulang secara berkala, karena halaman error provider bisa berubah.
// Bisa diperluas via --fingerprints (file lokal) atau --fingerprints-url (feed jarak jauh).
const FINGERPRINTS = [
  { provider: 'AWS S3', cname: /\.s3[.-][\w-]*\.amazonaws\.com$/i, body: /NoSuchBucket/i },
  { provider: 'GitHub Pages', cname: /\.github\.io$/i, body: /There isn'?t a GitHub Pages site here/i },
  { provider: 'Heroku', cname: /herokudns\.com$|herokuapp\.com$/i, body: /No such app/i },
  { provider: 'Azure', cname: /azurewebsites\.net$|cloudapp\.azure\.com$|azureedge\.net$|trafficmanager\.net$/i, body: /404 Web Site not found/i },
  { provider: 'Shopify', cname: /myshopify\.com$/i, body: /Sorry, this shop is currently unavailable/i },
  { provider: 'Fastly', cname: /fastly\.net$/i, body: /Fastly error: unknown domain/i },
  { provider: 'Zendesk', cname: /zendesk\.com$/i, body: /Help Center Closed/i },
  { provider: 'Cargo', cname: /cargocollective\.com$/i, body: /404 Not Found/i },
  { provider: 'Tumblr', cname: /tumblr\.com$/i, body: /Whatever you were looking for, it'?s not here/i },
  { provider: 'WordPress.com', cname: /wordpress\.com$/i, body: /Do you want to register/i },
  { provider: 'Unbounce', cname: /unbouncepages\.com$/i, body: /The requested URL was not found on this server/i },
  { provider: 'Pantheon', cname: /pantheonsite\.io$/i, body: /The gods are wise/i },
  { provider: 'CloudFront', cname: /\.cloudfront\.net$/i, body: /Bad Request|ERROR: The request could not be satisfied/i },
  { provider: 'Firebase', cname: /firebaseapp\.com$/i, body: /<title>Firebase Hosting<\/title>/i },
  { provider: 'Surge.sh', cname: /surge\.sh$/i, body: /project not found/i },
  { provider: 'Netlify', cname: /netlify\.app$|netlify\.com$/i, body: /Not Found/i },
  { provider: 'Vercel', cname: /cname\.vercel-dns\.com$/i, body: /DEPLOYMENT_NOT_FOUND/i },
  { provider: 'Bitbucket', cname: /bitbucket\.org$/i, body: /Repository not found/i },
  { provider: 'Amazon ELB', cname: /elb\.amazonaws\.com$/i, body: /503 Service Temporarily Unavailable/i },
  { provider: 'Squarespace', cname: /squarespace\.com$/i, body: /Website Expired/i },
  { provider: 'Help Scout', cname: /helpscoutdocs\.com$/i, body: /No settings were found for this company/i },
  { provider: 'UserVoice', cname: /uservoice\.com$/i, body: /This UserVoice subdomain is currently available/i },
  { provider: 'Webflow', cname: /proxy\.webflow\.com$|webflow\.io$/i, body: /The page you are looking for doesn'?t exist/i },
  { provider: 'Ghost(Pro)', cname: /ghost\.io$/i, body: /The thing you were looking for is no longer here, or never was/i },
];

// ---------------- Utility ----------------
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class SimpleCache {
  constructor() { this.store = new Map(); }
  get(key) { return this.store.get(key); }
  set(key, val) { this.store.set(key, val); }
  has(key) { return this.store.has(key); }
}

const dnsCache = new SimpleCache();

function isValidHostname(host) {
  if (typeof host !== 'string' || host.length === 0 || host.length > 253) return false;
  const re = /^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$/;
  return re.test(host);
}

// Perkiraan root domain (heuristik, menangani beberapa multi-part TLD umum).
const TWO_PART_TLDS = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'net.au',
  'co.jp', 'co.id', 'go.id', 'or.id', 'com.br', 'co.nz',
]);

function getRootDomain(hostname) {
  const parts = hostname.toLowerCase().split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  const lastTwo = parts.slice(-2).join('.');
  if (TWO_PART_TLDS.has(lastTwo) && parts.length >= 3) return parts.slice(-3).join('.');
  return lastTwo;
}

/** Retry generik dengan exponential backoff + jitter, hanya untuk error transient. */
async function withRetry(fn, { retries = 2, baseDelay = 300, isTransient = () => false, label = '' } = {}) {
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (!isTransient(err) || attempt === retries) throw err;
      const delay = baseDelay * 2 ** attempt + Math.random() * 100;
      log('debug', `Retry (${label}) percobaan ${attempt + 1}/${retries} setelah ${err.code || err.message}`);
      await sleep(delay);
    }
  }
  throw lastErr;
}

// ---------------- DNS ----------------
function setupResolver(resolverList) {
  if (!resolverList || resolverList.length === 0) return dnsPromises;
  const customResolver = new dnsPromises.Resolver();
  customResolver.setServers(resolverList);
  return customResolver;
}

async function resolveCnameSafe(domain) {
  if (dnsCache.has(domain)) return dnsCache.get(domain);
  try {
    const records = await activeResolver.resolveCname(domain);
    const result = records[0] ? records[0].replace(/\.$/, '') : null;
    dnsCache.set(domain, result);
    return result;
  } catch (e) {
    if (e.code === 'ENODATA' || e.code === 'ENOTFOUND') {
      dnsCache.set(domain, null);
      return null;
    }
    throw e;
  }
}

async function resolveCnameOnceWithRetry(domain) {
  return withRetry(() => resolveCnameSafe(domain), {
    retries: DNS_RETRIES,
    isTransient: (err) => TRANSIENT_DNS_CODES.has(err.code),
    label: `CNAME ${domain}`,
  });
}

/** Mengikuti rantai CNAME sampai maxDepth atau sampai tidak ada CNAME lagi. */
async function resolveCnameChain(domain, maxDepth = MAX_CNAME_DEPTH) {
  const chain = [];
  const seen = new Set([domain.toLowerCase()]);
  let current = domain;
  for (let i = 0; i < maxDepth; i++) {
    const next = await resolveCnameOnceWithRetry(current);
    if (!next) break;
    if (seen.has(next.toLowerCase())) break; // proteksi loop CNAME
    chain.push(next);
    seen.add(next.toLowerCase());
    current = next;
  }
  return chain;
}

async function resolveCnameChainSafe(domain, maxDepth = MAX_CNAME_DEPTH) {
  try {
    return await resolveCnameChain(domain, maxDepth);
  } catch {
    return [];
  }
}

async function resolveA(domain) {
  try {
    const records = await activeResolver.resolve4(domain);
    return records.length > 0;
  } catch {
    return false;
  }
}

// ---------------- Proxy (opsional, mengikuti env HTTP_PROXY/HTTPS_PROXY atau --proxy) ----------------
function getProxyForProtocol(protocol) {
  if (PROXY_URL) return PROXY_URL;
  const envVar = protocol === 'https:'
    ? (process.env.HTTPS_PROXY || process.env.https_proxy)
    : (process.env.HTTP_PROXY || process.env.http_proxy);
  return envVar || null;
}

/** Forward request http:// polos lewat proxy HTTP standar (absolute-URI). */
function requestViaHttpProxy(targetUrlStr, proxyUrlStr) {
  return new Promise((resolve, reject) => {
    let target, proxy;
    try {
      target = new URL(targetUrlStr);
      proxy = new URL(proxyUrlStr);
    } catch (e) {
      reject(Object.assign(new Error('invalid_proxy_or_url'), { code: 'invalid_proxy_or_url' }));
      return;
    }
    let settled = false;
    const settle = (fn, val) => { if (!settled) { settled = true; fn(val); } };
    let req;
    try {
      req = http.request({
        host: proxy.hostname,
        port: proxy.port || 80,
        method: 'GET',
        path: target.toString(),
        headers: { Host: target.hostname, 'User-Agent': `subdomain-takeover-scanner/${VERSION} (+security-research)` },
        timeout: HTTP_TIMEOUT,
      }, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          if (settled) return;
          data += chunk;
          if (data.length > MAX_BODY_BYTES) {
            req.destroy();
            settle(resolve, { status: res.statusCode, headers: res.headers, body: data.slice(0, MAX_BODY_BYTES) });
          }
        });
        res.on('end', () => settle(resolve, { status: res.statusCode, headers: res.headers, body: data }));
        res.on('error', (err) => settle(reject, err));
      });
    } catch (err) {
      settle(reject, err);
      return;
    }
    req.on('timeout', () => { req.destroy(); settle(reject, Object.assign(new Error('timeout'), { code: 'timeout' })); });
    req.on('error', (err) => settle(reject, err));
    req.end();
  });
}

/** Terowongan CONNECT untuk target https:// lewat HTTP/HTTPS proxy. */
function requestViaHttpsProxyTunnel(targetUrlStr, proxyUrlStr) {
  return new Promise((resolve, reject) => {
    let target, proxy;
    try {
      target = new URL(targetUrlStr);
      proxy = new URL(proxyUrlStr);
    } catch (e) {
      reject(Object.assign(new Error('invalid_proxy_or_url'), { code: 'invalid_proxy_or_url' }));
      return;
    }
    let settled = false;
    const settle = (fn, val) => { if (!settled) { settled = true; fn(val); } };
    const targetPort = target.port || 443;

    const connectReq = http.request({
      host: proxy.hostname,
      port: proxy.port || 80,
      method: 'CONNECT',
      path: `${target.hostname}:${targetPort}`,
      timeout: HTTP_TIMEOUT,
      headers: { Host: `${target.hostname}:${targetPort}` },
    });

    connectReq.on('connect', (res, socket) => {
      if (res.statusCode !== 200) {
        socket.destroy();
        settle(reject, Object.assign(new Error(`proxy_connect_${res.statusCode}`), { code: `proxy_connect_${res.statusCode}` }));
        return;
      }
      const req = https.request({
        host: target.hostname,
        port: targetPort,
        path: target.pathname + target.search,
        method: 'GET',
        socket,
        agent: false,
        rejectUnauthorized: false,
        timeout: HTTP_TIMEOUT,
        headers: { 'User-Agent': `subdomain-takeover-scanner/${VERSION} (+security-research)` },
      }, (httpsRes) => {
        let data = '';
        httpsRes.on('data', (chunk) => {
          if (settled) return;
          data += chunk;
          if (data.length > MAX_BODY_BYTES) {
            req.destroy();
            settle(resolve, { status: httpsRes.statusCode, headers: httpsRes.headers, body: data.slice(0, MAX_BODY_BYTES) });
          }
        });
        httpsRes.on('end', () => settle(resolve, { status: httpsRes.statusCode, headers: httpsRes.headers, body: data }));
        httpsRes.on('error', (err) => settle(reject, err));
      });
      req.on('timeout', () => { req.destroy(); settle(reject, Object.assign(new Error('timeout'), { code: 'timeout' })); });
      req.on('error', (err) => settle(reject, err));
      req.end();
    });

    connectReq.on('timeout', () => { connectReq.destroy(); settle(reject, Object.assign(new Error('proxy_timeout'), { code: 'proxy_timeout' })); });
    connectReq.on('error', (err) => settle(reject, err));
    connectReq.end();
  });
}

// ---------------- HTTP ----------------
function rawRequestDirect(urlStr) {
  return new Promise((resolve, reject) => {
    let url;
    try {
      url = new URL(urlStr);
    } catch (e) {
      reject(Object.assign(new Error('invalid_url'), { code: 'invalid_url' }));
      return;
    }
    const lib = url.protocol === 'https:' ? https : http;
    let settled = false;
    const settle = (fn, val) => { if (!settled) { settled = true; fn(val); } };

    let req;
    try {
      req = lib.get(url, {
        timeout: HTTP_TIMEOUT,
        headers: { 'User-Agent': `subdomain-takeover-scanner/${VERSION} (+security-research)` },
        rejectUnauthorized: false, // resource unclaimed sering punya sertifikat TLS tidak valid
      }, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          if (settled) return;
          data += chunk;
          if (data.length > MAX_BODY_BYTES) {
            req.destroy();
            settle(resolve, { status: res.statusCode, headers: res.headers, body: data.slice(0, MAX_BODY_BYTES) });
          }
        });
        res.on('end', () => settle(resolve, { status: res.statusCode, headers: res.headers, body: data }));
        res.on('error', (err) => settle(reject, err));
      });
    } catch (err) {
      settle(reject, err);
      return;
    }

    req.on('timeout', () => { req.destroy(); settle(reject, Object.assign(new Error('timeout'), { code: 'timeout' })); });
    req.on('error', (err) => settle(reject, err));
  });
}

/** Titik masuk request mentah tunggal: otomatis lewat proxy jika dikonfigurasi. */
function rawRequest(urlStr) {
  let parsed;
  try {
    parsed = new URL(urlStr);
  } catch (e) {
    return Promise.reject(Object.assign(new Error('invalid_url'), { code: 'invalid_url' }));
  }
  const proxyUrl = getProxyForProtocol(parsed.protocol);
  if (proxyUrl) {
    return parsed.protocol === 'https:'
      ? requestViaHttpsProxyTunnel(urlStr, proxyUrl)
      : requestViaHttpProxy(urlStr, proxyUrl);
  }
  return rawRequestDirect(urlStr);
}

/** GET dengan fallback https->http dan mengikuti redirect. Selalu resolve (tidak pernah reject). */
async function httpGet(hostname) {
  let lastError = null;
  for (const proto of ['https:', 'http:']) {
    let currentUrl = `${proto}//${hostname}/`;
    try {
      for (let hop = 0; hop < MAX_REDIRECTS; hop++) {
        const res = await rawRequest(currentUrl);
        if (REDIRECT_CODES.has(res.status) && res.headers.location) {
          currentUrl = new URL(res.headers.location, currentUrl).toString();
          continue;
        }
        return { ok: true, status: res.status, body: res.body };
      }
      return { ok: false, error: 'too_many_redirects' };
    } catch (err) {
      lastError = err;
      // coba protokol berikutnya
    }
  }
  return { ok: false, error: (lastError && (lastError.code || lastError.message)) || 'connection_error' };
}

/** Retry HTTP untuk error transient DAN untuk HTTP 429 (rate limited). */
async function httpGetWithRetry(hostname) {
  let result = await httpGet(hostname);
  let attempt = 0;
  while (attempt < HTTP_RETRIES) {
    const isRateLimited = result.ok && result.status === 429;
    const isTransientError = !result.ok && TRANSIENT_HTTP_ERRORS.has(result.error);
    if (!isRateLimited && !isTransientError) break;
    attempt++;
    const wait = 300 * attempt + Math.random() * 100;
    log('debug', `Retry HTTP (${hostname}) percobaan ${attempt}/${HTTP_RETRIES} (${isRateLimited ? 'HTTP 429' : result.error})`);
    await sleep(wait);
    result = await httpGet(hostname);
  }
  return result;
}

/** Fetch generik untuk URL lengkap (dipakai untuk mengambil feed fingerprint jarak jauh). */
async function fetchUrl(urlStr) {
  let currentUrl = urlStr;
  for (let hop = 0; hop < MAX_REDIRECTS; hop++) {
    const res = await rawRequest(currentUrl);
    if (REDIRECT_CODES.has(res.status) && res.headers.location) {
      currentUrl = new URL(res.headers.location, currentUrl).toString();
      continue;
    }
    if (res.status < 200 || res.status >= 300) {
      throw Object.assign(new Error(`http_status_${res.status}`), { status: res.status });
    }
    return res.body;
  }
  throw new Error('too_many_redirects');
}

// ---------------- Wildcard DNS detection ----------------
/**
 * Beberapa domain memakai wildcard DNS (*.domain.com -> satu server catch-all).
 * Tanpa deteksi ini, SEMUA subdomain acak akan "resolve" dan berpotensi
 * memicu false positive POTENTIAL_TAKEOVER secara massal. Kita uji dengan
 * label acak per root-domain sebelum scanning dimulai.
 */
async function buildWildcardMap(subdomains) {
  const map = new Map();
  if (!DO_WILDCARD_CHECK) return map;

  const roots = [...new Set(subdomains.map(getRootDomain).filter((r) => r && r.includes('.')))];
  for (const root of roots) {
    const probe = `wc-${crypto.randomBytes(4).toString('hex')}.${root}`;
    try {
      const chain = await resolveCnameChainSafe(probe);
      const hasA = chain.length === 0 ? await resolveA(probe) : false;
      if (chain.length === 0 && !hasA) continue; // tidak ada wildcard DNS untuk root ini

      let body = null;
      if (DO_HTTP_CHECK) {
        const resp = await httpGet(probe);
        if (resp.ok) body = resp.body;
      }
      map.set(root, { cnameChain: chain, body });
      log('warn', `Wildcard DNS terdeteksi pada *.${root} -- hasil akan difilter dari false positive.`);
    } catch {
      // probe gagal, anggap tidak ada wildcard untuk root ini
    }
  }
  return map;
}

// ---------------- Circuit breaker per root-domain ----------------
function createCircuitBreaker(threshold) {
  const state = new Map();
  return {
    isTripped(root) {
      const s = state.get(root);
      return !!(s && s.tripped);
    },
    record(root, isFailure) {
      if (!root) return;
      const s = state.get(root) || { fails: 0, tripped: false };
      if (isFailure) {
        s.fails += 1;
        if (s.fails >= threshold && !s.tripped) {
          s.tripped = true;
          log('warn', `Circuit breaker aktif untuk root domain "${root}" setelah ${s.fails} kegagalan berturut-turut. Sisa subdomain di root ini akan dilewati otomatis.`);
        }
      } else {
        s.fails = 0;
      }
      state.set(root, s);
    },
  };
}

// ---------------- Notifikasi & logging otomatis ----------------
function sendWebhookNotification(webhookUrl, payload) {
  try {
    const u = new URL(webhookUrl);
    const lib = u.protocol === 'https:' ? https : http;
    const data = JSON.stringify(payload);
    const req = lib.request(u, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
      timeout: 5000,
    }, (res) => { res.resume(); });
    req.on('error', () => { /* webhook bersifat best-effort */ });
    req.on('timeout', () => req.destroy());
    req.write(data);
    req.end();
  } catch {
    // Kegagalan webhook tidak boleh menghentikan proses scanning utama.
  }
}

function appendJsonLog(logFilePath, event) {
  try {
    const line = `${JSON.stringify({ ts: new Date().toISOString(), ...event })}\n`;
    fs.appendFileSync(logFilePath, line, 'utf-8');
  } catch {
    // Kegagalan logging tidak boleh menghentikan proses scanning utama.
  }
}

// ---------------- Core analysis ----------------
async function analyzeSubdomain(subdomain, wildcardMap) {
  const result = {
    subdomain, cname: null, cnameChain: [], hasARecord: false,
    category: 'UNKNOWN', provider: '', confidence: null, httpStatus: null, detail: '',
  };

  if (!isValidHostname(subdomain)) {
    result.category = 'INVALID_INPUT';
    result.detail = 'Format hostname tidak valid, dilewati.';
    return result;
  }

  let chain;
  try {
    chain = await resolveCnameChain(subdomain);
  } catch (err) {
    result.category = 'DNS_ERROR';
    result.detail = `DNS error: ${err.code || err.message}`;
    return result;
  }

  result.cnameChain = chain;
  result.cname = chain[0] || null;
  const finalTarget = chain.length ? chain[chain.length - 1] : null;

  if (!finalTarget) {
    if (DO_RESOLVE_A) {
      result.hasARecord = await resolveA(subdomain);
      result.category = result.hasARecord ? 'NO_CNAME_BUT_ALIVE' : 'NO_CNAME';
      result.detail = result.hasARecord
        ? 'Tidak ada CNAME tapi punya A record, mungkin masih aktif.'
        : 'Tidak ada CNAME maupun A record.';
    } else {
      result.category = 'NO_CNAME';
      result.detail = 'Tidak ada CNAME (gunakan --resolve-a untuk cek A record).';
    }
    return result;
  }

  if (INTERNAL_SUFFIXES.some((suf) => suf && finalTarget.toLowerCase().endsWith(suf.toLowerCase()))) {
    result.category = 'INTERNAL';
    result.detail = `CNAME mengarah ke domain internal (${finalTarget}), bukan pihak ketiga.`;
    return result;
  }

  const match = FINGERPRINTS.find((fp) => fp.cname.test(finalTarget));
  if (!match) {
    result.category = 'EXTERNAL_UNKNOWN';
    result.confidence = 'LOW';
    result.detail = `Rantai CNAME berakhir di ${finalTarget}, provider tidak dikenali. Perlu investigasi manual.`;
    return result;
  }
  result.provider = match.provider;

  if (!DO_HTTP_CHECK) {
    result.category = 'EXTERNAL_KNOWN';
    result.detail = `CNAME ke ${match.provider} (${finalTarget}), HTTP check dimatikan.`;
    return result;
  }

  const resp = await httpGetWithRetry(subdomain);
  if (!resp.ok) {
    result.category = 'UNREACHABLE';
    result.confidence = 'MEDIUM';
    result.detail = `CNAME ke ${match.provider}, tapi subdomain tidak bisa diakses (${resp.error || 'tidak merespon'}). Ini bisa jadi indikasi kuat takeover -- cek manual.`;
    return result;
  }
  result.httpStatus = resp.status;

  const wc = wildcardMap.get(getRootDomain(subdomain));
  if (wc && wc.body !== null && resp.body === wc.body) {
    result.category = 'WILDCARD_FALSE_POSITIVE';
    result.detail = 'Response identik dengan wildcard control test root domain ini -- kemungkinan besar false positive.';
    return result;
  }

  if (match.body.test(resp.body)) {
    result.category = 'POTENTIAL_TAKEOVER';
    result.confidence = 'HIGH';
    result.detail = `CNAME ke ${match.provider} (HTTP ${resp.status}), body cocok dengan fingerprint unclaimed resource. WAJIB verifikasi manual sebelum melapor.`;
  } else {
    result.category = 'EXTERNAL_ACTIVE';
    result.detail = `CNAME ke ${match.provider} (HTTP ${resp.status}), resource tampak masih diklaim.`;
  }
  return result;
}

// ---------------- Progress display ----------------
function formatTime(ms) {
  if (ms < 1000) return `${Math.round(ms)}ms`;
  const sec = Math.floor(ms / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  return `${min}m ${sec % 60}s`;
}

function drawProgress(current, total, startTime) {
  const elapsed = Date.now() - startTime;
  const pct = total > 0 ? (current / total) * 100 : 100;
  const rate = current / ((elapsed || 1) / 1000);
  const eta = rate > 0 ? ((total - current) / rate) * 1000 : 0;
  const barWidth = 24;
  const filled = Math.min(barWidth, Math.round((pct / 100) * barWidth));
  const bar = '#'.repeat(filled) + '-'.repeat(barWidth - filled);

  if (process.stdout.isTTY) {
    process.stdout.write(`\r[${bar}] ${current}/${total} (${pct.toFixed(1)}%) | ${formatTime(elapsed)} elapsed | ETA ${formatTime(eta)}   `);
  } else if (current === total || current % 25 === 0) {
    log('info', `Progress: ${current}/${total} (${pct.toFixed(1)}%)`);
  }
}

// ---------------- Worker pool (adaptive concurrency + circuit breaker) ----------------
/**
 * Dynamic worker pool: jumlah worker aktif menyesuaikan diri secara otomatis
 * berdasarkan tingkat kegagalan pada jendela permintaan terakhir. Setiap task
 * dibungkus try/catch supaya satu kegagalan tidak menjatuhkan seluruh proses.
 * Task yang root domain-nya sudah "tripped" oleh circuit breaker dilewati
 * tanpa request jaringan sama sekali.
 */
async function runPool(items, workerFn, resultsSink, opts = {}) {
  const {
    indices = items.map((_, i) => i),
    onProgress,
    onCheckpoint,
    checkpointEvery = 20,
    circuitBreaker = null,
  } = opts;

  const total = indices.length;
  if (total === 0) return;

  const startTime = Date.now();
  let ptr = 0;
  let completed = 0;
  let activeWorkers = 0;
  let currentConcurrency = Math.max(1, Math.min(CONCURRENCY, total));

  const window = [];
  const WINDOW_SIZE = 30;
  const FAILURE_CATS = new Set(['UNREACHABLE', 'DNS_ERROR', 'FATAL_ERROR']);

  function recordOutcome(isFailure) {
    if (!ADAPTIVE_CONCURRENCY) return;
    window.push(isFailure);
    if (window.length > WINDOW_SIZE) window.shift();
    if (window.length < 10) return;
    const failRate = window.filter(Boolean).length / window.length;
    if (failRate > 0.4 && currentConcurrency > 1) {
      const next = Math.max(1, Math.floor(currentConcurrency / 2));
      if (next !== currentConcurrency) {
        currentConcurrency = next;
        log('warn', `Adaptive throttling: concurrency diturunkan otomatis ke ${currentConcurrency} (fail rate ${(failRate * 100).toFixed(0)}%).`);
      }
    } else if (failRate < 0.1 && currentConcurrency < CONCURRENCY) {
      currentConcurrency += 1;
    }
  }

  return new Promise((resolveAll) => {
    async function runOne(idx) {
      const item = items[idx];
      const root = getRootDomain(item);
      let res;

      if (circuitBreaker && circuitBreaker.isTripped(root)) {
        res = {
          subdomain: item, cname: null, cnameChain: [], hasARecord: false,
          category: 'SKIPPED_CIRCUIT_BREAKER', provider: '', confidence: null, httpStatus: null,
          detail: `Dilewati otomatis oleh circuit breaker: terlalu banyak kegagalan berturut-turut pada root domain "${root}".`,
        };
      } else {
        try {
          res = await workerFn(item);
        } catch (err) {
          res = {
            subdomain: item, cname: null, cnameChain: [], hasARecord: false,
            category: 'FATAL_ERROR', provider: '', confidence: null, httpStatus: null,
            detail: `Unhandled error: ${err && err.message}`,
          };
        }
        if (circuitBreaker) circuitBreaker.record(root, FAILURE_CATS.has(res.category));
      }

      resultsSink[idx] = res;
      completed += 1;
      recordOutcome(FAILURE_CATS.has(res.category));

      if (VERBOSE) {
        const color = colorForCategory(res.category);
        log('debug', `${c(color, `[${res.category}]`)} ${res.subdomain}${res.cname ? ` -> ${res.cname}` : ''}`);
      }
      if (res.category === 'POTENTIAL_TAKEOVER' && WEBHOOK_URL) {
        sendWebhookNotification(WEBHOOK_URL, { event: 'potential_takeover', ...res, scannedAt: new Date().toISOString() });
      }
      if (LOG_FILE) {
        appendJsonLog(LOG_FILE, res);
      }
      if (onProgress) onProgress(completed, total, startTime);
      if (onCheckpoint && completed % checkpointEvery === 0) onCheckpoint();
      if (DELAY_MS > 0) await sleep(DELAY_MS);
    }

    function spawnMore() {
      while (activeWorkers < currentConcurrency && ptr < total) {
        activeWorkers += 1;
        const idx = indices[ptr];
        ptr += 1;
        runOne(idx).finally(() => {
          activeWorkers -= 1;
          if (completed >= total) {
            resolveAll();
          } else {
            spawnMore();
          }
        });
      }
    }

    spawnMore();
  });
}

// ---------------- Checkpoint / resume ----------------
function computeInputHash(list) {
  const h = crypto.createHash('sha256');
  h.update([...list].sort().join('\n'));
  return h.digest('hex');
}

function checkpointPathFor(outputPrefix) {
  return `${outputPrefix}.checkpoint.json`;
}

function saveCheckpoint(cpPath, inputHash, results) {
  try {
    const payload = { inputHash, savedAt: new Date().toISOString(), results };
    fs.writeFileSync(cpPath, JSON.stringify(payload), 'utf-8');
  } catch (err) {
    log('warn', `Gagal menyimpan checkpoint: ${err.message}`);
  }
}

function loadCheckpoint(cpPath) {
  try {
    if (!fs.existsSync(cpPath)) return null;
    return JSON.parse(fs.readFileSync(cpPath, 'utf-8'));
  } catch {
    return null;
  }
}

// ---------------- Output functions ----------------
function csvEscape(v) {
  return `"${String(v == null ? '' : v).replace(/"/g, '""')}"`;
}

function generateCsv(results) {
  const header = 'subdomain,cname,cname_chain,category,provider,confidence,http_status,detail\n';
  return header + results.map((r) => [
    csvEscape(r.subdomain),
    csvEscape(r.cname),
    csvEscape((r.cnameChain || []).join(' -> ')),
    csvEscape(r.category),
    csvEscape(r.provider),
    csvEscape(r.confidence),
    csvEscape(r.httpStatus),
    csvEscape(r.detail),
  ].join(',')).join('\n');
}

const CATEGORY_PRIORITY = [
  'POTENTIAL_TAKEOVER', 'UNREACHABLE', 'EXTERNAL_UNKNOWN', 'WILDCARD_FALSE_POSITIVE',
  'EXTERNAL_ACTIVE', 'EXTERNAL_KNOWN', 'INTERNAL', 'NO_CNAME_BUT_ALIVE', 'NO_CNAME',
  'DNS_ERROR', 'SKIPPED_CIRCUIT_BREAKER', 'INVALID_INPUT', 'FATAL_ERROR', 'UNKNOWN',
];

function sortedCategoryStats(results) {
  const stats = {};
  results.forEach((r) => { stats[r.category] = (stats[r.category] || 0) + 1; });
  return Object.entries(stats).sort((a, b) => {
    const pa = CATEGORY_PRIORITY.indexOf(a[0]);
    const pb = CATEGORY_PRIORITY.indexOf(b[0]);
    return (pa === -1 ? 999 : pa) - (pb === -1 ? 999 : pb);
  });
}

function generateSummary(results, meta = {}) {
  let out = '';
  out += 'SUBDOMAIN TAKEOVER SCAN -- RINGKASAN\n';
  out += '====================================\n';
  if (meta.startedAt) out += `Waktu mulai   : ${meta.startedAt}\n`;
  if (meta.durationMs != null) out += `Durasi        : ${formatTime(meta.durationMs)}\n`;
  out += `Total target  : ${results.length}\n\n`;
  out += 'KATEGORI                     JUMLAH\n';
  out += '------------------------------------\n';
  for (const [cat, cnt] of sortedCategoryStats(results)) {
    out += `${cat.padEnd(29)} ${cnt}\n`;
  }
  return out;
}

function generateMarkdown(results, meta = {}) {
  let md = '# Laporan Subdomain Takeover Scan\n\n';
  md += `- **Waktu mulai:** ${meta.startedAt || '-'}\n`;
  md += `- **Durasi:** ${meta.durationMs != null ? formatTime(meta.durationMs) : '-'}\n`;
  md += `- **Total target:** ${results.length}\n\n`;
  md += '## Ringkasan per kategori\n\n| Kategori | Jumlah |\n|---|---|\n';
  for (const [cat, cnt] of sortedCategoryStats(results)) md += `| ${cat} | ${cnt} |\n`;

  const takeover = results.filter((r) => r.category === 'POTENTIAL_TAKEOVER');
  md += `\n## Potensi Takeover (${takeover.length})\n\n`;
  if (takeover.length === 0) {
    md += 'Tidak ditemukan indikasi subdomain takeover.\n';
  } else {
    md += '| Subdomain | CNAME chain | Provider | Confidence | HTTP | Detail |\n|---|---|---|---|---|---|\n';
    for (const r of takeover) {
      md += `| ${r.subdomain} | ${(r.cnameChain || []).join(' -> ')} | ${r.provider} | ${r.confidence || '-'} | ${r.httpStatus || '-'} | ${r.detail} |\n`;
    }
  }
  md += '\n> Semua temuan wajib diverifikasi manual sebelum dilaporkan melalui program VDP resmi.\n';
  return md;
}

function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function generateHtml(results, meta = {}) {
  const stats = sortedCategoryStats(results);
  const takeover = results.filter((r) => r.category === 'POTENTIAL_TAKEOVER');

  const rows = results.map((r) => `
    <tr>
      <td>${escapeHtml(r.subdomain)}</td>
      <td>${escapeHtml((r.cnameChain || []).join(' -> '))}</td>
      <td><span class="badge badge-${escapeHtml(r.category)}">${escapeHtml(r.category)}</span></td>
      <td>${escapeHtml(r.provider)}</td>
      <td>${escapeHtml(r.confidence || '-')}</td>
      <td>${escapeHtml(r.httpStatus)}</td>
      <td>${escapeHtml(r.detail)}</td>
    </tr>`).join('');

  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Laporan Subdomain Takeover Scan</title>
<style>
  :root { color-scheme: dark; }
  body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 2rem; background: #0f1115; color: #e6e6e6; }
  h1 { font-size: 1.4rem; margin-bottom: 0.25rem; }
  .meta { color: #9aa0a6; font-size: 0.85rem; margin-bottom: 1.5rem; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 2rem; font-size: 0.85rem; }
  th, td { padding: 0.5rem 0.75rem; border-bottom: 1px solid #2a2e35; text-align: left; vertical-align: top; }
  th { background: #1a1d23; position: sticky; top: 0; }
  tr:hover { background: #1a1d23; }
  .badge { padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; white-space: nowrap; }
  .badge-POTENTIAL_TAKEOVER { background: #4d1a1a; color: #ff6b6b; }
  .badge-UNREACHABLE { background: #4d3a1a; color: #ffcc66; }
  .badge-EXTERNAL_UNKNOWN { background: #3a1a4d; color: #cc99ff; }
  .badge-EXTERNAL_ACTIVE { background: #1a4d24; color: #6bff8f; }
  .badge-WILDCARD_FALSE_POSITIVE { background: #1a3a4d; color: #66d9ff; }
  .badge-SKIPPED_CIRCUIT_BREAKER { background: #2a2a2a; color: #999999; }
  .summary-cards { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
  .card { background: #1a1d23; border: 1px solid #2a2e35; border-radius: 8px; padding: 1rem 1.25rem; min-width: 140px; }
  .card .n { font-size: 1.6rem; font-weight: 700; }
  .card .l { font-size: 0.75rem; color: #9aa0a6; text-transform: uppercase; letter-spacing: 0.04em; }
  .warn-banner { background: #4d1a1a; color: #ff9b9b; padding: 0.75rem 1rem; border-radius: 6px; margin-bottom: 1.5rem; font-size: 0.9rem; }
  footer { color: #9aa0a6; font-size: 0.8rem; }
</style>
</head>
<body>
  <h1>Laporan Subdomain Takeover Scan</h1>
  <div class="meta">
    Waktu mulai: ${escapeHtml(meta.startedAt || '-')} &middot;
    Durasi: ${escapeHtml(meta.durationMs != null ? formatTime(meta.durationMs) : '-')} &middot;
    Total target: ${results.length}
  </div>

  ${takeover.length > 0 ? `<div class="warn-banner">Ditemukan ${takeover.length} indikasi potensi subdomain takeover. Wajib diverifikasi manual sebelum dilaporkan melalui program VDP resmi.</div>` : ''}

  <div class="summary-cards">
    ${stats.map(([cat, cnt]) => `<div class="card"><div class="n">${cnt}</div><div class="l">${escapeHtml(cat)}</div></div>`).join('')}
  </div>

  <table>
    <thead><tr><th>Subdomain</th><th>CNAME Chain</th><th>Kategori</th><th>Provider</th><th>Confidence</th><th>HTTP</th><th>Detail</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>

  <footer>Dihasilkan otomatis oleh Subdomain Takeover Scanner v${VERSION}. Alat ini hanya melakukan deteksi pasif, bukan eksploitasi.</footer>
</body>
</html>`;
}

function loadExtraFingerprints(filePath) {
  const raw = fs.readFileSync(filePath, 'utf-8');
  const arr = JSON.parse(raw);
  if (!Array.isArray(arr)) throw new Error('File fingerprint harus berupa JSON array.');
  return arr.map((f) => ({
    provider: f.provider,
    cname: new RegExp(f.cname, 'i'),
    body: new RegExp(f.body, 'i'),
  }));
}

async function fetchRemoteFingerprints(url) {
  const body = await fetchUrl(url);
  let arr;
  try {
    arr = JSON.parse(body);
  } catch (e) {
    throw new Error(`Response dari ${url} bukan JSON yang valid.`);
  }
  if (!Array.isArray(arr)) throw new Error('Fingerprint feed harus berupa JSON array.');
  return arr.map((f) => ({
    provider: f.provider,
    cname: new RegExp(f.cname, 'i'),
    body: new RegExp(f.body, 'i'),
  }));
}

// ---------------- Konfigurasi: default, CLI, dan file config ----------------
const DEFAULT_OPTIONS = {
  input: null,
  targetsInline: null,
  outputPrefix: 'report',
  concurrency: 15,
  delay: 150,
  timeout: 7000,
  httpCheck: true,
  resolveA: false,
  wildcardCheck: true,
  verbose: false,
  quiet: false,
  timestamps: false,
  internalSuffixes: [],
  maxCnameDepth: 8,
  dnsRetries: 2,
  httpRetries: 1,
  fingerprintsFile: null,
  fingerprintsUrl: null,
  markdown: false,
  html: false,
  resolvers: null,
  proxy: null,
  webhook: null,
  logFile: null,
  resume: false,
  checkpointEvery: 20,
  adaptiveConcurrency: true,
  circuitBreakerThreshold: 8,
  configFile: null,
};

const HELP_TEXT = `
Subdomain Takeover Scanner v${VERSION}

Alat recon pasif untuk mendeteksi kandidat subdomain takeover. Tidak melakukan
eksploitasi apa pun -- hanya deteksi, korelasi fingerprint, dan pelaporan.

Penggunaan:
  node cname-checker.js -i <file> [opsi]
  cat subdomains.txt | node cname-checker.js [opsi]

Input target:
  -i, --input <file>          File daftar subdomain (satu per baris). Gunakan "-" untuk stdin.
      --targets <a,b,c>       Daftar subdomain inline, dipisahkan koma.
                              Jika tidak ada -i/--targets dan stdin di-pipe, tool otomatis membacanya.

Output:
  -o, --output <prefix>       Prefix nama file laporan (default: "report").
      --markdown              Tulis juga laporan Markdown (.md).
      --html                  Tulis juga laporan HTML mandiri (.html).
      --log-file <file>       Tulis log terstruktur JSON Lines (satu event per baris).
      --webhook <url>         Kirim notifikasi HTTP POST (JSON) tiap kali POTENTIAL_TAKEOVER ditemukan.

Kinerja & keandalan:
  -c, --concurrency <n>       Jumlah worker paralel maksimum (default: 15).
      --no-adaptive-concurrency
                              Matikan penyesuaian concurrency otomatis berdasarkan tingkat kegagalan.
  -d, --delay <ms>            Jeda antar request per worker (default: 150).
  -t, --timeout <ms>          Timeout HTTP per request (default: 7000).
      --dns-retries <n>       Jumlah retry DNS untuk error sementara (default: 2).
      --http-retries <n>      Jumlah retry HTTP untuk error sementara & HTTP 429 (default: 1).
      --circuit-breaker-threshold <n>
                              Kegagalan beruntun per root domain sebelum sisanya dilewati otomatis (default: 8).
      --resume                Lanjutkan dari checkpoint jika scan sebelumnya terhenti.
      --checkpoint-every <n>  Simpan checkpoint tiap n target selesai (default: 20).

Deteksi:
      --no-http               Matikan HTTP check (hanya cek DNS).
      --resolve-a             Cek A record saat tidak ada CNAME.
      --no-wildcard-check     Matikan deteksi wildcard DNS.
      --internal-suffix <s>   Suffix domain internal (bisa diulang beberapa kali).
      --max-cname-depth <n>   Kedalaman maksimum rantai CNAME (default: 8).
      --fingerprints <file>   Tambahkan fingerprint provider dari file JSON lokal.
      --fingerprints-url <u>  Tambahkan fingerprint provider dari feed JSON jarak jauh.

Jaringan:
      --resolver <ip1,ip2>    DNS resolver kustom (mis. 1.1.1.1,8.8.8.8) menggantikan resolver sistem.
      --proxy <url>           HTTP/HTTPS proxy untuk semua request (juga menghormati env HTTP_PROXY/HTTPS_PROXY).

Lain-lain:
      --config <file.json>    Muat opsi dari file konfigurasi JSON (opsi CLI menimpa opsi dari config).
      --timestamps            Tampilkan timestamp ISO 8601 pada tiap baris log.
  -v, --verbose                Tampilkan detail tiap subdomain saat diproses.
  -q, --quiet                  Kurangi output non-esensial.
  -h, --help                   Tampilkan bantuan ini.

Kode keluar:
  0    Selesai, tidak ada indikasi takeover.
  1    Fatal error (input tidak valid, config gagal dimuat, dsb).
  2    Selesai, ditemukan >=1 indikasi POTENTIAL_TAKEOVER (berguna sebagai gate CI/CD).
  130  Dihentikan manual (SIGINT/SIGTERM); laporan parsial tetap disimpan.

Catatan: alat ini hanya melakukan deteksi pasif. Selalu verifikasi manual sebelum
melaporkan lewat program VDP/bug bounty resmi.
`;

function requireIntArg(label, val) {
  const n = parseInt(val, 10);
  if (Number.isNaN(n) || n < 0) {
    console.error(`[ERR ] Nilai tidak valid untuk ${label}: "${val}"`);
    process.exit(1);
  }
  return n;
}

function parseArgs(argv) {
  const cli = {};
  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case '-i': case '--input': cli.input = argv[++i]; break;
      case '--targets': cli.targetsInline = argv[++i]; break;
      case '-o': case '--output': cli.outputPrefix = argv[++i]; break;
      case '-c': case '--concurrency': cli.concurrency = requireIntArg('--concurrency', argv[++i]); break;
      case '-d': case '--delay': cli.delay = requireIntArg('--delay', argv[++i]); break;
      case '-t': case '--timeout': cli.timeout = requireIntArg('--timeout', argv[++i]); break;
      case '--no-http': cli.httpCheck = false; break;
      case '--resolve-a': cli.resolveA = true; break;
      case '--no-wildcard-check': cli.wildcardCheck = false; break;
      case '--internal-suffix':
        cli.internalSuffixes = cli.internalSuffixes || [];
        cli.internalSuffixes.push(argv[++i]);
        break;
      case '--max-cname-depth': cli.maxCnameDepth = requireIntArg('--max-cname-depth', argv[++i]); break;
      case '--dns-retries': cli.dnsRetries = requireIntArg('--dns-retries', argv[++i]); break;
      case '--http-retries': cli.httpRetries = requireIntArg('--http-retries', argv[++i]); break;
      case '--fingerprints': cli.fingerprintsFile = argv[++i]; break;
      case '--fingerprints-url': cli.fingerprintsUrl = argv[++i]; break;
      case '--markdown': cli.markdown = true; break;
      case '--html': cli.html = true; break;
      case '--resolver':
        cli.resolvers = argv[++i].split(',').map((s) => s.trim()).filter(Boolean);
        break;
      case '--proxy': cli.proxy = argv[++i]; break;
      case '--webhook': cli.webhook = argv[++i]; break;
      case '--log-file': cli.logFile = argv[++i]; break;
      case '--resume': cli.resume = true; break;
      case '--checkpoint-every': cli.checkpointEvery = requireIntArg('--checkpoint-every', argv[++i]); break;
      case '--no-adaptive-concurrency': cli.adaptiveConcurrency = false; break;
      case '--circuit-breaker-threshold': cli.circuitBreakerThreshold = requireIntArg('--circuit-breaker-threshold', argv[++i]); break;
      case '--config': cli.configFile = argv[++i]; break;
      case '--timestamps': cli.timestamps = true; break;
      case '-v': case '--verbose': cli.verbose = true; break;
      case '-q': case '--quiet': cli.quiet = true; break;
      case '-h': case '--help': console.log(HELP_TEXT); process.exit(0); break;
      default:
        console.error(`[ERR ] Opsi tidak dikenal: ${argv[i]}`);
        console.log(HELP_TEXT);
        process.exit(1);
    }
  }
  return cli;
}

function loadConfigFile(filePath) {
  const raw = fs.readFileSync(path.resolve(filePath), 'utf-8');
  const parsed = JSON.parse(raw);
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('File konfigurasi harus berupa JSON object.');
  }
  return parsed;
}

function mergeOptions(defaults, config, cli) {
  return { ...defaults, ...config, ...cli };
}

function readTargets(opts) {
  let raw;
  if (opts.targetsInline) {
    raw = opts.targetsInline.split(',').join('\n');
  } else if (opts.input) {
    if (opts.input === '-') {
      raw = fs.readFileSync(0, 'utf-8');
    } else {
      const inputPath = path.resolve(opts.input);
      if (!fs.existsSync(inputPath)) {
        console.error(`[ERR ] File ${inputPath} tidak ditemukan.`);
        process.exit(1);
      }
      raw = fs.readFileSync(inputPath, 'utf-8');
    }
  } else {
    raw = fs.readFileSync(0, 'utf-8');
  }
  return raw.split('\n').map((s) => s.trim()).filter((s) => s.length > 0 && !s.startsWith('#'));
}

// ---------------- Finalize & write reports (dipakai di akhir normal & saat shutdown) ----------------
function finalizeAndWrite(results, opts, meta = {}) {
  const cleanResults = results.filter(Boolean);
  const prefix = opts.outputPrefix + (meta.partial ? '_PARTIAL' : '');
  const csvOut = `${prefix}.csv`;
  const jsonOut = `${prefix}.json`;
  const takeoverOut = `${prefix}_takeover.txt`;
  const summaryOut = `${prefix}_summary.txt`;

  fs.writeFileSync(csvOut, generateCsv(cleanResults), 'utf-8');
  fs.writeFileSync(jsonOut, JSON.stringify(cleanResults, null, 2), 'utf-8');
  fs.writeFileSync(summaryOut, generateSummary(cleanResults, meta), 'utf-8');

  const takeoverList = cleanResults.filter((r) => r.category === 'POTENTIAL_TAKEOVER');
  fs.writeFileSync(
    takeoverOut,
    takeoverList.map((r) => `${r.subdomain} -> ${(r.cnameChain || []).join(' -> ')} (${r.provider}, confidence: ${r.confidence || '-'})`).join('\n'),
    'utf-8',
  );

  let mdOut = null;
  if (opts.markdown) {
    mdOut = `${prefix}.md`;
    fs.writeFileSync(mdOut, generateMarkdown(cleanResults, meta), 'utf-8');
  }

  let htmlOut = null;
  if (opts.html) {
    htmlOut = `${prefix}.html`;
    fs.writeFileSync(htmlOut, generateHtml(cleanResults, meta), 'utf-8');
  }

  log('info', 'Laporan disimpan sebagai:');
  log('info', `  CSV       : ${path.resolve(csvOut)}`);
  log('info', `  JSON      : ${path.resolve(jsonOut)}`);
  log('info', `  Ringkasan : ${path.resolve(summaryOut)}`);
  log('info', `  Takeover  : ${path.resolve(takeoverOut)}`);
  if (mdOut) log('info', `  Markdown  : ${path.resolve(mdOut)}`);
  if (htmlOut) log('info', `  HTML      : ${path.resolve(htmlOut)}`);

  console.log(`\n${generateSummary(cleanResults, meta)}`);

  if (takeoverList.length > 0) {
    log('crit', `Ditemukan ${takeoverList.length} potensi subdomain takeover. Verifikasi manual & laporkan lewat program VDP yang sesuai.`);
    takeoverList.forEach((r) => console.log(`   - ${r.subdomain} -> ${(r.cnameChain || []).join(' -> ')} (${r.provider}, confidence: ${r.confidence || '-'})`));
  } else {
    log('ok', 'Tidak ditemukan indikasi subdomain takeover.');
  }
}

// ---------------- MAIN ----------------
async function main() {
  const cli = parseArgs(process.argv.slice(2));

  let config = {};
  if (cli.configFile) {
    try {
      config = loadConfigFile(cli.configFile);
    } catch (err) {
      console.error(`[ERR ] Gagal memuat file konfigurasi: ${err.message}`);
      process.exit(1);
    }
  }

  const opts = mergeOptions(DEFAULT_OPTIONS, config, cli);

  // Terapkan opsi ke variabel konfigurasi global modul.
  CONCURRENCY = opts.concurrency;
  DELAY_MS = opts.delay;
  HTTP_TIMEOUT = opts.timeout;
  DO_HTTP_CHECK = opts.httpCheck;
  DO_RESOLVE_A = opts.resolveA;
  DO_WILDCARD_CHECK = opts.wildcardCheck;
  VERBOSE = opts.verbose;
  QUIET = opts.quiet;
  TIMESTAMPS = opts.timestamps;
  MAX_CNAME_DEPTH = opts.maxCnameDepth;
  DNS_RETRIES = opts.dnsRetries;
  HTTP_RETRIES = opts.httpRetries;
  INTERNAL_SUFFIXES = opts.internalSuffixes || [];
  ADAPTIVE_CONCURRENCY = opts.adaptiveConcurrency;
  PROXY_URL = opts.proxy;
  WEBHOOK_URL = opts.webhook;
  LOG_FILE = opts.logFile ? path.resolve(opts.logFile) : null;

  activeResolver = setupResolver(opts.resolvers);

  if (opts.fingerprintsFile) {
    try {
      const extra = loadExtraFingerprints(path.resolve(opts.fingerprintsFile));
      FINGERPRINTS.push(...extra);
      log('info', `Memuat ${extra.length} fingerprint tambahan dari file ${opts.fingerprintsFile}.`);
    } catch (err) {
      console.error(`[ERR ] Gagal memuat file fingerprint: ${err.message}`);
      process.exit(1);
    }
  }

  if (opts.fingerprintsUrl) {
    try {
      const extra = await fetchRemoteFingerprints(opts.fingerprintsUrl);
      FINGERPRINTS.push(...extra);
      log('info', `Memuat ${extra.length} fingerprint tambahan dari feed ${opts.fingerprintsUrl}.`);
    } catch (err) {
      console.error(`[ERR ] Gagal memuat fingerprint feed: ${err.message}`);
      process.exit(1);
    }
  }

  if (!opts.input && !opts.targetsInline && process.stdin.isTTY) {
    console.error('[ERR ] Parameter -i <file>, --targets <daftar>, atau input via stdin (pipe) wajib diberikan.\n');
    console.log(HELP_TEXT);
    process.exit(1);
  }

  // Pastikan direktori output (untuk laporan, checkpoint, dan log file) tersedia.
  for (const p of [opts.outputPrefix, LOG_FILE].filter(Boolean)) {
    const dir = path.dirname(path.resolve(p));
    try {
      fs.mkdirSync(dir, { recursive: true });
    } catch (err) {
      console.error(`[ERR ] Gagal membuat direktori output "${dir}": ${err.message}`);
      process.exit(1);
    }
  }

  const allLines = readTargets(opts);
  const subdomains = [...new Set(allLines.map((s) => s.toLowerCase()))];
  const invalidCount = subdomains.filter((s) => !isValidHostname(s)).length;

  if (subdomains.length === 0) {
    console.error('[ERR ] Tidak ada subdomain valid untuk diproses.');
    process.exit(1);
  }

  log('info', `Loaded ${subdomains.length} unique subdomains${invalidCount ? ` (${invalidCount} format tidak valid akan dilewati)` : ''}.`);
  log('info', `Concurrency: ${CONCURRENCY} (adaptive: ${ADAPTIVE_CONCURRENCY ? 'ON' : 'OFF'}) | Delay: ${DELAY_MS}ms | Timeout: ${HTTP_TIMEOUT}ms`);
  log('info', `HTTP check: ${DO_HTTP_CHECK ? 'ON' : 'OFF'} | Resolve A fallback: ${DO_RESOLVE_A ? 'ON' : 'OFF'} | Wildcard check: ${DO_WILDCARD_CHECK ? 'ON' : 'OFF'}`);
  if (INTERNAL_SUFFIXES.length) log('info', `Internal suffix: ${INTERNAL_SUFFIXES.join(', ')}`);
  if (PROXY_URL) log('info', `Proxy: ${PROXY_URL}`);
  if (opts.resolvers) log('info', `Custom DNS resolver: ${opts.resolvers.join(', ')}`);
  if (WEBHOOK_URL) log('info', 'Webhook notifikasi: aktif untuk kategori POTENTIAL_TAKEOVER.');
  if (LOG_FILE) log('info', `Structured log: ${LOG_FILE}`);

  const startedAt = new Date().toISOString();
  const startTime = Date.now();

  const inputHash = computeInputHash(subdomains);
  const checkpointPath = checkpointPathFor(opts.outputPrefix);
  const results = new Array(subdomains.length);
  let indicesToProcess = subdomains.map((_, i) => i);

  if (opts.resume) {
    const cp = loadCheckpoint(checkpointPath);
    if (cp && cp.inputHash === inputHash && Array.isArray(cp.results)) {
      cp.results.forEach((r, i) => { if (r) results[i] = r; });
      indicesToProcess = indicesToProcess.filter((i) => !results[i]);
      log('info', `Melanjutkan scan sebelumnya: ${subdomains.length - indicesToProcess.length} target sudah selesai, ${indicesToProcess.length} tersisa.`);
    } else if (cp) {
      log('warn', 'Checkpoint ditemukan tapi tidak cocok dengan daftar input saat ini. Memulai scan baru dari awal.');
    }
  }

  log('info', 'Menjalankan wildcard DNS pre-check...');
  const wildcardMap = await buildWildcardMap(subdomains);

  const circuitBreaker = createCircuitBreaker(opts.circuitBreakerThreshold);

  let interrupted = false;
  const shutdownHandler = (signal) => {
    if (interrupted) { process.exit(130); return; }
    interrupted = true;
    log('warn', `Sinyal ${signal} diterima. Menyimpan laporan parsial...`);
    try {
      saveCheckpoint(checkpointPath, inputHash, results);
      finalizeAndWrite(results, opts, { startedAt, durationMs: Date.now() - startTime, partial: true });
    } catch (err) {
      console.error(`[ERR ] Gagal menyimpan laporan parsial: ${err.message}`);
    }
    process.exit(130);
  };
  const sigintHandler = () => shutdownHandler('SIGINT');
  const sigtermHandler = () => shutdownHandler('SIGTERM');
  process.on('SIGINT', sigintHandler);
  process.on('SIGTERM', sigtermHandler);

  await runPool(subdomains, (item) => analyzeSubdomain(item, wildcardMap), results, {
    indices: indicesToProcess,
    onProgress: drawProgress,
    onCheckpoint: () => saveCheckpoint(checkpointPath, inputHash, results),
    checkpointEvery: opts.checkpointEvery,
    circuitBreaker,
  });

  process.removeListener('SIGINT', sigintHandler);
  process.removeListener('SIGTERM', sigtermHandler);
  log('ok', 'Pemindaian selesai.');

  finalizeAndWrite(results, opts, { startedAt, durationMs: Date.now() - startTime });

  try { fs.unlinkSync(checkpointPath); } catch { /* tidak masalah jika checkpoint tidak ada */ }

  const takeoverCount = results.filter((r) => r && r.category === 'POTENTIAL_TAKEOVER').length;
  process.exitCode = takeoverCount > 0 ? 2 : 0;
}

if (require.main === module) {
  main().catch((err) => {
    console.error('[CRIT] Fatal error:', err);
    process.exit(1);
  });
}

module.exports = {
  isValidHostname, getRootDomain, generateCsv, generateSummary, generateMarkdown, generateHtml,
  FINGERPRINTS, resolveCnameChain, httpGet, analyzeSubdomain,
  createCircuitBreaker, mergeOptions, loadConfigFile, computeInputHash,
  parseArgs, DEFAULT_OPTIONS, runPool,
};

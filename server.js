// Domain Hunter - zero dependencies, needs Node 18+  ->  node server.js
const http = require('http'), fs = require('fs'), path = require('path'), net = require('net'), dns = require('dns').promises;
const https = require('https');
// Compatibility: Node < 18 has no global fetch, so provide a minimal one (follows redirects, 10s timeout).
if (typeof fetch === 'undefined') global.fetch = function f(url, o = {}, depth = 0) {
  return new Promise((resolve, reject) => {
    const req = (String(url).startsWith('http:') ? require('http') : https).request(url, { method: o.method || 'GET', headers: o.headers || {}, timeout: 10000 }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && depth < 4) { res.resume(); return resolve(f(new URL(res.headers.location, url).href, o, depth + 1)); }
      let b = ''; res.setEncoding('utf8'); res.on('data', d => b += d);
      res.on('end', () => resolve({ status: res.statusCode, ok: res.statusCode < 400, headers: { get: k => res.headers[k.toLowerCase()] ?? null }, text: async () => b, json: async () => JSON.parse(b) }));
    });
    req.on('timeout', () => req.destroy(new Error('timeout'))); req.on('error', reject); req.end();
  });
};
const tmo = ms => (typeof AbortSignal !== 'undefined' && AbortSignal.timeout) ? AbortSignal.timeout(ms) : undefined;
process.on('unhandledRejection', e => console.error('Unhandled:', e && e.message || e));
if (+process.versions.node.split('.')[0] < 18) console.warn('Warning: Node ' + process.version + ' is outdated. It works, but please upgrade to Node 18+ (https://nodejs.org).');
const PORT = process.env.PORT || 3000, CONCURRENCY = +process.env.CONCURRENCY || 8, MAX_COMBOS = +process.env.MAX_COMBOS || 600000;
const resolver = new dns.Resolver(); resolver.setServers(['1.1.1.1', '8.8.8.8']);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const code = e => e?.cause?.code || e?.code || e?.message || 'unknown error';

const REGISTRARS = [
  { id: 'porkbun',   name: 'Porkbun',   link: 'https://porkbun.com/checkout/search?q=' },
  { id: 'namecheap', name: 'Namecheap', link: 'https://www.namecheap.com/domains/registration/results/?domain=' },
  { id: 'cloudflare',name: 'Cloudflare',link: 'https://www.cloudflare.com/products/registrar/#' },
  { id: 'godaddy',   name: 'GoDaddy',   link: 'https://www.godaddy.com/domainsearch/find?domainToCheck=' },
  { id: 'namecom',   name: 'Name.com',  link: 'https://www.name.com/domain/search/' },
  { id: 'dynadot',   name: 'Dynadot',   link: 'https://www.dynadot.com/domain/search?domain=' },
  { id: 'hover',     name: 'Hover',     link: 'https://www.hover.com/domains/results?q=' },
  { id: 'gandi',     name: 'Gandi',     link: 'https://shop.gandi.net/en/domain/suggest?search=' },
  { id: 'spaceship', name: 'Spaceship', link: 'https://www.spaceship.com/domain-search/?query=' },
];

// ---------- RDAP (official registry lookup) ----------
let bootstrap = null, prices = null;
async function rdapBase(tld) {
  if (!bootstrap) bootstrap = fetch('https://data.iana.org/rdap/dns.json').then(r => r.json()).then(j => j.services).catch(e => { bootstrap = null; throw e; });
  const s = (await bootstrap).find(([tlds]) => tlds.includes(tld));
  return s ? (s[1].find(u => u.startsWith('https')) || s[1][0]).replace(/\/$/, '') : null;
}
const RDAP_DELAY = +process.env.RDAP_DELAY || 250;   // ms between registry requests (4/sec); small registries rate-limit hard
let nextSlot = 0;
async function throttle() { const now = Date.now(), at = Math.max(now, nextSlot); nextSlot = at + RDAP_DELAY; if (at > now) await sleep(at - now); }
const RDAP_HEADERS = { accept: 'application/rdap+json, application/json', 'user-agent': 'DomainHunter/1.0' };
// returns [status, reason]. 404 = not registered, 200 = registered, anything else = error with the real reason
async function rdapStatus(base, domain) {
  let why = 'no response';
  for (let a = 0; a < 4; a++) {
    try {
      await throttle();
      const r = await fetch(base + '/domain/' + domain, { signal: tmo(10000), headers: RDAP_HEADERS });
      if (r.status === 404) return ['available', ''];
      if (r.status === 200) return ['taken', ''];
      why = 'HTTP ' + r.status;
      if (r.status === 429 || r.status >= 500) { await sleep(Math.min(30, +r.headers.get('retry-after') || 2 ** a) * 1000); continue; }
      return ['error', why];
    } catch (e) { why = code(e); await sleep(1000 * (a + 1)); }
  }
  return ['error', why];
}

// ---------- WHOIS (port 43), used to double-check names for extensions without RDAP ----------
function whoisQuery(server, q) {
  return new Promise((resolve, reject) => {
    const s = net.connect(43, server); let data = '';
    s.setTimeout(8000, () => { s.destroy(); reject(new Error('WHOIS timeout')); });
    s.on('error', reject).on('connect', () => s.write(q + '\r\n')).on('data', d => data += d).on('end', () => resolve(data));
  });
}
const whoisServers = {};
async function whoisServer(tld) {
  if (!(tld in whoisServers)) { const m = (await whoisQuery('whois.iana.org', tld)).match(/^whois:\s*(\S+)/mi); whoisServers[tld] = m ? m[1] : null; }
  return whoisServers[tld];
}
async function whoisRegistered(domain, tld) {   // true = registered, false = no sign of registration
  const srv = await whoisServer(tld); if (!srv) return false;
  return /^\s*(domain(?: name)?|registrar|created|creation date|registered|nameserver|name server)\s*:/im.test(await whoisQuery(srv, domain));
}

// ---------- main check: returns [status, reason] ----------
// available = confirmed twice by registry (RDAP). unverified = no RDAP for this extension, not found in DNS/WHOIS. taken. error = could not verify.
async function check(domain, tld) {
  let base;
  try { base = await rdapBase(tld); } catch (e) { return ['error', 'cannot reach data.iana.org (' + code(e) + ')']; }
  if (base) {
    let [st, why] = await rdapStatus(base, domain);
    if (st === 'available') {
      [st, why] = await rdapStatus(base, domain);
      if (st === 'available') { try { await resolver.resolveNs(domain); return ['taken', '']; } catch {} }
    }
    // Rate-limited / busy registry: report it. Registry refusing us outright (403, 400, connection refused...): fall back to DNS/WHOIS below.
    if (st !== 'error' || /429|HTTP 5/.test(why)) return [st, st === 'error' ? 'registry ' + base + ' failed: ' + why : ''];
  }
  // No RDAP: DNS first (cheap), then WHOIS only for names that look unregistered
  let missing = false;
  try { await resolver.resolveNs(domain); return ['taken', '']; }
  catch (e) {
    if (e.code === 'ENODATA') return ['taken', ''];
    if (e.code === 'ENOTFOUND') missing = true;
    else try { await dns.lookup(domain); return ['taken', '']; }
    catch (e2) { if (e2.code === 'ENOTFOUND') missing = true; else return ['error', 'DNS lookup failed (' + code(e2) + ')']; }
  }
  if (missing) { try { if (await whoisRegistered(domain, tld)) return ['taken', '']; } catch {} }
  return ['unverified', ''];
}

// ---------- prices ----------
async function getPrices() {
  if (!prices) prices = (await (await fetch('https://api.porkbun.com/api/json/v3/pricing/get', { method: 'POST' })).json()).pricing || {};
  return prices;
}
function extraPrices() { try { return JSON.parse(fs.readFileSync(path.join(__dirname, 'prices.json'), 'utf8')); } catch { return {}; } }
async function offers(tld) {
  const p = (await getPrices().catch(() => ({})))[tld], extra = extraPrices();
  return REGISTRARS.map(r => {
    let x = null;
    if (r.id === 'porkbun' && p) x = { reg: +p.registration, ren: +p.renewal };
    else if (extra[r.id]?.[tld]) x = { reg: extra[r.id][tld].registration, ren: extra[r.id][tld].renewal };
    return { ...r, reg: x?.reg ?? null, ren: x?.ren ?? null };
  }).sort((a, b) => (a.reg ?? 1e9) - (b.reg ?? 1e9));
}

// ---------- diagnostics ----------
async function diag(tld) {
  const t = (name, fn) => Promise.race([fn().then(d => ({ name, ok: true, detail: d || '' })), sleep(8000).then(() => ({ name, ok: false, detail: 'timeout' }))])
    .catch(e => ({ name, ok: false, detail: code(e) }));
  return Promise.all([
    t('IANA RDAP list', () => fetch('https://data.iana.org/rdap/dns.json').then(r => { if (!r.ok) throw new Error('HTTP ' + r.status); })),
    t('.' + tld + ' registry lookup', async () => (await rdapBase(tld)) || 'no RDAP for this extension, using DNS/WHOIS'),
    t('Registry test request', async () => {
      const b = await rdapBase(tld); if (!b) return 'n/a';
      const r = await fetch(b + '/domain/nic.' + tld, { headers: RDAP_HEADERS });
      if (r.status !== 200 && r.status !== 404) throw new Error('HTTP ' + r.status);
      return 'HTTP ' + r.status + ', server answers';
    }),
    t('DNS (1.1.1.1)', () => resolver.resolveNs('google.com')),
    t('System DNS', () => dns.lookup('google.com')),
    t('WHOIS port 43', async () => { if (!(await whoisQuery('whois.iana.org', tld)).length) throw new Error('empty'); }),
    t('Porkbun prices', async () => ((await getPrices())[tld] ? '' : 'no price listed for .' + tld)),
  ]);
}

function nameAt(n, len, cs) {
  let s = '';
  for (let i = 0; i < len; i++) { s = cs[n % cs.length] + s; n = Math.floor(n / cs.length); }
  return s.startsWith('-') || s.endsWith('-') ? null : s;
}

const handle = async (req, res) => {
  if (process.env.APP_PASSWORD) {   // optional password so strangers can't use your server to scan registries
    const given = Buffer.from((req.headers.authorization || '').replace(/^Basic /, ''), 'base64').toString().split(':').slice(1).join(':');
    if (given !== process.env.APP_PASSWORD) { res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="Domain Hunter"' }); return res.end('Password required'); }
  }
  const u = new URL(req.url, 'http://x'), q = u.searchParams;
  const json = (o, c = 200) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
  if (u.pathname === '/') { res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end(fs.readFileSync(path.join(__dirname, 'public/index.html'))); }
  const tld = (q.get('tld') || '').replace(/^\./, '').toLowerCase();
  if (!/^[a-z0-9.-]{2,24}$/.test(tld)) return json({ error: 'Invalid extension' }, 400);

  if (u.pathname === '/api/offers') return json({ offers: await offers(tld) });
  if (u.pathname === '/api/diag') return json({ checks: await diag(tld) });

  if (u.pathname === '/api/search') {
    const len = +q.get('len');
    const cs = 'abcdefghijklmnopqrstuvwxyz' + (q.get('digits') === '1' ? '0123456789' : '') + (q.get('hyphen') === '1' ? '-' : '');
    const total = cs.length ** len;
    if (!(len >= 1 && len <= 63) || total > MAX_COMBOS) return json({ error: `Too many combinations (max ${MAX_COMBOS})` }, 400);
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' });
    let i = 0, stop = false, fatal = false, streak = 0; const reasons = {};
    res.on('close', () => stop = true);   // res (not req): req 'close' fires early on newer Node versions
    console.log('Search started: len=' + len + ' .' + tld);
    const send = o => { if (!res.writableEnded) res.write('data:' + JSON.stringify(o) + '\n\n'); };
    send({ total });
    const worker = async () => {
      while (!stop) {
        const n = i++; if (n >= total) return;
        const name = nameAt(n, len, cs); if (!name) { send({ skip: 1 }); continue; }
        const [s, why] = await check(name + '.' + tld, tld);
        if (s === 'error') {
          reasons[why] = (reasons[why] || 0) + 1;
          if (++streak >= 25 && !fatal) { fatal = stop = true; console.log('Search stopped, lookups failing: ' + why); send({ fatal: why }); }   // everything is failing: stop early and say why
        } else streak = 0;
        if (!fatal) send({ d: name + '.' + tld, s });
      }
    };
    await Promise.all(Array.from({ length: CONCURRENCY }, worker));
    if (!fatal) send({ done: 1, why: Object.entries(reasons).sort((a, b) => b[1] - a[1])[0]?.[0] });
    return res.end();
  }
  json({ error: 'Not found' }, 404);
};
http.createServer((req, res) => handle(req, res).catch(e => { try { res.writeHead(500); } catch {} res.end('Server error: ' + e.message); })).listen(PORT, () => console.log('Domain Hunter running on http://localhost:' + PORT));

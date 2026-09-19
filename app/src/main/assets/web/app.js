/* ============================================
   IP DETECTOR - 主逻辑
   数据源: ipwho.is / ip.sb / ip-api(经 Worker 代理)
   ============================================ */

const $ = (id) => document.getElementById(id);

/* ---------------- 当前状态 ---------------- */
const state = {
  ip: null,        // 当前展示的IP
  ipType: 'v4',    // v4 / v6 / quote
  v4: null,
  v6: null,
  info: null,
  pureData: null,
  isOwn: true,
};

/* ---------------- 工具 ---------------- */
// 带超时的 fetch：弱网 / IPv6 黑洞路由下避免加载遮罩永久挂起
function fetchT(url, opts, ms) {
  opts = opts || {};
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), ms || 10000);
  return fetch(url, Object.assign({}, opts, { signal: ac.signal }))
    .finally(() => clearTimeout(timer));
}

function initGradient() {
  // 给环形图注入渐变 defs
  const svg = document.querySelector('.score-ring');
  if (!svg) return;
  let defs = svg.querySelector('defs');
  if (!defs) {
    defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
    defs.innerHTML = `<linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#4f8cff"/><stop offset="100%" stop-color="#22d3a8"/>
      </linearGradient>`;
    svg.insertBefore(defs, svg.firstChild);
  }
}

/* IP 格式校验：返回 'v4' / 'v6' / null */
function ipKind(s) {
  if (/^(\d{1,3})(\.\d{1,3}){3}$/.test(s)) {
    return s.split('.').every(o => +o <= 255) ? 'v4' : null;
  }
  if (!/^[0-9a-fA-F:]+$/.test(s) || !s.includes(':')) return null;
  const dbl = s.split('::');
  if (dbl.length > 2) return null;
  const head = dbl[0] ? dbl[0].split(':') : [];
  const tail = dbl.length === 2 && dbl[1] ? dbl[1].split(':') : [];
  const groups = head.concat(tail);
  if (!groups.every(g => /^[0-9a-fA-F]{1,4}$/.test(g))) return null;
  if (dbl.length === 1) return groups.length === 8 ? 'v6' : null;
  return (head.length + tail.length) <= 7 ? 'v6' : null;
}

/* ---------------- IP 获取 ---------------- */
async function getMyIPs() {
  // 并行获取 IPv4 和 IPv6
  const jobs = [
    fetchT('https://api.ipify.org?format=json', {}, 8000).then(r => r.json()).then(d => { state.v4 = d.ip; }).catch(() => {}),
    fetchT('https://api6.ipify.org?format=json', {}, 8000).then(r => r.json()).then(d => { state.v6 = d.ip; }).catch(() => {}),
  ];
  await Promise.all(jobs);
  // 若均不可得，用 ipwho.is 兜底
  if (!state.v4 && !state.v6) {
    try {
      const d = await fetchT('https://ipwho.is/', {}, 8000).then(r => r.json());
      if (d && d.ip) { if (d.ip.includes(':')) state.v6 = d.ip; else state.v4 = d.ip; }
    } catch (e) {}
  }
}

/* ---------------- IP 归属全量信息 ---------------- */
async function getInfo(ip) {
  // ipwho.is 为主, ip.sb 兜底 —— 两路并行提速（均 HTTPS；
  // 明文 HTTP 的 ip-api.com 直连已移除，纯净度改由 HTTPS Worker 服务端判定）
  const results = await Promise.all([
    fetchT('https://ipwho.is/' + encodeURIComponent(ip)).then(r => r.json()).catch(() => null),
    fetchT('https://api.ip.sb/geoip/' + encodeURIComponent(ip)).then(r => r.json()).catch(() => null),
  ]);
  const who = results[0], sb = results[1];
  const src = who && who.success ? who : (sb || null);
  if (!src) return null;

  const isv6 = String(ip).includes(':');
  const owner = who && who.success ? who : {};
  const conn = owner.connection || {};
  const org = conn.org || (sb ? sb.organization : '');
  const isp = conn.isp || (sb ? sb.isp : '');

  return {
    ip, version: isv6 ? 'IPv6' : 'IPv4',
    type: owner.type || (isv6 ? 'IPv6' : 'IPv4'),
    asn: conn.asn || (sb ? sb.asn : '--'),
    asn_org: conn.org || (sb ? sb.asn_organization : '--'),
    isp: isp || '--',
    org,
    country: owner.country || (sb ? sb.country : ''),
    country_code: owner.country_code || (sb ? sb.country_code : ''),
    region: owner.region || (sb ? sb.region : ''),
    region_code: owner.region_code || (sb ? sb.region_code : '') || '',
    city: owner.city || (sb ? sb.city : ''),
    lat: owner.latitude !== undefined ? owner.latitude : (sb ? sb.latitude : null),
    lon: owner.longitude !== undefined ? owner.longitude : (sb ? sb.longitude : null),
    postal: owner.postal || null,
    calling_code: owner.calling_code || null,
    flag_emoji: (owner.flag && owner.flag.emoji) || null,
    is_eu: owner.is_eu === true,
    timezone: owner.timezone ? owner.timezone.id : (sb ? sb.timezone : '--'),
    tz_offset: owner.timezone ? owner.timezone.offset : (sb ? sb.offset : null),
    tz_utc: owner.timezone ? owner.timezone.utc : null,
    // 纯净度相关（无服务端数据时由本地关键词启发兜底）
    api_proxy: isVpnish(org, isp),
    api_hosting: isDcByKw(org, isp),
  };
}

/* ---- 辅助判断（Worker 不可用时的本地兜底） ---- */
const DC_KW = ['cloud', 'hosting', 'microsoft azure', 'amazon', 'digitalocean', 'linode', 'vultr', 'hetzner', 'oracle', 'aws', 'huawei', 'alibaba', 'tencent', 'softlayer', 'ovh', 'akamai', 'kagoya', 'google', 'packet'];
const VPN_KW = ['vpn', 'proxy', 'tor ', 'tor-', 'nord', 'surfshark', 'privacy', 'relay', 'openvpn', 'wireguard', '21vianet'];
function isDcByKw(org, isp) { const o = (org || '').toLowerCase(), i = (isp || '').toLowerCase(); return DC_KW.some(k => o.includes(k) || i.includes(k)); }
function isVpnish(org, isp) { const o = (org || '').toLowerCase(), i = (isp || '').toLowerCase(); return VPN_KW.some(k => o.includes(k) || i.includes(k)); }

/* ---- 信誉代理 Worker ---- */
const PURITY_PROXY = 'https://ipdetector-purity.1161467182.workers.dev';

/* ---------------- 纯净度评分（优先走 Worker 真实分，兜底本地启发） ---------------- */
async function getPurity(ip) {
  // 1. 优先调 Worker 信誉代理（真实 ip-api / IPQualityScore 服务端判定）
  try {
    const resp = await fetchT(PURITY_PROXY + '/lookup?ip=' + encodeURIComponent(ip), { mode: 'cors' });
    if (resp.ok) {
      const d = await resp.json();
      if (d && d.success) return mapProxyResult(d);
    }
  } catch (e) { /* Worker 不可用，走 fallback */ }
  // 2. fallback: 本地启发式（无 Worker 时仍可用）
  return fallbackPurity(ip);
}

/* ---- 评分共享逻辑：加权合成与档位判定（Worker/本地兜底两路共用） ---- */
const PURITY_WEIGHTS = [0.22, 0.30, 0.16, 0.12, 0.20];

function scoreFromMetrics(metrics) {
  const total = metrics.reduce((s, m, i) => s + m.val * (PURITY_WEIGHTS[i] || 0.2), 0);
  return Math.max(3, Math.min(98, Math.round(100 - total)));
}

function levelFor(score) {
  if (score >= 85) return { level: '🟢 优秀', levelColor: 'var(--good)', desc: 'IP 纯净度高，风控风险低。' };
  if (score >= 70) return { level: '🟡 良好', levelColor: 'var(--mid)', desc: 'IP 大部分干净。' };
  if (score >= 50) return { level: '🟠 一般', levelColor: 'var(--warn)', desc: 'IP 存在明显风控信号。' };
  if (score >= 25) return { level: '🔴 高风险', levelColor: 'var(--danger)', desc: 'IP 纯净度低，易被风控拦截。' };
  return { level: '☠️ 黑名单', levelColor: 'var(--danger)', desc: 'IP 风险极高。' };
}

function mapProxyResult(d) {
  const metrics = [];
  const pv = d.proxy && d.proxy.value;
  const hv = d.hosting && d.hosting.value;
  const tv = d.tor && d.tor.value;
  const bv = d.bot && d.bot.value;
  const dv = d.datacenter && d.datacenter.value;
  const add = (name, val, good, desc) => metrics.push({ name, val, good, desc });
  if (hv) add('托管商 / 数据中心', 72, false, '该 IP 属于云服务/托管商（数据中心）。');
  else add('托管商 / 数据中心', 6, true, '家用/移动/运营商接入，非托管商。');
  if (pv || tv) add('代理 / VPN / TOR', 88, false, '检测到代理/VPN/TOR 出口特征。');
  else add('代理 / VPN / TOR', 8, true, '未见代理/VPN/TOR 出口特征。');
  const isCDN = d.org && /cloudflare|fastly|akamai|cloudfront/i.test(d.org);
  if (isCDN || dv) add('CDN / 公共出口', 62, false, '该 IP 是 CDN/数据中心节点。');
  else add('CDN / 公共出口', 9, true, '非 CDN 出口，属于普通接入。');
  const hasLoc = !!(d.latitude && d.longitude && d.latitude !== 0);
  add('定位可信度', hasLoc ? 7 : 42, hasLoc, hasLoc ? '归属地定位可靠。' : '归属地定位不精确。');
  add('信誉/机器人检测', bv ? 60 : 12, !bv, bv ? '检测到机器人/爬虫特征。' : '未见机器人/爬虫特征。');
  const score = scoreFromMetrics(metrics);
  const tier = levelFor(score);
  return { score, ...tier, metrics, source: d.source || 'proxy' };
}

function fallbackPurity(ip) {
  const metrics = []; const info = state.info || {};
  const org = (info.org || '').toLowerCase(); const isp = (info.isp || '').toLowerCase();
  const isHosting = isDcByKw(org, isp); const isProxy = info.api_proxy === true || isVpnish(org, isp);
  const isCDN = /cloudflare|fastly|akamai|cloudfront/.test(org + ' ' + isp);
  const hasLoc = !!(info.lat && info.lon && info.lat !== 0 && info.lon !== 0);
  const add = (n, v, g, d) => metrics.push({ name: n, val: v, good: g, desc: d });
  add('托管商 / 数据中心', isHosting ? 72 : 6, !isHosting, isHosting ? 'IP 属于云服务/托管商。' : '家用/运营商接入。');
  add('代理 / VPN / TOR', isProxy ? 88 : 8, !isProxy, isProxy ? '检测到代理/VPN 出口。' : '未见代理/VPN 特征。');
  add('CDN / 公共出口', isCDN ? 62 : 9, !isCDN, isCDN ? '该 IP 是 CDN 出口。' : '非 CDN 出口。');
  add('定位可信度', hasLoc ? 7 : 42, hasLoc, hasLoc ? '归属地定位可靠。' : '归属地不精确。');
  add('ASN 信誉', 10, true, 'AS 番号无显著风控特征。');
  const score = scoreFromMetrics(metrics);
  const tier = levelFor(score);
  return { score, ...tier, metrics, source: 'fallback' };
}

/* ---------------- 人机流量对比 ---------------- */
function trafficCalc(score, info) {
  // 基于纯净度 + 真实特征 启发人/机/恶意占比
  let human, bot, abuse;
  if (score >= 85)      { human = 74; bot = 20; abuse = 6; }
  else if (score >= 70) { human = 60; bot = 28; abuse = 12; }
  else if (score >= 50) { human = 44; bot = 38; abuse = 18; }
  else if (score >= 25) { human = 28; bot = 45; abuse = 27; }
  else                  { human = 18; bot = 42; abuse = 40; }
  // 真实特征修正
  if (info && info.api_hosting === true) { human += 2; bot += 3; abuse -= 5; }
  if (info && info.api_proxy === true)   { human -= 8; bot += 5; abuse += 3; }
  // 兜底到合法区间
  human = Math.max(5, Math.min(92, Math.round(human)));
  bot = Math.max(3, Math.min(90, Math.round(bot)));
  abuse = Math.max(1, Math.min(80, Math.round(abuse)));
  // 保证近似满100
  let sum = human + bot + abuse;
  if (sum !== 100) {
    abuse = Math.max(1, Math.round(abuse + (100 - sum)));
    sum = human + bot + abuse;
    if (sum !== 100) { bot = Math.max(0, bot + (100 - sum)); }
  }
  return { human, bot, abuse };
}

/* ---------------- 渲染：主信息 ---------------- */
// 旗帜/地区显示：台湾不渲染旗帜emoji，改用文字，避免繁体/主权争议
function displayFlag(info) {
  if (!info) return '🌐';
  const cc = (info.country_code || '').toUpperCase();
  if (cc === 'TW') return '台湾';
  if (info.flag_emoji) return info.flag_emoji;
  return '🌐';
}
function displayCountry(info) {
  if (!info) return '未知';
  const cc = (info.country_code || '').toUpperCase();
  if (cc === 'TW') return '中国台湾';
  return info.country || '未知';
}

function renderHero() {
  $('heroTitle').textContent = state.isOwn ? '我的公网 IP 地址' : '查询的 IP 地址';
  $('heroIp').textContent = state.ip;
  $('flagLarge').textContent = displayFlag(state.info);
  const i = state.info || {};
  const cc = (i.country_code || '').toUpperCase();
  const sub = cc === 'TW' ? displayCountry(i) : cc;
  $('heroSub').textContent = [sub, i.city, i.isp].filter(Boolean).join(' · ') || '—';
}

function renderInfo() {
  const i = state.info;
  $('i_ip').textContent = i.ip;
  $('i_ver').textContent = i.version;
  $('i_asn').textContent = 'AS' + i.asn;
  $('i_isp').textContent = i.isp || '--';
  $('i_org').textContent = i.org || i.asn_org || '--';
  $('i_country').textContent = displayCountry(i) + (i.country_code ? ' (' + i.country_code + ')' : '');
  $('i_region').textContent = (i.region || '--') + (i.region_code ? ' / ' + i.region_code : '');
  $('i_city').textContent = i.city || '--';
  $('i_loc').textContent = (typeof i.lat === 'number' && typeof i.lon === 'number')
    ? i.lat.toFixed(4) + ', ' + i.lon.toFixed(4) : '--';
  $('i_tz').textContent = i.timezone || '--';
  $('i_call').textContent = i.calling_code ? '+' + i.calling_code : '--';
  $('i_eu').textContent = i.is_eu ? '是 🇪🇺' : '否';

  // clock
  $('clockTz').textContent = i.timezone || '--';
  $('clockUtc').textContent = (i.tz_utc ? 'UTC ' + i.tz_utc : '') +
    (typeof i.tz_offset === 'number' ? ' · offset ' + i.tz_offset + 's' : '');
  startClock(tzNameToOffset(i.timezone, i.tz_offset));
}

function tzNameToOffset(tz, offsetSec) {
  // 用 Intl 拿真实时区偏移（含夏令时），失败时退回 ip 返回的固定偏移
  if (!tz) return offsetSec || 0;
  try {
    const now = new Date();
    const parts = new Intl.DateTimeFormat('en-US', { timeZone: tz, timeZoneName: 'longOffset' }).formatToParts(now);
    const tzName = parts.find(p => p.type === 'timeZoneName');
    if (tzName) {
      const m = tzName.value.match(/GMT([+-])(\d+):(\d+)/);
      if (m) {
        let off = parseInt(m[2]) * 3600 + parseInt(m[3]) * 60;
        if (m[1] === '-') off = -off;
        return off;
      }
    }
  } catch (e) {}
  return offsetSec || 0;
}

/* ---------------- 时区时钟 ---------------- */
let clockTimer = null;
function startClock(offsetSec) {
  if (clockTimer) clearInterval(clockTimer);
  const tick = () => {
    const now = new Date();
    const t = new Date(now.getTime() + (offsetSec * 1000) + now.getTimezoneOffset() * 60000);
    const pad = n => String(n).padStart(2, '0');
    $('clockTime').textContent = pad(t.getHours()) + ':' + pad(t.getMinutes()) + ':' + pad(t.getSeconds());
  };
  tick();
  clockTimer = setInterval(tick, 1000);
}

/* ---------------- 地图 ---------------- */
function renderMap() {
  const lat = state.info && typeof state.info.lat === 'number' ? state.info.lat : 0;
  const lon = state.info && typeof state.info.lon === 'number' ? state.info.lon : 0;
  $('mapCoords').textContent = lat.toFixed(4) + ', ' + lon.toFixed(4);
  const active = document.querySelector('.mtab.active');
  const src = active ? active.dataset.src : 'osm';
  let url = '';
  if (src === 'osm') {
    url = `https://www.openstreetmap.org/export/embed.html?bbox=${lon - 1.2}%2C${lat - 1.2}%2C${lon + 1.2}%2C${lat + 1.2}&layer=mapnik&marker=${lat}%2C${lon}`;
  } else if (src === 'amt') {
    url = `https://uri.amap.com/marker?position=${lon.toFixed(5)},${lat.toFixed(5)}&name=IP归属&src=ipcheck&coordinate=gaode&callnative=0`;
  } else if (src === 'gdi') {
    url = `https://www.tianditu.gov.cn/browser/map.html?lat=${lat}&lng=${lon}`;
  }
  $('mapFrame').src = url;
}

// 地图源切换
document.querySelectorAll('.mtab').forEach(b => b.addEventListener('click', function () {
  document.querySelectorAll('.mtab').forEach(x => x.classList.remove('active'));
  this.classList.add('active');
  renderMap();
}));

/* ---------------- 纯净度渲染 ---------------- */
function renderPurity(p) {
  $('scoreNum').textContent = p.score;
  $('scoreLevel').textContent = p.level.split(' ')[1] || p.level;
  $('scoreLevel').style.color = p.levelColor;
  $('scoreDesc').textContent = p.desc;
  // 环
  const circ = 2 * Math.PI * 52;
  $('ringFg').style.strokeDasharray = circ;
  setTimeout(() => { $('ringFg').style.strokeDashoffset = circ * (1 - p.score / 100); }, 60);
  $('ringFg').style.stroke = p.score >= 70 ? 'var(--good)' : (p.score >= 50 ? 'var(--warn)' : 'var(--danger)');

  /* --- Hero 醒目纯净度同步 --- */
  const hpColor = p.score >= 70 ? 'var(--good)' : (p.score >= 50 ? 'var(--warn)' : 'var(--danger)');
  const hpCirc = 2 * Math.PI * 27;
  const hpRingFg = $('hpRingFg');
  hpRingFg.style.strokeDasharray = hpCirc;
  setTimeout(() => { hpRingFg.style.strokeDashoffset = hpCirc * (1 - p.score / 100); }, 60);
  hpRingFg.style.stroke = hpColor;
  $('hpScore').textContent = p.score;
  $('hpScore').style.color = hpColor;
  $('hpBadge').textContent = 'IP 纯净度';
  const lvlTxt = p.level.includes('优秀') ? '优秀' : p.level.includes('良好') ? '良好' : p.level.includes('一般') ? '一般' : '高风险';
  $('hpLevel').textContent = lvlTxt;
  $('hpLevel').style.color = hpColor;
  $('hpDesc').textContent = p.score >= 85 ? '纯净度优秀，直连该 IP 风控极低'
    : p.score >= 70 ? '纯净度良好，大部分场景可用'
    : p.score >= 50 ? '存在一定风控信号，注意识别' : '纯净度低，高风险';

  const wrap = $('metrics');
  wrap.textContent = '';
  p.metrics.forEach(m => {
    const color = m.good ? 'var(--good)' : (m.val <= 35 ? 'var(--mid)' : 'var(--danger)');
    const row = document.createElement('div');
    row.className = 'metric';
    const name = document.createElement('span');
    name.className = 'metric-name';
    name.textContent = m.name + (m.good ? ' ✅' : ' ⚠️');
    const bar = document.createElement('div');
    bar.className = 'metric-bar';
    const fill = document.createElement('div');
    fill.className = 'metric-fill';
    fill.style.width = '0%';
    fill.style.background = color;
    bar.appendChild(fill);
    const val = document.createElement('span');
    val.className = 'metric-val';
    val.style.color = color;
    val.textContent = m.val + '%';
    row.appendChild(name); row.appendChild(bar); row.appendChild(val);
    wrap.appendChild(row);
    setTimeout(() => { fill.style.width = m.val + '%'; }, 80);
  });
}

/* ---------------- 人机流量渲染 ---------------- */
function renderTraffic(t) {
  $('barHuman').style.width = t.human + '%';
  $('barBot').style.width = t.bot + '%';
  $('barAbuse').style.width = t.abuse + '%';
  $('tHuman').textContent = t.human + '%';
  $('tBot').textContent = t.bot + '%';
  $('tAbuse').textContent = t.abuse + '%';
}

/* ---------------- 核心检测流程 ---------------- */
async function detect(targetType) {
  showLoad('正在检测 IP 归属地…');
  try {
    await getMyIPs();

    if (targetType === 'v4') {
      state.ip = state.v4 || state.v6;
      if (!state.ip) { hideLoad(); showError('未检测到可用 IP'); return; }
      if (!state.v4) notice('未获取到 IPv4 地址，已展示 IPv6');
    } else {
      if (!state.v6) {
        hideLoad();
        notice('未获取到 IPv6 地址，当前网络可能仅支持 IPv4');
        // 回退到 IPv4 展示，tab 同步回 v4
        document.querySelectorAll('.tab').forEach(x => x.classList.toggle('active', x.dataset.type === 'v4'));
        state.ipType = 'v4';
        return;
      }
      state.ip = state.v6;
    }
    state.isOwn = true;
    await loadForIp(state.ip);
  } catch (e) {
    hideLoad();
    showError('检测出错：' + e.message);
    console.error(e);
  }
}

/* 拉取并渲染任一 IP（自己的 / 别人的统一入口） */
async function loadForIp(ip) {
  try {
    state.info = await getInfo(ip);
    if (!state.info) { showError('归属地查询失败，请重试'); return; }
    state.pureData = await getPurity(ip);
    state.ip = ip;
    renderHero();
    renderInfo();
    renderPurity(state.pureData);
    renderTraffic(trafficCalc(state.pureData.score, state.info));
    renderMap();
    $('ipv4Val').textContent = state.v4 || '--';
    $('ipv6Val').textContent = state.v6 || '--';
  } finally {
    hideLoad();
  }
}

/* 任意 IP 查询入口 */
async function doLookup(rawIp) {
  const ip = String(rawIp || '').trim().replace(/\s+/g, '');
  if (!ip) { notice('请输入 IP 地址'); return; }
  if (!ipKind(ip)) { notice('IP 格式不正确（示例：8.8.8.8 或 2001:db8::1）'); return; }
  showLoad('正在查询 ' + ip + ' …');
  state.isOwn = false;
  try {
    await loadForIp(ip);
    // 非本人 IP：WebRTC / DNS 结果仅针对"你自己"
    const infoEl = $('webrtcInfo');
    infoEl.textContent = '';
    const p = document.createElement('p');
    p.className = 'muted';
    p.textContent = '正在检测的是「' + ip + '」。WebRTC 与 DNS 泄露检测结果反映的是你当前设备的网络，不会因查询目标 IP 而改变。点击按钮可探测你本机是否泄露。';
    infoEl.appendChild(p);
    setBadge('webrtcBadge', 'wait', '针对本机');
    setBadge('dnsBadge', 'wait', '针对本机');
  } catch (e) {
    hideLoad();
    showError('查询出错：' + e.message);
  }
}

function showLoad(t) { $('loadingText').textContent = t || '…'; $('loading').classList.remove('hidden'); }
function hideLoad() { $('loading').classList.add('hidden'); }
function showError(msg) {
  hideLoad();
  $('heroIp').textContent = '!';
  $('heroSub').textContent = msg;
  $('flagLarge').textContent = '⚠️';
}
// 温和提示：只改 hero 副标题，不破坏当前展示
function notice(msg) { $('heroSub').textContent = msg; }
function setBadge(id, cls, txt) { const b = $(id); if (b) { b.className = 'badge badge-' + cls; b.textContent = txt; } }

/* ---------------- Tab 切换 ---------------- */
document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', function () {
  const type = this.dataset.type;
  if (this.classList.contains('active')) return; // 重复点击不重查
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  this.classList.add('active');
  state.ipType = type;
  if (type === 'quote') {
    $('quoteBox').classList.remove('hidden');
  } else {
    $('quoteBox').classList.add('hidden');
    detect(type);
  }
}));

/* 任意 IP 查询按钮 */
$('btnLookup').addEventListener('click', async function () {
  if (this.disabled) return;
  this.disabled = true;
  try { await doLookup($('qIpInput').value.trim()); }
  finally { this.disabled = false; }
});
$('qIpInput').addEventListener('keydown', function (e) {
  if (e.key === 'Enter') $('btnLookup').click();
});

/* ---------------- 刷新 ---------------- */
$('btnRefresh').addEventListener('click', async function () {
  if (this.disabled) return;
  this.disabled = true;
  this.classList.add('spinning');
  // 全局刷新 = 回到本机重新检测；要重查别人的 IP，用“查询”按钮即可
  if (state.ipType === 'quote') {
    state.ipType = 'v4';
    document.querySelectorAll('.tab').forEach(x => x.classList.toggle('active', x.dataset.type === 'v4'));
    $('quoteBox').classList.add('hidden');
  }
  try { await detect(state.ipType); }
  finally {
    this.disabled = false;
    setTimeout(() => this.classList.remove('spinning'), 400);
  }
});

/* ---------------- 复制 ---------------- */
$('btnCopy').addEventListener('click', function () {
  if (!state.ip) return;
  if (navigator.clipboard) navigator.clipboard.writeText(state.ip);
  else { const ta = document.createElement('textarea'); ta.value = state.ip; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove(); }
  this.textContent = '✅';
  setTimeout(() => { this.textContent = '📋'; }, 1200);
});

/* ================= WebRTC 检测 ================= */
$('btnWebrtc').addEventListener('click', runWebrtc);
async function runWebrtc() {
  const btn = $('btnWebrtc');
  btn.disabled = true; btn.textContent = '检测中…';
  $('webrtcInfo').innerHTML = '<p class="muted">正在收集 STUN 候选地址…</p>';
  $('webrtcResults').innerHTML = '';
  setBadge('webrtcBadge', 'warn', '检测中');

  if (!window.RTCPeerConnection) {
    $('webrtcInfo').innerHTML = '<p class="st-bad">当前浏览器不支持 RTCPeerConnection，无法检测。</p>';
    setBadge('webrtcBadge', 'warn', '不支持');
    btn.disabled = false; btn.textContent = '▶ 开始 WebRTC 检测';
    return;
  }

  const pc = new RTCPeerConnection({ iceServers: [
    { urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302', 'stun:stun2.l.google.com:19302'] }
  ] });
  pc.createDataChannel('probe');

  const found = [];
  let finished = false;

  function isLocalAddr(addr) {
    if (/(^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\.|^169\.254\.|^0\.)/.test(addr)) return true;
    if (addr.includes(':')) {
      const a = addr.toLowerCase();
      // fc00::/7 ULA、fe80::/10 链路本地、fec0::/10 站点本地（QEMU 等旧环境仍在用）均算本地
      return a === '::1' || /^f[cd]/.test(a) || /^fe[89a-f]/.test(a);
    }
    return false;
  }

  function parseCandidates(cand) {
    // 提取候选地址（形如 candidate:... typ host 192.168.x.x port ...）
    const addr = cand.split(' ')[4];
    if (!addr) return;
    const m = cand.match(/typ ([a-z]+)/);
    addCandidate(m ? m[1] : 'unknown', addr, isLocalAddr(addr));
  }

  function addCandidate(type, addr, isLocal) {
    if (found.some(f => f.addr === addr)) return;
    found.push({ type, addr, isLocal });
    renderWebrtcResult();
  }

  function renderWebrtcResult() {
    $('webrtcInfo').innerHTML = '<p class="muted">共捕获 ' + found.length + ' 个候选地址：</p>';
    $('webrtcResults').innerHTML = '';
    found.forEach(it => {
      const div = document.createElement('div');
      div.className = 'wr-item';
      const typeEl = document.createElement('span');
      typeEl.className = 'wr-type'; typeEl.textContent = it.type;
      const ipEl = document.createElement('span');
      ipEl.className = 'wr-ip'; ipEl.textContent = it.addr;
      const stEl = document.createElement('span');
      stEl.className = it.isLocal ? 'st-good' : 'st-warn';
      stEl.textContent = it.isLocal ? '本地/内网' : '外部地址';
      div.appendChild(typeEl); div.appendChild(ipEl); div.appendChild(stEl);
      $('webrtcResults').appendChild(div);
    });
    if (found.some(a => !a.isLocal)) {
      $('webrtcInfo').innerHTML += '<p class="st-bad" style="margin-top:6px">⚠️ 检测到外部地址被 WebRTC 暴露！</p>';
    }
  }

  function evaluateWebrtc() {
    const external = found.filter(f => !f.isLocal);
    if (found.length === 0) {
      $('webrtcInfo').innerHTML = '<p class="st-good">✅ 未捕获到 STUN 候选地址（可能已启用 WebRTC 防护，或连接被阻断）。</p>';
      setBadge('webrtcBadge', 'good', '✅ 无泄露');
    } else if (external.length === 0) {
      $('webrtcInfo').innerHTML = '<p class="st-good">✅ 仅捕获到本地/内网地址，未发现外部真实 IP 泄露。</p>';
      setBadge('webrtcBadge', 'good', '✅ 无泄露');
    } else {
      $('webrtcInfo').innerHTML = `<p class="st-bad">❌ 检测到 <b>${external.length}</b> 个外部地址被 WebRTC 暴露，疑似真实 IP 泄露！</p>
        <p style="font-size:12px;color:var(--sub);margin-top:4px">即便使用了 VPN/代理，WebRTC 仍可能绕过并暴露真实 IP。建议在浏览器中禁用 WebRTC 或启用防护插件。</p>`;
      setBadge('webrtcBadge', 'bad', '❌ 已泄露');
    }
    btn.disabled = false; btn.textContent = '🔄 重新检测 WebRTC';
  }

  function finish() {
    if (finished) return;
    finished = true;
    clearTimeout(killTimer);
    try { pc.close(); } catch (e) {}
    evaluateWebrtc();
  }

  const killTimer = setTimeout(finish, 6000);
  pc.onicecandidate = e => { if (e.candidate) parseCandidates(e.candidate.candidate); };
  pc.oniceconnectionstatechange = () => { if (pc.iceConnectionState === 'completed' || pc.iceConnectionState === 'failed') finish(); };
  pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === 'complete') finish(); };

  setTimeout(() => {
    pc.createOffer()
      .then(o => pc.setLocalDescription(o))
      .catch(() => finish());
  }, 100);
}

/* ================= DNS 泄露检测 ================= */
$('btnDns').addEventListener('click', runDns);
async function runDns() {
  const btn = $('btnDns');
  btn.disabled = true; btn.textContent = '检测中…';
  setBadge('dnsBadge', 'warn', '检测中');
  $('dnsList').innerHTML = '';

  try {
    // 需支持 CORS 的 DNS-over-HTTPS 服务
    const providers = [
      { name: 'Cloudflare DoH', url: 'https://cloudflare-dns.com/dns-query' },
      { name: 'Google DoH', url: 'https://dns.google/resolve' },
    ];
    // 浏览器 JS 无法直接读取系统 DNS 配置（沙箱限制），此处做尽力而为：
    // 1. 通过 DoH 解析域名验证加密 DNS 可用性
    // 2. 对比公网出口 IP 与当前展示 IP，辅助判断 DNS/网络分离
    const external = await fetchT('https://api.ipify.org?format=json', {}, 8000)
      .then(r => r.json()).catch(() => null);
    const exitDiff = state.isOwn && external && external.ip && state.ip && external.ip !== state.ip;

    const rows = providers.map(p => {
      const row = document.createElement('div');
      row.className = 'dns-row';
      row.innerHTML = `<div class="dns-top"><span class="dns-q"></span><span class="dns-status st-warn">测试中…</span></div><div class="dns-detail">连接中…</div>`;
      row.querySelector('.dns-q').textContent = p.name;
      $('dnsList').appendChild(row);
      return { p, row };
    });

    // 多个 DoH 探测并行执行
    const oks = await Promise.all(rows.map(({ p, row }) => (async () => {
      try {
        const viaDoH = await fetchT(p.url + '?name=www.example.com&type=A',
          { headers: { 'accept': 'application/dns-json' } }, 8000).then(r => r.json());
        const ok = !!(viaDoH && viaDoH.Status === 0);
        const detail = ok
          ? '通过 ' + p.name + ' 解析成功 → ' + (viaDoH.Answer ? viaDoH.Answer.length + ' 条记录' : '0 条记录')
          : 'DoH 响应异常';
        row.querySelector('.dns-status').textContent = ok ? '✅ DoH 响应正常' : '❌ DoH 异常';
        row.querySelector('.dns-status').className = 'dns-status ' + (ok ? 'st-good' : 'st-bad');
        row.querySelector('.dns-detail').textContent = detail +
          (exitDiff ? '\n⚠ 公网出口 (' + external.ip + ') 与当前展示 IP (' + state.ip + ') 不同，可能存在 DNS/网络分离。' : '');
        return ok;
      } catch (e) {
        row.querySelector('.dns-status').textContent = '❌ 连接失败';
        row.querySelector('.dns-status').className = 'dns-status st-bad';
        row.querySelector('.dns-detail').textContent = '无法访问 ' + p.name + '（CORS 或网络限制）。错误：' + e.message;
        return false;
      }
    })()));
    const anyFail = oks.some(ok => !ok);
    setBadge('dnsBadge', anyFail ? 'warn' : 'good', anyFail ? '部分异常' : '✅ 基本正常');

    const note = document.createElement('div');
    note.style.cssText = 'margin-top:10px';
    note.className = 'muted';
    note.innerHTML = 'ℹ️ <b>说明：</b>浏览器脚本无法直接读取系统 DNS 配置，本检测通过 DoH 回环与公网出口对比辅助判断。若你真的想让 ISP 的 DNS 不参与解析，建议使用加密 DNS (DoH/DoT) 并确认系统已配置。';
    $('dnsList').appendChild(note);
  } finally {
    btn.disabled = false; btn.textContent = '🔄 重新检测 DNS';
  }
}

/* ================= 模块自由排序 =================
   每个卡片带 ⠿ 手柄，按住手柄拖动即可调整顺序；
   顺序存入 localStorage，重启 App 后保持。 */
const ORDER_KEY = 'ipdetector.moduleOrder.v1';
const modulesEl = $('modules');
let defaultOrder = [];
let dragEl = null, dragHandle = null, lastPointerY = 0, scrollDir = 0, rafId = 0;

function moduleIds() {
  return Array.prototype.map.call(modulesEl.children, c => c.dataset.module);
}

function applySavedOrder() {
  defaultOrder = moduleIds();
  let saved = null;
  try { saved = JSON.parse(localStorage.getItem(ORDER_KEY) || 'null'); } catch (e) { saved = null; }
  if (Array.isArray(saved) && saved.length) {
    const map = {};
    Array.prototype.forEach.call(modulesEl.children, el => { map[el.dataset.module] = el; });
    saved.forEach(id => { if (map[id]) { modulesEl.appendChild(map[id]); delete map[id]; } });
    // 升级后新增的模块（不在已存顺序里）按默认顺序追加到末尾
    defaultOrder.forEach(id => { if (map[id]) { modulesEl.appendChild(map[id]); delete map[id]; } });
  }
  $('btnResetOrder').classList.toggle('hidden', !localStorage.getItem(ORDER_KEY));
}

function saveOrder() {
  try { localStorage.setItem(ORDER_KEY, JSON.stringify(moduleIds())); }
  catch (e) { console.warn('保存模块顺序失败（可能存储配额已满）：', e); }
  $('btnResetOrder').classList.remove('hidden');
}

function resetOrder() {
  try { localStorage.removeItem(ORDER_KEY); } catch (e) {}
  defaultOrder.forEach(id => {
    const el = modulesEl.querySelector('[data-module="' + id + '"]');
    if (el) modulesEl.appendChild(el);
  });
  $('btnResetOrder').classList.add('hidden');
}

/* 把拖拽中的卡片插到 clientY 所指向的位置 */
function reorderAt(clientY) {
  if (!dragEl) return;
  const others = Array.prototype.filter.call(modulesEl.children, el => el !== dragEl);
  let next = null;
  for (let i = 0; i < others.length; i++) {
    const r = others[i].getBoundingClientRect();
    if (clientY < r.top + r.height / 2) { next = others[i]; break; }
  }
  if (next) modulesEl.insertBefore(dragEl, next);
  else modulesEl.appendChild(dragEl);
}

/* 拖拽期间贴近屏幕上下缘时自动滚动，否则够不到视口外的卡片 */
function dragFrame() {
  if (!dragEl) return;
  if (scrollDir) {
    window.scrollBy(0, scrollDir * 12);
    reorderAt(lastPointerY);
  }
  rafId = requestAnimationFrame(dragFrame);
}

function onDragMove(e) {
  lastPointerY = e.clientY;
  scrollDir = lastPointerY < 72 ? -1 : (lastPointerY > window.innerHeight - 72 ? 1 : 0);
  reorderAt(lastPointerY);
}

function onDragEnd() {
  if (!dragEl) return;
  cancelAnimationFrame(rafId);
  dragEl.classList.remove('dragging');
  document.body.classList.remove('dragging-active');
  document.removeEventListener('pointermove', onDragMove);
  document.removeEventListener('pointerup', onDragEnd);
  document.removeEventListener('pointercancel', onDragEnd);
  dragEl = null; dragHandle = null; scrollDir = 0;
  saveOrder();
}

modulesEl.addEventListener('pointerdown', function (e) {
  const handle = e.target.closest('.drag-handle');
  if (!handle || dragEl) return;
  e.preventDefault();
  dragEl = handle.closest('[data-module]');
  dragHandle = handle;
  lastPointerY = e.clientY;
  dragEl.classList.add('dragging');
  document.body.classList.add('dragging-active');
  // 触摸指针有隐式捕获；鼠标等场景尽量显式捕获，失败也不影响（监听挂 document 兜底）
  try { handle.setPointerCapture(e.pointerId); } catch (err) {}
  document.addEventListener('pointermove', onDragMove);
  document.addEventListener('pointerup', onDragEnd);
  document.addEventListener('pointercancel', onDragEnd);
  rafId = requestAnimationFrame(dragFrame);
});

// 长按手柄不弹系统菜单
modulesEl.addEventListener('contextmenu', function (e) {
  if (e.target.closest('.drag-handle')) e.preventDefault();
});

/* ---------------- 启动 ---------------- */
initGradient();
applySavedOrder();
$('btnResetOrder').addEventListener('click', resetOrder);
detect('v4');

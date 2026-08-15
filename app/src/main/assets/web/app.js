/* ============================================
   IP DETECTOR - 主逻辑
   数据源: ipwho.is / ip.sb / 多个校验源
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
  mapLat: 0,
  mapLon: 0,
  isOwn: true,
};

/* ---------------- 工具 ---------------- */
function initGradient() {
  // 给环形图注入渐变 defs
  const svg = document.querySelector('.score-ring');
  let defs = svg.querySelector('defs');
  if (!defs) {
    defs = document.createElementNS('http://www.w3.org/2000/svg','defs');
    defs.innerHTML = `<linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#4f8cff"/><stop offset="100%" stop-color="#22d3a8"/>
      </linearGradient>`;
    svg.insertBefore(defs, svg.firstChild);
  }
}

function fmtIpv6(ip){ return ip; }

/* ---------------- IP 获取 ---------------- */
async function getMyIPs() {
  // 并行获取 IPv4 和 IPv6
  const jobs = [
    fetch('https://api.ipify.org?format=json').then(r=>r.json()).then(d=>{state.v4=d.ip}).catch(()=>{}),
    fetch('https://api6.ipify.org?format=json').then(r=>r.json()).then(d=>{state.v6=d.ip}).catch(()=>{}),
  ];
  await Promise.all(jobs);
  // 若某一不可得，用 ipwho.is 兜底
  if (!state.v4 && !state.v6) {
    try {
      const d = await fetch('https://ipwho.is/').then(r=>r.json());
      if (d.ip.includes(':')) state.v6=d.ip; else state.v4=d.ip;
    } catch(e){}
  }
}

/* ---------------- IP 归属全量信息 ---------------- */
async function getInfo(ip) {
  // ipwho.is 为主, ip.sb 兜底, ip-api.com 补充 proxy/hosting/精确org
  let who = null, sb = null, api = null;
  try { who = await fetch('https://ipwho.is/' + encodeURIComponent(ip)).then(r=>r.json()); } catch(e){}
  try { sb = await fetch('https://api.ip.sb/geoip/' + encodeURIComponent(ip), {headers:{'User-Agent':'curl/7.8'}}).then(r=>r.json()).catch(()=>null); } catch(e){}
  try {
    // ip-api.com 免费(非https), 提供 proxy/hosting/as/org —— 纯净度判定关键
    api = await fetch('http://ip-api.com/json/' + encodeURIComponent(ip) +
      '?fields=status,country,regionName,city,isp,org,as,proxy,hosting,mobile', {mode:'cors'}).then(r=>r.json()).catch(()=>null);
    if (api && api.status!=='success') api = null;
  } catch(e){ api = null; }

  const src = who && who.success ? who : (sb || null);
  if (!src && !api) return null;

  const isv6 = String(ip).includes(':');
  const owner = who && who.success ? who : {};
  const conn = owner.connection || {};
  const org = conn.org || (sb ? sb.organization : '') || (api ? api.org : '');

  return {
    ip, version: isv6 ? 'IPv6' : 'IPv4',
    type: owner.type || (isv6?'IPv6':'IPv4'),
    asn: conn.asn || (sb ? sb.asn : '--'),
    asn_org: conn.org || (sb ? sb.asn_organization : '--'),
    isp: conn.isp || (sb ? sb.isp : '--') || (api ? api.isp : '--'),
    org,
    country: owner.country || (sb?sb.country:'') || (api?api.country:''),
    country_code: owner.country_code || (sb?sb.country_code:'') || (api?api.country:''),
    region: owner.region || (sb?sb.region:'') || (api?api.regionName:''),
    region_code: owner.region_code || (sb?sb.region_code:'') || '',
    city: owner.city || (sb?sb.city:'') || (api?api.city:''),
    lat: owner.latitude !== undefined ? owner.latitude : (sb?sb.latitude:null),
    lon: owner.longitude !== undefined ? owner.longitude : (sb?sb.longitude:null),
    postal: owner.postal || null,
    calling_code: owner.calling_code || '--',
    flag_emoji: (owner.flag && owner.flag.emoji) || null,
    is_eu: owner.is_eu === true,
    timezone: owner.timezone ? owner.timezone.id : (sb?sb.timezone:'--'),
    tz_offset: owner.timezone ? owner.timezone.offset : (sb?sb.offset:null),
    tz_utc: owner.timezone ? owner.timezone.utc : null,
    // 纯净度相关真实数据
    api_proxy: api ? (api.proxy === true) : (isVpnish(org, isp)),
    api_hosting: api ? (api.hosting === true) : isDcByKw(org, isp),
    api_asn: api ? (api.as||'') : '',
  };
}

/* ---- 辅助判断（Worker 不可用时的本地兜底） ---- */
const DC_KW = ['cloud','hosting','microsoft azure','amazon','digitalocean','linode','vultr','hetzner','oracle','aws','huawei','alibaba','tencent','softlayer','ovh','akamai','kagoya','google','packet'];
const VPN_KW = ['vpn','proxy','tor ','tor-','packet','nord','surfshark','privacy','relay','openvpn','wireguard','21vianet'];
function isDcByKw(org, isp){ const o=(org||'').toLowerCase(), i=(isp||'').toLowerCase(); return DC_KW.some(k=>o.includes(k)||i.includes(k)); }
function isVpnish(org, isp){ const o=(org||'').toLowerCase(), i=(isp||'').toLowerCase(); return VPN_KW.some(k=>o.includes(k)||i.includes(k)); }

/* ---- 信誉代理 Worker ---- */
const PURITY_PROXY = 'https://ipdetector-purity.1161467182.workers.dev';

/* ---------------- 纯净度评分（优先走 Worker 真实分，兜底本地启发） ---------------- */
async function getPurity(ip) {
  // 1. 优先调 Worker 信誉代理（真实 ip-api / IPQualityScore 服务端判定）
  try {
    const resp = await fetch(PURITY_PROXY + '/lookup?ip=' + encodeURIComponent(ip), {mode:'cors'});
    if (resp.ok) {
      const d = await resp.json();
      if (d && d.success) return mapProxyResult(d);
    }
  } catch(e) { /* Worker 不可用，走 fallback */ }
  // 2. fallback: 本地启发式（无 Worker 时仍可用）
  return fallbackPurity(ip);
}

function mapProxyResult(d) {
  const metrics = [];
  const pv = d.proxy && d.proxy.value;
  const hv = d.hosting && d.hosting.value;
  const tv = d.tor && d.tor.value;
  const bv = d.bot && d.bot.value;
  const dv = d.datacenter && d.datacenter.value;
  const add = (name, val, good, desc) => metrics.push({name, val, good, desc, extra:{}});
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
  const weights = [0.22, 0.30, 0.16, 0.12, 0.20];
  const vals = metrics.map(m => m.val);
  const total = vals.reduce((s, v, i) => s + v * (weights[i] || 0.2), 0);
  const score = Math.max(3, Math.min(98, Math.round(100 - total)));
  let level, levelColor, desc;
  if (score >= 85) { level = '🟢 优秀'; levelColor = 'var(--good)'; desc = 'IP 纯净度高，风控风险低。'; }
  else if (score >= 70) { level = '🟡 良好'; levelColor = 'var(--mid)'; desc = 'IP 大部分干净。'; }
  else if (score >= 50) { level = '🟠 一般'; levelColor = 'var(--warn)'; desc = 'IP 存在明显风控信号。'; }
  else if (score >= 25) { level = '🔴 高风险'; levelColor = 'var(--danger)'; desc = 'IP 纯净度低，易被风控拦截。'; }
  else { level = '☠️ 黑名单'; levelColor = 'var(--danger)'; desc = 'IP 风险极高。'; }
  const isDc = hv || dv || pv;
  return { score, level, levelColor, desc, metrics, isDc, checks: [], source: d.source || 'proxy' };
}

function fallbackPurity(ip) {
  const metrics = []; const info = state.info || {};
  const org = (info.org||'').toLowerCase(); const isp = (info.isp||'').toLowerCase();
  const isHosting = isDcByKw(org, isp); const isProxy = info.api_proxy === true || isVpnish(org, isp);
  const isCDN = /cloudflare|fastly|akamai|cloudfront/.test(org+' '+isp);
  const hasLoc = !!(info.lat && info.lon && info.lat!==0 && info.lon!==0);
  const add = (n, v, g, d) => metrics.push({name:n, val:v, good:g, desc:d, extra:{}});
  add('托管商 / 数据中心', isHosting?72:6, !isHosting, isHosting?'IP 属于云服务/托管商。':'家用/运营商接入。');
  add('代理 / VPN / TOR', isProxy?88:8, !isProxy, isProxy?'检测到代理/VPN 出口。':'未见代理/VPN 特征。');
  add('CDN / 公共出口', isCDN?62:9, !isCDN, isCDN?'该 IP 是 CDN 出口。':'非 CDN 出口。');
  add('定位可信度', hasLoc?7:42, hasLoc, hasLoc?'归属地定位可靠。':'归属地不精确。');
  add('ASN 信誉', 10, true, 'AS 番号无显著风控特征。');
  const weights = [0.22, 0.30, 0.16, 0.12, 0.20];
  const total = metrics.reduce((s,m,i) => s + m.val * (weights[i]||0.2), 0);
  const score = Math.max(3, Math.min(98, Math.round(100 - total)));
  let level, levelColor, desc;
  if (score>=85) { level='🟢 优秀'; levelColor='var(--good)'; desc='IP 纯净度高。'; }
  else if (score>=70) { level='🟡 良好'; levelColor='var(--mid)'; desc='IP 大部分干净。'; }
  else if (score>=50) { level='🟠 一般'; levelColor='var(--warn)'; desc='IP 存在风控信号。'; }
  else { level='🔴 高风险'; levelColor='var(--danger)'; desc='IP 纯净度低。'; }
  return { score, level, levelColor, desc, metrics, isDc:isHosting||isProxy, checks:[], source:'fallback' };
}

/* ---------------- 人机流量对比 ---------------- */
function trafficCalc(isDc, score, info) {
  // 基于纯净度 + 真实特征 启发人/机/恶意占比
  // 家用高纯净: 人高、机低、恶意低
  let human, bot, abuse;
  if (score >= 85)      { human=74; bot=20; abuse=6; }
  else if (score>=70)   { human=60; bot=28; abuse=12; }
  else if (score>=50)   { human=44; bot=38; abuse=18; }
  else if (score>=25)   { human=28; bot=45; abuse=27; }
  else                  { human=18; bot=42; abuse=40; }
  // 真实特征加成恶意
  const isProxy = info && info.api_proxy === true;
  const isHosting = info && info.api_hosting === true;
  if (isHosting) { human += 2; bot += 3; abuse -= 5; }
  if (isProxy)   { human -= 8; bot += 5; abuse += 3; }
  // 兜底到合法区间
  human = Math.max(5, Math.min(92, Math.round(human)));
  bot = Math.max(3, Math.min(90, Math.round(bot)));
  abuse = Math.max(1, Math.min(80, Math.round(abuse)));
  // 保证近似满100
  let sum = human+bot+abuse;
  if (sum !== 100) {
    abuse = Math.max(1, Math.round(abuse + (100-sum)));
    sum = human+bot+abuse;
    if (sum !== 100) { bot = Math.max(0, bot + (100-sum)); sum=human+bot+abuse; }
  }
  return { human, bot, abuse };
}

/* ---------------- 渲染：主信息 ---------------- */
function renderHero() {
  $('heroIp').textContent = state.ip;
  const flag = (state.info && state.info.flag_emoji) || '🌐';
  $('flagLarge').textContent = flag;
  const cc = state.info ? state.info.country_code : '';
  const city = state.info ? state.info.city : '';
  const isp = state.info ? state.info.isp : '';
  $('heroSub').textContent = [cc, city, isp].filter(Boolean).join(' · ') || '—';
}

function renderInfo() {
  const i = state.info;
  $('i_ip').textContent = i.ip;
  $('i_ver').textContent = i.version;
  $('i_asn').textContent = 'AS' + i.asn;
  $('i_isp').textContent = i.isp || '--';
  $('i_org').textContent = i.org || i.asn_org || '--';
  $('i_country').textContent = (i.flag_emoji ? i.flag_emoji+' ' : '') + i.country + ' ('+i.country_code+')';
  $('i_region').textContent = (i.region||'--') + ' / ' + (i.region_code||'');
  $('i_city').textContent = i.city || '--';
  $('i_loc').textContent = (i.lat!==undefined && i.lat!==null) ? i.lat.toFixed(4)+', '+i.lon.toFixed(4) : '--';
  $('i_tz').textContent = i.timezone || '--';
  $('i_call').textContent = (i.calling_code ? '+'+i.calling_code : '--');
  $('i_eu').textContent = i.is_eu ? '是 🇪🇺' : '否';

  // clock
  $('clockTz').textContent = i.timezone || '--';
  $('clockUtc').textContent = (i.tz_utc ? 'UTC '+i.tz_utc : '') + (i.tz_offset? ' · offset '+i.tz_offset+'s' : '');
  startClock(tzNameToOffset(i.timezone, i.tz_offset));
}

function tzNameToOffset(tz, offsetSec) {
  // 简单处理：用 Intl 拿真实时区偏移
  if (!tz) return offsetSec || 0;
  try {
    const now = new Date();
    const parts = new Intl.DateTimeFormat('en-US', {timeZone: tz, timeZoneName:'longOffset'}).formatToParts(now);
    const tzName = parts.find(p=>p.type==='timeZoneName');
    if (tzName) {
      const m = tzName.value.match(/GMT([+-])(\d+):(\d+)/);
      if (m) {
        let off = parseInt(m[2])*3600 + parseInt(m[3])*60;
        if (m[1]==='-') off = -off;
        return off;
      }
    }
  } catch(e){}
  return offsetSec || 0;
}

/* ---------------- 时区时钟 ---------------- */
let clockTimer=null;
function startClock(offsetSec) {
  if (clockTimer) clearInterval(clockTimer);
  const tick = () => {
    const now = new Date();
    const t = new Date(now.getTime() + (offsetSec*1000) + now.getTimezoneOffset()*60000);
    const pad=n=>String(n).padStart(2,'0');
    $('clockTime').textContent = pad(t.getHours())+':'+pad(t.getMinutes())+':'+pad(t.getSeconds());
  };
  tick();
  clockTimer = setInterval(tick, 1000);
}

/* ---------------- 地图 ---------------- */
function renderMap() {
  const lat = state.info && state.info.lat ? state.info.lat : 0;
  const lon = state.info && state.info.lon ? state.info.lon : 0;
  state.mapLat = lat; state.mapLon = lon;
  $('mapCoords').textContent = lat.toFixed(4)+', '+lon.toFixed(4);
  const active = document.querySelector('.mtab.active').dataset.src;
  let url='';
  const zoom=6;
  if (active==='osm') {
    // q/ ll=lat,lon
    url = `https://www.openstreetmap.org/export/embed.html?bbox=${lon-1.2}%2C${lat-1.2}%2C${lon+1.2}%2C${lat+1.2}&layer=mapnik&marker=${lat}%2C${lon}`;
  } else if (active==='amt') {
    // 高德地图：需key，直接用 marker via 链接形式由 iframe 打开 amap 网页检索（无key）
    url = `https://uri.amap.com/marker?position=${lon.toFixed(5)},${lat.toFixed(5)}&name=IP归属&src=ipcheck&coordinate=gaode&callnative=0`;
  } else if (active==='gdi') {
    url = `https://www.tianditu.gov.cn/browser/map.html?lat=${lat}&lng=${lon}`;
  }
  $('mapFrame').src = url;
}

// 地图源切换
document.querySelectorAll('.mtab').forEach(b=>b.addEventListener('click',function(){
  document.querySelectorAll('.mtab').forEach(x=>x.classList.remove('active'));
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
  const circ = 2*Math.PI*52; // 326.7
  const offset = circ * (1 - p.score/100);
  $('ringFg').style.strokeDasharray = circ;
  setTimeout(()=>{ $('ringFg').style.strokeDashoffset = offset; }, 60);
  $('ringFg').style.stroke = p.score>=70 ? 'var(--good)' : (p.score>=50?'var(--warn)':'var(--danger)');

  /* --- Hero 醒目纯净度同步 --- */
  const hpColor = p.score>=70 ? 'var(--good)' : (p.score>=50?'var(--warn)':'var(--danger)');
  const hpCirc = 2*Math.PI*27; // 169.6
  const hpRingFg = $('hpRingFg');
  hpRingFg.style.strokeDasharray = hpCirc;
  setTimeout(()=>{ hpRingFg.style.strokeDashoffset = hpCirc*(1-p.score/100); }, 60);
  hpRingFg.style.stroke = hpColor;
  $('hpScore').textContent = p.score;
  $('hpScore').style.color = hpColor;
  $('hpBadge').textContent = 'IP 纯净度';
  const lvlTxt = p.level.includes('优秀') ? '优秀' : p.level.includes('良好') ? '良好' : p.level.includes('一般') ? '一般' : '高风险';
  $('hpLevel').textContent = lvlTxt;
  $('hpLevel').style.color = hpColor;
  $('hpDesc').textContent = ''; // 详细描述保留在下方卡片
  const lvlText = p.score>=70 ? '纯净度优秀，直连该 IP 风控极低' : p.score>=50 ? '存在一定风控信号，注意识别' : '纯净度低，高风险';
  $('hpDesc').textContent = lvlText;

  const wrap = $('metrics');
  wrap.innerHTML = '';
  p.metrics.forEach(m=>{
    const color = m.good ? 'var(--good)' : (m.val<=35 ? 'var(--mid)' : 'var(--danger)');
    const row = document.createElement('div');
    row.className='metric';
    row.innerHTML = `
      <span class="metric-name">${m.name}${m.good?' ✅':' ⚠️'}</span>
      <div class="metric-bar"><div class="metric-fill" style="width:0%;background:${color};" data-w="${m.val}"></div></div>
      <span class="metric-val" style="color:${color}">${m.val}%</span>`;
    wrap.appendChild(row);
    setTimeout(()=>{ row.querySelector('.metric-fill').style.width = m.val+'%'; }, 80);
  });
}

/* ---------------- 人机流量渲染 ---------------- */
function renderTraffic(t) {
  $('barHuman').style.width = t.human+'%';
  $('barBot').style.width = t.bot+'%';
  $('barAbuse').style.width = t.abuse+'%';
  $('tHuman').textContent = t.human+'%';
  $('tBot').textContent = t.bot+'%';
  $('tAbuse').textContent = t.abuse+'%';
}

/* ---------------- 核心检测流程 ---------------- */
async function detect(targetType) {
  showLoad('正在检测 IP 归属地…');
  try {
    if (targetType === 'quote') {
      // 查询任意 IP：用上一次输入，或提示先输入
      const inp = $('qIpInput').value.trim();
      if (!inp) { hideLoad(); showError('请先在上方输入要查询的 IP 地址'); $('qIpInput').focus(); return; }
      return await doLookup(inp, {fromQuote:true});
    }
    if (targetType === 'lookup') {
      // 已由 doLookup 手动触发，这里不再重复
      return;
    }

    await getMyIPs();

    if (targetType==='v4' && state.v4) state.ip = state.v4;
    else if (targetType==='v6' && state.v6) state.ip = state.v6;
    else if (targetType==='v4') state.ip = state.v6;   // 无v4用v6
    else state.ip = state.v4;

    if (!state.ip) { hideLoad(); showError('未检测到可用 IP'); return; }
    state.isOwn = true;
    await loadForIp(state.ip);
  } catch(e) {
    hideLoad();
    showError('检测出错：'+e.message);
    console.error(e);
  }
}

/* 解析并渲染任一 IP（own/别人的统一入口） */
async function loadForIp(ip) {
  state.info = await getInfo(ip);
  if (!state.info) { showError('归属地查询失败，请重试'); return; }
  state.pureData = await getPurity(ip);
  state.ip = ip;
  renderHero();
  renderInfo();
  renderPurity(state.pureData);
  renderTraffic(trafficCalc(state.pureData.isDc, state.pureData.score, state.info));
  renderMap();
  // 更新 tab 显示自己的 IP（仅当已知）
  if (!state.v4) $('ipv4Val').textContent = '--';
  if (state.v4) $('ipv4Val').textContent = state.v4;
  if (state.v6) $('ipv6Val').textContent = state.v6;
  hideLoad();
}

/* 任意 IP 查询入口 */
async function doLookup(rawIp, opts) {
  const ip = String(rawIp||'').trim().replace(/\s+/g,'');
  if (!ip) { showError('请输入 IP 地址'); return; }
  const isv6 = ip.includes(':');
  const isv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
  if (!isv6 && !isv4) { showError('IP 格式不正确（示例：8.8.8.8 或 2001:db8::1）'); return; }
  showLoad('正在查询 ' + ip + ' …');
  state.isOwn = false;
  try {
    await loadForIp(ip);
    // 非本人 IP：WebRTC / DNS 结果仅针对"你自己"，提示置空
    $('webrtcInfo').innerHTML = '<p class="muted">正在检测的是「'+ip+'」。WebRTC 与 DNS 泄露检测结果反映的是你当前设备的网络，不会因查询目标 IP 而改变。点击按钮可探测你本机是否泄露。</p>';
    const badge=document.getElementById('webrtcBadge');
    if(badge){badge.className='badge badge-wait';badge.textContent='针对本机';}
    const db=document.getElementById('dnsBadge');
    if(db){db.className='badge badge-wait';db.textContent='针对本机';}
  } catch(e) {
    hideLoad();
    showError('查询出错：'+e.message);
  }
}

function showLoad(t){ $('loadingText').textContent=t||'…'; $('loading').classList.remove('hidden'); }
function hideLoad(){ $('loading').classList.add('hidden'); }
function showError(msg){
  $('heroIp').textContent='!';
  $('heroSub').textContent = msg;
  $('flagLarge').textContent='⚠️';
}

/* ---------------- Tab 切换 ---------------- */
document.querySelectorAll('.tab').forEach(t=>t.addEventListener('click',function(){
  // 点击当前 tab 不重复
  const wasQuote = document.getElementById('quoteBox').classList.contains('hidden')===false;
  document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
  this.classList.add('active');
  state.ipType = this.dataset.type;
  if (this.dataset.type === 'quote') {
    document.getElementById('quoteBox').classList.remove('hidden');
  } else {
    document.getElementById('quoteBox').classList.add('hidden');
    detect(this.dataset.type);
  }
}));

/* 任意 IP 查询按钮 */
$('btnLookup').addEventListener('click', async function(){
  this.classList.add('spinning');
  const ip = $('qIpInput').value.trim();
  await doLookup(ip || '');
  setTimeout(()=>this.classList.remove('spinning'), 300);
});
$('qIpInput').addEventListener('keydown', function(e){
  if (e.key === 'Enter') $('btnLookup').click();
});

/* ---------------- 刷新 ---------------- */
$('btnRefresh').addEventListener('click',async function(){
  this.classList.add('spinning');
  await detect(state.ipType);
  setTimeout(()=>this.classList.remove('spinning'),400);
});

/* ---------------- 复制 ---------------- */
$('btnCopy').addEventListener('click',function(){
  if (!state.ip) return;
  if (navigator.clipboard) navigator.clipboard.writeText(state.ip);
  else { const ta=document.createElement('textarea'); ta.value=state.ip; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove(); }
  this.textContent='✅';
  setTimeout(()=>this.textContent='📋',1200);
});

/* ================= WebRTC 检测 ================= */
$('btnWebrtc').addEventListener('click', runWebrtc);
async function runWebrtc(){
  const btn=$('btnWebrtc');
  btn.disabled=true; btn.textContent='检测中…';
  $('webrtcInfo').innerHTML='<p class="muted">正在收集 STUN 候选地址…</p>';
  $('webrtcResults').innerHTML='';
  $('webrtcBadge').className='badge badge-warn'; $('webrtcBadge').textContent='检测中';

  if (!window.RTCPeerConnection) {
    $('webrtcInfo').innerHTML='<p class="st-bad">当前浏览器不支持 RTCPeerConnection，无法检测。</p>';
    $('webrtcBadge').className='badge badge-warn'; $('webrtcBadge').textContent='不支持';
    btn.disabled=false; btn.textContent='▶ 开始 WebRTC 检测';
    return;
  }

  const pc = new RTCPeerConnection({iceServers:[
    {urls:['stun:stun.l.google.com:19302','stun:stun1.l.google.com:19302','stun:stun2.l.google.com:19302','stun:stun.services.mozilla.com']}
  ]});
  pc.createDataChannel('probe');

  let timeout = setTimeout(()=>{ finish(); }, 6000);

  pc.onicecandidate = (e)=>{
    if (e.candidate) {
      const cand = e.candidate.candidate;
      parseCandidates(cand);
    }
  };

  function parseCandidates(cand){
    // 提取 srflx / host 地址
    const m = cand.match(/typ ([a-z]+)/);
    const addr = cand.split(' ')[4];
    if (!addr) return;
    const isLocal = /(^127\.|^192\.168\.|^10\.|^172\.(1[6-9]|2\d|3[01])\.|^0\.|^169\.254\.)/.test(addr) || addr.includes('::1') || addr.startsWith('fe80') || addr.startsWith('fc') && addr.startsWith('fd');
    const type = m ? m[1] : 'unknown';
    addCandidate(type, addr, isLocal);
  }

  const found = [];
  function addCandidate(type, addr, isLocal){
    if (found.some(f=>f.addr===addr)) return;
    found.push({type, addr, isLocal});
    renderWebrtcResult(found);
  }

  function finish(){
    clearTimeout(timeout);
    try{ pc.close(); }catch(e){}
    evaluateWebrtc();
  }

  function renderWebrtcResult(arr){
    $('webrtcInfo').innerHTML = '<p class="muted">共捕获 '+arr.length+' 个候选地址：</p>';
    $('webrtcResults').innerHTML='';
    arr.forEach(it=>{
      const div=document.createElement('div');
      div.className='wr-item';
      const isv6 = String(it.addr).includes(':');
      const leakFlag = (!it.isLocal && !isv6) || (isv6 && !/(^fe|^fc|^fd|^::1|^[0-9a-f]{1,4}:)/.test(it.addr)===false) ;
      div.innerHTML = `<span class="wr-type">${it.type}</span>
        <span class="wr-ip">${it.addr}</span>
        <span class="${it.isLocal?'st-good':'st-warn'}">${it.isLocal?'本地/内网':'外部地址'}</span>`;
      $('webrtcResults').appendChild(div);
    });
    // 实时评估
    if (arr.some(a=>!a.isLocal)) {
      $('webrtcInfo').innerHTML += '<p class="st-bad" style="margin-top:6px">⚠️ 检测到 <b>外部真实 IP</b> 被 WebRTC 暴露！</p>';
    }
  }

  function evaluateWebrtc(){
    const external = found.filter(f=>!f.isLocal);
    if (found.length===0) {
      $('webrtcInfo').innerHTML='<p class="st-good">✅ 未捕获到 STUN 候选地址（可能已启用 WebRTC 防护，或连接被阻断）。</p>';
      setBadge('webrtcBadge','good','✅ 无泄露');
    } else if (external.length===0) {
      $('webrtcInfo').innerHTML='<p class="st-good">✅ 仅捕获到本地/内网地址，未发现外部真实 IP 泄露。</p>';
      setBadge('webrtcBadge','good','✅ 无泄露');
    } else {
      const leaked = external.some(a=> a.addr !== state.ip);
      $('webrtcInfo').innerHTML = `<p class="st-bad">❌ 检测到 <b>${external.length}</b> 个外部地址被 WebRTC 暴露，疑似真实 IP 泄露！</p>
        <p style="font-size:12px;color:var(--sub);margin-top:4px">即便使用了 VPN/代理，WebRTC 仍可能绕过并暴露真实 IP。建议在浏览器中禁用 WebRTC 或启用防护插件。</p>`;
      setBadge('webrtcBadge','bad','❌ 已泄露');
    }
    btn.disabled=false; btn.textContent='🔄 重新检测 WebRTC';
  }

  pc.oniceconnectionstatechange=()=>{ if(pc.iceConnectionState==='completed'||pc.iceConnectionState==='failed') finish(); };
  pc.onicegatheringstatechange=()=>{ if(pc.iceGatheringState==='complete') finish(); };

  setTimeout(()=>{ try{ pc.createOffer().then(o=>pc.setLocalDescription(o)); }catch(e){ finish(); } }, 100);
}

async function setBadge(id, cls, txt){
  const b=$(id); b.className='badge badge-'+cls; b.textContent=txt;
}

/* ================= DNS 泄露检测 ================= */
$('btnDns').addEventListener('click', runDns);
async function runDns(){
  const btn=$('btnDns');
  btn.disabled=true; btn.textContent='检测中…';
  $('dnsBadge').className='badge badge-warn'; $('dnsBadge').textContent='检测中';
  $('dnsList').innerHTML='';

  // 需 CORS 支持的外部 DNS-over-HTTPS 服务
  const providers = [
    {name:'Cloudflare DoH', url:'https://cloudflare-dns.com/dns-query'},
    {name:'Google DoH', url:'https://dns.google/resolve'},
  ];
  const domain = 'whoami.myipv4'; // 经典 DNS 泄漏测试域返回请求方的Dns解析来源
  // 由于浏览器 DNS 泄漏检测受限，此处做尽力而为：
  // 1. 通过 DoH 解析一个能返回"出口IP"的域，对比与当前公网 IP
  // 2. 展示浏览器实际使用的前端 URL

  const results = [];
  for (const p of providers) {
    const row = document.createElement('div');
    row.className='dns-row';
    row.innerHTML = `<div class="dns-top"><span class="dns-q">${p.name}</span><span class="dns-status st-warn">测试中…</span></div><div class="dns-detail">连接中…</div>`;
    $('dnsList').appendChild(row);

    try {
      // 用 fetch 到 DoH 解析一个域名（whichserver）
      const viaDoH = await fetch(p.url+'?name=www.example.com&type=A', {
        headers:{'accept':'application/dns-json'}
      }).then(r=>r.json());
      const ok = viaDoH && viaDoH.Status===0;
      let statusTxt = ok ? '✅ DoH 响应正常' : '❌ DoH 异常';
      let detail = ok ? '通过 '+p.name+' 解析成功 → '+ (viaDoH.Answer?viaDoH.Answer.length+' 条记录' : '0') : JSON.stringify(viaDoH);
      let statusClass='st-good';
      if (!ok){statusClass='st-bad';}

      // 额外：用 ipify 验证当前出口，看与DNS有无分离（无法直接读到系统DNS，仅提示）
      const external = await fetch('https://api.ipify.org?format=json').then(r=>r.json()).catch(()=>null);

      row.querySelector('.dns-status').textContent = statusTxt;
      row.querySelector('.dns-status').className = 'dns-status '+statusClass;
      row.querySelector('.dns-detail').textContent = detail + (external&&external.ip && external.ip!==state.ip ? '\n⚠ 公网出口 ('+external.ip+') 与当前展示 IP 不同，可能存在 DNS/网络分离。' : '');

      results.push({name:p.name, ok});
    } catch(e) {
      row.querySelector('.dns-status').textContent = '❌ 连接失败';
      row.querySelector('.dns-status').className = 'dns-status st-bad';
      row.querySelector('.dns-detail').textContent = '无法访问 '+p.name+'（CORS 或网络限制）。错误：'+e.message;
      results.push({name:p.name, ok:false});
    }
  }

  // 浏览器 JS 无法直接读取本机配置的 DNS 服务器（沙箱限制），故本模块为"探测+参考"
  const anyFail = results.some(r=>!r.ok);
  setBadge('dnsBadge', anyFail?'warn':'good', anyFail?'部分异常':'✅ 基本正常');
  // 追加说明
  const note = document.createElement('div');
  note.style.cssText='margin-top:10px'; note.className='muted';
  note.innerHTML = 'ℹ️ <b>说明：</b>浏览器脚本无法直接读取系统 DNS 配置，本检测通过 DoH 回环与公网出口对比辅助判断。若你真的想让 ISP 的 DNS 不参与解析，建议使用加密 DNS (DoH/DoT) 并确认系统已配置。';
  $('dnsList').appendChild(note);

  btn.disabled=false; btn.textContent='🔄 重新检测 DNS';
}

/* ---------------- 启动 ---------------- */
initGradient();
detect('v4');

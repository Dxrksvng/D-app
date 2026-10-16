// BridgeSecure Wallet Preview: wallet-style flow with the BridgeSecure analysis built into the confirmation.
// Real data end to end: balance + fee from the chain RPC, analysis from the backend, activity from the chain.
// Signing and broadcasting are done by the user's connected wallet (this page never holds keys).
import { RiskGuardClient, WalletManager, units, isAddress, shortAddress, parsePaymentUri } from './sdk/riskguard.js';

const CFG = window.RISKGUARD_CONFIG || { apiBase: '', defaultChainId: 43113 };
const $ = (id) => document.getElementById(id);
const el = (t, a = {}, ...k) => { const e = document.createElement(t); for (const [x, v] of Object.entries(a)) x === 'text' ? (e.textContent = v) : e.setAttribute(x, v); k.forEach((c) => c != null && e.append(c)); return e; };
const svg = (d) => { const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); s.setAttribute('viewBox', '0 0 20 20'); s.innerHTML = d; return s; };
const api = new RiskGuardClient({ apiBase: CFG.apiBase });
const S = { chains: [], chainId: CFG.defaultChainId || 43113, balance: null, gasPrice: null, to: '', wei: 0n, risk: null, busy: false };
let wallet;

const HEAD = {
  HIGH: ['CRITICAL SECURITY ALERT', 'ความเสี่ยงสูง แนะนำให้ไม่โอน'],
  MEDIUM: ['SECURITY WARNING', 'พบสัญญาณที่ควรระวัง'],
  LOW: ['LOW RISK', 'ไม่พบสัญญาณความเสี่ยงจากการตรวจ'],
};
const LV = { LOW: 'Low risk', MEDIUM: 'Caution', HIGH: 'High risk', UNKNOWN: 'No data' };   // UNKNOWN only for seals written by engine < v2.1

const chain = () => S.chains.find((c) => c.chain_id === S.chainId) || { name: 'Avalanche Fuji C-Chain', short: 'Fuji', symbol: 'AVAX', rpc: 'https://api.avax-test.network/ext/bc/C/rpc', explorer: 'https://testnet.snowtrace.io' };
function toast(m, ms = 3200) { const t = $('toast'); t.textContent = m; t.hidden = false; clearTimeout(toast.t); toast.t = setTimeout(() => (t.hidden = true), ms); }
function go(id) {
  for (const s of ['home', 'explore', 'asset', 'send', 'review', 'result']) $(s).hidden = s !== id;
  if (id !== 'explore' && typeof stopExplore === 'function') stopExplore();
  document.querySelector('.bottom-nav').hidden = id !== 'home';
  document.querySelector('.site-bar').hidden = id !== 'home';
  document.querySelector('.bar').hidden = id !== 'home';
}
async function rpc(method, params, rpcUrl = chain().rpc) {
  const r = await fetch(rpcUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  const j = await r.json(); if (j.error) throw new Error(j.error.message); return j.result;
}
const fmt = (wei, max = 6) => `${units.format(wei, 18, max)} ${chain().symbol}`;

// ------------------------------------------------------------------ init / account
async function init() {
  try { S.chains = await api.getChains(); } catch { S.chains = []; }
  wallet = new WalletManager({ chains: S.chains });
  wallet.addEventListener('account', () => { renderAccount(); refresh(); });
  wallet.addEventListener('chain', (e) => { if (S.chains.some((c) => c.chain_id === e.detail)) { S.chainId = e.detail; renderNet(); refresh(); } });
  await wallet.discover();
  await wallet.restore().catch(() => null);
  renderNet(); renderAccount(); refresh();
}
function renderNet() {
  const c = chain(); const eth = S.chainId === 1;
  $('netName').textContent = c.name.replace(' C-Chain', '');
  document.querySelectorAll('.js-netname').forEach((s) => (s.textContent = c.name.replace(' C-Chain', '')));
  if (typeof renderNfts === 'function' && $('nftList')) renderNfts(); $('amtSym').textContent = c.symbol; $('rvNet').textContent = c.name;
  for (const id of ['siteNetIc', 'tokBadge', 'tokIc', 'sendTokIc', 'sendTokBadge']) setLogo($(id), S.chainId);
  $('tokName').textContent = c.symbol;
  $('siteHost').textContent = { 43113: 'Avalanche Testnet', 43114: 'Avalanche Mainnet', 1: 'Ethereum Mainnet' }[S.chainId] || c.name;
  $('sendTokName').textContent = c.symbol;
}
// Chain marks drawn as inline SVG so they render offline and in both themes.
const LOGO_AVAX = '<svg viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="16" fill="#E84142"/><path fill="#fff" d="M20.7 16.6c.5-.8 1.2-.8 1.7 0l3.1 5.4c.5.8.1 1.5-.8 1.5h-6.2c-.9 0-1.3-.7-.8-1.5zM14.8 6.3c.5-.8 1.2-.8 1.7 0l.7 1.2 1.6 2.9c.4.8.4 1.7 0 2.5l-5.4 9.3c-.5.8-1.3 1.3-2.2 1.3H6.7c-.9 0-1.3-.7-.8-1.5z"/></svg>';
const LOGO_ETH = '<svg viewBox="0 0 32 32" aria-hidden="true"><circle cx="16" cy="16" r="16" fill="#627EEA"/><g fill="#fff"><path fill-opacity=".6" d="M16.5 4v8.9l7.5 3.3z"/><path d="M16.5 4 9 16.2l7.5-3.3z"/><path fill-opacity=".6" d="M16.5 21.97V28L24 17.6z"/><path d="M16.5 28v-6.03L9 17.6z"/><path fill-opacity=".2" d="m16.5 20.57 7.5-4.35-7.5-3.33z"/><path fill-opacity=".6" d="m9 16.22 7.5 4.35v-7.68z"/></g></svg>';
function logoFor(chainId) { return chainId === 1 ? LOGO_ETH : LOGO_AVAX; }
function setLogo(node, chainId) { node.innerHTML = logoFor(chainId); node.classList.add('logo'); node.style.background = ''; }
document.querySelectorAll('.net-stack i').forEach((n, i) => setLogo(n, [43114, 1][i]));
function renderAccount() {
  const a = wallet.account;
  $('acctName').textContent = a ? 'Account 1' : 'Connect';
  $('siteAcct').textContent = a ? 'Account 1' : 'ยังไม่ได้เชื่อมต่อ';
  $('addrShort').textContent = a ? `${a.slice(0, 7)}...${a.slice(-4)}`.toUpperCase().replace('0X', '0x') : 'ยังไม่ได้เชื่อมต่อ';
  $('copyAddr').hidden = !a;
  $('discover').href = a ? `${chain().explorer}/address/${a}` : '#';
}

// USD price (CoinGecko public API); the testnet uses the mainnet coin price, as wallets do.
const PRICE_ID = { 43113: 'avalanche-2', 43114: 'avalanche-2', 1: 'ethereum' };
async function price() {
  const id = PRICE_ID[S.chainId]; const now = Date.now();
  if (S.price && S.price.id === id && now - S.price.at < 60000) return S.price;
  try {
    const j = await (await fetch(`${CFG.apiBase || ''}/v1/price`)).json();   // backend caches one quote for all users
    S.price = { id, usd: j[id].usd, chg: j[id].usd_24h_change ?? 0, at: now };
  } catch { if (S.price?.id !== id) S.price = null; }   // keep the last good price for this coin if the API is busy
  return S.price;
}
const usd = (n) => '$' + n.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

async function refresh() {
  if (!wallet?.account) {
    $('balance').textContent = '$0.00'; $('change').textContent = '+$0.00 (+0.00%)'; $('change').className = ''; $('tokUsd').textContent = '$–'; $('tokBal').textContent = '–'; $('tokChange').textContent = '-';
    $('activity').replaceChildren(); $('actNote').textContent = 'เชื่อมต่อกระเป๋าเพื่อดูยอดเงินและประวัติ'; return;
  }
  try { S.balance = BigInt(await rpc('eth_getBalance', [wallet.account, 'latest'])); } catch { S.balance = null; }
  const amount = S.balance === null ? null : Number(units.format(S.balance, 18, 8));
  $('tokBal').textContent = amount === null ? '–' : `${amount.toFixed(3)} ${chain().symbol}`;
  const p = await price();
  if (amount === 0) {   // nothing held: no gain or loss to show, so neutral zeros like the reference wallet
    $('balance').textContent = '$0.00'; $('tokUsd').textContent = '$0.00';
    $('change').textContent = '+$0.00 (+0.00%)'; $('change').className = ''; $('tokChange').textContent = '-';
  } else if (p && amount !== null) {
    const v = amount * p.usd; const diff = v - v / (1 + p.chg / 100); const sign = diff >= 0 ? '+' : '-';
    $('balance').textContent = usd(v); $('tokUsd').textContent = usd(v);
    $('change').textContent = `${sign}${usd(Math.abs(diff))} (${sign}${Math.abs(p.chg).toFixed(2)}%)`;
    $('change').className = diff >= 0 ? 'up' : 'down';
    $('tokChange').textContent = `${sign}${Math.abs(p.chg).toFixed(2)}%`;
  } else {
    $('balance').textContent = amount === null ? '$–' : `${amount.toFixed(4)} ${chain().symbol}`; $('tokUsd').textContent = '$–'; $('change').textContent = ''; $('tokChange').textContent = '-';
  }
  loadActivity();
}
function openConnect() {
  const body = $('sheetBody'); body.replaceChildren(el('h3', { text: 'Connect a wallet to sign' }));
  const list = wallet.list();
  list.forEach((w) => {
    const b = el('button', { class: 'opt', type: 'button' }); if (w.icon) b.append(el('img', { src: w.icon, alt: '' })); b.append(w.name);
    b.onclick = async () => { try { await wallet.connect(w.uuid); $('sheet').close(); toast(`Connected ${w.name}`); if (wallet.chainId !== S.chainId) await wallet.ensureChain(S.chainId).catch(() => {}); } catch (e) { toast(WalletManager.explain(e).th); } };
    body.append(b);
  });
  if (!list.length) body.append(el('p', { class: 'muted small center', text: 'ไม่พบกระเป๋าในเบราว์เซอร์นี้ ติดตั้ง MetaMask หรือเปิดหน้านี้ในแอปกระเป๋า' }));
  if (wallet.account) { const d = el('button', { class: 'opt', type: 'button', text: 'Disconnect' }); d.onclick = async () => { await wallet.disconnect(); $('sheet').close(); }; body.append(d); }
  $('sheet').showModal();
}
function openNetworks() {
  const body = $('sheetBody'); body.replaceChildren(el('h3', { text: 'Select network' }));
  S.chains.forEach((c) => {
    const b = el('button', { class: 'opt' + (c.chain_id === S.chainId ? ' on' : ''), type: 'button', text: `${c.name}${c.testnet ? ' · testnet' : ''}` });
    b.onclick = async () => { $('sheet').close(); if (wallet.account) { try { await wallet.ensureChain(c.chain_id); } catch (e) { toast(WalletManager.explain(e).th); return; } } S.chainId = c.chain_id; renderNet(); refresh(); };
    body.append(b);
  });
  $('sheet').showModal();
}
$('sheet').addEventListener('click', (e) => { if (e.target === $('sheet')) $('sheet').close(); });

// ------------------------------------------------------------------ activity (read from chain; verified seals)
async function loadActivity() {
  const ul = $('activity'); $('actNote').textContent = 'กำลังอ่านจาก blockchain…';
  try {
    const r = await api.verifyAddress({ chainId: S.chainId, address: wallet.account });
    ul.replaceChildren();
    r.transactions.sort((a, b) => (b.block_ts || 0) - (a.block_ts || 0)).forEach((t) => {
      const v = t.verification || {};
      const li = el('li', {},
        el('span', { class: 'tx-ic' }, svg('<path d="M10 15V5M5 10l5-5 5 5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>')),
        el('div', { class: 'tx-main' }, el('b', { text: `Sent to ${shortAddress(t.to)}` }), el('span', { text: t.block_ts ? new Date(t.block_ts * 1000).toLocaleString('th-TH', { dateStyle: 'medium', timeStyle: 'short' }) : '' })),
        el('div', { class: 'tx-side' }, el('div', { text: `-${units.format(BigInt(t.value_wei), 18, 4)} ${chain().symbol}` }),
          el('span', { class: `badge ${v.valid ? v.level : 'UNKNOWN'}`, text: v.valid ? `${LV[v.level]} · TS ${v.trust_score}` : 'unverified' })));
      li.onclick = () => window.open(`verify.html?chain_id=${S.chainId}&tx=${t.tx_hash}`, '_blank', 'noopener');
      ul.append(li);
    });
    $('actNote').textContent = r.count ? '' : 'ยังไม่มีธุรกรรมที่ผ่าน BridgeSecure';
  } catch { $('actNote').textContent = 'อ่านประวัติไม่สำเร็จ กดรีเฟรช'; }
}

// ------------------------------------------------------------------ send
// Step 1: asset picker — native coin of every supported network, with real balances and USD values.
async function openAssets() {
  if (!wallet.account) { openConnect(); return; }
  $('assetSearch').value = ''; go('asset');
  const ul = $('assetList'); ul.replaceChildren(el('li', { class: 'muted small' }, 'กำลังโหลดยอดเงิน…'));
  let prices = {};
  try { prices = await (await fetch(`${CFG.apiBase || ''}/v1/price`)).json(); } catch {}
  const rows = await Promise.all(S.chains.map(async (c) => {
    let bal = null; try { bal = BigInt(await rpc('eth_getBalance', [wallet.account, 'latest'], c.rpc)); } catch {}
    const px = prices[PRICE_ID[c.chain_id]]?.usd;
    return { c, bal, usdv: bal !== null && px ? Number(units.format(bal, 18, 8)) * px : null };
  }));
  S.assets = rows; renderAssets();
}
function renderAssets() {
  const q = $('assetSearch').value.trim().toLowerCase(); const only = S.assetNet;
  const ul = $('assetList'); ul.replaceChildren();
  S.assets.filter(({ c }) => (!only || c.chain_id === only) && (!q || `${c.symbol} ${c.name}`.toLowerCase().includes(q))).forEach(({ c, bal, usdv }) => {
    const ic = el('span', { class: 'tok-wrap' }, el('span', { class: 'tok-ic' }), el('span', { class: 'tok-badge' }));
    setLogo(ic.firstChild, c.chain_id); setLogo(ic.lastChild, c.chain_id);
    const name = el('b', {}, c.symbol); if (c.testnet) name.append(el('span', { class: 'tag', text: c.short }));
    const li = el('li', {}, ic, el('div', { class: 'a-main' }, name, el('span', { text: c.name })),
      el('div', { class: 'a-right' }, el('b', { text: usdv === null ? '$–' : usd(usdv) }), el('span', { text: bal === null ? '–' : `${Number(units.format(bal, 18, 8)).toFixed(3)} ${c.symbol}` })));
    li.onclick = () => selectAsset(c.chain_id);
    ul.append(li);
  });
  if (!ul.children.length) ul.append(el('li', { class: 'muted small' }, 'ไม่พบเหรียญที่ค้นหา'));
}
async function selectAsset(chainId) {
  S.chainId = chainId; S.unit = 'native'; renderNet();
  $('toInput').value = ''; $('amtInput').value = ''; go('send');
  try { S.balance = BigInt(await rpc('eth_getBalance', [wallet.account, 'latest'])); } catch { S.balance = null; }
  await price(); validate(); $('toInput').focus();
}

// Step 2: recipient + amount. The amount can be typed in the coin or in USD (⇅).
function amountToWei() {
  const raw = $('amtInput').value.trim(); if (!raw) return 0n;
  if (S.unit === 'usd') {
    if (!S.price || !/^\d+(\.\d+)?$/.test(raw)) throw new Error('bad');
    return units.parse((Number(raw) / S.price.usd).toFixed(18));
  }
  return units.parse(raw);
}
function validate() {
  const to = $('toInput').value.trim(); const h = $('toHint'); h.className = 'hint';
  let okTo = false;
  if (!to) h.textContent = '';
  else if (!isAddress(to)) { h.textContent = 'ที่อยู่ต้องขึ้นต้นด้วย 0x และมีอักขระอีก 40 ตัว'; h.className = 'hint bad'; }
  else { okTo = true; h.textContent = ''; }
  let okAmt = false; const ah = $('amtHint'); ah.className = 'hint'; ah.textContent = '';
  try { S.wei = amountToWei(); okAmt = S.wei > 0n; } catch { S.wei = 0n; }
  const coins = Number(units.format(S.wei, 18, 8));
  $('amtAlt').textContent = S.unit === 'usd' ? `${coins} ${chain().symbol}` : (S.price ? usd(coins * S.price.usd) : '$–');
  $('amtAvail').textContent = S.balance === null ? '' : `${Number(units.format(S.balance, 18, 5))} ${chain().symbol} available`;
  if (okAmt && S.balance !== null && S.wei > S.balance) { ah.textContent = 'ยอดเงินไม่พอ'; ah.className = 'hint bad'; okAmt = false; }
  $('continueBtn').disabled = !(okTo && okAmt);
}
function applyText(text) {
  const p = parsePaymentUri(text); if (!p) { toast('ไม่พบที่อยู่ในข้อความนี้'); return; }
  $('toInput').value = p.address; if (p.valueWei) { S.unit = 'native'; $('amtSym').textContent = chain().symbol; $('amtInput').value = units.format(p.valueWei, 18, 18); }
  if (p.chainId && p.chainId !== S.chainId && S.chains.some((c) => c.chain_id === p.chainId)) { S.chainId = p.chainId; renderNet(); }
  validate();
}

// ------------------------------------------------------------------ review (analysis built in)
async function openReview() {
  S.to = $('toInput').value.trim(); S.risk = null;
  $('rvAmount').textContent = fmt(S.wei, 8); $('rvFrom').textContent = wallet.account ? `Account 1 · ${shortAddress(wallet.account)}` : 'Not connected';
  $('rvTo').textContent = shortAddress(S.to); $('rvTo').className = 'mono'; $('rvNet').textContent = chain().name;
  $('ackRow').hidden = true; $('ack').checked = false; $('confirmBtn').disabled = true; $('confirmBtn').className = 'primary'; $('confirmBtn').textContent = 'Confirm';
  const an = $('analysis'); an.dataset.level = ''; an.classList.add('loading');
  $('anBody').replaceChildren(el('div', { class: 'skeleton' }), el('div', { class: 'skeleton short' }), el('p', { class: 'muted small center', text: 'กำลังวิเคราะห์ที่อยู่ปลายทางจาก blockchain…' }));
  go('review');
  rpc('eth_gasPrice', []).then((g) => {
    S.gasPrice = BigInt(g); const fee = S.gasPrice * 23000n;   // 21k transfer + ~2k for the attestation bytes
    $('rvFee').textContent = fee < 10n ** 12n ? `< 0.000001 ${chain().symbol}` : `≈ ${fmt(fee, 9)}`;
  }).catch(() => ($('rvFee').textContent = '–'));
  try { S.risk = await api.checkRisk({ chainId: S.chainId, to: S.to, from: wallet.account || undefined, valueWei: wallet.account ? S.wei : undefined }); }
  catch (e) { S.risk = { level: 'MEDIUM', error: true, signals: [], message: e.body?.message?.th }; }
  renderAnalysis(S.risk);
}

function validationText(v) {
  if (!v?.status) return '';
  if (v.status === 'validated') { const c = v[S.chainId === 1 ? 'ethereum' : 'avalanche'] || v.ethereum; return `ทดสอบย้อนหลังกับธุรกรรมจริงปี 2024–26: จับได้ ${Math.round(c.recall * 100)}% เตือนผิด ${(c.fpr * 100).toFixed(1)}%`; }
  return { deterministic: 'ตรวจแบบตรงตัว ไม่ใช่การคาดเดา', 'validated-low-recall': 'ผ่านการทดสอบ เตือนผิดต่ำ แต่พบไม่บ่อย', 'not-yet-validated': 'ยังไม่ได้วัดผลในการทดสอบย้อนหลัง', unverified: 'ข้อมูลจากผู้ใช้ ยังไม่ได้ตรวจยืนยัน' }[v.status] || '';
}

function renderAnalysis(r) {
  const an = $('analysis'); an.classList.remove('loading'); an.dataset.level = r.level;
  const body = $('anBody'); body.replaceChildren();
  if (r.error) {
    body.append(el('p', { class: 'an-level', text: 'SECURITY WARNING' }), el('h3', { class: 'an-title', text: 'ระวัง: ยังตรวจที่อยู่นี้ไม่สำเร็จ' }),
      el('p', { class: 'an-lead', text: `เหตุผล: เชื่อมต่อระบบวิเคราะห์ไม่ได้ (${r.message || 'เครือข่ายขัดข้อง'}) จึงยืนยันไม่ได้ว่าปลอดภัย ลองกด Cancel แล้วตรวจใหม่ หรือยืนยันที่อยู่กับผู้รับผ่านช่องทางอื่นก่อนโอน` }));
  } else {
    const [head, line] = HEAD[r.level] || HEAD.MEDIUM;
    body.append(el('p', { class: 'an-level', text: head }), el('h3', { class: 'an-title', text: line }),
      el('p', { class: 'an-lead', text: r.verdict?.th || '' }),
      el('div', { class: 'score' }, el('span', { text: 'Trust Score' }), el('b', { text: `${r.trust_score}/100` })));
    const ol = el('ul', { class: 'reasons' });
    [...r.signals.filter((s) => s.severity !== 'info'), ...r.signals.filter((s) => s.severity === 'info')].forEach((s) => {
      const li = el('li', { class: s.severity }, el('b', { text: s.title.th }), el('p', { text: s.detail.th }));
      const vt = validationText(s.validation); if (vt) li.append(el('span', { class: 'val', text: vt }));
      if (s.evidence_tx?.[0] && r.explorer) li.append(el('a', { href: `${r.explorer}/tx/${s.evidence_tx[0]}`, target: '_blank', rel: 'noopener', text: 'ดูธุรกรรมที่เป็นหลักฐาน' }));
      ol.append(li);
    });
    // Every check that ran, so each verdict shows its work: ✓ passed, ⚠ found something, – could not be checked.
    const ck = el('ul', { class: 'checks' });
    (r.checks || []).forEach((c) => ck.append(el('li', { class: c.result }, el('span', { class: 'ck-ic', text: { pass: '✓', flag: '⚠', skip: '–' }[c.result] }), el('span', { text: c.th }))));
    const ckBox = el('div', { class: 'checks-box' }, el('b', { text: `สิ่งที่ตรวจแล้ว (${(r.checks || []).length} ข้อ)` }), ck);
    const dl = el('dl', { class: 'an-meta' });
    [['ปลายทาง', S.to], ['จำนวน', fmt(S.wei, 8)], ['ประวัติที่วิเคราะห์', `${r.stats?.n_all_chains ?? r.stats?.n_total ?? 0} ธุรกรรม (ทุกเครือข่าย)`], ['แหล่งข้อมูล', (r.data_sources || []).join(', ')], ['เวลาวิเคราะห์', `${r.latency_ms} ms`], ['รหัสอ้างอิง', r.request_id]]
      .forEach(([k, v]) => dl.append(el('dt', { text: k }), el('dd', { text: String(v) })));
    body.append(ol, ckBox, dl, el('p', { class: 'an-foot', text: 'BridgeSecure เตือน ไม่บล็อก การตัดสินใจเป็นของคุณ' }));
    if (r.level === 'HIGH') { $('rvTo').className = 'mono to-risk'; $('rvTo').textContent = `⚠ ${shortAddress(S.to)}`; }
  }
  const high = r.level === 'HIGH';
  $('ackRow').hidden = !high;
  $('confirmBtn').className = high ? 'primary danger' : 'primary';
  $('confirmBtn').disabled = high;
}

// ------------------------------------------------------------------ confirm → real transfer via connected wallet
async function confirm() {
  if (S.busy) return;
  if (!wallet.account) { openConnect(); return; }
  S.busy = true; go('result');
  setResult('spin', 'ยืนยันในกระเป๋าที่เชื่อมต่อ…', 'กระเป๋าของคุณจะขอให้เซ็นธุรกรรม');
  try {
    await wallet.ensureChain(S.chainId);
    const att = S.risk?.attestation; const fresh = att && att.valid_until * 1000 > Date.now() && att.bound_to.value_wei === S.wei.toString();
    const hash = await wallet.sendNative({ to: S.to, valueWei: S.wei, data: fresh ? att.data_hex : undefined });
    setResult('spin', 'ส่งแล้ว รอเครือข่ายยืนยัน…', hash, `${chain().explorer}/tx/${hash}`);
    const rc = await wallet.waitForReceipt(hash);
    let v = null;
    if (fresh) for (let i = 0; i < 4 && !v?.verification; i++) { try { v = await api.verifyTx({ chainId: S.chainId, txHash: hash }); } catch {} if (!v?.verification) await new Promise((ok) => setTimeout(ok, 1500)); }
    setResult(rc.success ? 'ok' : 'bad', rc.success ? 'โอนสำเร็จ' : 'ธุรกรรมล้มเหลว', `${fmt(S.wei, 8)} → ${shortAddress(S.to)}`, `${chain().explorer}/tx/${hash}`, v?.verification);
  } catch (e) {
    setResult('bad', 'ไม่ได้โอน', e.message === 'RECEIPT_TIMEOUT' ? 'ยังไม่ได้รับการยืนยันภายใน 2 นาที' : WalletManager.explain(e).th);
  } finally { S.busy = false; $('doneBtn').hidden = false; }
}
function setResult(state, title, sub, link, seal) {
  const ic = $('resIcon'); ic.className = 'res-icon' + (state === 'spin' ? ' spin' : state === 'bad' ? ' bad' : ''); ic.textContent = state === 'ok' ? '✓' : state === 'bad' ? '!' : '';
  $('resTitle').textContent = title; $('resSub').textContent = sub || '';
  $('resLink').hidden = !link; if (link) $('resLink').href = link;
  const s = $('resSeal'); s.hidden = !seal?.valid;
  if (seal?.valid) s.replaceChildren(el('b', { text: 'Verified by BridgeSecure' }), el('span', { text: `${LV[seal.level]} · Trust Score ${seal.trust_score}/100 · ตราบันทึกอยู่บน blockchain` }));
  $('doneBtn').hidden = state === 'spin';
}

// ------------------------------------------------------------------ events
$('acctBtn').onclick = openConnect;
$('netBtn').onclick = openNetworks;
$('copyAddr').onclick = async () => { try { await navigator.clipboard.writeText(wallet.account); toast('คัดลอกที่อยู่แล้ว'); } catch { toast(wallet.account); } };
$('sendBtn').onclick = openAssets;
$('assetSearch').oninput = renderAssets;
$('assetNetBtn').onclick = () => {
  const body = $('sheetBody'); body.replaceChildren(el('h3', { text: 'Networks' }));
  const opt = (label, id) => { const b = el('button', { class: 'opt' + ((S.assetNet || 0) === id ? ' on' : ''), type: 'button', text: label }); b.onclick = () => { S.assetNet = id || null; $('assetNetLabel').textContent = label; $('sheet').close(); renderAssets(); }; body.append(b); };
  opt('All networks', 0); S.chains.forEach((c) => opt(c.name, c.chain_id));
  $('sheet').showModal();
};
$('unitBtn').onclick = async () => {
  if (!S.price) await price();
  if (!S.price) { toast('ยังดึงราคา USD ไม่ได้ ลองใหม่อีกครั้ง'); return; }
  let wei = 0n; try { wei = amountToWei(); } catch {}
  S.unit = S.unit === 'usd' ? 'native' : 'usd';
  $('amtSym').textContent = S.unit === 'usd' ? 'USD' : chain().symbol;
  if (wei > 0n) {
    const coins = Number(units.format(wei, 18, 8)); const v = S.price ? coins * S.price.usd : 0;
    // keep small amounts visible instead of rounding them to 0.00
    $('amtInput').value = S.unit === 'usd' ? (S.price ? (v >= 0.01 ? v.toFixed(2) : v.toFixed(6).replace(/0+$/, '')) : '') : units.format(S.lastWei ?? wei, 18, 18);
    S.lastWei = wei;
  }
  validate();
};
$('recvBtn').onclick = () => { if (!wallet.account) { openConnect(); return; } $('sheetBody').replaceChildren(el('h3', { text: 'Receive' }), el('p', { class: 'mono center', text: wallet.account }), el('p', { class: 'muted small center', text: `ส่งเฉพาะเหรียญบน ${chain().name}` })); $('sheet').showModal(); };
$('refreshAct').onclick = refresh;
const soon = (name) => toast(`${name}: เร็ว ๆ นี้`);
$('buyBtn').onclick = () => { const c = chain(); if (c.testnet && c.faucet) window.open(c.faucet, '_blank', 'noopener'); else soon('Buy'); };
$('swapBtn').onclick = () => soon('Swap');
$('sortBtn').onclick = () => soon('เรียงลำดับ');
$('navPerps').onclick = () => soon('Perps');
// home panels: tokens / defi / nfts (tabs) and activity (bottom nav)
function tab(which) {
  for (const [t, p] of [['tokens', 'Tokens'], ['defi', 'Defi'], ['nfts', 'Nfts']]) { $('tab' + p).classList.toggle('on', which === t); $('panel' + p).hidden = which !== t; }
  $('panelActivity').hidden = which !== 'activity';
  document.querySelector('.tabs').hidden = which === 'activity';
  $('navHome').classList.toggle('on', which !== 'activity'); $('navActivity').classList.toggle('on', which === 'activity');
}
$('tabTokens').onclick = () => tab('tokens');
$('tabDefi').onclick = () => tab('defi');
$('tabNfts').onclick = () => tab('nfts');
$('navHome').onclick = () => { go('home'); tab('tokens'); };
$('navActivity').onclick = () => { go('home'); tab('activity'); };
$('siteNet').onclick = openNetworks;
// Theme toggle (light / dark), remembered per browser.
const SUN = '<circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M12 2.8v2.4M12 18.8v2.4M2.8 12h2.4M18.8 12h2.4M5.5 5.5l1.7 1.7M16.8 16.8l1.7 1.7M5.5 18.5l1.7-1.7M16.8 7.2l1.7-1.7" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>';
const MOON = '<path d="M19.5 14.5A7.5 7.5 0 0 1 9.5 4.5a7.5 7.5 0 1 0 10 10z" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>';
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  const b = $('siteSettings'); b.querySelector('svg').innerHTML = t === 'dark' ? MOON : SUN;
  b.setAttribute('aria-label', t === 'dark' ? 'เปลี่ยนเป็นธีมสว่าง' : 'เปลี่ยนเป็นธีมมืด');
  try { localStorage.setItem('bs.theme', t); } catch {}
}
$('siteSettings').onclick = () => applyTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
let savedTheme = 'light'; try { savedTheme = localStorage.getItem('bs.theme') || 'light'; } catch {}
applyTheme(savedTheme);
$('moreBtn').onclick = () => $('menuBtn').click();
$('siteDisconnect').onclick = async () => { if (wallet.account) { await wallet.disconnect(); toast('ตัดการเชื่อมต่อแล้ว'); } else openConnect(); };
// ------------------------------------------------------------------ explore: trending crypto · perps · stocks (live)
const EX = { tab: 'all', data: null, timer: null, ws: null };
const compact = (n) => n == null ? '–' : '$' + Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 2 }).format(n);
function priceText(p, kind) {
  if (p == null) return '$–';
  if (p >= 1) return '$' + p.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  if (kind === 'crypto' && p < 0.01) return '<$0.01';
  return '$' + Number(p.toPrecision(4)).toString();
}
function rowEl(x, kind) {
  const ic = el('span', { class: 'mk-ic' });
  if (x.image) { const im = el('img', { src: x.image, alt: '', loading: 'lazy' }); im.onerror = () => { im.remove(); ic.textContent = x.symbol.slice(0, 1); }; ic.append(im); } else ic.textContent = x.symbol.slice(0, 1);
  const name = el('b', {}, x.name); if (kind === 'perps' && x.max_leverage) name.append(el('span', { class: 'lev', text: `${x.max_leverage}x` }));
  const sub = kind === 'perps' ? `${x.symbol} · ${compact(x.volume)} Vol` : `${compact(x.market_cap)} cap · ${compact(x.volume)} vol`;
  const chg = x.change_24h;
  const row = el('div', { class: 'mk-row', 'data-id': `${kind}:${x.id}` }, ic, el('div', { class: 'mk-main' }, name, el('span', { text: sub })),
    el('div', { class: 'mk-right' }, el('b', { text: priceText(x.price, kind) }), el('span', { class: chg == null ? '' : chg >= 0 ? 'up' : 'down', text: chg == null ? '–' : `${chg >= 0 ? '+' : ''}${chg.toFixed(2)}%` })));
  return row;
}
function renderExplore() {
  const body = $('exBody'); if (!EX.data) return; body.replaceChildren();
  const q = $('exSearch').value.trim().toLowerCase();
  const sections = [['crypto', 'Crypto'], ['perps', 'Perps'], ['stocks', 'Stocks']].filter(([k]) => EX.tab === 'all' || EX.tab === k);
  let shown = 0;
  for (const [k, title] of sections) {
    let rows = (EX.data[k] || []).filter((x) => !q || `${x.name} ${x.symbol}`.toLowerCase().includes(q));
    if (!rows.length) continue;
    if (EX.tab === 'all' && !q) rows = rows.slice(0, 3);
    const va = el('button', { class: 'view-all', type: 'button' }, 'View all', svg('<path d="m7 4 6 6-6 6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>'));
    va.onclick = () => setExTab(k);
    const sec = el('div', { class: 'ex-sec' }, el('div', { class: 'ex-sec-head' }, el('h3', { text: title }), EX.tab === 'all' ? va : el('span')));
    rows.forEach((x) => sec.append(rowEl(x, k))); body.append(sec); shown += rows.length;
  }
  if (!shown) body.append(el('p', { class: 'muted center', text: q ? 'ไม่พบสินทรัพย์ที่ค้นหา' : 'ยังไม่มีข้อมูล' }));
}
function setExTab(t) { EX.tab = t; document.querySelectorAll('.ex-tabs .tab').forEach((b) => b.classList.toggle('on', b.dataset.ex === t)); renderExplore(); $('exBody').scrollTop = 0; }
async function loadMarket() {
  try {
    EX.data = await (await fetch(`${CFG.apiBase || ''}/v1/market`)).json();
    renderExplore();
    $('exUpdated').textContent = `Live · อัปเดต ${new Date().toLocaleTimeString('th-TH')} · Perps เรียลไทม์จาก Hyperliquid`;
  } catch { $('exUpdated').textContent = 'โหลดราคาไม่สำเร็จ จะลองใหม่อัตโนมัติ'; }
}
function connectPerpsStream() {
  try {
    const ws = new WebSocket('wss://api.hyperliquid.xyz/ws'); EX.ws = ws;
    ws.onopen = () => ws.send(JSON.stringify({ method: 'subscribe', subscription: { type: 'allMids' } }));
    ws.onmessage = (ev) => {
      const m = JSON.parse(ev.data); if (m.channel !== 'allMids' || !EX.data) return;
      const mids = m.data.mids;
      for (const x of EX.data.perps || []) {
        const nv = Number(mids[x.name]); if (!nv || nv === x.price) continue;
        const prev = x.change_24h != null && x.price ? x.price / (1 + x.change_24h / 100) : null;
        const dir = nv > x.price ? 'flash-up' : 'flash-down'; x.price = nv; if (prev) x.change_24h = (nv - prev) / prev * 100;
        const row = document.querySelector(`[data-id="perps:${CSS.escape(x.id)}"]`);
        if (row) {
          row.querySelector('.mk-right b').textContent = priceText(nv, 'perps');
          const s = row.querySelector('.mk-right span'); s.className = x.change_24h >= 0 ? 'up' : 'down'; s.textContent = `${x.change_24h >= 0 ? '+' : ''}${x.change_24h.toFixed(2)}%`;
          row.classList.remove('flash-up', 'flash-down'); void row.offsetWidth; row.classList.add(dir); setTimeout(() => row.classList.remove(dir), 600);
        }
      }
    };
    ws.onclose = () => { if (EX.ws === ws && !$('explore').hidden) setTimeout(connectPerpsStream, 3000); };
  } catch {}
}
function openExplore() {
  go('explore'); $('exSearch').value = ''; setExTab('all');
  loadMarket(); clearInterval(EX.timer); EX.timer = setInterval(loadMarket, 15000);
  if (!EX.ws) connectPerpsStream();
}
function stopExplore() { clearInterval(EX.timer); EX.timer = null; if (EX.ws) { const w = EX.ws; EX.ws = null; try { w.close(); } catch {} } }
$('searchBtn').onclick = openExplore;

// ------------------------------------------------------------------ NFTs: import with on-chain ownership check + BridgeSecure contract check
const nftKey = () => `bs.nfts.${S.chainId}.${wallet?.account || ''}`;
const loadNfts = () => { try { return JSON.parse(localStorage.getItem(nftKey()) || '[]'); } catch { return []; } };
const saveNfts = (l) => { try { localStorage.setItem(nftKey(), JSON.stringify(l)); } catch {} };
function decodeString(hex) {
  try { const b = hex.slice(2); const len = parseInt(b.slice(64, 128), 16); const bytes = b.slice(128, 128 + len * 2).match(/../g) || []; return new TextDecoder().decode(new Uint8Array(bytes.map((h) => parseInt(h, 16)))); } catch { return ''; }
}
function renderNfts() {
  const list = loadNfts(); const ul = $('nftList'); ul.replaceChildren();
  list.forEach((n) => {
    const li = el('li', { class: 'nft-row' }, el('span', { class: 'tok-ic', text: (n.name || 'N').slice(0, 1) }),
      el('div', { class: 'tx-main' }, el('b', { text: `${n.name || 'NFT'} #${n.tokenId}` }), el('span', { text: shortAddress(n.contract) })),
      el('div', { class: 'tx-side' }, el('span', { class: `badge ${n.level}`, text: LV[n.level] || n.level })));
    li.onclick = () => window.open(`${chain().explorer}/token/${n.contract}?a=${n.tokenId}`, '_blank', 'noopener');
    ul.append(li);
  });
  $('nftEmpty').querySelector('p').hidden = list.length > 0; $('nftEmpty').querySelector('.illu').hidden = list.length > 0;
}
$('importNft').onclick = () => {
  if (!wallet.account) { openConnect(); return; }
  const body = $('sheetBody');
  const addr = el('input', { placeholder: 'Contract address (0x…)', spellcheck: 'false', autocomplete: 'off' });
  const id = el('input', { placeholder: 'Token ID', inputmode: 'numeric', autocomplete: 'off' });
  const msg = el('p', { class: 'hint' }); const go2 = el('button', { class: 'primary block', type: 'button', text: 'Import' });
  body.replaceChildren(el('h3', { text: 'Import NFT' }), el('div', { class: 'nft-form' }, addr, id, msg, go2));
  go2.onclick = async () => {
    const c = addr.value.trim(); const t = id.value.trim();
    if (!isAddress(c) || !/^\d+$/.test(t)) { msg.className = 'hint bad'; msg.textContent = 'กรอก contract (0x + 40 ตัว) และ Token ID เป็นตัวเลข'; return; }
    go2.disabled = true; msg.className = 'hint'; msg.textContent = 'กำลังตรวจความเป็นเจ้าของบน blockchain และให้ BridgeSecure ตรวจ contract…';
    try {
      const owner = await rpc('eth_call', [{ to: c, data: '0x6352211e' + BigInt(t).toString(16).padStart(64, '0') }, 'latest']);
      if (!owner || owner.length < 66 || ('0x' + owner.slice(-40)).toLowerCase() !== wallet.account) throw new Error('not owner');
      const name = decodeString(await rpc('eth_call', [{ to: c, data: '0x06fdde03' }, 'latest']).catch(() => '0x'));
      let level = 'MEDIUM'; try { level = (await api.checkRisk({ chainId: S.chainId, to: c })).level; } catch {}
      const list = loadNfts().filter((n) => !(n.contract === c.toLowerCase() && n.tokenId === t));
      list.push({ contract: c.toLowerCase(), tokenId: t, name, level }); saveNfts(list); renderNfts(); $('sheet').close();
      toast(level === 'HIGH' ? 'นำเข้าแล้ว ⚠ BridgeSecure พบว่า contract นี้มีความเสี่ยงสูง ระวัง NFT หลอกลวง' : 'นำเข้า NFT แล้ว');
    } catch { msg.className = 'hint bad'; msg.textContent = 'ไม่พบ NFT นี้ในกระเป๋าของคุณบนเครือข่ายนี้ (ตรวจด้วย ownerOf)'; }
    finally { go2.disabled = false; }
  };
  $('sheet').showModal(); addr.focus();
};
document.querySelectorAll('.js-net').forEach((b) => (b.onclick = openNetworks));
document.querySelectorAll('.js-more').forEach((b) => (b.onclick = () => $('menuBtn').click()));
$('exSearch').oninput = renderExplore;
document.querySelectorAll('.ex-tabs .tab').forEach((b) => (b.onclick = () => setExTab(b.dataset.ex)));
$('menuBtn').onclick = () => {
  const body = $('sheetBody'); body.replaceChildren(el('h3', { text: 'Menu' }));
  const item = (label, fn) => { const b = el('button', { class: 'opt', type: 'button', text: label }); b.onclick = () => { $('sheet').close(); fn(); }; body.append(b); };
  item(`Network: ${chain().name}`, openNetworks);
  item('ตรวจสอบธุรกรรม (Verify)', () => window.open('verify.html', '_blank', 'noopener'));
  item(wallet.account ? 'Disconnect' : 'Connect', () => (wallet.account ? wallet.disconnect() : openConnect()));
  $('sheet').showModal();
};
document.querySelectorAll('[data-go]').forEach((b) => (b.onclick = () => go(b.dataset.go)));
$('toInput').oninput = validate; $('amtInput').oninput = () => { S.lastWei = null; validate(); };
$('toInput').addEventListener('paste', (e) => { const t = e.clipboardData?.getData('text'); if (t && !isAddress(t.trim())) { e.preventDefault(); applyText(t); } });
$('maxBtn').onclick = () => {
  if (S.balance === null) return;
  const keep = units.parse('0.001');   // leave room for the network fee
  const wei = S.balance > keep ? S.balance - keep : 0n;
  $('amtInput').value = S.unit === 'usd' ? (S.price ? (Number(units.format(wei, 18, 8)) * S.price.usd).toFixed(2) : '') : units.format(wei, 18, 18);
  validate();
};
$('continueBtn').onclick = openReview;
$('cancelBtn').onclick = () => { go('home'); toast('ยกเลิกแล้ว ไม่มีการโอน'); };
$('ack').onchange = () => ($('confirmBtn').disabled = !$('ack').checked);
$('confirmBtn').onclick = confirm;
$('doneBtn').onclick = () => { go('home'); refresh(); };
init();

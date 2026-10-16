// Reference integration of the BridgeSecure SDK (backend team). The Frontend team owns the real UI;
// this page shows the contract: one "Send" → analyse → alert sheet → MetaMask → verified seal → history.
import { RiskGuardClient, WalletManager, guardedSend, units, isAddress, shortAddress, parsePaymentUri } from './sdk/riskguard.js';

const CFG = window.RISKGUARD_CONFIG || { apiBase: '', walletConnectProjectId: '', defaultChainId: 43113 };
// Server sets snapId from SNAP_ID; an empty value means no Snap is offered (cloud pilot before the npm publish).
const SNAP_ID = 'snapId' in CFG ? CFG.snapId : 'local:http://localhost:8081';
const $ = (id) => document.getElementById(id);
const api = new RiskGuardClient({ apiBase: CFG.apiBase });
const state = { chains: [], chainId: CFG.defaultChainId, balance: null, busy: false, lastRisk: null };
let wallet;

const HEAD = {
  HIGH: ['CRITICAL SECURITY ALERT', 'ความเสี่ยงสูง แนะนำให้ไม่โอน'],
  MEDIUM: ['SECURITY WARNING', 'พบสัญญาณที่ควรระวัง'],
  LOW: ['LOW RISK', 'ไม่พบสัญญาณความเสี่ยงจากการตรวจ'],
};
const LV_TH = { LOW: 'ความเสี่ยงต่ำ', MEDIUM: 'ความเสี่ยงปานกลาง', HIGH: 'ความเสี่ยงสูง', UNKNOWN: 'ข้อมูลไม่พอ' };   // UNKNOWN: seals from engine < v2.1 only

function toast(msg, ms = 3400) { const t = $('toast'); t.textContent = msg; t.hidden = false; clearTimeout(toast.t); toast.t = setTimeout(() => (t.hidden = true), ms); }
const chain = (id = state.chainId) => state.chains.find((c) => c.chain_id === id) || { symbol: 'AVAX', explorer: '', name: '' };
const el = (tag, attrs = {}, ...kids) => { const e = document.createElement(tag); Object.entries(attrs).forEach(([k, v]) => (k === 'text' ? (e.textContent = v) : e.setAttribute(k, v))); kids.forEach((k) => k != null && e.append(k)); return e; };
const when = (ts) => (ts ? new Date(ts * 1000).toLocaleString('th-TH', { dateStyle: 'medium', timeStyle: 'short' }) : '–');

// ------------------------------------------------------------ init
async function init() {
  try { state.chains = await api.getChains(); } catch { state.chains = [{ chain_id: 43113, name: 'Avalanche Fuji C-Chain', short: 'Fuji', symbol: 'AVAX', explorer: 'https://testnet.snowtrace.io', rpc: 'https://api.avax-test.network/ext/bc/C/rpc', testnet: true }]; }
  state.chains.forEach((c) => $('network').append(el('option', { value: c.chain_id, text: c.short + (c.testnet ? ' (ทดสอบ)' : '') })));
  $('network').value = String(state.chainId);
  wallet = new WalletManager({ walletConnectProjectId: CFG.walletConnectProjectId, chains: state.chains });
  wallet.addEventListener('account', renderWallet);
  wallet.addEventListener('chain', onWalletChain);
  wallet.addEventListener('wallets', renderWalletList);
  await wallet.discover(); renderWalletList();
  await wallet.restore().catch(() => null);
  renderWallet(); updateSymbol();
  api.health().then((h) => { $('ver').textContent = h.engine_version; $('health').textContent = Object.values(h.upstreams).every((v) => v === 'ok') ? 'แหล่งข้อมูลพร้อม' : 'บางแหล่งช้า (ใช้ตัวสำรอง)'; }).catch(() => ($('health').textContent = 'ติดต่อระบบไม่ได้'));
}

// ------------------------------------------------------------ wallet
function renderWalletList() {
  const ul = $('walletList'); ul.replaceChildren(); const list = wallet.list();
  list.forEach((w) => { const b = el('button', { class: 'btn ghost', type: 'button' }); if (w.icon) b.append(el('img', { src: w.icon, alt: '' })); b.append(w.name); b.onclick = () => doConnect(w.uuid); ul.append(el('li', {}, b)); });
  if (wallet.hasWalletConnect()) { const b = el('button', { class: 'btn ghost', type: 'button', text: 'WalletConnect (QR)' }); b.onclick = () => doConnect('walletconnect'); ul.append(el('li', {}, b)); }
  $('noWallet').hidden = !(list.length === 0 && !wallet.hasWalletConnect());
  $('mmLink').href = `https://metamask.app.link/dapp/${location.href.replace(/^https?:\/\//, '')}`;
  $('trustLink').href = `https://link.trustwallet.com/open_url?coin_id=60&url=${encodeURIComponent(location.href)}`;
}
async function doConnect(uuid) {
  try {
    const r = await wallet.connect(uuid, { snapId: SNAP_ID || undefined }); $('walletDialog').close();
    toast(wallet.snapInstalled ? `เชื่อมต่อ ${r.wallet.name} และเปิดใช้ BridgeSecure Guardian แล้ว` : `เชื่อมต่อ ${r.wallet.name} แล้ว`);
    if (state.chains.some((c) => c.chain_id === r.chainId)) { state.chainId = r.chainId; $('network').value = String(r.chainId); updateSymbol(); }
    else await switchTo(state.chainId);
  } catch (e) { toast(WalletManager.explain(e).th); }
}
function renderWallet() {
  const a = wallet?.account;
  $('connectBtn').hidden = Boolean(a); $('accountBtn').hidden = !a; $('maxBtn').disabled = !a;
  $('accountBtn').textContent = a ? shortAddress(a) : '';
  $('walletState').textContent = a ? `${wallet.info?.name || 'กระเป๋า'} · ${shortAddress(a)}` : 'ยังไม่ได้เชื่อมต่อกระเป๋า';
  if (!a) { $('balance').textContent = ''; state.balance = null; }
  $('sendBtn').textContent = a ? 'ส่ง' : 'Connect เพื่อส่ง';
  refreshBalance(); validateTo(); loadHistory();
  $('snapCard').hidden = true; state.snap = false;
  if (a) refreshSnapState();
}
// When the Guardian Snap is installed, MetaMask itself shows the BridgeSecure analysis (MetaMask-drawn UI),
// so the site does not show its own popup. Without the Snap (mobile, other wallets) the site popup is the fallback.
async function refreshSnapState() {
  if (!SNAP_ID) { state.snap = false; state.flask = false; return; }   // cloud deploy without a published Snap: web alerts only
  const id = SNAP_ID;
  state.snap = await wallet.hasSnap(id);
  const flask = /flask/i.test(`${wallet.info?.rdns || ''} ${wallet.info?.name || ''}`) || (await wallet.isFlask());
  state.flask = flask;
  $('snapCard').hidden = state.snap || !flask;
  $('walletState').textContent = `${wallet.info?.name || 'กระเป๋า'} · ${shortAddress(wallet.account)}${state.snap ? ' · Guardian เปิดอยู่' : ''}`;
}
$('snapBtn').onclick = async () => {
  try { await wallet.installSnap(SNAP_ID); await refreshSnapState(); toast('ติดตั้ง BridgeSecure Guardian แล้ว ลองส่งเหรียญจากหน้า Send ของ MetaMask ได้เลย'); }
  catch (e) { toast(WalletManager.explain(e).th); }
};
function onWalletChain(ev) {
  const id = ev.detail;
  if (state.chains.some((c) => c.chain_id === id)) { state.chainId = id; $('network').value = String(id); updateSymbol(); loadHistory(); }
  refreshBalance();
}
async function switchTo(id) {
  if (!wallet.account) return true;
  try { await wallet.ensureChain(id); return true; } catch (e) { toast(WalletManager.explain(e).th); $('network').value = String(wallet.chainId || state.chainId); return false; }
}
async function refreshBalance() {
  if (!wallet?.account) return;
  if (wallet.chainId !== state.chainId) { $('balance').textContent = 'กระเป๋ายังอยู่บนเครือข่ายอื่น ระบบจะสลับให้ตอนส่ง'; return; }
  try {
    state.balance = await wallet.balance(); const c = chain();
    $('balance').replaceChildren(`ยอดคงเหลือ ${units.format(state.balance)} ${c.symbol}`);
    if (c.testnet && c.faucet && state.balance < units.parse('0.05')) $('balance').append(' · ', el('a', { href: c.faucet, target: '_blank', rel: 'noopener', text: 'ขอเหรียญทดสอบ' }));
  } catch { $('balance').textContent = ''; }
}
function updateSymbol() { $('symbol').textContent = chain().symbol; }

// ------------------------------------------------------------ form
function validateTo() {
  const v = $('to').value.trim(); const h = $('toHint'); h.className = 'hint';
  if (!v) { h.textContent = ''; return false; }
  if (!isAddress(v)) { h.textContent = 'ที่อยู่ต้องขึ้นต้นด้วย 0x และมีอักขระอีก 40 ตัว'; h.className = 'hint bad'; return false; }
  h.textContent = wallet?.account && v.toLowerCase() === wallet.account ? 'นี่คือที่อยู่ของคุณเอง' : `${v.slice(0, 6)} … ${v.slice(-6)} · ตรวจตัวอักษรต้นและท้ายให้ตรงกับที่ได้รับมา`;
  return true;
}
function applyPaymentText(text) {
  const p = parsePaymentUri(text);
  if (!p) { toast('ไม่พบที่อยู่กระเป๋าในข้อความหรือ QR นี้'); return; }
  $('to').value = p.address;
  if (p.valueWei) $('amount').value = units.format(p.valueWei, 18, 18);
  if (p.chainId && p.chainId !== state.chainId && state.chains.some((c) => c.chain_id === p.chainId)) { $('network').value = String(p.chainId); $('network').dispatchEvent(new Event('change')); }
  validateTo();
}

// ------------------------------------------------------------ alert sheet (the "decide" step)
function showAlert(risk, { to, valueWei }) {
  return new Promise((resolve) => {
    const level = risk.error ? 'MEDIUM' : risk.level;
    const s = $('alertSheet'); s.dataset.level = level;
    const [head, sub] = HEAD[level] || HEAD.MEDIUM;
    $('alertLevel').textContent = head;
    $('alertTitle').textContent = risk.error ? 'ระวัง: ยังตรวจที่อยู่นี้ไม่สำเร็จ' : sub;
    $('alertLead').textContent = risk.error ? 'เหตุผล: เชื่อมต่อระบบวิเคราะห์ไม่ได้ จึงยืนยันไม่ได้ว่าปลอดภัย ยืนยันที่อยู่กับผู้รับผ่านช่องทางอื่นก่อนโอน' : (risk.verdict?.th || '');
    $('alertScore').textContent = risk.trust_score != null ? `${risk.trust_score}/100` : '–';
    const ol = $('reasonList'); ol.replaceChildren();
    (risk.signals || []).forEach((g) => {
      const li = el('li', { class: `sig ${g.severity}` }, el('b', { text: g.title.th }), el('p', { text: g.detail.th }));
      if (g.evidence_tx?.length && risk.explorer) { const ev = el('div', { class: 'ev' }, 'หลักฐาน:'); g.evidence_tx.forEach((h) => ev.append(el('a', { href: `${risk.explorer}/tx/${h}`, target: '_blank', rel: 'noopener', text: h.slice(0, 10) + '…' }))); li.append(ev); }
      const vt = validationText(g.validation); if (vt) li.append(el('span', { class: 'val', text: vt }));
      ol.append(li);
    });
    // The checklist: every check that ran and what it found, so each verdict shows its work.
    if (risk.checks?.length) ol.append(el('li', { class: 'sig info' }, el('b', { text: `สิ่งที่ตรวจแล้ว (${risk.checks.length} ข้อ)` }),
      ...risk.checks.map((c) => el('p', { text: `${{ pass: '✓', flag: '⚠', skip: '–' }[c.result]} ${c.th}` }))));
    const dl = $('alertMeta'); dl.replaceChildren();
    const meta = risk.error ? [] : [['ปลายทาง', to], ['จำนวน', `${units.format(valueWei)} ${chain().symbol}`], ['ประวัติที่วิเคราะห์', `${risk.stats?.n_all_chains ?? risk.stats?.n_total ?? 0} ธุรกรรม (ทุกเครือข่าย)`], ['แหล่งข้อมูล', (risk.data_sources || []).join(', ')], ['เวลาวิเคราะห์', `${risk.latency_ms} ms`], ['รหัสอ้างอิง', risk.request_id]];
    if (risk.attestation) meta.push(['ตราบนธุรกรรม', 'MetaMask จะแสดงว่ามี "Data" แนบไป นั่นคือตรา Verified by BridgeSecure']);
    meta.forEach(([k, v]) => dl.append(el('dt', { text: k }), el('dd', { text: String(v) })));
    $('reasons').open = risk.level === 'HIGH';
    $('ackRow').hidden = risk.level !== 'HIGH'; $('ack').checked = false;
    $('proceedBtn').className = risk.level === 'HIGH' ? 'btn danger' : 'btn primary';
    $('proceedBtn').textContent = risk.level === 'HIGH' ? 'โอนแม้มีความเสี่ยง' : 'ดำเนินการต่อใน MetaMask';
    $('proceedBtn').disabled = risk.level === 'HIGH';
    $('ack').onchange = () => ($('proceedBtn').disabled = !$('ack').checked);
    $('reportBtn').hidden = Boolean(risk.error);
    $('reportBtn').onclick = async () => { try { const r = await api.report({ chainId: state.chainId, address: to, category: 'other' }); toast(r.message.th); } catch (e) { toast(e.body?.message?.th || 'ส่งรายงานไม่สำเร็จ'); } };
    const done = (v) => { s.close(); resolve(v); };
    $('cancelBtn').onclick = () => done(false);
    $('proceedBtn').onclick = () => done(true);
    s.oncancel = (e) => { e.preventDefault(); done(false); };
    s.showModal();
  });
}
function validationText(v) {
  if (!v?.status) return '';
  if (v.status === 'validated') { const c = v[state.chainId === 1 ? 'ethereum' : 'avalanche'] || v.ethereum; return `ผ่านการทดสอบย้อนหลังกับธุรกรรมจริงปี 2024–26: จับได้ ${(c.recall * 100).toFixed(0)}% เตือนผิด ${(c.fpr * 100).toFixed(1)}%`; }
  return { deterministic: 'ตรวจแบบตรงตัว ไม่ใช่การคาดเดา', 'validated-low-recall': 'ผ่านการทดสอบ เตือนผิดต่ำ แต่พบไม่บ่อย', 'not-yet-validated': 'ยังไม่ได้วัดผลในการทดสอบย้อนหลัง', unverified: 'ข้อมูลจากผู้ใช้ ยังไม่ได้ตรวจยืนยัน' }[v.status] || '';
}

// ------------------------------------------------------------ send (one button)
async function onSend(ev) {
  ev.preventDefault();
  if (state.busy) return;
  if (!wallet.account) { renderWalletList(); $('walletDialog').showModal(); return; }
  if (!validateTo()) { $('to').focus(); toast('กรอกที่อยู่ปลายทางให้ถูกต้องก่อน'); return; }
  let wei; try { wei = units.parse($('amount').value || ''); } catch { toast('กรอกจำนวนให้ถูกต้อง'); $('amount').focus(); return; }
  if (wei <= 0n) { toast('จำนวนต้องมากกว่า 0'); return; }
  if (wallet.chainId === state.chainId) { await refreshBalance(); if (state.balance !== null && wei > state.balance) { toast('ยอดเงินไม่พอ'); return; } }
  const to = $('to').value.trim(); const c = chain();
  // Flask without the Guardian Snap (e.g. connected before the combined Connect existed): install it first,
  // so the analysis appears inside MetaMask instead of this page.
  if (SNAP_ID && state.flask && !state.snap) {
    try { toast('ขอติดตั้ง BridgeSecure Guardian ใน MetaMask ก่อนโอน…'); await wallet.installSnap(SNAP_ID); await refreshSnapState(); }
    catch (e) { if (e?.code === 4001) toast('ไม่ได้ติดตั้ง Guardian จะแสดงคำเตือนบนหน้าเว็บแทน'); else toast('ติดตั้ง Guardian ไม่สำเร็จ: ' + WalletManager.explain(e).th); }
  }
  state.busy = true; const btn = $('sendBtn'); btn.disabled = true;
  const stageText = { checking: 'BridgeSecure กำลังวิเคราะห์ปลายทาง…', deciding: 'รอคุณตัดสินใจ…', switching: 'กำลังสลับเครือข่ายใน MetaMask…', signing: 'ยืนยันใน MetaMask…', pending: 'ส่งแล้ว รอเครือข่ายยืนยัน…' };
  try {
    const r = await guardedSend({ api, wallet, chainId: state.chainId, to, valueWei: wei,
      decide: (risk) => {
        state.lastRisk = risk;
        if (state.snap) { toast('BridgeSecure จะแสดงผลวิเคราะห์ในหน้าต่าง MetaMask'); return true; }  // MetaMask-drawn alert via the Snap
        return showAlert(risk, { to, valueWei: wei });                                                  // fallback: no Snap
      },
      onStage: (st) => { if (stageText[st]) btn.replaceChildren(el('span', { class: 'spinner', 'aria-hidden': 'true' }), ' ' + stageText[st]); } });
    if (r.status === 'cancelled') { toast('ยกเลิกแล้ว ไม่มีการโอน'); return; }
    showResult(r, c, wei, to); refreshBalance(); setTimeout(loadHistory, 1500);
  } catch (e) {
    showResult({ status: 'error', message: e.message === 'RECEIPT_TIMEOUT' ? 'ยังไม่ได้รับการยืนยันภายใน 2 นาที ตรวจสอบใน Explorer' : WalletManager.explain(e).th }, c, wei, to);
  } finally { state.busy = false; btn.disabled = false; btn.textContent = 'ส่ง'; }
}

function showResult(r, c, wei, to) {
  const card = $('resultCard'); card.hidden = false;
  const v = r.verification?.verification; const ok = r.status === 'confirmed';
  card.dataset.level = v?.valid ? v.level : ok ? 'LOW' : 'ERR';
  $('sealRing').textContent = v?.valid ? String(v.trust_score) : ok ? '✓' : '!';
  $('resultTitle').textContent = !ok ? (r.status === 'failed' ? 'ธุรกรรมล้มเหลวบนเครือข่าย' : 'ไม่ได้โอน') : v?.valid ? 'โอนสำเร็จ · Verified by BridgeSecure' : 'โอนสำเร็จ';
  $('resultSub').textContent = r.message || (v?.valid ? `${LV_TH[v.level]} · Trust Score ${v.trust_score}/100 · ตราอยู่บน blockchain ในธุรกรรมนี้` : ok ? 'ธุรกรรมนี้ไม่มีตรา (ปลายทางเป็น contract หรือตรวจไม่สำเร็จ)' : '');
  const dl = $('resultMeta'); dl.replaceChildren();
  if (r.txHash) [['ธุรกรรม', r.txHash], ['ปลายทาง', to], ['จำนวน', `${units.format(wei)} ${c.symbol}`], ['บล็อก', r.receipt ? parseInt(r.receipt.blockNumber, 16) : '–']]
    .concat(v?.valid ? [['สัญญาณที่พบ', v.signals.length ? v.signals.join(', ') : 'ไม่มี'], ['ตรวจก่อนบันทึกบน chain', `${Math.max(0, v.seconds_from_check_to_block ?? 0)} วินาที`]] : [])
    .forEach(([k, val]) => dl.append(el('dt', { text: k }), el('dd', { text: String(val) })));
  $('txLink').hidden = !r.txHash; if (r.txHash) $('txLink').href = `${c.explorer}/tx/${r.txHash}`;
  $('verifyLink').hidden = !r.txHash; if (r.txHash) $('verifyLink').href = `verify.html?chain_id=${state.chainId}&tx=${r.txHash}`;
  card.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'nearest' });
}

// ------------------------------------------------------------ history (read from chain, nothing stored)
async function loadHistory() {
  const ul = $('history'); const note = $('histNote');
  if (!wallet?.account) { ul.replaceChildren(); note.textContent = 'เชื่อมต่อกระเป๋าเพื่อดูประวัติ ข้อมูลอ่านจาก blockchain โดยตรง BridgeSecure ไม่ได้เก็บไว้'; return; }
  note.textContent = 'กำลังอ่านจาก blockchain…';
  try {
    const r = await api.verifyAddress({ chainId: state.chainId, address: wallet.account }); const c = chain();
    ul.replaceChildren();
    r.transactions.sort((a, b) => (b.block_ts || 0) - (a.block_ts || 0)).forEach((t) => {
      const v = t.verification || {};
      ul.append(el('li', { class: `hist ${v.valid ? v.level : 'BAD'}` },
        el('div', { class: 'hist-main' }, el('b', { text: `${units.format(BigInt(t.value_wei))} ${c.symbol} → ${shortAddress(t.to)}` }), el('span', { class: 'muted', text: when(t.block_ts) })),
        el('div', { class: 'hist-side' }, el('span', { class: `badge ${v.valid ? v.level : 'UNKNOWN'}`, text: v.valid ? `${LV_TH[v.level]} · TS ${v.trust_score}` : 'ตราไม่ถูกต้อง' }),
          el('a', { href: `verify.html?chain_id=${t.chain_id}&tx=${t.tx_hash}`, target: '_blank', rel: 'noopener', text: 'รายละเอียด' }),
          el('a', { href: `${t.explorer}/tx/${t.tx_hash}`, target: '_blank', rel: 'noopener', text: 'Explorer' }))));
    });
    note.textContent = r.count ? `${r.count} ธุรกรรมล่าสุดบน ${c.short || c.name} ที่มีตรา BridgeSecure` : `ยังไม่มีธุรกรรมที่ผ่าน BridgeSecure บน ${c.short || c.name}`;
  } catch (e) { note.textContent = e.body?.message?.th || 'อ่านประวัติไม่สำเร็จ กดรีเฟรชอีกครั้ง'; }
}

// ------------------------------------------------------------ events
$('connectBtn').onclick = () => { renderWalletList(); $('walletDialog').showModal(); };
$('closeDialog').onclick = () => $('walletDialog').close();
$('accountBtn').onclick = async () => { await wallet.disconnect(); toast('ตัดการเชื่อมต่อแล้ว'); };
$('network').onchange = async (e) => { const id = Number(e.target.value); if (await switchTo(id)) { state.chainId = id; updateSymbol(); refreshBalance(); loadHistory(); } };
$('to').oninput = validateTo;
$('to').addEventListener('paste', (e) => { const t = e.clipboardData?.getData('text'); if (t && !isAddress(t.trim())) { e.preventDefault(); applyPaymentText(t); } });
$('pasteBtn').onclick = async () => { try { applyPaymentText(await navigator.clipboard.readText()); } catch { $('to').focus(); toast('กด Ctrl+V ในช่องได้เลย'); } };
$('maxBtn').onclick = async () => { await refreshBalance(); if (state.balance !== null) { const keep = units.parse('0.01'); $('amount').value = units.format(state.balance > keep ? state.balance - keep : 0n, 18, 18); } };
$('sendForm').onsubmit = onSend;
$('histRefresh').onclick = loadHistory;
$('newBtn').onclick = () => { $('resultCard').hidden = true; $('to').value = ''; $('amount').value = ''; validateTo(); $('to').focus(); };
init();

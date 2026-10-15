import { RiskGuardClient, units, shortAddress } from './sdk/riskguard.js';
const api = new RiskGuardClient({ apiBase: (window.RISKGUARD_CONFIG || {}).apiBase || '' });
const $ = (id) => document.getElementById(id);
const el = (t, a = {}, ...k) => { const e = document.createElement(t); for (const [x, v] of Object.entries(a)) x === 'text' ? (e.textContent = v) : e.setAttribute(x, v); k.forEach((c) => c && e.append(c)); return e; };
const LV = { LOW: 'ความเสี่ยงต่ำ', MEDIUM: 'ความเสี่ยงปานกลาง', HIGH: 'ความเสี่ยงสูง', UNKNOWN: 'ข้อมูลไม่พอ' };
const chains = await api.getChains().catch(() => [{ chain_id: 43113, short: 'Fuji', symbol: 'AVAX' }]);
chains.forEach((c) => $('chain').append(el('option', { value: c.chain_id, text: c.short })));
const sym = () => (chains.find((c) => c.chain_id === Number($('chain').value)) || {}).symbol || '';

function renderTx(r) {
  const o = $('out'); o.hidden = false; o.replaceChildren();
  if (!r.found) { o.append(el('h2', { text: 'ไม่พบธุรกรรมนี้บนเครือข่ายที่เลือก' })); return; }
  const v = r.verification; const ok = r.attested && v?.valid;
  const seal = el('div', { class: `seal ${ok ? v.level : 'none'}` }, el('div', { class: 'ring', text: ok ? String(v.trust_score) : '–' }),
    el('h2', { text: ok ? 'Verified by BridgeSecure' : r.attested ? 'ตราไม่ถูกต้อง' : 'ธุรกรรมนี้ไม่มีตรา BridgeSecure' }),
    el('p', { class: 'muted', text: ok ? `${LV[v.level]} · Trust Score ${v.trust_score}/100 · ตรวจก่อนโอน ${Math.max(0, v.seconds_from_check_to_block ?? 0)} วินาที` : (v?.reason || 'ไม่ได้ผ่านการตรวจก่อนโอน') }));
  o.append(seal);
  const dl = el('dl', { class: 'kv' });
  const rows = [['ธุรกรรม', r.tx_hash], ['สถานะ', r.status === 'success' ? 'สำเร็จ' : r.status || 'รอยืนยัน'], ['ผู้ส่ง', r.from], ['ผู้รับ', r.to],
    ['จำนวน', `${units.format(BigInt(r.value_wei))} ${sym()}`], ['บล็อก', r.block]];
  if (ok) rows.push(['สัญญาณที่พบ', v.signals.length ? v.signals.join(', ') : 'ไม่มี'], ['เวลาตรวจ', new Date(v.checked_at * 1000).toLocaleString('th-TH')], ['รหัสอ้างอิง', v.request_id]);
  rows.forEach(([k, val]) => dl.append(el('dt', { text: k }), el('dd', { text: String(val) })));
  o.append(dl, el('a', { class: 'btn ghost', href: `${r.explorer}/tx/${r.tx_hash}`, target: '_blank', rel: 'noopener', text: 'ดูธุรกรรมใน Explorer' }));
}
function renderAddr(r) {
  const o = $('out'); o.hidden = false; o.replaceChildren(el('h2', { text: `ธุรกรรมที่มีตรา ${r.count} รายการ · ${shortAddress(r.address)}` }));
  const ul = el('ul', { class: 'list' });
  r.transactions.forEach((t) => {
    const v = t.verification || {};
    ul.append(el('li', {}, el('a', { href: `?chain_id=${r.chain_id}&tx=${t.tx_hash}` }, el('span', { text: `${shortAddress(t.to)} · ${units.format(BigInt(t.value_wei))} ${sym()}` }),
      el('span', { class: `badge ${v.valid ? v.level : 'UNKNOWN'}`, text: v.valid ? `TS ${v.trust_score}` : 'ไม่ผ่าน' }))));
  });
  if (!r.count) ul.append(el('li', { class: 'muted', text: 'ยังไม่มีธุรกรรมที่ผ่านการตรวจจากที่อยู่นี้ในช่วงล่าสุด' }));
  o.append(ul);
}
async function run() {
  const q = $('q').value.trim(); const chainId = Number($('chain').value);
  const o = $('out'); o.hidden = false; o.replaceChildren(el('p', { class: 'muted', text: 'กำลังอ่านข้อมูลจาก blockchain…' }));
  try {
    if (/^0x[0-9a-fA-F]{64}$/.test(q)) renderTx(await api.verifyTx({ chainId, txHash: q }));
    else if (/^0x[0-9a-fA-F]{40}$/.test(q)) renderAddr(await api.verifyAddress({ chainId, address: q }));
    else o.replaceChildren(el('p', { text: 'กรอก tx hash (66 ตัว) หรือที่อยู่กระเป๋า (42 ตัว)' }));
  } catch (e) { o.replaceChildren(el('p', { text: e.body?.message?.th || 'ตรวจสอบไม่สำเร็จ ลองใหม่อีกครั้ง' })); }
}
$('go').onclick = run;
$('q').onkeydown = (e) => { if (e.key === 'Enter') run(); };
const p = new URLSearchParams(location.search);
if (p.get('chain_id')) $('chain').value = p.get('chain_id');
if (p.get('tx') || p.get('address')) { $('q').value = p.get('tx') || p.get('address'); run(); }

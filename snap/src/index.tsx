/**
 * BridgeSecure Guardian — MetaMask Snap.
 *
 * Shows the full BridgeSecure analysis inside MetaMask's transaction confirmation (MetaMask-drawn UI),
 * with the same content as the Local web view, all visible without extra clicks:
 *   logo · level banner · headline · main reason · Trust Score · every reason (with accuracy + evidence)
 *   · destination · amount · history analysed · data sources · analysis time · reference id
 * Runs for every transaction reviewed in MetaMask (its own Send screen, any dapp, ERC-20 transfer, approve).
 * The Snap never blocks; the user decides.
 */
import type { OnTransactionHandler, OnInstallHandler } from '@metamask/snaps-sdk';
import { Box, Text, Bold, Link, Row, Address, Banner, Section, Image, Divider } from '@metamask/snaps-sdk/jsx';
import { LOGO_SVG } from './logo';

const API_BASE = process.env.API_BASE as string; // set in snap.config.ts at build time
const TRANSFER = '0xa9059cbb'; // ERC-20 transfer(address,uint256)
const APPROVE = '0x095ea7b3';  // ERC-20 approve(address,uint256)

const HEAD: Record<string, { title: string; severity: 'danger' | 'warning' | 'success' | 'info'; line: string }> = {
  HIGH: { title: 'CRITICAL SECURITY ALERT', severity: 'danger', line: 'ความเสี่ยงสูง แนะนำให้ไม่โอน' },
  MEDIUM: { title: 'SECURITY WARNING', severity: 'warning', line: 'พบสัญญาณที่ควรระวัง' },
  LOW: { title: 'LOW RISK', severity: 'success', line: 'ไม่พบสัญญาณความเสี่ยงจากการตรวจ' },
};

type Signal = {
  code: string; severity: 'high' | 'medium' | 'info'; title: { th: string }; detail: { th: string };
  evidence_tx?: string[]; validation?: { status?: string; avalanche?: { recall: number; fpr: number }; ethereum?: { recall: number; fpr: number } };
};
type Check = { id: string; result: 'pass' | 'flag' | 'skip'; th: string };
type Risk = {
  level: string; trust_score: number; signals: Signal[]; explorer: string; request_id: string;
  verdict?: { th: string }; checks?: Check[];
  stats?: { n_total?: number; n_all_chains?: number }; data_sources?: string[]; latency_ms?: number;
};
const CHECK_ICON: Record<Check['result'], string> = { pass: '✓', flag: '⚠', skip: '–' };
type Kind = 'native' | 'token-transfer' | 'approve' | 'contract-call';

/** Who actually receives value: native `to`, ERC-20 transfer recipient, or approve spender. */
export function counterparty(tx: { to?: string; data?: string }): { address: string; kind: Kind } | null {
  const data = (tx.data ?? '0x').toLowerCase();
  if (data.startsWith(TRANSFER) && data.length >= 138) return { address: '0x' + data.slice(34, 74), kind: 'token-transfer' };
  if (data.startsWith(APPROVE) && data.length >= 138) return { address: '0x' + data.slice(34, 74), kind: 'approve' };
  if (!tx.to) return null;
  return { address: tx.to.toLowerCase(), kind: data === '0x' || data === '' ? 'native' : 'contract-call' };
}

/** Hex wei -> "0.0001 AVAX" with exact BigInt math. */
function formatValue(hexWei: string | undefined, chainId: number): string {
  const symbol = chainId === 1 ? 'ETH' : 'AVAX';
  const v = BigInt(hexWei && hexWei !== '0x' ? hexWei : '0x0');
  const base = 10n ** 18n;
  const frac = (v % base).toString().padStart(18, '0').replace(/0+$/, '');
  return `${(v / base).toString()}${frac ? '.' + frac.slice(0, 8) : ''} ${symbol}`;
}

/** How reliable a reason is, from the backend's pre-registered audit. */
function validationText(s: Signal, chainId: number): string {
  const v = s.validation;
  const stats = chainId === 1 ? v?.ethereum : v?.avalanche ?? v?.ethereum;
  if (v?.status === 'validated' && stats) return `ทดสอบย้อนหลังกับธุรกรรมจริงปี 2024–26: จับได้ ${Math.round(stats.recall * 100)}% เตือนผิด ${(stats.fpr * 100).toFixed(1)}%`;
  if (v?.status === 'deterministic') return 'ตรวจแบบตรงตัว ไม่ใช่การคาดเดา';
  if (v?.status === 'validated-low-recall') return 'ผ่านการทดสอบ เตือนผิดต่ำ แต่พบไม่บ่อย';
  if (v?.status === 'not-yet-validated') return 'ยังไม่ได้วัดผลในการทดสอบย้อนหลัง';
  if (v?.status === 'unverified') return 'ข้อมูลจากผู้ใช้ ยังไม่ได้ตรวจยืนยัน';
  return '';
}

async function check(chainId: number, to: string, from?: string): Promise<Risk> {
  const q = new URLSearchParams({ chain_id: String(chainId), to });
  if (from) q.set('from', from);
  const res = await fetch(`${API_BASE}/v1/risk?${q}`, { headers: { Accept: 'application/json' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

const KIND_LABEL: Record<Kind, string> = {
  'native': 'ปลายทาง', 'token-transfer': 'ผู้รับโทเคน', 'approve': 'ผู้ขอสิทธิ์ใช้โทเคน', 'contract-call': 'Contract ปลายทาง',
};

export function Insight({ risk, cp, chainId, value }: { risk: Risk; cp: { address: string; kind: Kind }; chainId: number; value?: string }) {
  const head = HEAD[risk.level] ?? HEAD.MEDIUM;
  const lead = risk.verdict?.th ?? '';
  const ordered = [...risk.signals.filter((s) => s.severity !== 'info'), ...risk.signals.filter((s) => s.severity === 'info')];
  return (
    <Box>
      <Box alignment="center" center>
        <Image src={LOGO_SVG} alt="BridgeSecure" width={160} />
      </Box>
      <Banner title={head.title} severity={head.severity}>
        <Text><Bold>{head.line}</Bold></Text>
        <Text>{lead}</Text>
      </Banner>
      <Section>
        <Row label="Trust Score"><Text><Bold>{`${risk.trust_score}/100`}</Bold></Text></Row>
      </Section>
      {cp.kind === 'approve'
        ? <Text><Bold>คุณกำลังให้สิทธิ์ที่อยู่นี้ดึงโทเคนออกจากกระเป๋าของคุณ</Bold> ซึ่งเป็นวิธีหลักที่ wallet drainer ใช้</Text>
        : null}
      <Text><Bold>เหตุผลการวิเคราะห์</Bold></Text>
      {ordered.map((s) => (
        <Section>
          <Text><Bold>{s.title.th}</Bold></Text>
          <Text>{s.detail.th}</Text>
          {validationText(s, chainId) ? <Text color="muted">{validationText(s, chainId)}</Text> : null}
          {s.evidence_tx?.[0] && risk.explorer?.startsWith('https://')
            ? <Link href={`${risk.explorer}/tx/${s.evidence_tx[0]}`}>ดูธุรกรรมที่เป็นหลักฐาน</Link> : null}
        </Section>
      ))}
      <Text><Bold>{`สิ่งที่ตรวจแล้ว (${(risk.checks ?? []).length} ข้อ)`}</Bold></Text>
      <Section>
        {(risk.checks ?? []).map((c) => (
          <Text color={c.result === 'skip' ? 'muted' : 'default'}>{`${CHECK_ICON[c.result]} ${c.th}`}</Text>
        ))}
      </Section>
      <Section>
        <Row label={KIND_LABEL[cp.kind]}><Address address={cp.address as `0x${string}`} /></Row>
        {cp.kind === 'native' ? <Row label="จำนวน"><Text>{formatValue(value, chainId)}</Text></Row> : null}
        <Row label="ประวัติที่วิเคราะห์"><Text>{`${risk.stats?.n_all_chains ?? risk.stats?.n_total ?? 0} ธุรกรรม (ทุกเครือข่าย)`}</Text></Row>
        <Row label="แหล่งข้อมูล"><Text>{(risk.data_sources ?? []).join(', ') || '-'}</Text></Row>
        <Row label="เวลาวิเคราะห์"><Text>{`${risk.latency_ms ?? 0} ms`}</Text></Row>
        <Row label="รหัสอ้างอิง"><Text>{risk.request_id}</Text></Row>
      </Section>
      <Divider />
      <Text color="muted">BridgeSecure เตือน ไม่บล็อก การตัดสินใจเป็นของคุณ</Text>
      {API_BASE.startsWith('https://') ? <Link href={`${API_BASE}/verify.html`}>ตรวจสอบธุรกรรมกับ BridgeSecure</Link> : null}
    </Box>
  );
}

export const onTransaction: OnTransactionHandler = async ({ transaction, chainId }) => {
  const numericChain = Number(String(chainId).split(':')[1]); // CAIP-2 "eip155:43113"
  const tx = transaction as { to?: string; data?: string; from?: string; value?: string };
  const cp = counterparty(tx);
  if (!cp) return { content: <Box><Text>BridgeSecure: ธุรกรรมนี้เป็นการสร้าง contract ไม่มีปลายทางให้ตรวจ</Text></Box> };
  let risk: Risk;
  try {
    risk = await check(numericChain, cp.address, tx.from);
  } catch {
    return { content: (
      <Box>
        <Image src={LOGO_SVG} alt="BridgeSecure" width={160} />
        <Banner title="SECURITY WARNING" severity="warning">
          <Text><Bold>ระวัง: ยังตรวจที่อยู่นี้ไม่สำเร็จ</Bold></Text>
          <Text>เหตุผล: เชื่อมต่อระบบวิเคราะห์ BridgeSecure ไม่ได้ จึงยืนยันไม่ได้ว่าปลายทางปลอดภัย ยืนยันที่อยู่กับผู้รับผ่านช่องทางอื่นก่อนดำเนินการต่อ</Text>
        </Banner>
      </Box>
    ) };
  }
  const content = <Insight risk={risk} cp={cp} chainId={numericChain} value={tx.value} />;
  return risk.level === 'HIGH' ? { content, severity: 'critical' } : { content };
};

export const onInstall: OnInstallHandler = async () => {
  // Nothing to store: the Snap keeps no user data.
};

/**
 * Runs the built Snap inside the official MetaMask Snaps simulator and calls the REAL backend
 * (start it first:  python poc/backend/app.py  → http://localhost:8080).
 */
import { installSnap } from '@metamask/snaps-jest';

const SCAM = '0xa9fac309ea02c09f5eb7137bbaaca80032dcea5b';   // on the ScamSniffer list
const FRESH = '0x' + 'ab'.repeat(20);                        // no history
const WAVAX_FUJI = '0xd00ae08403b9bbb9124bb305c09058e32c39a48c';
const FROM = '0x1111111111111111111111111111111111111111';
const pad = (a: string) => a.slice(2).padStart(64, '0');

async function insight(tx: Record<string, string>) {
  const { onTransaction } = await installSnap();
  const res = await onTransaction({ chainId: 'eip155:43113', from: FROM, value: '0x0', data: '0x', ...tx });
  const err = (res.response as { error?: unknown }).error;
  if (err) throw new Error('Snap error: ' + JSON.stringify(err));
  const ui = res.getInterface();
  const text = JSON.stringify(ui.content);
  const severity = (res.response as { result?: { severity?: string } }).result?.severity;
  return { text, severity };
}

describe('BridgeSecure Guardian onTransaction', () => {
  it('flags a listed scam address as CRITICAL and explains why', async () => {
    const { text, severity } = await insight({ to: SCAM, value: '0x38d7ea4c68000' });
    expect(severity).toBe('critical');
    expect(text).toContain('CRITICAL SECURITY ALERT');
    expect(text).toContain('อยู่ในรายชื่อที่อยู่อันตราย');
    expect(text).toContain('ScamSniffer');
    expect(text).toContain('Trust Score');
    expect(text).toContain('"type":"Banner"');
    expect(text).toContain('"severity":"danger"');
    expect(text).toContain('เหตุผลการวิเคราะห์');
    expect(text).toContain('ตรวจแบบตรงตัว ไม่ใช่การคาดเดา');
    expect(text).toContain('0.001 AVAX');
    expect(text).toContain('ประวัติที่วิเคราะห์');
    expect(text).toContain('แหล่งข้อมูล');
    expect(text).toContain('รหัสอ้างอิง');
    expect(text).toContain('"type":"Image"');  });

  it('does not raise a critical alert for a fresh address, and says data is limited', async () => {
    const { text, severity } = await insight({ to: FRESH, value: '0x38d7ea4c68000' });
    expect(severity).toBeUndefined();
    expect(text).toContain('ข้อมูลไม่พอสำหรับประเมิน');
  });

  it('checks the spender of an ERC-20 approve (drainer entry point)', async () => {
    const data = '0x095ea7b3' + pad(SCAM) + 'f'.repeat(64);
    const { text, severity } = await insight({ to: WAVAX_FUJI, data });
    expect(severity).toBe('critical');
    expect(text).toContain('ผู้ขอสิทธิ์ใช้โทเคน');
    expect(text).toContain('ดึงโทเคนออกจากกระเป๋าของคุณ');
  });

  it('checks the recipient of an ERC-20 transfer, not the token contract', async () => {
    const data = '0xa9059cbb' + pad(SCAM) + '0'.repeat(63) + '1';
    const { severity } = await insight({ to: WAVAX_FUJI, data });
    expect(severity).toBe('critical');
  });
});

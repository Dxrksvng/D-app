# ส่งมอบ Backend ให้ทีม Frontend: BridgeSecure บน MetaMask (Pilot)

ทีมเรา (Backend) เป็นระบบหลังบ้านของ DApp ไม่ได้ออกแบบ UX/UI โดยส่งมอบ 4 อย่าง:
1. **API** วิเคราะห์ที่อยู่ปลายทางแบบ real-time
2. **SDK** ต่อ MetaMask และคุม flow การโอนที่มีการตรวจ
3. **ตราตรวจสอบที่ลงลายเซ็นแล้ว** ฝังอยู่ในทุกธุรกรรม
4. **MetaMask Snap** สำหรับเด้ง alert ในหน้ายืนยันของ MetaMask เอง

`web/index.html` ใช้แค่เป็นตัวอย่างการต่อระบบ ทีม Frontend ออกแบบหน้าจอเองทั้งหมด

---

## 1. ข้อจำกัดของ MetaMask ที่กำหนดสถาปัตยกรรม (ตรวจจาก docs.metamask.io เมื่อ 15 ต.ค. 2026)

| สิ่งที่อยากทำ (ตามหน้าจอใน Frontend PoC.pdf) | ทำได้แค่ไหน | วิธีของเรา |
|---|---|---|
| ผู้ใช้กรอกหรือสแกนปลายทาง **ในหน้า Send ของ MetaMask** แล้วเราเห็น | ❌ DApp มองไม่เห็นหน้าจอภายในของ MetaMask | ให้ผู้ใช้กรอกหรือสแกนปลายทาง **ใน DApp ของเรา** (หน้า Contract) |
| เด้ง alert **ก่อน** ผู้ใช้ยืนยัน | ✅ ทำได้ทั้งมือถือและ desktop | `guardedSend()` เรียก `decide(risk)` ให้ UI เด้ง popup **ก่อน** ส่ง `eth_sendTransaction` |
| alert **ทับหน้า Review ของ MetaMask** (ภาพหน้า 2) | ⚠️ ทำได้ผ่าน Snap เท่านั้น ซึ่งใช้ได้บน extension · popup ระดับ critical มีเฉพาะ **Flask** · ถ้าจะเรียก API ของเราบน MetaMask ปกติต้อง **ผ่าน allowlist** | `poc/snap/` (source พร้อมแล้ว · ยังไม่ได้ build) |
| แสดงผลวิเคราะห์บน **ทุกธุรกรรม** (ภาพหน้า 4 "Verified by BridgeSecure") | ✅ | ใส่ตราที่ลงลายเซ็นแล้วใน `data` ของธุรกรรม (เห็นบน Explorer) + `/v1/verify/tx` + `verify.html` |

**สรุป:** pilot บนมือถือ (iPhone ตามภาพ) ใช้ flow ของ DApp + MetaMask Connect ส่วน Snap เป็นช่องทางเสริมบน desktop

---

## 2. Flow ของ Pilot

```
[DApp] Connect → MetaMask Connect / EIP-6963        wallet.connect() | wallet.useProvider(mmConnectProvider)
[DApp] หน้า Contract: วาง / สแกน QR ปลายทาง           parsePaymentUri(text)  → {address, chainId?, valueWei?}
[DApp] กรอกจำนวน → กด "ส่ง"
        └─ guardedSend({ api, wallet, chainId, to, valueWei, decide })
             1. GET /v1/risk?chain_id&to&from&value_wei      ← Backend วิเคราะห์ (0.4–6 วินาที)
             2. decide(risk)  →  UI เด้ง popup "CRITICAL SECURITY ALERT" + "Show more reason"
                ผู้ใช้เลือก ยกเลิก | ดำเนินการต่อ        (เราเตือน ไม่บล็อก)
             3. wallet.ensureChain(chainId)
             4. eth_sendTransaction { to, value, data: <ตรา BridgeSecure> }  → MetaMask เปิดหน้า Review
             5. waitForReceipt → GET /v1/verify/tx → "Verified by BridgeSecure · Trust Score xx"
```

ใช้งาน:
```js
import { RiskGuardClient, WalletManager, guardedSend, parsePaymentUri, units } from '/sdk/riskguard.js';

const api = new RiskGuardClient({ apiBase: 'https://api.bridgesecure.com' });
const wallet = new WalletManager({ chains: await api.getChains() });

// มือถือ: provider จาก MetaMask Connect (หน้าจอ "Continue in MetaMask")
await wallet.useProvider(metamaskConnectProvider, { name: 'MetaMask' });
// desktop: await wallet.discover(); await wallet.connect(uuid);

const p = parsePaymentUri(qrText);                 // รองรับ 0x…, ethereum:0x…@43113?value=…
const result = await guardedSend({
  api, wallet, chainId: p.chainId ?? 43113, to: p.address, valueWei: units.parse(amount),
  decide: (risk) => showBridgeAlert(risk),        // ← UI ของทีม Frontend; resolve true = โอนต่อ, false = ยกเลิก
  onStage: (stage, info) => updateProgress(stage, info),  // checking | deciding | switching | signing | pending | confirmed | failed
});
// result.status: 'cancelled' | 'confirmed' | 'failed' · result.risk · result.txHash · result.verification
```

---

## 3. ข้อมูลที่ popup ต้องใช้ (`risk`)

| ฟิลด์ | ใช้ทำอะไรใน UI |
|---|---|
| `level` | `HIGH` → "CRITICAL SECURITY ALERT" (แดง) · `MEDIUM` (ส้ม) · `LOW` (เขียว) · `UNKNOWN` (เทา **ห้ามใช้เขียว**) |
| `trust_score` | "Trust Score 95/100" เป็นดัชนีความรุนแรง **ไม่ใช่ความน่าจะเป็น** (สูตรอยู่ที่ `/v1/rules`) |
| `signals[0].title.th` | ข้อความหลักบน popup เช่น "อยู่ในรายชื่อที่อยู่อันตราย" |
| `signals[].detail.th` + `evidence_tx[]` | หน้า "Show more reason": เหตุผลทุกข้อ + ลิงก์ `{explorer}/tx/{hash}` |
| `signals[].validation` | บรรทัดเล็ก "ผ่านการทดสอบย้อนหลัง 2024–26: จับได้ 59% เตือนผิด 1.5%" |
| `attestation` | SDK จัดการเองใน `guardedSend` |

ตัวอย่างการจับคู่ข้อความกับดีไซน์หน้า 2:
- `L0_LISTED` / `L2_LINKED` → "Identified direct links to known Money Laundering / Scam"
- `R4_DRAINER` → "Wallet-drainer behaviour"
- `POISONING_LOOKALIKE` → "Look-alike of an address you used"

**ห้ามเขียนข้อความเกินหลักฐาน** เช่น ห้ามบอกว่า "ฟอกเงิน" ถ้า signal ไม่ได้บอกแบบนั้น

---

## 4. ตรา "Verified by BridgeSecure" บนทุกธุรกรรม (ภาพหน้า 4)

- **ที่เก็บ:** อยู่ใน input data ของธุรกรรมโอนเอง (86 bytes ≈ gas เพิ่มประมาณ 1,400) เปิด Snowtrace / Etherscan → Input Data → View as UTF-8 จะเห็นข้อความแบบนี้:
  `BRIDGESECURE|v1|c=43113|l=LOW|ts=95|s=-|t=1792079958|r=409ad926082c|k=…`
- **ปลอมหรือคัดลอกไม่ได้:** ลายเซ็น HMAC ผูกกับ chain, ผู้ส่ง, ผู้รับ และจำนวนเงิน (มี test ยืนยัน)
- **หน้ายืนยัน:** `verify.html?chain_id=43113&tx=0x…` หรือใส่ที่อยู่กระเป๋าเพื่อดูประวัติทุกธุรกรรมที่มีตรา (`/v1/verify/address`)
- **Backend ไม่เก็บข้อมูลธุรกรรม:** ทุกครั้งที่ยืนยันจะอ่านข้อมูลจาก chain ใหม่
- **ใส่ตราได้เฉพาะเมื่อปลายทางเป็นกระเป๋า (EOA):** ถ้าเป็น contract จะไม่ใส่ เพื่อไม่ให้รบกวนการเรียกฟังก์ชัน
- **ปิดได้:** ส่ง `attest: false` ถ้าผู้ใช้ไม่ต้องการ

> หมายเหตุ: ตรานี้ไม่ใช่ "Validator" ของ blockchain (เราไม่ได้เป็น validator ของ BSC หรือ Avalanche) จึงควรใช้คำว่า "Verified by BridgeSecure" ไม่ใช่ "Validator: BridgeSecure"

---

## 5. MetaMask Snap (`poc/snap/`)
- **ทำอะไร:** ตรวจ **ทุกธุรกรรม** ใน MetaMask extension รวมการส่งจากหน้า Send ของ MetaMask เอง, ERC-20 transfer และ `approve` (ช่องทางหลักของ drainer)
- **ระดับ HIGH:** ส่งคืน `severity: "critical"` ซึ่ง Flask จะแสดง popup ให้ผู้ใช้ยอมรับก่อนยืนยัน
- **สถานะ:** source พร้อม แต่ยังไม่ได้ build เพราะเครื่องนี้ไม่มี Node.js (ขั้นตอนอยู่ใน `snap/README.md`)

---

## 6. ทดสอบ
```bash
python poc/backend/app.py                 # http://localhost:8080
cd poc && python -m unittest discover -s backend/tests -t .     # 27 tests
```
เหรียญ Fuji: https://build.avax.network/console/primary-network/faucet

| ผลที่คาด | ปลายทาง (Fuji) |
|---|---|
| `HIGH` | `0xa9fac309ea02c09f5eb7137bbaaca80032dcea5b` (อยู่ในรายชื่อ ScamSniffer จริง ห้ามโอนบน mainnet) |
| `MEDIUM` | `0xd00ae08403B9bbb9124bB305C09058E32C39A48c` (contract ของ WAVAX) |
| `UNKNOWN` | ที่อยู่ใหม่ |
| `HIGH` poisoning | ที่อยู่ที่ขึ้นต้นและลงท้าย 4 ตัวเหมือนที่อยู่ที่คุณเคยโอนไป |
| QR | `ethereum:0x9f8c163cBA728e99993ABe7495F06c0A3c8Ac8b9@43113?value=1e16` |

## 7. ข้อจำกัด
- โอนได้เฉพาะเหรียญหลัก (AVAX/ETH) ใน DApp flow (Snap ตรวจ ERC-20 ได้)
- ต้องใช้ HTTPS เพื่อให้ MetaMask บนมือถือเชื่อมได้
- ตั้ง `ATTESTATION_SECRET` ใน production ทุก instance ต้องใช้ค่าเดียวกัน ถ้าเปลี่ยนค่า ตราเก่าจะตรวจไม่ผ่าน
- ยังไม่ได้ทดสอบกับ MetaMask จริงและ Snap บน Flask ทีมต้องทดสอบด้วยกระเป๋าจริง

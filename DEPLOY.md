# นำ BridgeSecure ขึ้นคลาวด์ (Render + GitHub)

ผลลัพธ์: ได้ลิงก์ HTTPS เช่น `https://bridgesecure.onrender.com` ใครก็เปิดแล้วกด Connect MetaMask ได้เหมือนที่เราทดสอบใน Local
(หน้าแรก `/` = wallet.html, หน้าตรวจตรา = `/verify.html`, API = `/v1/...`)

## 1. เอาโค้ดขึ้น GitHub (ครั้งแรก)
1. แตกไฟล์ `bridgesecure-cloud.zip` ข้อมูลข้างในคือ **root ของ repo** (มี `Dockerfile`, `render.yaml` อยู่ชั้นบนสุด)
2. ใน repo `MISZURIE/Bridge-Crypto` (หรือสร้าง repo ใหม่) → **Add file → Upload files** → ลากทุกไฟล์/โฟลเดอร์ในโฟลเดอร์ที่แตกไว้ → Commit
   - ไฟล์ลับ (`backend/.env`, `audit/.dataapi_key`, `data/.attestation_secret`) ไม่ได้อยู่ใน zip นี้ อย่าอัปโหลดเพิ่ม

## 2. Deploy บน Render
1. สมัคร/เข้าสู่ระบบ https://render.com ด้วย GitHub (ทำเอง)
2. **New → Blueprint** → เลือก repo → Render อ่าน `render.yaml` เอง → **Apply**
3. ช่อง `DATA_API_KEY` ให้วางคีย์ Avalanche Data API เอง (ไม่ใส่ก็ได้ จะใช้ Routescan แทน)
4. รอ build ~3–5 นาที → เปิด `https://<ชื่อ>.onrender.com/v1/health` ต้องเห็น `"status": "ok"`

`ATTESTATION_SECRET` Render สุ่มให้และเก็บไว้เอง ห้ามเปลี่ยน ไม่งั้นตราบนธุรกรรมเก่าจะตรวจไม่ผ่าน

## 3. ให้คนอื่นทดสอบ
- ส่งลิงก์ให้ได้เลย ใช้ได้กับ MetaMask บน Chrome/Brave/Edge และ **MetaMask มือถือ** (เปิดลิงก์ในเบราว์เซอร์ของแอป)
- เครือข่ายเริ่มต้น Avalanche Fuji (testnet) ขอเหรียญทดสอบจากปุ่ม Buy → faucet
- การวิเคราะห์ปลายทางแสดงในหน้า Review ของ wallet ก่อนกดยืนยันทุกครั้ง แล้ว MetaMask ขึ้นให้เซ็นตามปกติ

## 4. (ทางเลือก) ให้ผลวิเคราะห์ขึ้นใน MetaMask ผ่าน Snap
Snap แบบ `local:` ใช้ได้แค่เครื่องเรา คนอื่นต้องติดตั้งจาก npm:
```
cd snap
$env:API_BASE="https://<ชื่อ>.onrender.com"; npm run build
npm login        # บัญชี npm ของทีม (ทำเอง)
npm publish
```
แล้วตั้ง `SNAP_ID=npm:bridgesecure-guardian-snap` ใน Render → Environment
ข้อจำกัดจาก MetaMask: Snap ที่ใช้ `network-access` ต้องผ่าน allowlist ของ MetaMask ก่อน ระหว่างนี้ติดตั้งได้เฉพาะผู้ใช้ **MetaMask Flask** เท่านั้น ผู้ใช้ MetaMask ปกติจะเห็นคำเตือนบนหน้าเว็บแทน

## หมายเหตุ
- แพลน free: ไม่มีคนใช้ ~15 นาทีจะหลับ ครั้งแรกโหลด ~50 วินาที ถ้าจะให้กรรมการกดแล้วเร็วทันที ใช้ Starter ($7/เดือน) ในวันนำเสนอ
- ไม่มีการเก็บข้อมูลธุรกรรมผู้ใช้: log ไม่มี address, ประวัติอ่านจาก chain โดยตรง
- อัปเดตโค้ด: แก้ใน GitHub → Render deploy ใหม่อัตโนมัติ
- ใช้คลาวด์อื่นได้ (Cloud Run / Fly.io / VPS) เพราะเป็น Docker ธรรมดา: `docker build -t bridgesecure . && docker run -p 8080:8080 -e ATTESTATION_SECRET=<สุ่มยาว> bridgesecure`

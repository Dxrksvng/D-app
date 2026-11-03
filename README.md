<div align="center">

# RiskGuard

**Check the destination address before you send crypto. Every reason explained, never blocked.**

![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white) ![Dependencies none (stdlib)](https://img.shields.io/badge/Dependencies-none_(stdlib)-2ea44f?style=for-the-badge) ![Chains Avalanche · Ethereum](https://img.shields.io/badge/Chains-Avalanche_·_Ethereum-E84142?style=for-the-badge) ![Mode warn-only](https://img.shields.io/badge/Mode-warn--only-F59E0B?style=for-the-badge)

</div>

> Engine v2 uses only signals that passed the pre-registered E5 audit. The backend is Python standard library only, so there is nothing to install.

## Tech stack

<p align="center">
  <img src="https://skillicons.dev/icons?i=py,js,html,css,ts,docker,gcp&perline=10" alt="Tech stack" />
</p>

## How it works

```mermaid
flowchart LR
    U([User]) --> W["Web UI / riskguard.js SDK"]
    U --> S["MetaMask Snap\nin-wallet alert"]
    W -->|"GET /v1/verify/address\n/v1/verify/tx"| API["backend/app.py\nHTTP API"]
    S --> API
    API --> SVC["service.py\nparallel fetch + 60 s cache"]
    SVC --> SRC["sources.py\nAvalanche Data API\n-> Routescan fallback"]
    SVC --> BL["blocklists.py\nScamSniffer, OFAC SDN,\nForta, MEW (6 h refresh)"]
    SVC --> RPC["Chain RPC\neth_getCode"]
    SRC --> ENG["engine_v2.py\nassess()"]
    BL --> ENG
    RPC --> ENG
    ENG --> V{{"Verdict + reasons\n(never blocks)"}}
    V --> W
    V --> S
    V --> ATT["attestation.py\nsigned on-chain memo\n+ trust score"]
    ATT --> VER["verify.html\npublic seal check"]
```

---

Checks the destination address before a user sends crypto, explains every reason, and never blocks.
Engine v2 uses only signals that passed the pre-registered E5 audit (`../audit/report`).

```
poc/
  backend/        Python 3.10+ standard library only (no dependencies)
    app.py        HTTP API + static hosting       engine_v2.py  pure risk logic
    service.py    parallel fetch + cache          sources.py    Avalanche Data API → Routescan fallback
    blocklists.py daily L0 feeds                  tests/        19 tests incl. E5 regression
    attestation.py signed on-chain memo + trust score (no server-side storage)
  web/            reference UI + sdk/riskguard.js (Frontend handoff) + verify.html (public seal check)
  snap/           MetaMask Snap: in-wallet alert for every transaction (source; build needs Node.js)
  data/seed/      offline blocklist snapshot (used until the first refresh)
  openapi.yaml    API contract                    HANDOFF.md    for the Frontend team (Thai)
```

## Run locally
```bash
python poc/backend/app.py
```
Open http://localhost:8080. Optional settings: copy `backend/.env.example` to `backend/.env`.

## Test
```bash
cd poc
python -m unittest discover -s backend/tests -t .
```

## Deploy (public HTTPS is required for wallets on other devices)
**Docker / Cloud Run** (the original repo already targets GCP):
```bash
cd poc
gcloud run deploy riskguard --source . --region asia-southeast1 --allow-unauthenticated --set-env-vars DATA_API_KEY=...,ALLOWED_ORIGINS=https://your-frontend
```
Any container host works (`docker build -t riskguard . && docker run -p 8080:8080 riskguard`).
For a quick public demo from a laptop, a tunnel such as `cloudflared tunnel --url http://localhost:8080` gives a temporary HTTPS URL.

## Data sources
- Avalanche Data API: history (`/v1/chains/{id}/addresses/{a}/transactions`) and token metadata, for Fuji and C-Chain.
- Chain RPC `eth_getCode`: contract detection.
- Routescan: Ethereum, and automatic fallback when the Data API is rate-limited (circuit breaker).
- Blocklists, refreshed every 6 h: ScamSniffer (daily), OFAC SDN, Forta, MyEtherWallet.

## Privacy
Nothing about a check is written to disk or logs (access logs record path and status only). Results are cached in memory for 60 s.
Community reports store `address, chain, category, time` only.

## Known limits
- Native-coin transfers only.
- Rate limiting is per IP and in memory (one instance). With `TRUST_PROXY=1` the first `X-Forwarded-For` entry is used.
- WalletConnect support is wired but untested without a project id.

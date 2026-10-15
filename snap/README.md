# BridgeSecure Guardian (MetaMask Snap)

Shows the BridgeSecure analysis **inside MetaMask's own confirmation window** for every transaction. This covers:
- sends from MetaMask's own Send screen
- transactions from other dapps
- ERC-20 `transfer` (checks the token recipient)
- ERC-20 `approve` (checks the spender, which is the drainer entry point)

HIGH risk returns `severity: "critical"`. MetaMask then shows a CRITICAL SECURITY ALERT that the user must acknowledge before confirming. Every reason is shown with its evidence link and audit numbers. The Snap never blocks.

## Status
- Built with `@metamask/snaps-cli` 8.4.1 and SDK 12.1.0.
- `npm test`: 4/4 pass in the official Snaps simulator (`@metamask/snaps-jest`) against the live backend:
  - scam address → critical
  - fresh address → no false alert
  - `approve` to a drainer → critical
  - ERC-20 transfer → recipient checked
- `tsc --noEmit` reports no type errors.
- Not yet tested by a human in MetaMask Flask.

## Platform limits (docs.metamask.io, checked 2026-10-15)
| Item | Status |
|---|---|
| Insight tab in the confirmation | MetaMask extension |
| `severity: "critical"` modal | **MetaMask Flask only** (experimental) |
| `endowment:network-access` (calls our API) | Protected. Regular MetaMask requires allowlisting; Flask installs it without review |
| MetaMask Mobile | Not documented for Snaps. The mobile pilot uses the dapp popup (`guardedSend`) |
| Links in Snap UI | Must be `https:`. The local `http://localhost` backend link is hidden automatically |

## Test it in MetaMask Flask (desktop Chrome)
1. Install [MetaMask Flask](https://metamask.io/flask/) in a **separate Chrome profile**. Disable regular MetaMask in that profile, then import a test wallet.
2. Start the backend and the Snap server:
   ```bash
   python poc/backend/app.py
   cd poc/snap && npm run serve
   ```
   The backend runs on http://localhost:8080 and the Snap server on http://localhost:8081.
3. Open http://localhost:8080 and click **Connect**. When the wallet is Flask, the card **"ติดตั้ง BridgeSecure Guardian"** appears. Click it and approve.
4. In Flask's **own Send screen**, send 0.001 AVAX on Fuji to `0xa9fac309ea02c09f5eb7137bbaaca80032dcea5b`. The BridgeSecure critical alert should appear, followed by the insight with reasons.

## Build for production
```bash
API_BASE=https://api.your-domain npm run build
npm test
npm publish
```
Then submit the MetaMask Snaps allowlist form. Once approved, users install from the Snaps Directory on regular MetaMask, and you set `SNAP_ID=npm:bridgesecure-guardian-snap` on the backend.

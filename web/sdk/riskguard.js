/**
 * RiskGuard SDK — framework-free ES module for the Frontend team.
 *
 *   import { RiskGuardClient, WalletManager, units } from './sdk/riskguard.js';
 *
 * RiskGuardClient  → talks to the backend (risk checks, chains, reports)
 * WalletManager    → real wallet connection: EIP-6963 discovery + EIP-1193 provider
 *                    (MetaMask, Core, Trust Wallet, Rabby, Coinbase Wallet, any injected wallet,
 *                    and WalletConnect when a project id is configured)
 * units            → exact decimal <-> wei conversion with BigInt (no floating point)
 *
 * The SDK never blocks a transfer: it returns the risk result and leaves the decision to the UI/user.
 */

// ---------------------------------------------------------------- units
export const units = {
  /** "1.25" -> 1250000000000000000n (18 decimals). Throws on invalid input. */
  parse(amount, decimals = 18) {
    const s = String(amount).trim();
    if (!/^\d+(\.\d+)?$/.test(s)) throw new Error('INVALID_AMOUNT');
    const [i, f = ''] = s.split('.');
    if (f.length > decimals) throw new Error('TOO_MANY_DECIMALS');
    return BigInt(i) * 10n ** BigInt(decimals) + BigInt((f + '0'.repeat(decimals)).slice(0, decimals) || '0');
  },
  /** 1250000000000000000n -> "1.25" */
  format(wei, decimals = 18, maxFraction = 6) {
    const v = BigInt(wei); const base = 10n ** BigInt(decimals);
    const i = v / base; let f = (v % base).toString().padStart(decimals, '0').slice(0, maxFraction).replace(/0+$/, '');
    return f ? `${i}.${f}` : `${i}`;
  },
  toHex: (n) => '0x' + BigInt(n).toString(16),
};

export const isAddress = (a) => /^0x[0-9a-fA-F]{40}$/.test(String(a || '').trim());

/**
 * Parse whatever a user pasted or a QR code contained:
 *   "0xabc…", "ethereum:0xabc…", "ethereum:0xabc…@43113", "ethereum:0xabc…@43113?value=1e16",
 *   "avalanche:0xabc…" and text with surrounding spaces/newlines.
 * Returns { address, chainId?, valueWei? } or null. ERC-20 "…/transfer?address=" URIs return the token
 * recipient as `address` and the token contract as `token`.
 */
export function parsePaymentUri(text) {
  const s = String(text || '').trim();
  if (isAddress(s)) return { address: s };
  const m = s.match(/^(?:ethereum|avalanche|eth):(?:pay-)?(0x[0-9a-fA-F]{40})(?:@(\d+))?(?:\/(\w+))?(?:\?(.*))?$/i);
  if (!m) { const any = s.match(/0x[0-9a-fA-F]{40}/); return any ? { address: any[0] } : null; }
  const q = new URLSearchParams(m[4] || ''); const out = { address: m[1] };
  if (m[2]) out.chainId = Number(m[2]);
  if (m[3] === 'transfer' && isAddress(q.get('address'))) { out.token = m[1]; out.address = q.get('address'); }
  const v = q.get('value');
  if (v && /^\d+(\.\d+)?(e\d+)?$/i.test(v)) {
    const [mant, exp = '0'] = v.toLowerCase().split('e'); const [i, f = ''] = mant.split('.');
    const e = Number(exp) - f.length; out.valueWei = e >= 0 ? BigInt(i + f) * 10n ** BigInt(e) : undefined;
  }
  return out;
}
export const shortAddress = (a) => (a ? `${a.slice(0, 6)}…${a.slice(-4)}` : '');

// ---------------------------------------------------------------- backend client
export class RiskGuardClient {
  constructor({ apiBase = '', timeoutMs = 15000 } = {}) { this.apiBase = apiBase.replace(/\/$/, ''); this.timeoutMs = timeoutMs; }

  async _fetch(path, init = {}) {
    const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), this.timeoutMs);
    try {
      const r = await fetch(this.apiBase + path, { ...init, signal: ctl.signal, headers: { 'Content-Type': 'application/json', ...(init.headers || {}) } });
      const body = await r.json().catch(() => ({}));
      if (!r.ok) { const e = new Error(body.error || `HTTP_${r.status}`); e.status = r.status; e.body = body; throw e; }
      return body;
    } catch (e) {
      if (e.name === 'AbortError') { const x = new Error('TIMEOUT'); x.body = { message: { th: 'ระบบตรวจสอบตอบช้าเกินไป', en: 'Risk check timed out' } }; throw x; }
      throw e;
    } finally { clearTimeout(t); }
  }

  /** @returns {Promise<RiskResult>} level: LOW | MEDIUM | HIGH | UNKNOWN */
  /** Pass `from` + `valueWei` to receive `attestation.data_hex`, the signed verdict to embed in the transfer. */
  checkRisk({ chainId, to, from, valueWei }) {
    const q = new URLSearchParams({ chain_id: String(chainId), to });
    if (from) q.set('from', from);
    if (valueWei !== undefined && valueWei !== null) q.set('value_wei', BigInt(valueWei).toString());
    return this._fetch(`/v1/risk?${q}`);
  }
  verifyTx({ chainId, txHash }) { return this._fetch(`/v1/verify/tx?${new URLSearchParams({ chain_id: String(chainId), tx_hash: txHash })}`); }
  verifyAddress({ chainId, address }) { return this._fetch(`/v1/verify/address?${new URLSearchParams({ chain_id: String(chainId), address })}`); }
  getChains() { return this._fetch('/v1/chains').then((r) => r.chains); }
  health() { return this._fetch('/v1/health'); }
  report({ chainId, address, category = 'other' }) {
    return this._fetch('/v1/reports', { method: 'POST', body: JSON.stringify({ chain_id: chainId, address, category }) });
  }
}

// ---------------------------------------------------------------- one-call guarded transfer
/**
 * The whole protected flow in one call. The UI supplies `decide(risk)`, which shows the alert popup and
 * resolves true (send) or false (cancel). Nothing is blocked by the SDK; the user decides.
 *
 *   const r = await guardedSend({ api, wallet, chainId: 43113, to, valueWei,
 *                                 decide: (risk) => showAlertPopup(risk) });   // your UI
 *   // r.status: 'cancelled' | 'confirmed' | 'failed', r.risk, r.txHash, r.verification
 *
 * attest=true writes the signed verdict into the transaction (shown on explorers, verifiable via /v1/verify/tx).
 */
export async function guardedSend({ api, wallet, chainId, to, valueWei, decide, attest = true, onStage = () => {} }) {
  if (!wallet.account) throw new Error('NOT_CONNECTED');
  onStage('checking');
  let risk;
  try { risk = await api.checkRisk({ chainId, to, from: wallet.account, valueWei }); }
  catch (e) { risk = { level: 'UNKNOWN', error: true, signals: [], message: e.body?.message }; }
  onStage('deciding', risk);
  if (!(await decide(risk))) return { status: 'cancelled', risk };
  onStage('switching');
  await wallet.ensureChain(chainId);
  const fresh = risk.attestation && risk.attestation.valid_until * 1000 > Date.now();
  onStage('signing', risk);
  const txHash = await wallet.sendNative({ to, valueWei, data: attest && fresh ? risk.attestation.data_hex : undefined });
  onStage('pending', { txHash });
  const rc = await wallet.waitForReceipt(txHash);
  let verification = null;
  if (attest && fresh) {
    for (let i = 0; i < 4 && !verification?.verification; i++) {  // the RPC node may lag the receipt by a block
      try { verification = await api.verifyTx({ chainId, txHash }); } catch {}
      if (!verification?.verification) await new Promise((ok) => setTimeout(ok, 1500));
    }
  }
  onStage(rc.success ? 'confirmed' : 'failed', { txHash, verification });
  return { status: rc.success ? 'confirmed' : 'failed', risk, txHash, receipt: rc, verification };
}

// ---------------------------------------------------------------- wallets
const LEGACY_NAMES = [['isAvalanche', 'Core'], ['isRabby', 'Rabby'], ['isTrust', 'Trust Wallet'], ['isTrustWallet', 'Trust Wallet'],
  ['isCoinbaseWallet', 'Coinbase Wallet'], ['isOkxWallet', 'OKX Wallet'], ['isMetaMask', 'MetaMask']];

export class WalletManager extends EventTarget {
  constructor({ walletConnectProjectId = '', chains = [] } = {}) {
    super();
    this.wcProjectId = walletConnectProjectId; this.chains = chains;
    this.wallets = new Map(); this.provider = null; this.info = null; this.account = null; this.chainId = null;
    this._onAccounts = (a) => this._setAccount(a?.[0] || null);
    this._onChain = (c) => { this.chainId = Number(c); this._emit('chain', this.chainId); };
    this._onDisconnect = () => this._reset();
  }

  /** Discover installed wallets (EIP-6963) with a legacy window.ethereum fallback. Resolves after `waitMs`. */
  discover(waitMs = 400) {
    const onAnnounce = (ev) => { const d = ev.detail; if (d?.info?.uuid) { this.wallets.set(d.info.uuid, d); this._emit('wallets', this.list()); } };
    window.addEventListener('eip6963:announceProvider', onAnnounce);
    window.dispatchEvent(new Event('eip6963:requestProvider'));
    return new Promise((res) => setTimeout(() => {
      if (this.wallets.size === 0 && window.ethereum) {
        const eth = window.ethereum; const name = (LEGACY_NAMES.find(([k]) => eth[k]) || [null, 'Browser wallet'])[1];
        this.wallets.set('legacy', { info: { uuid: 'legacy', name, icon: '', rdns: 'legacy.injected' }, provider: eth });
      }
      res(this.list());
    }, waitMs));
  }
  list() { return [...this.wallets.values()].map((w) => w.info); }
  hasWalletConnect() { return Boolean(this.wcProjectId); }

  /**
   * Connect. With `snapId`, MetaMask is asked ONCE for both the account connection and installing the
   * BridgeSecure Guardian Snap (wallet_requestPermissions with eth_accounts + wallet_snap). Wallets that
   * cannot install the Snap (regular MetaMask before allowlisting, other wallets) fall back to a plain connect.
   */
  async connect(uuid, { snapId } = {}) {
    const d = uuid === 'walletconnect' ? await this._walletConnect() : this.wallets.get(uuid);
    if (!d) throw new Error('WALLET_NOT_FOUND');
    this._detach(); this.provider = d.provider; this.info = d.info;
    this.snapInstalled = false;
    if (snapId && /metamask/i.test(`${d.info.rdns} ${d.info.name}`)) {
      try {
        await this.provider.request({ method: 'wallet_requestPermissions', params: [{ eth_accounts: {}, wallet_snap: { [snapId]: {} } }] });
        this.snapInstalled = await this.hasSnap(snapId);
      } catch (e) {
        if (e?.code === 4001) throw e;   // the user said no: respect it
      }
    }
    const accounts = await this.provider.request({ method: 'eth_requestAccounts' });
    this.chainId = Number(await this.provider.request({ method: 'eth_chainId' }));
    this.provider.on?.('accountsChanged', this._onAccounts);
    this.provider.on?.('chainChanged', this._onChain);
    this.provider.on?.('disconnect', this._onDisconnect);
    try { localStorage.setItem('riskguard.wallet', this.info.rdns || this.info.name); } catch {}
    this._setAccount(accounts?.[0] || null); this._emit('chain', this.chainId);
    return { account: this.account, chainId: this.chainId, wallet: this.info };
  }

  /** Reconnect silently if the user connected before (no popup: eth_accounts). */
  async restore() {
    let saved = null; try { saved = localStorage.getItem('riskguard.wallet'); } catch {}
    if (!saved) return null;
    const d = [...this.wallets.values()].find((w) => (w.info.rdns || w.info.name) === saved);
    if (!d) return null;
    const accounts = await d.provider.request({ method: 'eth_accounts' }).catch(() => []);
    if (!accounts?.length) return null;
    return this.connect(d.info.uuid);
  }

  async disconnect() {
    try { await this.provider?.request?.({ method: 'wallet_revokePermissions', params: [{ eth_accounts: {} }] }); } catch {}
    try { await this.provider?.disconnect?.(); } catch {}
    try { localStorage.removeItem('riskguard.wallet'); } catch {}
    this._reset();
  }

  /** Switch the wallet to `chainId`, adding the network first if the wallet does not know it. */
  async ensureChain(chainId) {
    if (this.chainId === chainId) return;
    const hex = units.toHex(chainId);
    try {
      await this.provider.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: hex }] });
    } catch (e) {
      if (e.code !== 4902 && e?.data?.originalError?.code !== 4902) throw e;
      const c = this.chains.find((x) => x.chain_id === chainId);
      if (!c) throw e;
      await this.provider.request({ method: 'wallet_addEthereumChain', params: [{ chainId: hex, chainName: c.name,
        nativeCurrency: { name: c.symbol, symbol: c.symbol, decimals: 18 }, rpcUrls: [c.rpc], blockExplorerUrls: [c.explorer] }] });
    }
    this.chainId = Number(await this.provider.request({ method: 'eth_chainId' }));
  }

  /** True when the connected wallet is MetaMask Flask (needed today for the Snap's critical alert). */
  async isFlask() {
    try { return /flask/i.test(await this.provider.request({ method: 'web3_clientVersion' })); } catch { return false; }
  }

  /** True when the BridgeSecure Guardian Snap is installed and connected to this site. */
  async hasSnap(snapId) {
    try { const s = await this.provider.request({ method: 'wallet_getSnaps' }); return Boolean(s && s[snapId] && !s[snapId].error); } catch { return false; }
  }

  /** Install / update the BridgeSecure Guardian Snap. snapId: 'local:http://localhost:8081' (dev) or 'npm:bridgesecure-guardian-snap'. */
  installSnap(snapId) {
    return this.provider.request({ method: 'wallet_requestSnaps', params: { [snapId]: {} } });
  }

  async balance() {
    const hex = await this.provider.request({ method: 'eth_getBalance', params: [this.account, 'latest'] });
    return BigInt(hex);
  }

  /**
   * Use a provider you created yourself, e.g. MetaMask Connect for mobile browsers
   * ("Continue in MetaMask"):  wallet.useProvider(metamaskConnectProvider, { name: 'MetaMask' })
   */
  async useProvider(provider, info = {}) {
    const uuid = info.uuid || 'external';
    this.wallets.set(uuid, { info: { uuid, name: info.name || 'Wallet', icon: info.icon || '', rdns: info.rdns || 'external' }, provider });
    return this.connect(uuid);
  }

  /** Native-coin transfer. `data` (optional) carries the RiskGuard attestation. Returns the tx hash. */
  sendNative({ to, valueWei, data }) {
    const tx = { from: this.account, to, value: units.toHex(valueWei) };
    if (data) tx.data = data;
    return this.provider.request({ method: 'eth_sendTransaction', params: [tx] });
  }

  async waitForReceipt(hash, { timeoutMs = 120000, intervalMs = 1500 } = {}) {
    const end = Date.now() + timeoutMs;
    while (Date.now() < end) {
      const r = await this.provider.request({ method: 'eth_getTransactionReceipt', params: [hash] }).catch(() => null);
      if (r) return { ...r, success: r.status === '0x1' };
      await new Promise((ok) => setTimeout(ok, intervalMs));
    }
    throw new Error('RECEIPT_TIMEOUT');
  }

  /** Maps wallet / RPC errors to a user-facing message. */
  static explain(e) {
    const code = e?.code ?? e?.data?.originalError?.code; const msg = String(e?.message || '');
    if (code === 4001 || /reject|denied|cancel/i.test(msg)) return { th: 'คุณยกเลิกในกระเป๋า', en: 'You rejected the request in your wallet' };
    if (code === -32002) return { th: 'มีคำขอค้างอยู่ในกระเป๋า เปิดกระเป๋าเพื่อดำเนินการต่อ', en: 'A request is already pending in your wallet' };
    if (/insufficient funds/i.test(msg)) return { th: 'ยอดเงินไม่พอสำหรับจำนวนและค่าธรรมเนียม', en: 'Insufficient funds for amount plus gas' };
    if (code === 4902) return { th: 'กระเป๋ายังไม่รู้จักเครือข่ายนี้', en: 'Network not added to wallet' };
    return { th: 'กระเป๋าตอบกลับด้วยข้อผิดพลาด: ' + msg.slice(0, 140), en: msg.slice(0, 140) };
  }

  // -- internals
  async _walletConnect() {
    if (!this.wcProjectId) throw new Error('WALLETCONNECT_NOT_CONFIGURED');
    const { EthereumProvider } = await import('https://cdn.jsdelivr.net/npm/@walletconnect/ethereum-provider@2.17.0/+esm');
    const rpcMap = Object.fromEntries(this.chains.map((c) => [c.chain_id, c.rpc]));
    const provider = await EthereumProvider.init({ projectId: this.wcProjectId, showQrModal: true, optionalChains: this.chains.map((c) => c.chain_id),
      rpcMap, metadata: { name: 'RiskGuard', description: 'Destination risk check before you send', url: location.origin, icons: [] } });
    await provider.connect();
    return { info: { uuid: 'walletconnect', name: 'WalletConnect', icon: '', rdns: 'walletconnect' }, provider };
  }
  _setAccount(a) { this.account = a ? a.toLowerCase() : null; this._emit('account', this.account); if (!a) this._reset(); }
  _detach() { this.provider?.removeListener?.('accountsChanged', this._onAccounts); this.provider?.removeListener?.('chainChanged', this._onChain); this.provider?.removeListener?.('disconnect', this._onDisconnect); }
  _reset() { this._detach(); this.provider = null; this.info = null; this.account = null; this.chainId = null; this._emit('account', null); }
  _emit(type, detail) { this.dispatchEvent(new CustomEvent(type, { detail })); }
}

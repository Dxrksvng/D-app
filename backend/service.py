"""Orchestrates one risk check: fetch in parallel, run engine v2, cache briefly in memory.
Nothing about the user (sender address, destination, result) is written to disk or logs."""
import time, threading, uuid
from concurrent.futures import ThreadPoolExecutor
from . import config, engine_v2, attestation
from .sources import OnChain, UpstreamError
from .blocklists import Blocklists

POOL = ThreadPoolExecutor(max_workers=24, thread_name_prefix='upstream')


def _quiet(fut, timeout):
    """Result of an optional lookup, or None when that source failed (the checklist then shows it as not checked)."""
    try:
        return fut.result(timeout=timeout)
    except Exception:
        return None


class TTLCache:
    def __init__(self, ttl, max_items=5000):
        self.ttl, self.max = ttl, max_items; self.d = {}; self.lock = threading.Lock()

    def get(self, k):
        with self.lock:
            v = self.d.get(k)
            if v and v[0] > time.time(): return v[1]
            self.d.pop(k, None)

    def put(self, k, v):
        with self.lock:
            if len(self.d) >= self.max:
                for key in sorted(self.d, key=lambda x: self.d[x][0])[: self.max // 10]: self.d.pop(key, None)
            self.d[k] = (time.time() + self.ttl, v)


class RiskService:
    def __init__(self, onchain=None, blocklists=None):
        self.onchain = onchain or OnChain(); self.bl = blocklists or Blocklists()
        self.cache = TTLCache(config.RISK_CACHE_TTL_S); self.started = time.time()

    def check(self, chain, to, frm=None, value_wei=None):
        """Risk check. When `frm` and `value_wei` are given and the destination is a wallet (EOA),
        the result includes a signed attestation to put in the transaction's data field."""
        res = self._check(chain, to, frm)
        if frm and value_wei is not None and not res['is_contract']:
            res = {**res, 'attestation': attestation.make(chain, frm, to, value_wei, res['level'], res['trust_score'],
                                                          res['signals'], res['request_id'])}
        return res

    def verify_tx(self, chain, tx_hash):
        tx = self.onchain.get_tx(chain, tx_hash)
        if not tx: return {'found': False, 'chain_id': chain, 'tx_hash': tx_hash}
        memo = attestation.parse(tx['input'])
        out = {'found': True, 'chain_id': chain, 'tx_hash': tx['hash'], 'from': tx['from'], 'to': tx['to'],
               'value_wei': str(tx['value_wei']), 'block': tx['block'], 'block_ts': tx['block_ts'], 'status': tx['status'],
               'explorer': config.CHAINS[chain]['explorer'], 'attested': bool(memo)}
        if memo:
            out['memo'] = memo
            out['verification'] = attestation.verify(memo, chain, tx['from'], tx['to'], tx['value_wei'], tx['block_ts'])
        return out

    def verify_address(self, chain, addr, limit=20):
        hashes, src = self.onchain.outgoing_memo_txs(chain, addr, limit)
        items = list(POOL.map(lambda h: self.verify_tx(chain, h), hashes))
        return {'chain_id': chain, 'address': addr, 'count': len(items), 'transactions': items, 'data_source': src}

    def _check(self, chain, to, frm=None):
        key = (chain, to, frm or '')
        hit = self.cache.get(key)
        if hit: return {**hit, 'cached': True}
        t0 = time.time(); wait = config.UPSTREAM_TIMEOUT_S * 2
        others = [c for c in config.CHAINS if c != chain]   # the same address on every other supported chain
        f_hist = POOL.submit(self.onchain.history, chain, to)
        f_contract = POOL.submit(self.onchain.contract_info, chain, to)
        f_state = POOL.submit(lambda: self.onchain.account_state(chain, to))
        f_sender = POOL.submit(self.onchain.history, chain, frm) if frm else None
        f_cross = {c: (POOL.submit(self.onchain.history, c, to), POOL.submit(lambda c=c: self.onchain.account_state(c, to))) for c in others}
        f_l1 = POOL.submit(lambda: self.onchain.active_chains(to))
        sources, history_ok, contract_ok = set(), True, True
        try:
            txs, capped, src = f_hist.result(timeout=wait); sources.add(src)
        except Exception:
            txs, capped, history_ok = [], False, False
        try:
            contract, src = f_contract.result(timeout=wait); sources.add(src)
        except Exception:
            contract, contract_ok = {'is_contract': False}, False
        state = _quiet(f_state, wait)
        if state is not None: sources.add('rpc')
        recipients = cps = None
        if f_sender:
            try:
                stx, _, src = f_sender.result(timeout=wait); sources.add(src)
                recipients = sorted({t['to'] for t in stx if t['frm'] == frm and t['to']})
                cps = sorted({(t['to'] if t['frm'] == frm else t['frm']) for t in stx} - {frm, ''})
            except Exception:
                pass
        cross = []
        for c, (fh, fs) in f_cross.items():
            h = _quiet(fh, wait)
            if h is None:
                cross.append({'chain': c, 'ok': False}); continue
            ctxs, ccapped, src = h; sources.add(src)
            cross.append({'chain': c, 'ok': True, 'txs': ctxs, 'capped': ccapped, 'state': _quiet(fs, wait),
                          'linked': self.bl.any_listed(engine_v2.features(to, ctxs)['counterparties'])})
        l1 = _quiet(f_l1, wait)
        if l1 is not None: sources.add('avalanche-data-api')
        feats = engine_v2.features(to, txs)
        linked = self.bl.any_listed(feats['counterparties'])
        bl_status = self.bl.status()
        res = engine_v2.assess(to, chain, txs, capped, contract, self.bl.lookup(to), linked, self.bl.reported(to),
                               recipients, history_ok, contract_ok, sender_cps=cps, cross=cross, l1_chains=l1, state=state,
                               bl_stats={'lists': len(bl_status['feeds']), 'addresses': bl_status['unique_addresses']}, sender=frm)
        out = {'request_id': uuid.uuid4().hex[:12], 'chain_id': chain, 'address': to, **res,
               'is_contract': contract.get('is_contract', False),
               'engine_version': config.ENGINE_VERSION, 'data_sources': sorted(sources) + ['blocklists'],
               'checked_at': int(time.time()), 'latency_ms': int((time.time() - t0) * 1000), 'cached': False,
               'explorer': config.CHAINS[chain]['explorer'],
               'disclaimer': {'th': 'ผลนี้เป็นการเตือนความเสี่ยง ไม่ได้บล็อกธุรกรรม การตัดสินใจเป็นของคุณ',
                              'en': 'This is a risk warning, not a block. The decision is yours.'}}
        if history_ok and contract_ok:
            self.cache.put(key, out)
        return out

    def health(self):
        return {'status': 'ok', 'engine_version': config.ENGINE_VERSION, 'uptime_s': int(time.time() - self.started),
                'upstreams': self.onchain.status(), 'blocklists': self.bl.status(),
                'data_api_key_configured': bool(config.DATA_API_KEY)}

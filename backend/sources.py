"""On-chain data clients.

Primary: Avalanche Data API (data-api.avax.network) for every chain it indexes.
Fallback: Routescan Etherscan-compatible API, used when a chain is not indexed by the Data API
or when the Data API is rate-limited / failing (circuit breaker). Every result says which source
answered, so the UI and logs can show provenance.

All transactions are normalized to the shape the engine expects:
    {ts, block, hash, frm, to, value, ok, selector}
"""
import json, time, threading, urllib.request, urllib.error, urllib.parse
from . import config

DATA_API = 'https://data-api.avax.network'
ROUTESCAN = 'https://api.routescan.io/v2/network/{net}/evm/{chain}/etherscan/api'
UA = {'User-Agent': 'riskguard-backend/2 (+poc)'}
HIST_DATAAPI_PAGES = 3      # 300 most recent tx before the check
HIST_ROUTESCAN_LIMIT = 1000


class UpstreamError(Exception):
    pass


class RateLimited(UpstreamError):
    def __init__(self, retry_after):
        super().__init__(f'rate limited, retry after {retry_after}s'); self.retry_after = retry_after


def _get(url, headers=None, timeout=None):
    req = urllib.request.Request(url, headers={**UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout or config.UPSTREAM_TIMEOUT_S) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise RateLimited(int(e.headers.get('Retry-After', '60') or 60))
        if e.code == 404:
            return None
        raise UpstreamError(f'HTTP {e.code}')
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        raise UpstreamError(type(e).__name__)


class Breaker:
    """Opens after a 429 (for Retry-After seconds, capped) or 3 consecutive failures (60 s)."""
    def __init__(self):
        self.until = 0.0; self.fails = 0; self.lock = threading.Lock(); self.reason = ''

    def open(self):
        return time.time() < self.until

    def trip(self, seconds, reason):
        with self.lock:
            self.until = time.time() + seconds; self.reason = reason

    def ok(self):
        with self.lock:
            self.fails = 0

    def fail(self, reason):
        with self.lock:
            self.fails += 1
            if self.fails >= 3:
                self.until = time.time() + 60; self.reason = reason; self.fails = 0


class DataAPI:
    name = 'avalanche-data-api'

    def __init__(self):
        self.breaker = Breaker()

    def _call(self, path):
        if self.breaker.open():
            raise UpstreamError(f'circuit open: {self.breaker.reason}')
        hdr = {'x-glacier-api-key': config.DATA_API_KEY} if config.DATA_API_KEY else {}
        try:
            j = _get(DATA_API + path, hdr)
            self.breaker.ok(); return j
        except RateLimited as e:
            self.breaker.trip(min(e.retry_after, 3600), 'rate limited'); raise
        except UpstreamError as e:
            self.breaker.fail(str(e)); raise

    @staticmethod
    def _norm(t):
        n = t.get('nativeTransaction', t)
        sel = ((n.get('method') or {}).get('methodHash') or '').lower()
        return {'ts': int(n['blockTimestamp']), 'block': int(n['blockNumber']), 'hash': n['txHash'],
                'frm': n['from']['address'].lower(), 'to': ((n.get('to') or {}).get('address') or '').lower(),
                'value': int(n['value']) / 1e18, 'ok': str(n.get('txStatus')) == '1', 'selector': sel or '0x'}

    def history(self, chain, addr, end_block=None):
        """Most recent transactions where addr is sender or recipient (Etherscan 'txlist' definition)."""
        q = {'pageSize': 100, 'sortOrder': 'desc'}
        if end_block: q['endBlock'] = end_block
        out, tok, capped = [], None, False
        for i in range(HIST_DATAAPI_PAGES):
            if tok: q['pageToken'] = tok
            j = self._call(f'/v1/chains/{chain}/addresses/{addr}/transactions?' + urllib.parse.urlencode(q)) or {}
            for t in j.get('transactions', []):
                x = self._norm(t)
                if x['frm'] == addr or x['to'] == addr: out.append(x)
            tok = j.get('nextPageToken')
            if not tok: break
            if i == HIST_DATAAPI_PAGES - 1: capped = True
        return out, capped

    def active_chains(self, addr):
        """Avalanche L1s (C-Chain and other EVM L1s indexed by the Data API) where addr has any activity."""
        j = self._call(f'/v1/address/{addr}/chains') or {}
        return [{'chain_id': int(c['chainId']) if str(c.get('chainId', '')).isdigit() else c.get('chainId'),
                 'name': c.get('chainName') or str(c.get('chainId'))} for c in j.get('indexedChains', [])]

    def contract_info(self, chain, addr):
        j = self._call(f'/v1/chains/{chain}/addresses/{addr}')
        if not j: return {'is_contract': False}
        erc = j.get('ercType') or 'UNKNOWN'
        return {'is_contract': erc not in ('UNKNOWN', None) or bool(j.get('deploymentDetails')),
                'erc_type': erc, 'name': j.get('name'), 'symbol': j.get('symbol')}


class Routescan:
    name = 'routescan'

    def __init__(self):
        self.breaker = Breaker()

    def _call(self, chain, **params):
        if self.breaker.open():
            raise UpstreamError(f'circuit open: {self.breaker.reason}')
        if config.ROUTESCAN_API_KEY: params['apikey'] = config.ROUTESCAN_API_KEY
        url = ROUTESCAN.format(net=config.CHAINS[chain]['routescan'], chain=chain) + '?' + urllib.parse.urlencode(params)
        try:
            j = _get(url)
        except RateLimited as e:
            self.breaker.trip(min(e.retry_after, 600), 'rate limited'); raise
        except UpstreamError as e:
            self.breaker.fail(str(e)); raise
        if isinstance(j, dict) and str(j.get('status')) == '0' and isinstance(j.get('result'), str) and 'rate' in j['result'].lower():
            self.breaker.trip(30, 'rate limited'); raise RateLimited(30)
        self.breaker.ok()
        return (j or {}).get('result')

    def history(self, chain, addr, end_block=None):
        r = self._call(chain, module='account', action='txlist', address=addr, startblock=0,
                       endblock=(end_block - 1) if end_block else 999999999, page=1, offset=HIST_ROUTESCAN_LIMIT, sort='desc')
        r = r if isinstance(r, list) else []
        out = [{'ts': int(t['timeStamp']), 'block': int(t['blockNumber']), 'hash': t['hash'], 'frm': t['from'].lower(),
                'to': (t.get('to') or '').lower(), 'value': int(t['value']) / 1e18, 'ok': t.get('isError') == '0',
                'selector': t['input'][:10].lower() if t.get('input', '0x') not in ('0x', '') else '0x'} for t in r]
        return out, len(r) >= HIST_ROUTESCAN_LIMIT

    def contract_info(self, chain, addr):
        code = self._call(chain, module='proxy', action='eth_getCode', address=addr, tag='latest')
        return {'is_contract': code not in (None, '0x', '0x0', ''), 'erc_type': None, 'name': None, 'symbol': None}


class OnChain:
    """Chooses the source per call: Data API first where it indexes the chain, Routescan otherwise."""
    def __init__(self, dataapi=None, routescan=None):
        self.dataapi = dataapi or DataAPI(); self.routescan = routescan or Routescan()

    def _order(self, chain):
        return [self.dataapi, self.routescan] if config.CHAINS[chain]['dataapi'] else [self.routescan]

    def _try(self, chain, method, *a):
        errors = []
        for src in self._order(chain):
            try:
                return getattr(src, method)(chain, *a), src.name
            except UpstreamError as e:
                errors.append(f'{src.name}: {e}')
        raise UpstreamError('; '.join(errors))

    def history(self, chain, addr, end_block=None):
        (txs, capped), src = self._try(chain, 'history', addr, end_block)
        return txs, capped, src

    def contract_info(self, chain, addr):
        """is_contract from eth_getCode on the chain's public RPC (authoritative); token name/symbol from the Data API."""
        try:
            body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_getCode', 'params': [addr, 'latest']}).encode()
            req = urllib.request.Request(config.CHAINS[chain]['rpc'], data=body, headers={**UA, 'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=config.UPSTREAM_TIMEOUT_S) as r:
                code = json.load(r).get('result')
            info, src = {'is_contract': code not in (None, '0x', '0x0', ''), 'erc_type': None, 'name': None, 'symbol': None}, 'rpc'
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            return self._try(chain, 'contract_info', addr)
        if info['is_contract'] and config.CHAINS[chain]['dataapi']:
            try:
                meta = self.dataapi._call(f'/v1/chains/{chain}/addresses/{addr}') or {}
                info.update(erc_type=meta.get('ercType'), name=meta.get('name'), symbol=meta.get('symbol')); src = 'rpc+avalanche-data-api'
            except UpstreamError:
                pass
        if info['is_contract'] and not info.get('erc_type'):
            info.update(self._erc20_probe(chain, addr))   # works without any indexer: ask the contract itself
        return info, src

    def _erc20_probe(self, chain, addr):
        """ERC-20 if the contract answers decimals() and symbol() (eth_call, read-only)."""
        try:
            dec = self.rpc(chain, 'eth_call', [{'to': addr, 'data': '0x313ce567'}, 'latest'])
            sym = self.rpc(chain, 'eth_call', [{'to': addr, 'data': '0x95d89b41'}, 'latest'])
        except UpstreamError:
            return {}
        if not dec or len(dec) != 66 or not sym or len(sym) < 130:
            return {}
        try:
            n = int(sym[66:130], 16); symbol = bytes.fromhex(sym[130:130 + 2 * n]).decode('utf-8', 'replace')
        except ValueError:
            symbol = None
        return {'erc_type': 'ERC-20', 'symbol': symbol}

    def rpc(self, chain, method, params):
        body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
        req = urllib.request.Request(config.CHAINS[chain]['rpc'], data=body, headers={**UA, 'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=config.UPSTREAM_TIMEOUT_S) as r:
                j = json.load(r)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            raise UpstreamError(f'rpc {type(e).__name__}')
        if 'error' in j: raise UpstreamError(f"rpc {j['error'].get('message', '')[:80]}")
        return j.get('result')

    def active_chains(self, addr):
        return self.dataapi.active_chains(addr)

    def account_state(self, chain, addr):
        """Nonce (txs ever sent) and native balance straight from the chain's RPC; works even when no indexer has history."""
        nonce = int(self.rpc(chain, 'eth_getTransactionCount', [addr, 'latest']), 16)
        bal = int(self.rpc(chain, 'eth_getBalance', [addr, 'latest']), 16)
        return {'nonce': nonce, 'balance_wei': bal}

    def get_tx(self, chain, tx_hash):
        """Full transaction + receipt status + block time from the chain's RPC (authoritative)."""
        tx = self.rpc(chain, 'eth_getTransactionByHash', [tx_hash])
        if not tx: return None
        rc = self.rpc(chain, 'eth_getTransactionReceipt', [tx_hash]) if tx.get('blockNumber') else None
        blk = self.rpc(chain, 'eth_getBlockByNumber', [tx['blockNumber'], False]) if tx.get('blockNumber') else None
        return {'hash': tx['hash'], 'from': tx['from'].lower(), 'to': (tx.get('to') or '').lower(), 'value_wei': int(tx['value'], 16),
                'input': tx.get('input', '0x'), 'block': int(tx['blockNumber'], 16) if tx.get('blockNumber') else None,
                'block_ts': int(blk['timestamp'], 16) if blk else None,
                'status': None if not rc else ('success' if rc.get('status') == '0x1' else 'failed')}

    def outgoing_memo_txs(self, chain, addr, limit=20):
        """Recent outgoing txs of `addr` whose input starts with the attestation prefix ('BRID' = 0x42524944)."""
        txs, _, src = self.history(chain, addr)
        return [t['hash'] for t in txs if t['frm'] == addr and t['selector'] == '0x42524944'][:limit], src

    def status(self):
        return {s.name: ('degraded: ' + s.breaker.reason) if s.breaker.open() else 'ok' for s in (self.dataapi, self.routescan)}

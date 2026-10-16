"""RiskGuard backend — HTTP API + static hosting for the reference web app.

Run:  python -m backend.app          (from the poc/ folder)
      or: python poc/backend/app.py
Endpoints are documented in poc/openapi.yaml.
"""
import json, os, re, sys, threading, time, mimetypes, logging
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

if __package__ in (None, ''):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    __package__ = 'backend'
from backend import config
from backend.service import RiskService

ADDR = re.compile(r'^0x[0-9a-fA-F]{40}$')
REPORT_CATEGORIES = {'phishing', 'drainer', 'impersonation', 'investment_scam', 'address_poisoning', 'other'}
log = logging.getLogger('riskguard')
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
SERVICE = None


class RateLimiter:
    """Token bucket per client IP, in memory."""
    def __init__(self, per_min):
        self.rate = per_min / 60.0; self.cap = per_min; self.b = {}; self.lock = threading.Lock()

    def allow(self, ip):
        now = time.time()
        with self.lock:
            tokens, last = self.b.get(ip, (self.cap, now))
            tokens = min(self.cap, tokens + (now - last) * self.rate)
            if tokens < 1:
                self.b[ip] = (tokens, now); return False, int((1 - tokens) / self.rate) + 1
            self.b[ip] = (tokens - 1, now); return True, 0


LIMITER = RateLimiter(config.RATE_LIMIT_PER_MIN)

_PRICE = {'at': 0, 'data': None}
_PRICE_LOCK = threading.Lock()


_MARKET = {'crypto': (0, None), 'stocks': (0, None), 'perps': (0, None)}
_MARKET_TTL = {'crypto': 60, 'stocks': 60, 'perps': 10}
_MARKET_LOCK = threading.Lock()


def _num(v):
    if isinstance(v, (int, float)): return float(v)
    try: return float(str(v).replace('$', '').replace(',', '').strip())
    except ValueError: return None


def _fetch_market(section):
    import urllib.request
    ua = {'User-Agent': 'riskguard-backend/2', 'Content-Type': 'application/json'}
    if section == 'crypto':      # CoinGecko trending coins
        with urllib.request.urlopen(urllib.request.Request('https://api.coingecko.com/api/v3/search/trending', headers=ua), timeout=10) as r:
            coins = json.load(r).get('coins', [])
        out = []
        for c in coins:
            it = c['item']; d = it.get('data', {})
            out.append({'id': it.get('id'), 'name': it.get('name'), 'symbol': (it.get('symbol') or '').upper(), 'image': it.get('small') or it.get('thumb'),
                        'price': _num(d.get('price')), 'change_24h': _num((d.get('price_change_percentage_24h') or {}).get('usd')),
                        'market_cap': _num(d.get('market_cap')), 'volume': _num(d.get('total_volume'))})
        return out
    if section == 'stocks':      # tokenized stocks on CoinGecko
        url = 'https://api.coingecko.com/api/v3/coins/markets?vs_currency=usd&category=tokenized-stock&order=volume_desc&per_page=20&price_change_percentage=24h'
        with urllib.request.urlopen(urllib.request.Request(url, headers=ua), timeout=10) as r:
            rows = json.load(r)
        return [{'id': x['id'], 'name': x['name'], 'symbol': (x['symbol'] or '').upper(), 'image': x.get('image'), 'price': x.get('current_price'),
                 'change_24h': x.get('price_change_percentage_24h'), 'market_cap': x.get('market_cap'), 'volume': x.get('total_volume')} for x in rows]
    # perps: Hyperliquid public info API
    body = json.dumps({'type': 'metaAndAssetCtxs'}).encode()
    with urllib.request.urlopen(urllib.request.Request('https://api.hyperliquid.xyz/info', data=body, headers=ua), timeout=10) as r:
        meta, ctxs = json.load(r)
    rows = []
    for u, c in zip(meta['universe'], ctxs):
        if u.get('isDelisted'): continue
        mark, prev = _num(c.get('markPx')), _num(c.get('prevDayPx'))
        rows.append({'id': u['name'], 'name': u['name'], 'symbol': u['name'], 'image': None, 'price': mark,
                     'change_24h': ((mark - prev) / prev * 100) if mark and prev else None, 'volume': _num(c.get('dayNtlVlm')),
                     'open_interest': (_num(c.get('openInterest')) or 0) * (mark or 0), 'max_leverage': u.get('maxLeverage')})
    rows.sort(key=lambda x: x['volume'] or 0, reverse=True)
    return rows[:30]


def market_data():
    """Explore screen data: trending crypto (CoinGecko), perps (Hyperliquid), tokenized stocks (CoinGecko).
    Each section is cached server-side so every user shares one upstream call."""
    out = {'updated_at': int(time.time()), 'sources': {'crypto': 'coingecko trending', 'stocks': 'coingecko tokenized-stock', 'perps': 'hyperliquid'}}
    with _MARKET_LOCK:
        for s in ('crypto', 'perps', 'stocks'):
            at, data = _MARKET[s]
            if data is None or time.time() - at > _MARKET_TTL[s]:
                try:
                    data = _fetch_market(s); _MARKET[s] = (time.time(), data)
                except Exception:
                    pass  # keep the last good copy
            out[s] = _MARKET[s][1] or []
            out[s + '_age_s'] = int(time.time() - _MARKET[s][0]) if _MARKET[s][1] else None
    return out


def price_quotes():
    """USD quotes for AVAX and ETH, fetched once per 2 minutes for all users (CoinGecko public API).
    On failure the last good quote is served with stale=true."""
    import urllib.request
    with _PRICE_LOCK:
        if _PRICE['data'] and time.time() - _PRICE['at'] < 120:
            return _PRICE['data']
        try:
            url = 'https://api.coingecko.com/api/v3/simple/price?ids=avalanche-2,ethereum&vs_currencies=usd&include_24hr_change=true'
            with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'riskguard-backend/2'}), timeout=8) as r:
                j = json.load(r)
            _PRICE['data'] = {'avalanche-2': {'usd': j['avalanche-2']['usd'], 'usd_24h_change': j['avalanche-2'].get('usd_24h_change', 0)},
                              'ethereum': {'usd': j['ethereum']['usd'], 'usd_24h_change': j['ethereum'].get('usd_24h_change', 0)},
                              'source': 'coingecko', 'fetched_at': int(time.time()), 'stale': False}
            _PRICE['at'] = time.time()
        except Exception:
            if _PRICE['data']:
                _PRICE['data'] = {**_PRICE['data'], 'stale': True}
            else:
                return {'error': 'price_unavailable'}
        return _PRICE['data']


class Handler(BaseHTTPRequestHandler):
    server_version = 'RiskGuard/2'
    sys_version = ''

    def log_message(self, fmt, *args):  # access log without query strings (no addresses in logs)
        origin = self.headers.get('Origin') or '-'
        caller = 'metamask-snap' if origin in ('null', '-') and 'value_wei' not in self.path else 'web' if origin.startswith('http') else origin[:40]
        log.info('%s %s %s caller=%s', self.command, urlparse(self.path).path, args[1] if len(args) > 1 else '', caller)

    # ---- helpers ----------------------------------------------------------------------------
    def _ip(self):
        if os.environ.get('TRUST_PROXY') == '1' and self.headers.get('X-Forwarded-For'):
            return self.headers['X-Forwarded-For'].split(',')[0].strip()
        return self.client_address[0]

    def _cors(self):
        origin = self.headers.get('Origin')
        if '*' in config.ALLOWED_ORIGINS:
            self.send_header('Access-Control-Allow-Origin', '*')
        elif origin and origin in config.ALLOWED_ORIGINS:
            self.send_header('Access-Control-Allow-Origin', origin); self.send_header('Vary', 'Origin')

    def _common(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')

    def _json(self, code, obj, extra=None):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        for k, v in (extra or {}).items(): self.send_header(k, v)
        self._cors(); self._common(); self.end_headers()
        if self.command != 'HEAD': self.wfile.write(body)

    def _err(self, code, err, msg_th, msg_en, extra=None):
        self._json(code, {'error': err, 'message': {'th': msg_th, 'en': msg_en}}, extra)

    def _limited(self):
        ok, wait = LIMITER.allow(self._ip())
        if not ok:
            self._err(429, 'rate_limited', f'เรียกถี่เกินไป ลองใหม่ใน {wait} วินาที', f'Too many requests, retry in {wait}s', {'Retry-After': str(wait)})
        return not ok

    # ---- routing ----------------------------------------------------------------------------
    def do_OPTIONS(self):
        self.send_response(204); self._cors()
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.send_header('Access-Control-Max-Age', '600'); self.end_headers()

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query).items()}
        try:
            if u.path == '/v1/health':
                return self._json(200, SERVICE.health())
            if u.path == '/v1/chains':
                return self._json(200, {'chains': [{'chain_id': cid, **{k: v for k, v in c.items() if k not in ('dataapi', 'routescan')},
                                                    'data_source': 'avalanche-data-api' if c['dataapi'] else 'routescan'}
                                                   for cid, c in config.CHAINS.items()]})
            if u.path == '/v1/rules':
                from backend.engine_v2 import VALIDATION
                return self._json(200, {'engine_version': config.ENGINE_VERSION, 'rules': VALIDATION,
                                        'audit': 'Pre-registered E5 replay on 894 real 2024-2026 transfers; see audit/report',
                                        'trust_score': {'meaning': "severity index 0-100 computed from the address's own evidence; higher = fewer risk signals; NOT a probability and NOT a constant per level",
                                                        'evidence': 'age_days, n_all (tx across chains), chains_active, zero_share; returned in `evidence`',
                                                        'formula': {'HIGH': '25 - 5*(extra high) - 2*(medium) - 3*(extra lists) + 0.1*pos, band 0-28',
                                                                    'MEDIUM': '60 - 7*(medium signals) - 10*zero_share + 0.3*pos, band 30-69',
                                                                    'LOW': '70 + pos, max 98',
                                                                    'pos': '12*age(<=730d) + 12*log10(1+tx)/3 + 2*(extra active chains), 0-28 points'}},
                                        'attestation': {'where': 'transaction input data (UTF-8 visible on explorers)',
                                                        'format': 'BRIDGESECURE|v1|c=<chain>|l=<level>|ts=<score>|s=<signals>|t=<unix>|r=<request_id>|k=<hmac>',
                                                        'binding': 'HMAC covers chain, from, to and value, so a copied memo fails verification',
                                                        'verify': '/v1/verify/tx?chain_id=&tx_hash='}})
            if u.path == '/v1/risk':
                if self._limited(): return
                return self._risk(q)
            if u.path == '/v1/price':
                return self._json(200, price_quotes())
            if u.path == '/v1/market':
                return self._json(200, market_data())
            if u.path in ('/v1/verify/tx', '/v1/verify/address'):
                if self._limited(): return
                return self._verify(u.path, q)
            if u.path == '/config.js':
                cfg = {'apiBase': '', 'walletConnectProjectId': config.WALLETCONNECT_PROJECT_ID, 'defaultChainId': 43113,
                       'snapId': '' if os.environ.get('SNAP_ID', '').lower() == 'none' else os.environ.get('SNAP_ID', 'local:http://localhost:8081')}
                body = ('window.RISKGUARD_CONFIG = ' + json.dumps(cfg) + ';').encode()
                self.send_response(200); self.send_header('Content-Type', 'application/javascript; charset=utf-8')
                self.send_header('Cache-Control', 'no-store'); self.send_header('Content-Length', str(len(body))); self._common(); self.end_headers()
                if self.command != 'HEAD': self.wfile.write(body)
                return
            if u.path == '/openapi.yaml':
                return self._static(os.path.join(os.path.dirname(config.WEB_DIR), 'openapi.yaml'))
            return self._static_web(u.path)
        except Exception:
            log.exception('unhandled'); return self._err(500, 'internal', 'เกิดข้อผิดพลาดภายใน', 'Internal error')

    def do_POST(self):
        u = urlparse(self.path)
        try:
            if u.path != '/v1/reports':
                return self._err(404, 'not_found', 'ไม่พบ', 'Not found')
            if self._limited(): return
            n = int(self.headers.get('Content-Length') or 0)
            if n <= 0 or n > 2048:
                return self._err(400, 'bad_request', 'ข้อมูลไม่ถูกต้อง', 'Invalid body size')
            body = json.loads(self.rfile.read(n))
            addr, chain, cat = str(body.get('address', '')), body.get('chain_id'), str(body.get('category', 'other'))
            if not ADDR.match(addr) or chain not in config.CHAINS or cat not in REPORT_CATEGORIES:
                return self._err(400, 'bad_request', 'ที่อยู่ เครือข่าย หรือหมวดหมู่ไม่ถูกต้อง', 'Invalid address, chain_id or category')
            count = SERVICE.bl.add_report(addr.lower(), chain, cat)
            return self._json(201, {'status': 'received', 'address': addr.lower(), 'total_reports': count,
                                    'message': {'th': 'ขอบคุณ รายงานของคุณจะแสดงเป็นข้อมูลประกอบ (ยังไม่ยืนยัน)', 'en': 'Thank you. Shown as unverified.'}})
        except (ValueError, json.JSONDecodeError):
            return self._err(400, 'bad_request', 'JSON ไม่ถูกต้อง', 'Invalid JSON')
        except Exception:
            log.exception('unhandled'); return self._err(500, 'internal', 'เกิดข้อผิดพลาดภายใน', 'Internal error')

    def _risk(self, q):
        to, frm = q.get('to', '').strip(), (q.get('from') or '').strip() or None
        try:
            chain = int(q.get('chain_id', q.get('chain', '43113')))
        except ValueError:
            chain = -1
        if chain not in config.CHAINS:
            return self._err(400, 'unsupported_chain', 'ไม่รองรับเครือข่ายนี้', 'Unsupported chain', None)
        if not ADDR.match(to):
            return self._err(400, 'invalid_address', 'ที่อยู่ปลายทางไม่ถูกต้อง (ต้องเป็น 0x ตามด้วยอักขระ 40 ตัว)', 'Invalid destination address')
        if frm is not None and not ADDR.match(frm):
            return self._err(400, 'invalid_address', 'ที่อยู่ผู้ส่งไม่ถูกต้อง', 'Invalid sender address')
        value = q.get('value_wei')
        if value is not None and not re.fullmatch(r'\d{1,78}', value):
            return self._err(400, 'invalid_value', 'จำนวนต้องเป็นหน่วย wei (ตัวเลขจำนวนเต็ม)', 'value_wei must be an integer string')
        res = SERVICE.check(chain, to.lower(), frm.lower() if frm else None, int(value) if value is not None else None)
        return self._json(200, res)

    def _verify(self, path, q):
        try:
            chain = int(q.get('chain_id', ''))
        except ValueError:
            chain = -1
        if chain not in config.CHAINS:
            return self._err(400, 'unsupported_chain', 'ไม่รองรับเครือข่ายนี้', 'Unsupported chain')
        from backend.sources import UpstreamError
        try:
            if path == '/v1/verify/tx':
                h = q.get('tx_hash', '')
                if not re.fullmatch(r'0x[0-9a-fA-F]{64}', h):
                    return self._err(400, 'invalid_tx_hash', 'tx hash ไม่ถูกต้อง', 'Invalid transaction hash')
                return self._json(200, SERVICE.verify_tx(chain, h.lower()))
            a = q.get('address', '')
            if not ADDR.match(a):
                return self._err(400, 'invalid_address', 'ที่อยู่ไม่ถูกต้อง', 'Invalid address')
            return self._json(200, SERVICE.verify_address(chain, a.lower()))
        except UpstreamError:
            return self._err(503, 'upstream_unavailable', 'อ่านข้อมูลจาก chain ไม่ได้ชั่วคราว', 'Chain data temporarily unavailable', {'Retry-After': '10'})

    # ---- static -----------------------------------------------------------------------------
    def _static_web(self, path):
        rel = config.HOME_PAGE if path in ('', '/') else path.lstrip('/')
        full = os.path.realpath(os.path.join(config.WEB_DIR, rel))
        if not full.startswith(os.path.realpath(config.WEB_DIR) + os.sep) or not os.path.isfile(full):
            return self._err(404, 'not_found', 'ไม่พบ', 'Not found')
        return self._static(full)

    def _static(self, full):
        if not os.path.isfile(full):
            return self._err(404, 'not_found', 'ไม่พบ', 'Not found')
        with open(full, 'rb') as fh:
            data = fh.read()
        ctype = mimetypes.guess_type(full)[0] or 'application/octet-stream'
        if full.endswith('.js'): ctype = 'application/javascript'
        if full.endswith('.yaml'): ctype = 'text/yaml'
        self.send_response(200)
        self.send_header('Content-Type', ctype + ('; charset=utf-8' if ctype.startswith(('text/', 'application/javascript')) else ''))
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-cache')
        if full.endswith('.html'):
            self.send_header('Content-Security-Policy',
                             "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                             "font-src https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' https: wss:; frame-src https://verify.walletconnect.com https://verify.walletconnect.org; frame-ancestors 'none'")
        self._common(); self.end_headers()
        if self.command != 'HEAD': self.wfile.write(data)


def main():
    global SERVICE
    mimetypes.add_type('application/javascript', '.js'); mimetypes.add_type('text/css', '.css')
    SERVICE = RiskService()
    srv = ThreadingHTTPServer((config.HOST, config.PORT), Handler)
    srv.daemon_threads = True
    log.info('RiskGuard %s listening on http://%s:%d  (Data API key: %s)', config.ENGINE_VERSION, config.HOST, config.PORT,
             'configured' if config.DATA_API_KEY else 'not set, anonymous quota')
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()

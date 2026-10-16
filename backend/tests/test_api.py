"""HTTP API tests against a real server instance with stubbed on-chain sources (no network needed)."""
import json, threading, unittest, urllib.request, urllib.error
from http.server import ThreadingHTTPServer
from backend import app, config
from backend.service import RiskService
from backend.sources import UpstreamError

SCAM = '0x' + '5' * 40; CLEAN = '0x' + '6' * 40; DOWN = '0x' + '7' * 40


class StubChain:
    def history(self, chain, addr, end_block=None):
        if addr == DOWN: raise UpstreamError('down')
        return ([{'ts': 1, 'block': 1, 'hash': '0x' + '1' * 64, 'frm': '0x' + '8' * 40, 'to': addr, 'value': 1.0, 'ok': True, 'selector': '0x'}], False, 'stub')
    def contract_info(self, chain, addr): return {'is_contract': False}, 'stub'
    def account_state(self, chain, addr):
        if addr == DOWN: raise UpstreamError('down')
        return {'nonce': 1, 'balance_wei': 0}
    def active_chains(self, addr): return []
    def status(self): return {'stub': 'ok'}
    txs = {}
    def get_tx(self, chain, h): return self.txs.get(h)
    def outgoing_memo_txs(self, chain, addr, limit=20): return [h for h, t in self.txs.items() if t['from'] == addr], 'stub'


class StubLists:
    def __init__(self): self.reports = {}
    def lookup(self, a): return [{'list': 'scamsniffer', 'label': 'ScamSniffer'}] if a == SCAM else []
    def any_listed(self, addrs): return {}
    def reported(self, a): return self.reports.get(a, 0)
    def add_report(self, a, c, cat): self.reports[a] = self.reports.get(a, 0) + 1; return self.reports[a]
    def status(self): return {'feeds': {'scamsniffer': {}}, 'unique_addresses': 1}


class API(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.SERVICE = RiskService(StubChain(), StubLists())
        app.LIMITER = app.RateLimiter(1000)
        cls.srv = ThreadingHTTPServer(('127.0.0.1', 0), app.Handler)
        cls.base = f'http://127.0.0.1:{cls.srv.server_address[1]}'
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls): cls.srv.shutdown()

    def get(self, path):
        try:
            with urllib.request.urlopen(self.base + path) as r: return r.status, json.load(r), r.headers
        except urllib.error.HTTPError as e: return e.code, json.load(e), e.headers

    def post(self, path, body):
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode(), headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req) as r: return r.status, json.load(r)
        except urllib.error.HTTPError as e: return e.code, json.load(e)

    def test_health_and_chains(self):
        s, b, _ = self.get('/v1/health'); self.assertEqual(s, 200); self.assertEqual(b['engine_version'], config.ENGINE_VERSION)
        s, b, _ = self.get('/v1/chains'); self.assertEqual({c['chain_id'] for c in b['chains']}, set(config.CHAINS))

    def test_risk_levels(self):
        s, b, h = self.get(f'/v1/risk?chain_id=43113&to={SCAM}'); self.assertEqual((s, b['level']), (200, 'HIGH'))
        self.assertEqual(h['Cache-Control'], 'no-store'); self.assertEqual(h['Access-Control-Allow-Origin'], '*')
        s, b, _ = self.get(f'/v1/risk?chain_id=43113&to={CLEAN}'); self.assertEqual(b['level'], 'LOW')
        s, b, _ = self.get(f'/v1/risk?chain_id=43113&to={DOWN}'); self.assertEqual(b['level'], 'MEDIUM')
        self.assertIn('UNVERIFIABLE', [x['code'] for x in b['signals']]); self.assertTrue(b['verdict']['th'] and b['checks'])

    def test_checksum_case_is_accepted(self):
        s, b, _ = self.get('/v1/risk?chain_id=43113&to=' + SCAM.upper().replace('0X', '0x')); self.assertEqual(b['level'], 'HIGH')

    def test_validation_errors(self):
        self.assertEqual(self.get('/v1/risk?chain_id=43113&to=0x123')[1]['error'], 'invalid_address')
        self.assertEqual(self.get(f'/v1/risk?chain_id=999&to={CLEAN}')[1]['error'], 'unsupported_chain')
        self.assertEqual(self.get(f'/v1/risk?chain_id=43113&to={CLEAN}&from=abc')[1]['error'], 'invalid_address')

    def test_reports(self):
        s, b = self.post('/v1/reports', {'chain_id': 43113, 'address': CLEAN, 'category': 'phishing'}); self.assertEqual(s, 201)
        s, b, _ = self.get(f'/v1/risk?chain_id=43113&to={CLEAN}&from={SCAM}')  # different cache key
        self.assertEqual(b['level'], 'MEDIUM')
        self.assertEqual(self.post('/v1/reports', {'chain_id': 43113, 'address': 'bad', 'category': 'x'})[0], 400)

    def test_static_and_traversal(self):
        with urllib.request.urlopen(self.base + '/') as r:
            self.assertIn('Content-Security-Policy', r.headers); self.assertIn(b'BridgeSecure', r.read())
        self.assertEqual(self.get('/../backend/config.py')[0], 404)

    def test_attestation_end_to_end(self):
        frm = '0x' + '9' * 40
        s, r, _ = self.get(f'/v1/risk?chain_id=43113&to={CLEAN}&from={frm}&value_wei=1000')
        self.assertIn('attestation', r); self.assertIn('trust_score', r)
        h_ok, h_copy = '0x' + 'a' * 64, '0x' + 'b' * 64
        base = {'hash': h_ok, 'from': frm, 'to': CLEAN, 'value_wei': 1000, 'input': r['attestation']['data_hex'], 'block': 5, 'block_ts': r['checked_at'] + 4, 'status': 'success'}
        StubChain.txs = {h_ok: base, h_copy: {**base, 'hash': h_copy, 'value_wei': 999}}
        s, v, _ = self.get(f'/v1/verify/tx?chain_id=43113&tx_hash={h_ok}')
        self.assertTrue(v['attested']); self.assertTrue(v['verification']['valid']); self.assertEqual(v['verification']['trust_score'], r['trust_score'])
        s, v, _ = self.get(f'/v1/verify/tx?chain_id=43113&tx_hash={h_copy}')
        self.assertFalse(v['verification']['valid'])
        s, v, _ = self.get(f'/v1/verify/address?chain_id=43113&address={frm}')
        self.assertEqual(v['count'], 2)
        self.assertEqual(self.get('/v1/risk?chain_id=43113&to=' + CLEAN + '&value_wei=1.5')[1]['error'], 'invalid_value')
        self.assertEqual(self.get('/v1/verify/tx?chain_id=43113&tx_hash=0x12')[1]['error'], 'invalid_tx_hash')

    def test_rate_limit(self):
        app.LIMITER = app.RateLimiter(2)
        codes = [self.get(f'/v1/risk?chain_id=43113&to={CLEAN}')[0] for _ in range(4)]
        app.LIMITER = app.RateLimiter(1000)
        self.assertIn(429, codes)


if __name__ == '__main__':
    unittest.main()

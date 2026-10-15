"""Unit tests for engine v2 + a regression test on the real E5 audit events (if the audit folder is present).
Run from poc/:  python -m unittest discover -s backend/tests -t ."""
import json, os, unittest
from backend import engine_v2 as E

A = '0x' + 'a' * 40
def tx(frm, to, value=1.0, sel='0x', h=None, ts=1_700_000_000):
    return {'ts': ts, 'block': 1, 'hash': h or '0x' + os.urandom(32).hex(), 'frm': frm, 'to': to, 'value': value, 'ok': True, 'selector': sel}


class Rules(unittest.TestCase):
    def run_(self, txs=(), l0=(), linked=None, reports=0, recipients=None, contract=None, capped=False, history_ok=True):
        return E.assess(A, 43113, list(txs), capped, contract or {'is_contract': False}, list(l0), linked or {}, reports, recipients, history_ok)

    def codes(self, r): return [s['code'] for s in r['signals']]

    def test_clean_address_is_low(self):
        r = self.run_([tx('0x' + 'b' * 40, A), tx(A, '0x' + 'c' * 40)] * 3)
        self.assertEqual(r['level'], 'LOW'); self.assertEqual(self.codes(r), [])

    def test_thin_history_is_informational_only(self):
        r = self.run_([tx('0x' + 'b' * 40, A)])
        self.assertEqual(r['level'], 'LOW'); self.assertEqual(self.codes(r), ['THIN_HISTORY'])

    def test_no_history_is_unknown_not_low(self):
        r = self.run_([]); self.assertEqual(r['level'], 'UNKNOWN'); self.assertIn('NO_HISTORY', self.codes(r))

    def test_l0_is_high_even_without_history(self):
        r = self.run_([], l0=[{'list': 'scamsniffer', 'label': 'ScamSniffer'}])
        self.assertEqual(r['level'], 'HIGH'); self.assertEqual(r['signals'][0]['code'], 'L0_LISTED')

    def test_r4_drainer_threshold(self):
        two = [tx(A, '0x' + 'd' * 40, 0, E.SEL_TRANSFER_FROM) for _ in range(2)]
        self.assertNotIn('R4_DRAINER', self.codes(self.run_(two)))
        three = two + [tx(A, '0x' + 'd' * 40, 0, E.SEL_TRANSFER_FROM)]
        r = self.run_(three); self.assertEqual(r['level'], 'HIGH'); self.assertIn('R4_DRAINER', self.codes(r))
        self.assertEqual(len(r['signals'][0]['evidence_tx']), 3)

    def test_inbound_transferfrom_does_not_count(self):
        r = self.run_([tx('0x' + 'e' * 40, A, 0, E.SEL_TRANSFER_FROM) for _ in range(5)])
        self.assertNotIn('R4_DRAINER', self.codes(r))

    def test_address_poisoning_lookalike(self):
        real = '0xa1b2' + '0' * 32 + 'c3d4'; fake = '0xa1b2' + '9' * 32 + 'c3d4'
        r = E.assess(fake, 1, [], False, {'is_contract': False}, [], {}, 0, [real])
        self.assertEqual(r['level'], 'HIGH'); self.assertIn('POISONING_LOOKALIKE', self.codes(r))
        self.assertIsNone(E.lookalike(real, [real]))  # same address is not a look-alike

    def test_medium_signals(self):
        self.assertEqual(self.run_([tx('0x' + 'b' * 40, A)], reports=2)['level'], 'MEDIUM')
        self.assertEqual(self.run_([tx('0x' + 'b' * 40, A)], linked={'0x' + 'b' * 40: ['ofac']})['level'], 'MEDIUM')
        zero = [tx('0x' + str(i) * 40, A, 0) for i in range(1, 7)]
        self.assertIn('R6_ZERO_VALUE', self.codes(self.run_(zero)))
        tok = self.run_([tx('0x' + 'b' * 40, A)], contract={'is_contract': True, 'erc_type': 'ERC-20', 'symbol': 'USDC'})
        self.assertEqual(tok['level'], 'MEDIUM'); self.assertIn('TOKEN_CONTRACT', self.codes(tok))

    def test_failure_degrades_to_unknown_not_low(self):
        r = self.run_([], history_ok=False)
        self.assertEqual(r['level'], 'UNKNOWN'); self.assertIn('CHECK_INCOMPLETE', self.codes(r))

    def test_removed_rules_do_not_fire(self):
        # Collector pattern (R1 in v1) produced 18% false warnings in E5 and must not raise the level any more.
        fanin = [tx('0x%040x' % i, A, 0.05) for i in range(1, 30)]
        self.assertEqual(self.run_(fanin)['level'], 'LOW')

    def test_every_signal_is_bilingual_and_explained(self):
        r = self.run_([tx(A, '0x' + 'd' * 40, 0, E.SEL_TRANSFER_FROM)] * 3, l0=[{'list': 'x', 'label': 'X'}], reports=1, recipients=[])
        for s in r['signals']:
            for k in ('th', 'en'):
                self.assertTrue(s['title'][k] and s['detail'][k])
            self.assertIn('status', s['validation'])


AUDIT = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'audit', 'results')


@unittest.skipUnless(os.path.exists(os.path.join(AUDIT, 'events_eth_pos_B.json')), 'audit events not available')
class RegressionE5(unittest.TestCase):
    """Engine v2's R4 must reproduce the audited E5 numbers on the same real events (no L0, no sender)."""
    def rate(self, f):
        with open(os.path.join(AUDIT, f), encoding='utf-8') as fh:
            ev = json.load(fh)
        hits = sum('R4_DRAINER' in [s['code'] for s in E.assess(e['address'], e['chain'], e['history'], False, {'is_contract': False}, [], {}, 0)['signals']] for e in ev)
        return hits / len(ev), len(ev)

    def test_r4_recall_eth_b(self):
        r, n = self.rate('events_eth_pos_B.json'); self.assertAlmostEqual(r, 0.59, delta=0.005, msg=f'n={n}')

    def test_r4_fpr_eth_controls(self):
        r, n = self.rate('events_eth_ctl.json'); self.assertAlmostEqual(r, 0.015, delta=0.005, msg=f'n={n}')


if __name__ == '__main__':
    unittest.main()

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

    def test_unused_everywhere_is_medium_with_reason(self):
        cross = [{'chain': 1, 'ok': True, 'txs': [], 'state': {'nonce': 0, 'balance_wei': 0}}]
        r = E.assess(A, 43113, [], False, {'is_contract': False}, [], {}, 0, [], True, True, sender_cps=[], cross=cross,
                     l1_chains=[], state={'nonce': 0, 'balance_wei': 0}, bl_stats={'lists': 5, 'addresses': 100})
        self.assertEqual(r['level'], 'MEDIUM'); self.assertIn('FRESH_ADDRESS', self.codes(r))
        self.assertIn('Ethereum', r['signals'][0]['detail']['th'])
        self.assertTrue(r['verdict']['th'].startswith('เหตุผล'))

    def test_unused_here_but_clean_elsewhere_is_low(self):
        clean = [tx('0x' + 'b' * 40, A), tx(A, '0x' + 'c' * 40)] * 3
        r = E.assess(A, 43113, [], False, {'is_contract': False}, [], {}, 0, cross=[{'chain': 43114, 'ok': True, 'txs': clean}], l1_chains=[])
        self.assertEqual(r['level'], 'LOW'); self.assertIn('CROSS_CHAIN_ACTIVE', self.codes(r))

    def test_drainer_on_another_chain_is_high(self):
        drain = [tx(A, '0x' + 'd' * 40, 0, E.SEL_TRANSFER_FROM) for _ in range(3)]
        r = E.assess(A, 43113, [], False, {'is_contract': False}, [], {}, 0, cross=[{'chain': 1, 'ok': True, 'txs': drain}])
        self.assertEqual(r['level'], 'HIGH'); self.assertIn('Ethereum', r['signals'][0]['title']['th'])

    def test_balance_or_nonce_means_not_fresh(self):
        r = E.assess(A, 43113, [], False, {'is_contract': False}, [], {}, 0, state={'nonce': 3, 'balance_wei': 0}, l1_chains=[])
        self.assertNotIn('FRESH_ADDRESS', self.codes(r)); self.assertEqual(r['level'], 'LOW')

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

    def test_trust_score_follows_evidence_inside_the_level_band(self):
        old, young = 1_500_000_000, 1_790_000_000
        deep = [tx('0x' + 'b' * 40, A, ts=old)] * 50 + [tx(A, '0x' + 'c' * 40, ts=young)] * 50
        shallow = [tx('0x' + 'b' * 40, A, ts=young)] * 5
        s_deep = E.assess(A, 43113, deep, False, {'is_contract': False}, [], {}, 0, now=1_792_000_000)
        s_thin = E.assess(A, 43113, shallow, False, {'is_contract': False}, [], {}, 0, now=1_792_000_000)
        self.assertEqual((s_deep['level'], s_thin['level']), ('LOW', 'LOW'))
        self.assertGreater(s_deep['trust_score'], s_thin['trust_score'])          # same level, different evidence
        self.assertTrue(70 <= s_thin['trust_score'] < s_deep['trust_score'] <= 98)
        dust = [tx('0x' + str(i) * 40, A, 0) for i in range(1, 9)]
        m1 = E.assess(A, 43113, dust, False, {'is_contract': False}, [], {}, 0, now=1_792_000_000)
        m2 = E.assess(A, 43113, dust[:1] + [tx('0x' + 'e' * 40, A, 1.0)] * 7, False, {'is_contract': False}, [], {}, 1, now=1_792_000_000)
        self.assertEqual(m1['level'], 'MEDIUM'); self.assertTrue(30 <= m1['trust_score'] <= 69)
        hi = E.assess(A, 43113, [], False, {'is_contract': False}, [{'list': 'a', 'label': 'A'}, {'list': 'b', 'label': 'B'}], {}, 0)
        self.assertEqual(hi['level'], 'HIGH'); self.assertLessEqual(hi['trust_score'], 28)
        self.assertGreater(70, 69); self.assertLess(m1['trust_score'], s_thin['trust_score'])
        self.assertLess(hi['trust_score'], m1['trust_score'])

    def test_burn_and_system_addresses_are_high(self):
        for burn in ('0x' + '0' * 40, '0x000000000000000000000000000000000000dEaD', '0x' + '0' * 39 + '1'):
            r = E.assess(burn, 43113, [], False, {'is_contract': False}, [], {}, 0)
            self.assertEqual(r['level'], 'HIGH'); self.assertEqual(r['signals'][0]['code'], 'BURN_ADDRESS')
        self.assertFalse(E.is_burn('0x' + '0' * 30 + '1' + '0' * 9))

    def test_contract_is_not_flagged_for_dusting_or_links(self):
        zero = [tx('0x' + str(i) * 40, A, 0) for i in range(1, 7)]
        r = E.assess(A, 43113, zero, False, {'is_contract': True, 'erc_type': 'ERC-20', 'symbol': 'WAVAX'}, [], {'0x' + '1' * 40: ['x']}, 0)
        self.assertEqual([s['code'] for s in r['signals'] if s['severity'] != 'info'], ['TOKEN_CONTRACT'])

    def test_self_transfer_is_explained(self):
        r = E.assess(A, 43113, [tx('0x' + 'b' * 40, A)] * 6, False, {'is_contract': False}, [], {}, 0, [], sender=A)
        self.assertEqual(r['level'], 'LOW'); self.assertIn('SELF_TRANSFER', self.codes(r)); self.assertNotIn('FIRST_TIME_RECIPIENT', self.codes(r))

    def test_failure_is_caution_not_low(self):
        r = self.run_([], history_ok=False)
        self.assertEqual(r['level'], 'MEDIUM'); self.assertIn('UNVERIFIABLE', self.codes(r))

    def test_every_result_has_level_verdict_and_checks(self):
        cases = [self.run_([]), self.run_([], history_ok=False), self.run_([tx('0x' + 'b' * 40, A)] * 6),
                 self.run_([], l0=[{'list': 'x', 'label': 'X'}])]
        for r in cases:
            self.assertIn(r['level'], ('LOW', 'MEDIUM', 'HIGH'))
            self.assertTrue(r['verdict']['th'] and r['verdict']['en'])
            self.assertGreaterEqual(len(r['checks']), 6)
            for c in r['checks']: self.assertIn(c['result'], ('pass', 'flag', 'skip'))

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

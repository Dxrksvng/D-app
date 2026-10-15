"""Attestation: the signed verdict embedded in the user's transaction must be verifiable and unforgeable."""
import unittest
from backend import attestation as A

FROM, TO, OTHER = '0x' + '1' * 40, '0x' + '2' * 40, '0x' + '3' * 40
SIGS = [{'code': 'FIRST_TIME_RECIPIENT', 'severity': 'info'}]


class Attestation(unittest.TestCase):
    def setUp(self):
        self.att = A.make(43113, FROM, TO, 10 ** 16, 'LOW', 95, SIGS, 'abc123def456')

    def test_memo_is_ascii_and_roundtrips_through_input_data(self):
        self.assertTrue(self.att['memo'].startswith('BRIDGESECURE|v1|'))
        self.assertLess(len(self.att['memo']), 200)
        self.assertEqual(A.parse(self.att['data_hex']), self.att['memo'])

    def test_valid_on_the_bound_transaction(self):
        v = A.verify(self.att['memo'], 43113, FROM, TO, 10 ** 16, None)
        self.assertTrue(v['valid']); self.assertEqual((v['level'], v['trust_score']), ('LOW', 95)); self.assertEqual(v['signals'], [])

    def test_copied_to_another_transaction_fails(self):
        for args in [(43113, FROM, OTHER, 10 ** 16), (43113, OTHER, TO, 10 ** 16), (43113, FROM, TO, 10 ** 17), (43114, FROM, TO, 10 ** 16)]:
            self.assertFalse(A.verify(self.att['memo'], *args, None)['valid'], args)

    def test_tampered_level_fails(self):
        forged = self.att['memo'].replace('l=LOW', 'l=HIGH')
        self.assertFalse(A.verify(forged, 43113, FROM, TO, 10 ** 16, None)['valid'])

    def test_non_memo_input_is_ignored(self):
        self.assertIsNone(A.parse('0xa9059cbb' + '0' * 128)); self.assertIsNone(A.parse('0x')); self.assertIsNone(A.parse('0xzz'))

    def test_trust_score_is_monotonic_with_severity(self):
        low = A.trust_score('LOW', [], 10); med = A.trust_score('MEDIUM', [{'severity': 'medium'}], 10)
        high = A.trust_score('HIGH', [{'severity': 'high'}], 10); unk = A.trust_score('UNKNOWN', [], 0)
        self.assertTrue(high < med < unk < low)
        self.assertEqual(A.trust_score('LOW', [], 2), 80)


if __name__ == '__main__':
    unittest.main()

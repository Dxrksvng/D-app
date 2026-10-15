"""On-chain attestation: the analysis result travels inside the user's own transaction.

Why: the product must show the analysis on every transaction, but the backend must not store
transaction data. So the result is written into the transaction's input data (visible on any
explorer as UTF-8), signed with HMAC so nobody can forge or copy it to another transaction.
Verification reads the transaction back from the chain; nothing is kept on our side.

Memo format (ASCII, ~120 bytes):
    BRIDGESECURE|v1|c=43113|l=LOW|ts=95|s=FIRST_TIME_RECIPIENT|t=1792078000|r=ab12cd34ef56|k=<hmac16>
The HMAC covers the memo fields AND the tx fields that must match on-chain (chain, from, to, value),
so a memo copied into a different transaction fails verification.
"""
import hmac, hashlib, os, re, time
from . import config

PREFIX = 'BRIDGESECURE|v1|'
MAX_AGE_S = 30 * 60   # a signed check is valid for sending within 30 minutes
_SECRET = (os.environ.get('ATTESTATION_SECRET') or '').encode()
if not _SECRET:  # dev fallback: stable per data dir so restarts keep verifying old memos
    p = os.path.join(config.DATA_DIR, '.attestation_secret')
    os.makedirs(config.DATA_DIR, exist_ok=True)
    if not os.path.exists(p):
        with open(p, 'w') as f: f.write(os.urandom(32).hex())
    _SECRET = open(p).read().strip().encode()

# Trust score: a transparent severity index (NOT a probability). Documented in /v1/rules.
def trust_score(level, signals, n_total):
    highs = sum(1 for s in signals if s['severity'] == 'high'); meds = sum(1 for s in signals if s['severity'] == 'medium')
    if level == 'HIGH': return max(0, 20 - 5 * (highs - 1) - 2 * meds)
    if level == 'MEDIUM': return max(25, 45 - 5 * (meds - 1))   # evidence of risk ranks below "no data" (50)
    if level == 'UNKNOWN': return 50
    return 95 if n_total >= 5 else 80   # LOW; thin history caps the score


def _mac(fields, chain, frm, to, value_wei):
    msg = '|'.join([fields, str(chain), (frm or '').lower(), to.lower(), str(int(value_wei))]).encode()
    return hmac.new(_SECRET, msg, hashlib.sha256).hexdigest()[:16]


def make(chain, frm, to, value_wei, level, score, signals, request_id):
    codes = ','.join(s['code'] for s in signals if s['severity'] in ('high', 'medium'))[:80] or '-'
    fields = f"c={chain}|l={level}|ts={score}|s={codes}|t={int(time.time())}|r={request_id}"
    memo = PREFIX + fields + '|k=' + _mac(fields, chain, frm, to, value_wei)
    return {'memo': memo, 'data_hex': '0x' + memo.encode('ascii').hex(), 'valid_until': int(time.time()) + MAX_AGE_S,
            'bound_to': {'chain_id': chain, 'from': (frm or '').lower(), 'to': to.lower(), 'value_wei': str(int(value_wei))}}


def parse(input_hex):
    """Extract the memo from tx input data (plain transfer whose data is exactly the memo)."""
    try:
        raw = bytes.fromhex((input_hex or '')[2:]).decode('ascii')
    except (ValueError, UnicodeDecodeError):
        return None
    return raw if raw.startswith(PREFIX) else None


MEMO_RE = re.compile(r'^BRIDGESECURE\|v1\|(?P<fields>c=(?P<c>\d+)\|l=(?P<l>[A-Z]+)\|ts=(?P<ts>\d+)\|s=(?P<s>[A-Z0-9_,\-]+)\|t=(?P<t>\d+)\|r=(?P<r>[0-9a-f]+))\|k=(?P<k>[0-9a-f]{16})$')


def verify(memo, chain, frm, to, value_wei, block_ts):
    m = MEMO_RE.match(memo or '')
    if not m:
        return {'valid': False, 'reason': 'malformed'}
    ok_mac = hmac.compare_digest(m['k'], _mac(m['fields'], int(m['c']), frm, to, value_wei))
    out = {'valid': ok_mac and int(m['c']) == chain, 'level': m['l'], 'trust_score': int(m['ts']),
           'signals': [] if m['s'] == '-' else m['s'].split(','), 'checked_at': int(m['t']), 'request_id': m['r'],
           'seconds_from_check_to_block': (block_ts - int(m['t'])) if block_ts else None}
    if not ok_mac: out['reason'] = 'signature does not match this transaction (forged or copied)'
    elif int(m['c']) != chain: out['reason'] = 'chain mismatch'
    return out

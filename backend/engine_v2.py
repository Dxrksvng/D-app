"""Risk engine v2 — pure logic, no I/O.

Only signals that survived the pre-registered E5 audit (audit/results/*.json) can raise the level to HIGH:
  L0 known lists, R4 drainer, and the address-poisoning look-alike check (deterministic).
R1/R3 and the 2019 Random Forest were removed because E5 measured 18-48% false warnings.
Every signal carries its own human-readable reason, on-chain evidence and validation status.
"""
SEL_TRANSFER_FROM = '0x23b872dd'
SEVERITY_ORDER = {'high': 3, 'medium': 2, 'info': 1}

# Validation numbers copied from audit/results/metrics_v1.json and v2_candidate.json (E5, 2024-2026 replay).
VALIDATION = {
    'R4_DRAINER': {'status': 'validated', 'study': 'E5',
                   'ethereum': {'recall': 0.590, 'recall_ci': [0.521, 0.656], 'fpr': 0.015, 'fpr_ci': [0.005, 0.043]},
                   'avalanche': {'recall': 0.477, 'recall_ci': [0.375, 0.581], 'fpr': 0.005, 'fpr_ci': [0.001, 0.028]}},
    'R6_ZERO_VALUE': {'status': 'validated-low-recall', 'study': 'E5',
                      'ethereum': {'recall': 0.025, 'fpr': 0.010}},
    'L0_LISTED': {'status': 'deterministic', 'note': 'match against published lists; quality depends on the list'},
    'POISONING_LOOKALIKE': {'status': 'deterministic', 'note': 'exact prefix/suffix comparison with your own past recipients'},
    'L2_LINKED': {'status': 'not-yet-validated', 'note': 'shown as MEDIUM until measured in a future audit'},
    'COMMUNITY_REPORTED': {'status': 'unverified', 'note': 'reports from users of this service; not reviewed'},
}


def _sig(code, severity, th, en, evidence=None, **extra):
    return {'code': code, 'severity': severity, 'title': {'th': th[0], 'en': en[0]}, 'detail': {'th': th[1], 'en': en[1]},
            'evidence_tx': (evidence or [])[:3], 'validation': VALIDATION.get(code, {'status': 'informational'}), **extra}


def lookalike(dest, recipients):
    """Return the past recipient that `dest` imitates (same first 4 and last 4 hex chars, different address)."""
    d = dest.lower()
    for r in recipients:
        r = r.lower()
        if r != d and len(r) == 42 and r[2:6] == d[2:6] and r[-4:] == d[-4:]:
            return r
    return None


def features(addr, txs):
    a = addr.lower()
    inn = [t for t in txs if t['to'] == a]; out = [t for t in txs if t['frm'] == a]
    tf = [t for t in out if t['selector'] == SEL_TRANSFER_FROM]
    return {
        'n_total': len(txs), 'n_in': len(inn), 'n_out': len(out),
        'out_transferFrom': len(tf), 'transferFrom_tx': [t['hash'] for t in tf if t.get('hash')],
        'zero_val_in_share': (sum(1 for t in inn if t['value'] == 0) / len(inn)) if inn else 0.0,
        'zero_val_tx': [t['hash'] for t in inn if t['value'] == 0 and t.get('hash')],
        'first_seen': min((t['ts'] for t in txs), default=None), 'last_seen': max((t['ts'] for t in txs), default=None),
        'counterparties': {t['frm'] if t['to'] == a else t['to'] for t in txs} - {a, ''},
        'cp_tx': {(t['frm'] if t['to'] == a else t['to']): t['hash'] for t in txs if t.get('hash')},
    }


def assess(dest, chain, dest_txs, capped, contract, l0_hits, linked, community_reports, sender_recipients=None,
           history_ok=True, contract_ok=True):
    """dest_txs: destination history before now; l0_hits: [{'list','label'}]; linked: {counterparty: [lists]}."""
    f = features(dest, dest_txs); s = []
    if l0_hits:
        names = ', '.join(sorted({h['label'] for h in l0_hits}))
        s.append(_sig('L0_LISTED', 'high', ('อยู่ในรายชื่อที่อยู่อันตราย', f'พบในรายชื่อ: {names}'),
                      ('Listed as malicious', f'Found in: {names}'), lists=[h['list'] for h in l0_hits]))
    if sender_recipients is not None:
        twin = lookalike(dest, sender_recipients)
        if twin:
            s.append(_sig('POISONING_LOOKALIKE', 'high',
                          ('ที่อยู่หน้าตาคล้ายกับที่อยู่ที่คุณเคยโอน', f'คุณเคยโอนไปที่ {twin} ซึ่งขึ้นต้นและลงท้ายเหมือนกัน แต่ไม่ใช่ที่อยู่เดียวกัน รูปแบบนี้คือ address poisoning'),
                          ('Look-alike of an address you used', f'You previously sent to {twin}; same first and last characters, different address (address poisoning)'),
                          imitates=twin))
    if f['out_transferFrom'] >= 3:
        s.append(_sig('R4_DRAINER', 'high',
                      ('พฤติกรรมแบบ wallet drainer', f"ที่อยู่นี้เคยเรียก transferFrom ดึงโทเคนจากกระเป๋าอื่น {f['out_transferFrom']} ครั้ง ซึ่งเป็นวิธีที่ drainer ใช้หลังหลอกให้เหยื่อกด approve"),
                      ('Wallet-drainer behaviour', f"This address called transferFrom to pull tokens from other wallets {f['out_transferFrom']} times"),
                      f['transferFrom_tx']))
    if community_reports:
        s.append(_sig('COMMUNITY_REPORTED', 'medium', ('มีผู้ใช้รายงาน', f'ผู้ใช้รายงานที่อยู่นี้ {community_reports} ครั้ง (ยังไม่ได้ตรวจยืนยัน)'),
                      ('Reported by users', f'Reported {community_reports} time(s); not verified')))
    if linked:
        cps = sorted(linked)[:3]
        s.append(_sig('L2_LINKED', 'medium', ('เคยทำธุรกรรมกับที่อยู่อันตราย', f'เคยรับหรือส่งเงินกับที่อยู่ในรายชื่ออันตราย {len(linked)} ราย'),
                      ('Transacted with listed addresses', f'Interacted with {len(linked)} listed address(es)'),
                      [f['cp_tx'][c] for c in cps if c in f['cp_tx']], counterparties=cps))
    if f['zero_val_in_share'] >= 0.5 and f['n_in'] >= 5:
        s.append(_sig('R6_ZERO_VALUE', 'medium', ('ได้รับธุรกรรมมูลค่า 0 จำนวนมาก', f"{f['zero_val_in_share']:.0%} ของธุรกรรมขาเข้ามีมูลค่า 0 (พบบ่อยในการ dusting / poisoning)"),
                      ('Many zero-value transfers', f"{f['zero_val_in_share']:.0%} of incoming transactions carry zero value"), f['zero_val_tx']))
    if contract.get('is_contract'):
        if (contract.get('erc_type') or '').startswith('ERC-20'):
            s.append(_sig('TOKEN_CONTRACT', 'medium', ('ปลายทางเป็น contract ของโทเคน', f"นี่คือ contract ของโทเคน {contract.get('symbol') or ''} ไม่ใช่กระเป๋า การส่งเหรียญเข้าไปตรงนี้มักเรียกคืนไม่ได้"),
                          ('Destination is a token contract', 'Coins sent to a token contract are usually unrecoverable')))
        else:
            s.append(_sig('CONTRACT', 'info', ('ปลายทางเป็น smart contract', 'ตรวจสอบให้แน่ใจว่าเป็น contract ที่คุณตั้งใจจะใช้'),
                          ('Destination is a smart contract', 'Make sure this is the contract you intend to use')))
    if sender_recipients is not None and dest.lower() not in {r.lower() for r in sender_recipients}:
        s.append(_sig('FIRST_TIME_RECIPIENT', 'info', ('ครั้งแรกที่คุณโอนไปที่อยู่นี้', 'ตรวจทุกตัวอักษรของที่อยู่อีกครั้งก่อนยืนยัน'),
                      ('First transfer to this address', 'Double-check every character before confirming')))
    if capped:
        s.append(_sig('HIGH_VOLUME', 'info', ('ที่อยู่ธุรกรรมหนาแน่น', 'มีธุรกรรมจำนวนมาก มักเป็นกระเป๋าของ exchange หรือบริการ ระบบจึงวิเคราะห์จากธุรกรรมล่าสุดเท่านั้น'),
                      ('High-volume address', 'Typical of exchanges or services; only recent activity was analysed')))
    if history_ok and 0 < f['n_total'] < 5:
        s.append(_sig('THIN_HISTORY', 'info', ('ประวัติธุรกรรมน้อย', f"พบเพียง {f['n_total']} ธุรกรรม ระบบประเมินพฤติกรรมได้จำกัด"),
                      ('Little history', f"Only {f['n_total']} transaction(s); behavioural assessment is limited")))
    if history_ok and f['n_total'] == 0:
        s.append(_sig('NO_HISTORY', 'info', ('ยังไม่มีประวัติธุรกรรม', 'ที่อยู่นี้ยังไม่เคยทำธุรกรรม ระบบตรวจได้เฉพาะรายชื่ออันตราย จึงประเมินพฤติกรรมไม่ได้'),
                      ('No transaction history', 'Only the known-bad lists could be checked')))
    if not history_ok or not contract_ok:
        s.append(_sig('CHECK_INCOMPLETE', 'info', ('ตรวจได้ไม่ครบ', 'แหล่งข้อมูล on-chain ไม่ตอบในตอนนี้ ผลนี้มาจากรายชื่ออันตรายเท่านั้น'),
                      ('Check incomplete', 'On-chain data source unavailable; result is based on lists only')))

    top = max((SEVERITY_ORDER[x['severity']] for x in s), default=0)
    if top == 3: level = 'HIGH'
    elif top == 2: level = 'MEDIUM'
    elif not history_ok or f['n_total'] == 0: level = 'UNKNOWN'
    else: level = 'LOW'
    s.sort(key=lambda x: -SEVERITY_ORDER[x['severity']])
    return {'level': level, 'signals': s,
            'stats': {k: f[k] for k in ('n_total', 'n_in', 'n_out', 'first_seen', 'last_seen')} | {'history_capped': capped}}

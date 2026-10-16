"""Risk engine v2 — pure logic, no I/O.

Only signals that survived the pre-registered E5 audit (audit/results/*.json) can raise the level to HIGH:
  L0 known lists, R4 drainer, and the address-poisoning look-alike check (deterministic).
R1/R3 and the 2019 Random Forest were removed because E5 measured 18-48% false warnings.
Every result is LOW, MEDIUM or HIGH and carries its reasons (signals), the checks that were run and a one-line verdict.
"""
import math, time

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
    'POISONING_LOOKALIKE': {'status': 'deterministic', 'note': 'exact prefix/suffix comparison with addresses you transacted with'},
    'L2_LINKED': {'status': 'not-yet-validated', 'note': 'shown as MEDIUM until measured in a future audit'},
    'COMMUNITY_REPORTED': {'status': 'unverified', 'note': 'reports from users of this service; not reviewed'},
    'FRESH_ADDRESS': {'status': 'precautionary',
                      'note': 'not proof of a scam: E5 showed "new address" alone also flags many real wallets, so it can raise MEDIUM, never HIGH'},
    'UNVERIFIABLE': {'status': 'precautionary', 'note': 'history could not be read; caution until it can be checked'},
    'BURN_ADDRESS': {'status': 'deterministic', 'note': 'no private key exists for this address; anything sent is unrecoverable'},
}
# Addresses nobody controls: coins sent here are gone for good.
BURN_ADDRESSES = {'0x' + '0' * 40, '0x000000000000000000000000000000000000dead', '0xdead000000000000000042069420694206942069'}


def is_burn(addr):
    """Zero/dead addresses and the low system range (EVM precompiles 0x01-0x0a and reserved slots) up to 0xffff."""
    a = addr.lower()
    return a in BURN_ADDRESSES or int(a, 16) <= 0xffff
CHAIN_NAMES = {43113: 'Avalanche Fuji', 43114: 'Avalanche C-Chain', 1: 'Ethereum'}
BEHAVIOUR_CODES = {'R4_DRAINER', 'L2_LINKED', 'R6_ZERO_VALUE'}


def _sig(code, severity, th, en, evidence=None, **extra):
    return {'code': code, 'severity': severity, 'title': {'th': th[0], 'en': en[0]}, 'detail': {'th': th[1], 'en': en[1]},
            'evidence_tx': (evidence or [])[:3], 'validation': VALIDATION.get(code, {'status': 'informational'}), **extra}


def _chain_name(c):
    return CHAIN_NAMES.get(c, f'chain {c}')


def lookalike(dest, recipients):
    """Return the past address that `dest` imitates (same first 4 and last 4 hex chars, different address)."""
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


def _behaviour_signals(f, linked, where_th='', where_en='', wallet=True):
    """Drainer / linked / dusting patterns on one chain's history. where_*: ' (บน Ethereum)' style suffix.
    wallet=False (contracts, burn addresses): only R4 applies; busy contracts naturally touch listed addresses and
    receive zero-value calls, so L2/R6 would be false warnings there."""
    s = []
    if f['out_transferFrom'] >= 3:
        s.append(_sig('R4_DRAINER', 'high',
                      ('พฤติกรรมแบบ wallet drainer' + where_th, f"ที่อยู่นี้เคยเรียก transferFrom ดึงโทเคนจากกระเป๋าอื่น {f['out_transferFrom']} ครั้ง{where_th} ซึ่งเป็นวิธีที่ drainer ใช้หลังหลอกให้เหยื่อกด approve"),
                      ('Wallet-drainer behaviour' + where_en, f"This address called transferFrom to pull tokens from other wallets {f['out_transferFrom']} times{where_en}"),
                      f['transferFrom_tx']))
    if linked and wallet:
        cps = sorted(linked)[:3]
        s.append(_sig('L2_LINKED', 'medium', ('เคยทำธุรกรรมกับที่อยู่อันตราย' + where_th, f'เคยรับหรือส่งเงินกับที่อยู่ในรายชื่ออันตราย {len(linked)} ราย{where_th}'),
                      ('Transacted with listed addresses' + where_en, f'Interacted with {len(linked)} listed address(es){where_en}'),
                      [f['cp_tx'][c] for c in cps if c in f['cp_tx']], counterparties=cps))
    if wallet and f['zero_val_in_share'] >= 0.5 and f['n_in'] >= 5:
        s.append(_sig('R6_ZERO_VALUE', 'medium', ('ได้รับธุรกรรมมูลค่า 0 จำนวนมาก' + where_th, f"{f['zero_val_in_share']:.0%} ของธุรกรรมขาเข้ามีมูลค่า 0{where_th} (พบบ่อยในการ dusting / poisoning)"),
                      ('Many zero-value transfers' + where_en, f"{f['zero_val_in_share']:.0%} of incoming transactions carry zero value{where_en}"), f['zero_val_tx']))
    return s


def assess(dest, chain, dest_txs, capped, contract, l0_hits, linked, community_reports, sender_recipients=None,
           history_ok=True, contract_ok=True, *, sender_cps=None, cross=None, l1_chains=None, state=None, bl_stats=None,
           sender=None, now=None):
    """Every call ends in LOW, MEDIUM or HIGH with written reasons and the list of checks that produced it.

    dest_txs: destination history on `chain`; l0_hits: [{'list','label'}]; linked: {counterparty: [lists]}.
    sender_recipients: addresses the sender sent to; sender_cps: every address the sender transacted with (poisoning check).
    cross: [{'chain', 'ok', 'txs', 'capped', 'linked', 'state'}] the same address on the other supported chains.
    l1_chains: Avalanche L1s with activity per the Data API (None = lookup failed). state: {'nonce','balance_wei'} on `chain`.
    """
    f = features(dest, dest_txs); s = []; cross = cross or []; now = now or time.time()
    here = _chain_name(chain)
    burn = is_burn(dest); wallet = not burn and not contract.get('is_contract')
    if burn:
        s.append(_sig('BURN_ADDRESS', 'high', ('ที่อยู่เผาทิ้ง ไม่มีใครเป็นเจ้าของ',
                                               'ที่อยู่นี้เป็นที่อยู่ศูนย์ / dead / ที่อยู่ระบบ ไม่มี private key เหรียญที่ส่งไปจะหายถาวร กู้คืนไม่ได้'),
                      ('Burn address, nobody owns it', 'Zero / dead / system address with no private key; anything sent is lost forever')))
    if sender and sender.lower() == dest.lower():
        s.append(_sig('SELF_TRANSFER', 'info', ('โอนเข้ากระเป๋าตัวเอง', 'ปลายทางคือที่อยู่เดียวกับกระเป๋าที่ใช้ส่ง เงินไม่ได้ออกไปไหน เสียแค่ค่าธรรมเนียม'),
                      ('Sending to yourself', 'Destination is the sending wallet; only the network fee is spent')))
    if l0_hits:
        names = ', '.join(sorted({h['label'] for h in l0_hits}))
        s.append(_sig('L0_LISTED', 'high', ('อยู่ในรายชื่อที่อยู่อันตราย', f'พบในรายชื่อ: {names}'),
                      ('Listed as malicious', f'Found in: {names}'), lists=[h['list'] for h in l0_hits]))
    pool = sender_cps if sender_cps is not None else sender_recipients
    twin = lookalike(dest, pool) if pool is not None else None
    if twin:
        s.append(_sig('POISONING_LOOKALIKE', 'high',
                      ('ที่อยู่หน้าตาคล้ายกับที่อยู่ที่คุณเคยใช้', f'คุณเคยทำธุรกรรมกับ {twin} ซึ่งขึ้นต้นและลงท้ายเหมือนกัน แต่ไม่ใช่ที่อยู่เดียวกัน รูปแบบนี้คือ address poisoning'),
                      ('Look-alike of an address you used', f'You previously transacted with {twin}; same first and last characters, different address (address poisoning)'),
                      imitates=twin))
    s += _behaviour_signals(f, linked, wallet=wallet)
    cross_ok = [c for c in cross if c.get('ok')]
    cross_feats = {}
    for c in cross_ok:
        cf = features(dest, c.get('txs') or []); cross_feats[c['chain']] = cf
        s += _behaviour_signals(cf, c.get('linked') or {}, f" (บน {_chain_name(c['chain'])})", f" (on {_chain_name(c['chain'])})", wallet=wallet)
    if community_reports:
        s.append(_sig('COMMUNITY_REPORTED', 'medium', ('มีผู้ใช้รายงาน', f'ผู้ใช้รายงานที่อยู่นี้ {community_reports} ครั้ง (ยังไม่ได้ตรวจยืนยัน)'),
                      ('Reported by users', f'Reported {community_reports} time(s); not verified')))
    if contract.get('is_contract'):
        if (contract.get('erc_type') or '').startswith('ERC-20'):
            s.append(_sig('TOKEN_CONTRACT', 'medium', ('ปลายทางเป็น contract ของโทเคน', f"นี่คือ contract ของโทเคน {contract.get('symbol') or ''} ไม่ใช่กระเป๋า การส่งเหรียญเข้าไปตรงนี้มักเรียกคืนไม่ได้"),
                          ('Destination is a token contract', 'Coins sent to a token contract are usually unrecoverable')))
        else:
            s.append(_sig('CONTRACT', 'info', ('ปลายทางเป็น smart contract', 'ตรวจสอบให้แน่ใจว่าเป็น contract ที่คุณตั้งใจจะใช้'),
                          ('Destination is a smart contract', 'Make sure this is the contract you intend to use')))

    # Activity across every place we looked: this chain, the other supported chains, Avalanche L1s, RPC nonce/balance.
    n_cross = sum(cf['n_total'] for cf in cross_feats.values())
    nonce_any = (state or {}).get('nonce', 0) + sum((c.get('state') or {}).get('nonce', 0) for c in cross_ok)
    bal_any = (state or {}).get('balance_wei', 0) + sum((c.get('state') or {}).get('balance_wei', 0) for c in cross_ok)
    l1_names = [c['name'] for c in (l1_chains or [])]
    active_elsewhere = [_chain_name(c) for c, cf in cross_feats.items() if cf['n_total'] > 0]
    n_all = f['n_total'] + n_cross
    looked_ok = history_ok or bool(cross_ok)
    fresh = looked_ok and n_all == 0 and nonce_any == 0 and bal_any == 0 and not l1_names and wallet

    if fresh:
        where = ', '.join([here] + [_chain_name(c['chain']) for c in cross_ok])
        if l1_chains is not None: where += ' และ Avalanche L1 ทั้งหมดที่ Data API รู้จัก'
        s.append(_sig('FRESH_ADDRESS', 'medium',
                      ('ที่อยู่ใหม่ ไม่เคยถูกใช้งานที่ไหนเลย',
                       f'ตรวจแล้วบน {where}: ไม่มีธุรกรรม ไม่เคยส่ง (nonce 0) และไม่มียอดเงิน '
                       'กระเป๋าที่เพิ่งสร้างเป็นรูปแบบที่มิจฉาชีพใช้รับเงินบ่อย เพราะสร้างใหม่ได้เรื่อย ๆ เพื่อหลบรายชื่อดำ '
                       'ถ้าคุณไม่ได้รับที่อยู่นี้จากผู้รับโดยตรง ให้ยืนยันกับเขาผ่านช่องทางอื่นก่อนโอน'),
                      ('Brand-new address, never used anywhere',
                       'No transactions, nonce 0 and zero balance on every chain checked. Freshly created wallets are a common scam '
                       'receiving pattern because they evade blocklists; confirm with the recipient through another channel.')))
    elif f['n_total'] == 0 and (active_elsewhere or l1_names or nonce_any or bal_any):
        seen = active_elsewhere + [n for n in l1_names if n not in active_elsewhere]
        s.append(_sig('CROSS_CHAIN_ACTIVE', 'info',
                      (f'ยังไม่เคยใช้บน {here} แต่มีประวัติที่อื่น',
                       f"พบการใช้งานบน {', '.join(seen) or 'เครือข่ายนี้ (มียอดเงินหรือ nonce)'} ({n_cross} ธุรกรรมที่วิเคราะห์ได้) ระบบนำประวัติส่วนนั้นมาวิเคราะห์แทน"),
                      (f'Unused on {here} but active elsewhere', f"Activity on {', '.join(seen) or 'this chain (balance/nonce)'}; that history was analysed instead")))
    if not looked_ok:
        s.append(_sig('UNVERIFIABLE', 'medium', ('ตรวจประวัติธุรกรรมไม่ได้ในขณะนี้',
                                                 'แหล่งข้อมูล on-chain ไม่ตอบ จึงยืนยันพฤติกรรมของที่อยู่นี้ไม่ได้ ระบบให้ระดับระวังไว้ก่อนจนกว่าจะตรวจได้'),
                      ('History could not be read', 'On-chain sources did not respond, so behaviour is unverified; caution until it can be checked')))
    if sender_recipients is not None and dest.lower() not in {r.lower() for r in sender_recipients} and not (sender and sender.lower() == dest.lower()):
        s.append(_sig('FIRST_TIME_RECIPIENT', 'info', ('ครั้งแรกที่คุณโอนไปที่อยู่นี้', 'ตรวจทุกตัวอักษรของที่อยู่อีกครั้งก่อนยืนยัน'),
                      ('First transfer to this address', 'Double-check every character before confirming')))
    if capped:
        s.append(_sig('HIGH_VOLUME', 'info', ('ที่อยู่ธุรกรรมหนาแน่น', 'มีธุรกรรมจำนวนมาก มักเป็นกระเป๋าของ exchange หรือบริการ ระบบจึงวิเคราะห์จากธุรกรรมล่าสุดเท่านั้น'),
                      ('High-volume address', 'Typical of exchanges or services; only recent activity was analysed')))
    if 0 < n_all < 5:
        s.append(_sig('THIN_HISTORY', 'info', ('ประวัติธุรกรรมน้อย', f"พบเพียง {n_all} ธุรกรรม ระบบประเมินพฤติกรรมได้จำกัด"),
                      ('Little history', f"Only {n_all} transaction(s); behavioural assessment is limited")))

    top = max((SEVERITY_ORDER[x['severity']] for x in s), default=0)
    level = 'HIGH' if top == 3 else 'MEDIUM' if top == 2 else 'LOW'
    s.sort(key=lambda x: -SEVERITY_ORDER[x['severity']])
    firsts = [x for x in [f['first_seen']] + [cf['first_seen'] for cf in cross_feats.values()] if x]
    ev = {'age_days': round((now - min(firsts)) / 86400, 1) if firsts else 0, 'n_all': n_all,
          'chains_active': sum(1 for ok, cf in [(True, f)] + [(True, v) for v in cross_feats.values()] if cf['n_total'] > 0)
                           + (1 if (f['n_total'] == 0 and nonce_any + bal_any > 0) else 0),
          'zero_share': max([f['zero_val_in_share']] + [cf['zero_val_in_share'] for cf in cross_feats.values()])}
    checks = _checks(chain, f, cross, cross_feats, l0_hits, community_reports, pool, twin, contract, contract_ok,
                     history_ok, l1_chains, state, bl_stats, s)
    return {'level': level, 'signals': s, 'checks': checks, 'verdict': _verdict(s, checks, n_all, ev),
            'evidence': ev, 'trust_score': trust_score(level, s, ev),
            'stats': {k: f[k] for k in ('n_total', 'n_in', 'n_out', 'first_seen', 'last_seen')}
                     | {'history_capped': capped, 'n_all_chains': n_all, 'nonce': (state or {}).get('nonce')}}


def trust_score(level, signals, ev):
    """Severity index 0-100 computed from this address's own evidence (NOT a probability, NOT a constant per level).
    The level fixes the band (HIGH 0-28, MEDIUM 30-69, LOW 70-98); inside the band the score moves with what was measured:
    account age, transaction depth, chains with activity, listed counterparties/lists and how much zero-value dusting."""
    highs = [s for s in signals if s['severity'] == 'high']; meds = [s for s in signals if s['severity'] == 'medium']
    age = min(ev.get('age_days') or 0, 730) / 730
    depth = min(math.log10(1 + (ev.get('n_all') or 0)) / 3, 1)
    chains = min(ev.get('chains_active') or 0, 3)
    pos = 12 * age + 12 * depth + 2 * max(chains - 1, 0)          # 0..28 points of positive evidence
    if level == 'HIGH':
        lists = max((len(s.get('lists', [])) for s in highs), default=1)
        return max(0, round(25 - 5 * (len(highs) - 1) - 2 * len(meds) - 3 * max(lists - 1, 0) + 0.1 * pos))
    if level == 'MEDIUM':
        pen = 7 * len(meds) + (10 * ev.get('zero_share', 0) if any(s['code'] == 'R6_ZERO_VALUE' for s in meds) else 0)
        return max(30, min(69, round(60 - pen + 0.3 * pos)))
    return min(98, round(70 + pos))


def _chk(cid, result, th, en):
    return {'id': cid, 'result': result, 'th': th, 'en': en}   # result: pass | flag | skip


def _checks(chain, f, cross, cross_feats, l0_hits, reports, pool, twin, contract, contract_ok, history_ok, l1_chains, state, bl, s):
    """The checklist shown to the user: every check that ran, with what it found."""
    codes = {x['code'] for x in s}; c = []
    nl, na = (bl or {}).get('lists', 0), (bl or {}).get('addresses', 0)
    c.append(_chk('blocklists', 'flag' if l0_hits else 'pass',
                  f"เทียบรายชื่ออันตราย {nl} แหล่ง ({na:,} ที่อยู่): " + ('พบ' if l0_hits else 'ไม่พบ'),
                  f"{nl} blocklists ({na:,} addresses): " + ('listed' if l0_hits else 'not listed')))
    c.append(_chk('reports', 'flag' if reports else 'pass', f"รายงานจากผู้ใช้: {reports or 'ไม่มี'}", f"User reports: {reports or 'none'}"))
    if pool is None:
        c.append(_chk('poisoning', 'skip', 'เทียบที่อยู่หน้าตาคล้าย (poisoning): ต้องเชื่อมกระเป๋าก่อน', 'Look-alike check: connect a wallet first'))
    else:
        c.append(_chk('poisoning', 'flag' if twin else 'pass',
                      f"เทียบกับ {len(pool)} ที่อยู่ที่คุณเคยทำธุรกรรม: " + (f'คล้าย {twin}' if twin else 'ไม่พบที่อยู่หน้าตาคล้าย'),
                      f"Compared with {len(pool)} addresses you used: " + (f'imitates {twin}' if twin else 'no look-alike')))
    if contract_ok:
        is_c = contract.get('is_contract')
        c.append(_chk('code', 'flag' if 'TOKEN_CONTRACT' in codes else 'pass',
                      'ชนิดปลายทาง: ' + ('smart contract' if is_c else 'กระเป๋าทั่วไป (EOA)'),
                      'Destination type: ' + ('contract' if is_c else 'wallet (EOA)')))
    else:
        c.append(_chk('code', 'skip', 'ชนิดปลายทาง: อ่านไม่ได้', 'Destination type: unavailable'))
    nonce = (state or {}).get('nonce')
    if history_ok:
        c.append(_chk('history', 'pass', f"ประวัติบน {_chain_name(chain)}: {f['n_total']} ธุรกรรม" + (f' (nonce {nonce})' if nonce is not None else ''),
                      f"History on {_chain_name(chain)}: {f['n_total']} tx"))
    else:
        c.append(_chk('history', 'skip', f'ประวัติบน {_chain_name(chain)}: อ่านไม่ได้', f'History on {_chain_name(chain)}: unavailable'))
    for x in cross:
        nm = _chain_name(x['chain'])
        if not x.get('ok'):
            c.append(_chk(f"cross_{x['chain']}", 'skip', f'ประวัติบน {nm}: อ่านไม่ได้', f'History on {nm}: unavailable')); continue
        c.append(_chk(f"cross_{x['chain']}", 'pass', f"ประวัติบน {nm}: {cross_feats[x['chain']]['n_total']} ธุรกรรม",
                      f"History on {nm}: {cross_feats[x['chain']]['n_total']} tx"))
    if l1_chains is None:
        c.append(_chk('l1', 'skip', 'Avalanche L1 อื่น ๆ (Data API): อ่านไม่ได้', 'Other Avalanche L1s (Data API): unavailable'))
    else:
        names = ', '.join(x['name'] for x in l1_chains)
        c.append(_chk('l1', 'pass', f"Avalanche L1 ที่มีการใช้งาน (Data API): {names or 'ไม่พบ'}", f"Avalanche L1 activity: {names or 'none'}"))
    n_beh = f['n_total'] + sum(v['n_total'] for v in cross_feats.values())
    beh = codes & BEHAVIOUR_CODES
    if n_beh:
        c.append(_chk('behaviour', 'flag' if beh else 'pass', f'พฤติกรรม drainer / ติดต่อที่อยู่อันตราย / dusting จาก {n_beh} ธุรกรรม: ' + ('พบ' if beh else 'ไม่พบ'),
                      f'Drainer / linked / dusting patterns over {n_beh} tx: ' + ('found' if beh else 'none')))
    else:
        c.append(_chk('behaviour', 'skip', 'พฤติกรรม drainer / dusting: ไม่มีธุรกรรมให้ตรวจ', 'Behaviour patterns: no transactions to analyse'))
    if 'FRESH_ADDRESS' in codes:
        c.append(_chk('fresh', 'flag', 'ไม่เคยถูกใช้งานบนเครือข่ายใดที่ตรวจ', 'Never used on any chain checked'))
    return c


def _verdict(s, checks, n_all, ev=None):
    """One line that says why this level was given."""
    risky = [x for x in s if x['severity'] in ('high', 'medium')]
    if risky:
        return {'th': 'เหตุผล: ' + ' · '.join(x['title']['th'] for x in risky[:3]),
                'en': 'Because: ' + ' · '.join(x['title']['en'] for x in risky[:3])}
    passed = sum(1 for x in checks if x['result'] == 'pass')
    age = f" อายุที่อยู่ประมาณ {int(ev['age_days'])} วัน" if ev and ev.get('age_days') else ''
    return {'th': f'ผ่านการตรวจ {passed} ข้อ ไม่พบสัญญาณอันตราย' + (f' จากประวัติ {n_all} ธุรกรรม{age}' if n_all else ''),
            'en': f'Passed {passed} checks with no risk signal' + (f' across {n_all} transactions' + (f", address age ~{int(ev['age_days'])} days" if ev and ev.get('age_days') else '') if n_all else '')}

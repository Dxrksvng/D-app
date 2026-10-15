"""L0: known-bad address lists, refreshed in the background.

E5 showed older independent lists cover almost none of the 2024-2026 scams, so the daily ScamSniffer
feed is the primary list; the others add sanctions and historical phishing labels.
Addresses are chain-agnostic on EVM, so one list protects every supported chain.
Community reports are kept separately and are never treated as confirmed.
"""
import csv, io, json, os, threading, time, urllib.request
from . import config

FEEDS = [
    ('scamsniffer', 'https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/all.json', 'json:address', 'Wallet drainer / phishing (ScamSniffer, daily)'),
    ('ofac', 'https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_ETH.txt', 'lines', 'US Treasury OFAC sanctions (SDN)'),
    ('forta_phishing', 'https://raw.githubusercontent.com/forta-network/labelled-datasets/main/labels/1/phishing_scams.csv', 'csv:address', 'Etherscan phish-hack label (Forta dataset)'),
    ('forta_malicious', 'https://raw.githubusercontent.com/forta-network/labelled-datasets/main/labels/1/etherscan_malicious_labels.csv', 'csv:banned_address', 'Etherscan exploit / heist / phish label (Forta dataset)'),
    ('mew_darklist', 'https://raw.githubusercontent.com/MyEtherWallet/ethereum-lists/master/src/addresses/addresses-darklist.json', 'json:list.address', 'MyEtherWallet darklist'),
]
CACHE = os.path.join(config.DATA_DIR, 'blocklists_cache.json')
SEED = os.path.join(config.DATA_DIR, 'seed')
REPORTS = os.path.join(config.DATA_DIR, 'community_reports.jsonl')


def _parse(kind, raw):
    if kind == 'lines':
        return {l.strip().lower() for l in raw.splitlines() if l.strip().startswith('0x')}
    if kind.startswith('csv:'):
        col = kind[4:]
        return {r[col].strip().lower() for r in csv.DictReader(io.StringIO(raw)) if r.get(col, '').startswith('0x')}
    j = json.loads(raw)
    if kind == 'json:address':
        j = j['address'] if isinstance(j, dict) else j
        return {a.lower() for a in j if isinstance(a, str)}
    if kind == 'json:list.address':
        return {(x['address'] if isinstance(x, dict) else x).lower() for x in j}
    raise ValueError(kind)


class Blocklists:
    def __init__(self, fetch=True):
        self.lock = threading.Lock(); self.index = {}; self.meta = {}; self.reports = {}
        self._load_disk()
        self._load_reports()
        if fetch:
            threading.Thread(target=self._loop, daemon=True, name='blocklist-refresh').start()

    # ---- persistence -------------------------------------------------------------------------
    def _load_disk(self):
        src = CACHE if os.path.exists(CACHE) else os.path.join(SEED, 'blocklists_seed.json')
        if os.path.exists(src):
            d = json.load(open(src, encoding='utf-8'))
            self._install({k: set(v) for k, v in d['lists'].items()}, d['meta'])

    def _install(self, lists, meta):
        idx = {}
        for name, addrs in lists.items():
            for a in addrs: idx.setdefault(a, []).append(name)
        with self.lock:
            self.index, self.meta = idx, meta

    def refresh(self):
        lists, meta = {}, {}
        with self.lock:
            old = {n: m for n, m in self.meta.items()}
        prev = {}
        for a, names in self.index.items():
            for n in names: prev.setdefault(n, set()).add(a)
        for name, url, kind, label in FEEDS:
            try:
                with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'riskguard-backend/2'}), timeout=60) as r:
                    lists[name] = _parse(kind, r.read().decode('utf-8'))
                meta[name] = {'label': label, 'url': url, 'count': len(lists[name]), 'fetched_at': int(time.time()), 'status': 'ok'}
            except Exception as e:  # keep the last good copy of this feed
                lists[name] = prev.get(name, set())
                meta[name] = {**old.get(name, {'label': label, 'url': url, 'count': len(lists[name])}), 'status': f'stale ({type(e).__name__})'}
        self._install(lists, meta)
        os.makedirs(config.DATA_DIR, exist_ok=True)
        tmp = CACHE + '.tmp'
        json.dump({'lists': {k: sorted(v) for k, v in lists.items()}, 'meta': meta}, open(tmp, 'w', encoding='utf-8'))
        os.replace(tmp, CACHE)

    def _loop(self):
        while True:
            try:
                self.refresh()
            except Exception:
                pass
            time.sleep(config.BLOCKLIST_REFRESH_S)

    # ---- community reports (unverified; stored without any reporter identity) ----------------
    def _load_reports(self):
        if os.path.exists(REPORTS):
            for line in open(REPORTS, encoding='utf-8'):
                try:
                    r = json.loads(line); self.reports[r['address']] = self.reports.get(r['address'], 0) + 1
                except ValueError:
                    pass

    def add_report(self, address, chain, category):
        rec = {'address': address, 'chain': chain, 'category': category, 'ts': int(time.time())}
        os.makedirs(config.DATA_DIR, exist_ok=True)
        with self.lock:
            with open(REPORTS, 'a', encoding='utf-8') as f: f.write(json.dumps(rec) + '\n')
            self.reports[address] = self.reports.get(address, 0) + 1
        return self.reports[address]

    # ---- lookups ------------------------------------------------------------------------------
    def lookup(self, address):
        with self.lock:
            return [{'list': n, 'label': self.meta.get(n, {}).get('label', n)} for n in self.index.get(address, [])]

    def any_listed(self, addresses):
        with self.lock:
            return {a: self.index[a] for a in addresses if a in self.index}

    def reported(self, address):
        return self.reports.get(address, 0)

    def status(self):
        with self.lock:
            return {'feeds': self.meta, 'unique_addresses': len(self.index), 'community_reported_addresses': len(self.reports)}

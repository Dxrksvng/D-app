"""Runtime configuration. Everything comes from environment variables (or poc/backend/.env) so the
same code runs locally, in Docker and on Cloud Run. No secret is ever logged."""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _load_dotenv():
    p = os.path.join(HERE, '.env')
    if not os.path.exists(p):
        return
    for line in open(p, encoding='utf-8'):
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            os.environ.setdefault(k.strip(), v.strip())


_load_dotenv()

HOST = os.environ.get('HOST', '0.0.0.0')
PORT = int(os.environ.get('PORT', '8080'))
DATA_API_KEY = os.environ.get('DATA_API_KEY', '')            # Avalanche Data API (x-glacier-api-key); optional
ROUTESCAN_API_KEY = os.environ.get('ROUTESCAN_API_KEY', '')  # optional, raises Routescan limits
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get('ALLOWED_ORIGINS', '*').split(',') if o.strip()]
RATE_LIMIT_PER_MIN = int(os.environ.get('RATE_LIMIT_PER_MIN', '30'))
RISK_CACHE_TTL_S = int(os.environ.get('RISK_CACHE_TTL_S', '60'))
BLOCKLIST_REFRESH_S = int(os.environ.get('BLOCKLIST_REFRESH_S', str(6 * 3600)))
UPSTREAM_TIMEOUT_S = float(os.environ.get('UPSTREAM_TIMEOUT_S', '8'))
DATA_DIR = os.environ.get('DATA_DIR', os.path.join(ROOT, 'data'))
WEB_DIR = os.environ.get('WEB_DIR', os.path.join(ROOT, 'web'))
HOME_PAGE = os.environ.get('HOME_PAGE', 'index.html')  # page served at "/" (cloud pilot: wallet.html)
WALLETCONNECT_PROJECT_ID = os.environ.get('WALLETCONNECT_PROJECT_ID', '')  # optional, enables WalletConnect in the reference UI
ENGINE_VERSION = 'v2.0.0'

# Chains the API accepts. 'dataapi' = indexed by the Avalanche Data API; 'routescan' = network segment for Routescan.
CHAINS = {
    43113: {'name': 'Avalanche Fuji C-Chain', 'short': 'Fuji', 'testnet': True, 'symbol': 'AVAX', 'dataapi': True,
            'routescan': 'testnet', 'rpc': 'https://api.avax-test.network/ext/bc/C/rpc',
            'explorer': 'https://testnet.snowtrace.io', 'faucet': 'https://build.avax.network/console/primary-network/faucet'},
    43114: {'name': 'Avalanche C-Chain', 'short': 'Avalanche', 'testnet': False, 'symbol': 'AVAX', 'dataapi': True,
            'routescan': 'mainnet', 'rpc': 'https://api.avax.network/ext/bc/C/rpc', 'explorer': 'https://snowtrace.io'},
    1: {'name': 'Ethereum Mainnet', 'short': 'Ethereum', 'testnet': False, 'symbol': 'ETH', 'dataapi': False,
        'routescan': 'mainnet', 'rpc': 'https://ethereum-rpc.publicnode.com', 'explorer': 'https://etherscan.io'},
}

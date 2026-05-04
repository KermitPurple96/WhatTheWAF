"""API key management — loads keys from config file or environment variables.

Keys are loaded in this priority order:
1. Environment variables (highest priority)
2. Config file: ~/.config/whatthewaf/api_keys.conf
3. Project-local: .whatthewaf_keys (gitignored)

Config file format (INI-style):
    [keys]
    shodan_api_key = YOUR_KEY
    censys_api_id = YOUR_ID
    censys_api_secret = YOUR_SECRET
    ...
"""

import os
import configparser

# Config file search paths (first found wins, env vars always override)
_CONFIG_PATHS = [
    os.path.expanduser("~/.config/whatthewaf/api_keys.conf"),
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), ".whatthewaf_keys"),
]

# Map: config key -> environment variable name
_KEY_MAP = {
    "shodan_api_key":       "SHODAN_API_KEY",
    "censys_api_id":        "CENSYS_API_ID",
    "censys_api_secret":    "CENSYS_API_SECRET",
    "fofa_email":           "FOFA_EMAIL",
    "fofa_key":             "FOFA_KEY",
    "zoomeye_key":          "ZOOMEYE_KEY",
    "securitytrails_key":   "SECURITYTRAILS_KEY",
    "virustotal_api_key":   "VIRUSTOTAL_KEY",
    "chinaz_api_key":       "CHINAZ_KEY",
    "passivetotal_username": "PASSIVETOTAL_USER",
    "passivetotal_key":     "PASSIVETOTAL_KEY",
    "whoxy_api_key":        "WHOXY_API_KEY",
}

_cache = None


def _load_keys():
    """Load API keys from config file(s), then overlay env vars."""
    keys = {}

    # Load from config file
    for path in _CONFIG_PATHS:
        if os.path.isfile(path):
            cp = configparser.ConfigParser()
            cp.read(path)
            if cp.has_section("keys"):
                for key in _KEY_MAP:
                    val = cp.get("keys", key, fallback="").strip()
                    if val:
                        keys[key] = val
            break  # use first file found

    # Env vars override config file
    for key, env_var in _KEY_MAP.items():
        val = os.environ.get(env_var, "").strip()
        if val:
            keys[key] = val

    return keys


def get(key_name):
    """Get a single API key by config name (e.g. 'shodan_api_key').

    Returns the key string, or empty string if not configured.
    """
    global _cache
    if _cache is None:
        _cache = _load_keys()
    return _cache.get(key_name, "")


def get_all():
    """Return dict of all configured API keys (non-empty only)."""
    global _cache
    if _cache is None:
        _cache = _load_keys()
    return dict(_cache)


def status():
    """Return dict of key_name -> bool (configured or not) for display."""
    global _cache
    if _cache is None:
        _cache = _load_keys()
    return {name: bool(_cache.get(name)) for name in _KEY_MAP}


def config_path():
    """Return the path where user should create their config file."""
    return _CONFIG_PATHS[0]


def reload():
    """Force reload keys (useful after editing config)."""
    global _cache
    _cache = None


def init_config():
    """Create a template config file if none exists. Returns the path created, or None."""
    path = _CONFIG_PATHS[0]
    if os.path.isfile(path):
        return None

    os.makedirs(os.path.dirname(path), exist_ok=True)

    template = """[keys]
# WhatTheWAF API Keys
# Uncomment and fill in the keys you have.
# Environment variables (e.g. SHODAN_API_KEY) always take priority.

# shodan_api_key =
# censys_api_id =
# censys_api_secret =
# fofa_email =
# fofa_key =
# zoomeye_key =
# securitytrails_key =
# virustotal_api_key =
# chinaz_api_key =
# passivetotal_username =
# passivetotal_key =
# whoxy_api_key =
"""
    with open(path, "w") as f:
        f.write(template)
    os.chmod(path, 0o600)
    return path

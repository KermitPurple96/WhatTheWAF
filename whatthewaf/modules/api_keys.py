"""API key management — loads keys from config file or environment variables.

Supports multiple keys per service for automatic rotation when one gets banned:
    [keys]
    shodan_api_key = key1, key2, key3

Keys are loaded in this priority order:
1. Environment variables (highest priority)
2. Config file: ~/.config/whatthewaf/api_keys.conf
3. Project-local: .whatthewaf_keys (gitignored)
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
    "dnstrails_api_key":    "DNSTRAILS_API_KEY",
}

_cache = None          # {key_name: [key1, key2, ...]}
_failed = {}           # {key_name: {failed_key, ...}}
_current_index = {}    # {key_name: int}


def _load_keys():
    """Load API keys from config file(s), then overlay env vars.

    Each key can have multiple values separated by commas.
    Returns dict of {key_name: [list of keys]}.
    """
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
                        # Split comma-separated keys, strip whitespace
                        keys[key] = [k.strip() for k in val.split(",") if k.strip()]
            break  # use first file found

    # Env vars override config file (also support comma-separated)
    for key, env_var in _KEY_MAP.items():
        val = os.environ.get(env_var, "").strip()
        if val:
            keys[key] = [k.strip() for k in val.split(",") if k.strip()]

    return keys


def _ensure_loaded():
    global _cache
    if _cache is None:
        _cache = _load_keys()


def get(key_name):
    """Get the current active API key for a service.

    Returns the first non-failed key, or empty string if none available.
    Supports automatic rotation: if a key is marked as failed via mark_failed(),
    this returns the next available key.
    """
    _ensure_loaded()
    key_list = _cache.get(key_name, [])
    if not key_list:
        return ""

    failed_set = _failed.get(key_name, set())

    # Return first non-failed key
    for k in key_list:
        if k not in failed_set:
            return k

    # All keys failed — reset and try first again
    _failed.pop(key_name, None)
    return key_list[0]


def request_with_rotation(key_name, make_request):
    """Execute an API request with automatic key rotation on failure.

    Args:
        key_name: config key name (e.g. 'shodan_api_key')
        make_request: callable(key_value) that makes the API call.
            Must return the response object. Raises on network errors.

    Returns the first successful response, or None if all keys fail.
    Marks keys as failed on 401, 403, 429 status codes.
    """
    _ensure_loaded()
    key_list = _cache.get(key_name, [])
    if not key_list:
        return None

    failed_set = _failed.get(key_name, set())

    for key_value in key_list:
        if key_value in failed_set:
            continue
        try:
            resp = make_request(key_value)
            if resp.status_code in (401, 403, 429):
                mark_failed(key_name, key_value)
                continue
            return resp
        except Exception:
            continue

    return None


def get_all_keys(key_name):
    """Get all configured keys for a service (list)."""
    _ensure_loaded()
    return list(_cache.get(key_name, []))


def mark_failed(key_name, key_value=None):
    """Mark a key as failed/banned so get() skips it and returns the next one.

    If key_value is None, marks the current active key.
    Returns the next available key, or empty string if none left.
    """
    _ensure_loaded()
    if key_value is None:
        key_value = get(key_name)

    if key_value:
        if key_name not in _failed:
            _failed[key_name] = set()
        _failed[key_name].add(key_value)

    return get(key_name)


def reset_failed(key_name=None):
    """Reset failed keys. If key_name is None, resets all."""
    if key_name:
        _failed.pop(key_name, None)
    else:
        _failed.clear()


def get_all():
    """Return dict of all configured API keys (first active key per service)."""
    _ensure_loaded()
    return {name: get(name) for name in _KEY_MAP if get(name)}


def status():
    """Return dict for --api-status display.

    Each entry: key_name -> {"configured": bool, "count": int, "failed": int}
    """
    _ensure_loaded()
    result = {}
    for name in _KEY_MAP:
        key_list = _cache.get(name, [])
        failed_set = _failed.get(name, set())
        result[name] = {
            "configured": len(key_list) > 0,
            "count": len(key_list),
            "failed": len(failed_set & set(key_list)),
        }
    return result


def config_path():
    """Return the path where user should create their config file."""
    return _CONFIG_PATHS[0]


def reload():
    """Force reload keys (useful after editing config)."""
    global _cache
    _cache = None
    _failed.clear()
    _current_index.clear()


def init_config():
    """Create a template config file if none exists. Returns the path created, or None."""
    path = _CONFIG_PATHS[0]
    if os.path.isfile(path):
        return None

    os.makedirs(os.path.dirname(path), exist_ok=True)

    template = """[keys]
# WhatTheWAF API Keys
# Remove the # at the start of a line to activate it.
# Environment variables (e.g. SHODAN_API_KEY) always override this file.
#
# Multiple keys per service (comma-separated) — auto-rotates if one gets banned:
#   shodan_api_key = key1, key2, key3

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
# dnstrails_api_key =
"""
    with open(path, "w") as f:
        f.write(template)
    os.chmod(path, 0o600)
    return path

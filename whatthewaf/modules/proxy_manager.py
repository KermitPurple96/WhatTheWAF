"""Proxy management — test proxy effectiveness against WAF detection."""

import hashlib
import shutil
import subprocess
import httpx

PROTON_SOCKS = "socks5://127.0.0.1:1080"

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


def test_proton_connectivity(timeout=10):
    """Test if ProtonVPN SOCKS proxy is available.

    Returns dict with: available, exit_ip, country
    """
    result = {"available": False, "exit_ip": "", "country": ""}

    try:
        with httpx.Client(
            timeout=timeout, proxy=PROTON_SOCKS, verify=False,
            headers={"User-Agent": DEFAULT_UA},
        ) as client:
            resp = client.get("https://api.ipify.org?format=json")
            if resp.status_code == 200:
                data = resp.json()
                result["available"] = True
                result["exit_ip"] = data.get("ip", "")

                # Try to get country
                try:
                    geo_resp = client.get(f"http://ip-api.com/json/{result['exit_ip']}?fields=country,countryCode,city,isp,org")
                    if geo_resp.status_code == 200:
                        geo = geo_resp.json()
                        result["country"] = geo.get("country", "")
                        result["city"] = geo.get("city", "")
                        result["isp"] = geo.get("isp", "")
                        result["org"] = geo.get("org", "")
                except Exception:
                    pass
    except Exception as e:
        result["error"] = str(e)

    return result


def proton_status():
    """Full ProtonVPN status check: CLI installed, logged in, connected, IP rotation.

    Returns dict with: cli_installed, cli_version, logged_in, connected,
                       current_server, exit_ip, country, can_rotate, error
    """
    result = {
        "cli_installed": False,
        "cli_version": "",
        "logged_in": False,
        "connected": False,
        "current_server": "",
        "exit_ip": "",
        "country": "",
        "city": "",
        "isp": "",
        "can_rotate": False,
        "socks_available": False,
        "direct_ip": "",
    }

    # 1. Get our direct IP (without proxy)
    try:
        with httpx.Client(timeout=5, verify=False, headers={"User-Agent": DEFAULT_UA}) as client:
            resp = client.get("https://api.ipify.org?format=json")
            if resp.status_code == 200:
                result["direct_ip"] = resp.json().get("ip", "")
    except Exception:
        pass

    # 2. Check if protonvpn-cli is installed
    for cli_name in ["protonvpn-cli", "protonvpn", "pvpn"]:
        cli_path = shutil.which(cli_name)
        if cli_path:
            result["cli_installed"] = True
            result["cli_name"] = cli_name
            break

    if not result["cli_installed"]:
        # Try the newer proton-cli
        cli_path = shutil.which("proton-cli")
        if cli_path:
            result["cli_installed"] = True
            result["cli_name"] = "proton-cli"

    if result["cli_installed"]:
        # Get version
        try:
            proc = subprocess.run(
                [result["cli_name"], "--version"],
                capture_output=True, text=True, timeout=5,
            )
            result["cli_version"] = proc.stdout.strip() or proc.stderr.strip()
        except Exception:
            pass

        # Get status (connected/disconnected)
        try:
            proc = subprocess.run(
                [result["cli_name"], "status"],
                capture_output=True, text=True, timeout=10,
            )
            output = proc.stdout + proc.stderr
            output_lower = output.lower()

            if "connected" in output_lower and "disconnected" not in output_lower:
                result["connected"] = True
                result["logged_in"] = True
                # Try to extract server name
                for line in output.split("\n"):
                    if "server" in line.lower():
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            result["current_server"] = parts[1].strip()
                    if "ip" in line.lower():
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            ip_candidate = parts[1].strip()
                            if _is_ip(ip_candidate):
                                result["exit_ip"] = ip_candidate
            elif "disconnected" in output_lower:
                result["logged_in"] = True  # CLI works but not connected
            elif "not logged in" in output_lower or "login" in output_lower:
                result["logged_in"] = False

        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

    # 3. Test SOCKS proxy availability
    socks_test = test_proton_connectivity(timeout=5)
    if socks_test.get("available"):
        result["socks_available"] = True
        result["exit_ip"] = result["exit_ip"] or socks_test["exit_ip"]
        result["country"] = socks_test.get("country", "")
        result["city"] = socks_test.get("city", "")
        result["isp"] = socks_test.get("isp", "")

    # 4. Determine if we can rotate IP
    if result["cli_installed"] and result["connected"]:
        result["can_rotate"] = True
    elif result["socks_available"]:
        result["can_rotate"] = True

    return result


def rotate_proton_ip(timeout=30):
    """Disconnect and reconnect ProtonVPN to get a new IP.

    Returns dict with: success, old_ip, new_ip, new_country
    """
    result = {"success": False, "old_ip": "", "new_ip": "", "new_country": ""}

    # Get current IP through proxy
    old_check = test_proton_connectivity(timeout=5)
    result["old_ip"] = old_check.get("exit_ip", "")

    # Find CLI
    cli_name = None
    for name in ["protonvpn-cli", "protonvpn", "pvpn", "proton-cli"]:
        if shutil.which(name):
            cli_name = name
            break

    if not cli_name:
        result["error"] = "ProtonVPN CLI not found"
        return result

    # Disconnect
    try:
        subprocess.run([cli_name, "disconnect"], capture_output=True, timeout=15)
    except Exception:
        pass

    # Reconnect to random server
    try:
        proc = subprocess.run(
            [cli_name, "connect", "--fastest"],
            capture_output=True, text=True, timeout=timeout,
        )
        if proc.returncode != 0:
            # Try alternative connect syntax
            proc = subprocess.run(
                [cli_name, "c", "-f"],
                capture_output=True, text=True, timeout=timeout,
            )
    except subprocess.TimeoutExpired:
        result["error"] = "Connection timeout"
        return result
    except Exception as e:
        result["error"] = str(e)
        return result

    # Wait a moment and check new IP
    import time
    time.sleep(2)

    new_check = test_proton_connectivity(timeout=10)
    if new_check.get("available"):
        result["success"] = True
        result["new_ip"] = new_check.get("exit_ip", "")
        result["new_country"] = new_check.get("country", "")

        if result["new_ip"] == result["old_ip"]:
            result["warning"] = "IP did not change — try again or use a different server"
    else:
        result["error"] = "Could not verify new connection"
        result["detail"] = new_check.get("error", "")

    return result


def _is_ip(s):
    """Quick check if string looks like an IP."""
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def get_proxy_chain(proxy_list=None, use_proton=False):
    """Build a list of proxy URLs to use.

    Args:
        proxy_list: comma-separated string or list of proxy URLs
        use_proton: add ProtonVPN SOCKS proxy

    Returns list of proxy URLs
    """
    proxies = []

    if proxy_list:
        if isinstance(proxy_list, str):
            proxies = [p.strip() for p in proxy_list.split(",") if p.strip()]
        else:
            proxies = list(proxy_list)

    if use_proton:
        proxies.append(PROTON_SOCKS)

    return proxies


def test_proxy_effectiveness(domain, proxies, timeout=15):
    """Test if different proxies affect WAF behavior.

    Returns dict with: baseline, proxy_results, findings
    """
    result = {"baseline": None, "proxy_results": [], "findings": []}

    url = f"https://{domain}/"

    # Baseline (no proxy)
    result["baseline"] = _fetch_through(url, None, timeout)

    if result["baseline"].get("error"):
        return result

    baseline_status = result["baseline"].get("status_code", 0)
    baseline_hash = result["baseline"].get("body_hash", "")

    # Test each proxy
    for proxy_url in proxies:
        proxy_result = _fetch_through(url, proxy_url, timeout)
        proxy_result["proxy"] = proxy_url

        if proxy_result.get("status_code") and proxy_result["status_code"] != baseline_status:
            proxy_result["status_changed"] = True
            if proxy_result["status_code"] in (200, 301, 302) and baseline_status in (403, 503):
                result["findings"].append(
                    f"Proxy {proxy_url} bypasses WAF block: {baseline_status} -> {proxy_result['status_code']}"
                )
            elif proxy_result["status_code"] in (403, 503) and baseline_status in (200, 301, 302):
                result["findings"].append(
                    f"Proxy {proxy_url} gets blocked by WAF: {proxy_result['status_code']}"
                )
        else:
            proxy_result["status_changed"] = False

        if proxy_result.get("body_hash") and proxy_result["body_hash"] != baseline_hash:
            proxy_result["content_changed"] = True
        else:
            proxy_result["content_changed"] = False

        result["proxy_results"].append(proxy_result)

    return result


def _fetch_through(url, proxy, timeout):
    """Fetch URL optionally through a proxy."""
    try:
        kw = {
            "timeout": timeout,
            "follow_redirects": True,
            "verify": False,
            "headers": {"User-Agent": DEFAULT_UA},
        }
        if proxy:
            kw["proxy"] = proxy

        with httpx.Client(**kw) as client:
            resp = client.get(url)

        body = resp.text[:10000]
        return {
            "status_code": resp.status_code,
            "body_hash": hashlib.sha256(body.encode()).hexdigest()[:16],
            "server": resp.headers.get("server", ""),
            "content_length": len(resp.content),
        }
    except Exception as e:
        return {"error": str(e)}

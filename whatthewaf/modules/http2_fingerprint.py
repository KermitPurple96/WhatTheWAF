"""HTTP/2 fingerprint evasion — use curl-impersonate to emulate browser HTTP/2 SETTINGS.

curl-impersonate is a patched version of curl that impersonates Chrome/Firefox at the
TLS and HTTP/2 level, including:
- TLS ClientHello (exact cipher suite order, extensions, curves)
- HTTP/2 SETTINGS frame (HEADER_TABLE_SIZE, MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE)
- HTTP/2 WINDOW_UPDATE, PRIORITY frames
- HTTP/2 pseudo-header order (:method, :authority, :scheme, :path)

This makes traffic indistinguishable from a real browser at the protocol level.
"""

import os
import platform
import shutil
import subprocess
import stat
import tarfile
import tempfile

# curl-impersonate release info
CURL_IMPERSONATE_VERSION = "0.6.1"
CURL_IMPERSONATE_REPO = "https://github.com/lwthiker/curl-impersonate"
INSTALL_DIR = os.path.expanduser("~/.local/bin")

# Available browser profiles
PROFILES = {
    "chrome120": "curl_chrome120",
    "chrome116": "curl_chrome116",
    "chrome110": "curl_chrome110",
    "chrome107": "curl_chrome107",
    "chrome104": "curl_chrome104",
    "chrome101": "curl_chrome101",
    "chrome100": "curl_chrome100",
    "chrome99": "curl_chrome99",
    "firefox121": "curl_ff121",
    "firefox117": "curl_ff117",
    "firefox109": "curl_ff109",
    "firefox102": "curl_ff102",
    "safari17": "curl_safari17_0",
    "safari15": "curl_safari15_5",
}

DEFAULT_PROFILE = "chrome120"


def is_installed():
    """Check if curl-impersonate is installed."""
    for profile_name, binary_name in PROFILES.items():
        path = shutil.which(binary_name) or os.path.join(INSTALL_DIR, binary_name)
        if os.path.isfile(path):
            return True
    return False


def get_binary_path(profile="chrome120"):
    """Get path to curl-impersonate binary for a given profile."""
    binary_name = PROFILES.get(profile, PROFILES[DEFAULT_PROFILE])

    # Check in PATH first
    path = shutil.which(binary_name)
    if path:
        return path

    # Check in ~/.local/bin
    path = os.path.join(INSTALL_DIR, binary_name)
    if os.path.isfile(path):
        return path

    # Check for the wrapper script
    wrapper = shutil.which("curl-impersonate-chrome")
    if wrapper:
        return wrapper

    return None


def install(verbose=False):
    """Download and install curl-impersonate.

    Returns dict with: success, path, error
    """
    result = {"success": False, "path": "", "error": ""}

    arch = platform.machine()
    if arch == "x86_64":
        arch_str = "x86_64"
    elif arch in ("aarch64", "arm64"):
        arch_str = "aarch64"
    else:
        result["error"] = f"Unsupported architecture: {arch}"
        return result

    # Download URL
    filename = f"curl-impersonate-v{CURL_IMPERSONATE_VERSION}.{arch_str}-linux-gnu.tar.gz"
    url = f"{CURL_IMPERSONATE_REPO}/releases/download/v{CURL_IMPERSONATE_VERSION}/{filename}"

    os.makedirs(INSTALL_DIR, exist_ok=True)

    try:
        if verbose:
            print(f"  Downloading curl-impersonate v{CURL_IMPERSONATE_VERSION}...")

        # Download
        tmp_file = os.path.join(tempfile.gettempdir(), filename)
        proc = subprocess.run(
            ["wget", "-q", "-O", tmp_file, url],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode != 0:
            # Try curl as fallback
            proc = subprocess.run(
                ["curl", "-sL", "-o", tmp_file, url],
                capture_output=True, text=True, timeout=120,
            )
        if proc.returncode != 0:
            result["error"] = f"Download failed: {proc.stderr}"
            return result

        # Extract
        if verbose:
            print(f"  Extracting to {INSTALL_DIR}...")

        with tarfile.open(tmp_file, "r:gz") as tar:
            tar.extractall(INSTALL_DIR)

        # Make binaries executable
        for _, binary_name in PROFILES.items():
            binary_path = os.path.join(INSTALL_DIR, binary_name)
            if os.path.isfile(binary_path):
                os.chmod(binary_path, os.stat(binary_path).st_mode | stat.S_IEXEC)

        # Also handle wrapper scripts
        for f in os.listdir(INSTALL_DIR):
            if f.startswith("curl_") or f.startswith("curl-impersonate"):
                fp = os.path.join(INSTALL_DIR, f)
                if os.path.isfile(fp):
                    os.chmod(fp, os.stat(fp).st_mode | stat.S_IEXEC)

        # Clean up
        os.remove(tmp_file)

        # Verify
        path = get_binary_path(DEFAULT_PROFILE)
        if path:
            result["success"] = True
            result["path"] = path
        else:
            # Check what was actually extracted
            extracted = [f for f in os.listdir(INSTALL_DIR) if "curl" in f.lower()]
            if extracted:
                result["success"] = True
                result["path"] = os.path.join(INSTALL_DIR, extracted[0])
            else:
                result["error"] = "Extraction succeeded but no curl binary found"

    except Exception as e:
        result["error"] = str(e)

    return result


def fetch_as_browser(url, profile="chrome120", method="GET", headers=None,
                     data=None, timeout=15, proxy=None):
    """Fetch a URL using curl-impersonate (full browser TLS + HTTP/2 emulation).

    Returns dict with: status_code, headers, body, error
    """
    result = {"status_code": 0, "headers": {}, "body": "", "error": ""}

    binary = get_binary_path(profile)
    if not binary:
        result["error"] = "curl-impersonate not installed. Run: whatthewaf --install-curl-impersonate"
        return result

    cmd = [binary, "-s", "-k", "-D", "-", "-o", "-", "-X", method]

    if timeout:
        cmd += ["--max-time", str(timeout)]
    if proxy:
        cmd += ["-x", proxy]
    if headers:
        for k, v in headers.items():
            cmd += ["-H", f"{k}: {v}"]
    if data:
        cmd += ["-d", data]

    cmd.append(url)

    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout + 5)

        output = proc.stdout.decode("utf-8", errors="replace")

        # Parse response (headers + body separated by \r\n\r\n)
        if "\r\n\r\n" in output:
            header_section, body = output.split("\r\n\r\n", 1)
        elif "\n\n" in output:
            header_section, body = output.split("\n\n", 1)
        else:
            header_section = ""
            body = output

        result["body"] = body

        # Parse status code and headers
        for line in header_section.split("\n"):
            line = line.strip()
            if line.startswith("HTTP/"):
                parts = line.split(" ", 2)
                if len(parts) >= 2:
                    try:
                        result["status_code"] = int(parts[1])
                    except ValueError:
                        pass
            elif ":" in line:
                key, val = line.split(":", 1)
                result["headers"][key.strip()] = val.strip()

    except subprocess.TimeoutExpired:
        result["error"] = "timeout"
    except FileNotFoundError:
        result["error"] = f"Binary not found: {binary}"
    except Exception as e:
        result["error"] = str(e)

    return result


def compare_fingerprints(domain, timeout=10):
    """Compare HTTP/2 fingerprint: normal curl vs curl-impersonate.

    Returns dict showing what's different.
    """
    result = {
        "curl_impersonate_available": is_installed(),
        "tests": [],
    }

    url = f"https://{domain}/"

    # Test with normal curl
    try:
        proc = subprocess.run(
            ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_version} %{http_code}", url],
            capture_output=True, text=True, timeout=timeout,
        )
        normal = proc.stdout.strip()
        result["tests"].append({"client": "curl (normal)", "result": normal})
    except Exception as e:
        result["tests"].append({"client": "curl (normal)", "error": str(e)})

    # Test with curl-impersonate
    if is_installed():
        binary = get_binary_path(DEFAULT_PROFILE)
        if binary:
            try:
                proc = subprocess.run(
                    [binary, "-sk", "-o", "/dev/null", "-w", "%{http_version} %{http_code}", url],
                    capture_output=True, text=True, timeout=timeout,
                )
                impersonate = proc.stdout.strip()
                result["tests"].append({"client": f"curl-impersonate ({DEFAULT_PROFILE})", "result": impersonate})
            except Exception as e:
                result["tests"].append({"client": "curl-impersonate", "error": str(e)})

    return result

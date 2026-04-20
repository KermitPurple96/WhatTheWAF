"""Headless browser with stealth — bypass JavaScript challenges and Canvas/WebGL fingerprinting.

Uses Playwright with stealth techniques to:
- Execute JavaScript challenges (Cloudflare Turnstile, DataDome, PerimeterX)
- Pass Canvas/WebGL fingerprinting checks
- Maintain realistic browser profile (plugins, screen size, timezone, fonts)
- Extract cookies after challenge completion for use in other tools

Requires: pip install playwright && playwright install chromium
"""

import json
import os
import shutil
import subprocess
import tempfile


def is_installed():
    """Check if Playwright and Chromium are available."""
    try:
        import playwright
        # Check if chromium is installed
        proc = subprocess.run(
            ["playwright", "install", "--dry-run", "chromium"],
            capture_output=True, text=True, timeout=10,
        )
        # If dry-run doesn't error, it's installed
        # Actually just try to find the browser
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


def install(verbose=False):
    """Install Playwright and Chromium browser.

    Returns dict with: success, error
    """
    result = {"success": False, "error": ""}

    try:
        # Install playwright package
        if verbose:
            print("  Installing playwright...")
        proc = subprocess.run(
            ["pip", "install", "playwright", "--break-system-packages", "-q"],
            capture_output=True, text=True, timeout=120,
        )
        if proc.returncode != 0:
            # Try without --break-system-packages
            proc = subprocess.run(
                ["pip", "install", "playwright", "-q"],
                capture_output=True, text=True, timeout=120,
            )

        # Install chromium browser
        if verbose:
            print("  Installing Chromium browser...")
        proc = subprocess.run(
            ["playwright", "install", "chromium"],
            capture_output=True, text=True, timeout=300,
        )
        if proc.returncode != 0:
            # Try python -m
            proc = subprocess.run(
                ["python3", "-m", "playwright", "install", "chromium"],
                capture_output=True, text=True, timeout=300,
            )

        if proc.returncode != 0:
            result["error"] = f"Browser install failed: {proc.stderr}"
            return result

        result["success"] = True

    except Exception as e:
        result["error"] = str(e)

    return result


# Stealth JavaScript to inject into every page
STEALTH_JS = """
// Override navigator properties to look like a real browser
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });
Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
Object.defineProperty(navigator, 'deviceMemory', { get: () => 8 });
Object.defineProperty(navigator, 'maxTouchPoints', { get: () => 0 });

// Override permissions
const originalQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (parameters) => (
    parameters.name === 'notifications' ?
        Promise.resolve({ state: Notification.permission }) :
        originalQuery(parameters)
);

// Chrome-specific properties
window.chrome = { runtime: {}, loadTimes: function() {}, csi: function() {} };

// Override WebGL renderer
const getParameter = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = function(parameter) {
    if (parameter === 37445) return 'Intel Inc.';
    if (parameter === 37446) return 'Intel Iris OpenGL Engine';
    return getParameter.apply(this, arguments);
};

// Override Canvas fingerprint — add subtle noise
const toBlob = HTMLCanvasElement.prototype.toBlob;
const toDataURL = HTMLCanvasElement.prototype.toDataURL;
const getImageData = CanvasRenderingContext2D.prototype.getImageData;

HTMLCanvasElement.prototype.toBlob = function() {
    const context = this.getContext('2d');
    if (context) {
        const imageData = context.getImageData(0, 0, this.width, this.height);
        for (let i = 0; i < imageData.data.length; i += 4) {
            imageData.data[i] ^= (Math.random() * 2) | 0;
        }
        context.putImageData(imageData, 0, 0);
    }
    return toBlob.apply(this, arguments);
};

HTMLCanvasElement.prototype.toDataURL = function() {
    const context = this.getContext('2d');
    if (context) {
        const imageData = context.getImageData(0, 0, this.width, this.height);
        for (let i = 0; i < imageData.data.length; i += 100) {
            imageData.data[i] ^= 1;
        }
        context.putImageData(imageData, 0, 0);
    }
    return toDataURL.apply(this, arguments);
};

// Prevent detection of automation
delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;
"""


def solve_challenge(url, timeout=30, proxy=None, wait_for=None, extract_cookies=True,
                    screenshot_path=None, verbose=False):
    """Load a URL in stealth headless browser, wait for JS challenges to resolve.

    Args:
        url: target URL
        timeout: max seconds to wait for page load + challenge
        proxy: proxy URL (http:// or socks5://)
        wait_for: CSS selector to wait for (indicates challenge passed)
        extract_cookies: return cookies after page load
        screenshot_path: save screenshot for evidence
        verbose: print progress

    Returns dict with:
        success, status_code, title, cookies, headers, body_snippet,
        challenge_detected, challenge_solved, screenshot_path, error
    """
    result = {
        "success": False,
        "status_code": 0,
        "title": "",
        "cookies": [],
        "headers": {},
        "body_snippet": "",
        "challenge_detected": False,
        "challenge_solved": False,
        "screenshot_path": screenshot_path,
        "error": "",
    }

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        result["error"] = "Playwright not installed. Run: pip install playwright && playwright install chromium"
        return result

    try:
        with sync_playwright() as p:
            # Browser launch options
            launch_opts = {
                "headless": True,
                "args": [
                    "--disable-blink-features=AutomationControlled",
                    "--disable-features=IsolateOrigins,site-per-process",
                    "--disable-dev-shm-usage",
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-infobars",
                    "--window-size=1920,1080",
                    "--start-maximized",
                ],
            }

            if proxy:
                launch_opts["proxy"] = {"server": proxy}

            browser = p.chromium.launch(**launch_opts)

            # Create context with realistic profile
            context = browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                locale="en-US",
                timezone_id="America/New_York",
                geolocation={"latitude": 40.7128, "longitude": -74.0060},
                permissions=["geolocation"],
                color_scheme="light",
                extra_http_headers={
                    "Accept-Language": "en-US,en;q=0.9",
                },
            )

            # Inject stealth scripts before any page loads
            context.add_init_script(STEALTH_JS)

            page = context.new_page()

            if verbose:
                print(f"  Loading {url}...")

            # Navigate
            response = page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)

            if response:
                result["status_code"] = response.status
                result["headers"] = dict(response.headers)

            # Check for challenge indicators
            content = page.content()
            challenge_indicators = [
                "cf-challenge", "challenge-platform", "challenge-running",
                "ray-id", "checking your browser", "please wait",
                "ddos-protection", "security check", "just a moment",
                "datadome", "perimeterx", "px-captcha",
            ]

            content_lower = content.lower()
            for indicator in challenge_indicators:
                if indicator in content_lower:
                    result["challenge_detected"] = True
                    if verbose:
                        print(f"  Challenge detected: {indicator}")
                    break

            # Wait for challenge to resolve
            if result["challenge_detected"]:
                if verbose:
                    print(f"  Waiting for challenge resolution (max {timeout}s)...")

                if wait_for:
                    try:
                        page.wait_for_selector(wait_for, timeout=timeout * 1000)
                        result["challenge_solved"] = True
                    except Exception:
                        pass
                else:
                    # Wait for navigation/redirect after challenge
                    try:
                        page.wait_for_load_state("networkidle", timeout=timeout * 1000)
                        # Re-check content
                        new_content = page.content()
                        new_lower = new_content.lower()
                        # If challenge indicators are gone, it's solved
                        still_challenged = any(i in new_lower for i in challenge_indicators)
                        if not still_challenged:
                            result["challenge_solved"] = True
                            content = new_content
                    except Exception:
                        pass

            result["title"] = page.title()
            result["body_snippet"] = content[:5000]
            result["success"] = True

            # Extract cookies
            if extract_cookies:
                cookies = context.cookies()
                result["cookies"] = cookies
                if verbose and cookies:
                    print(f"  Extracted {len(cookies)} cookie(s)")

            # Screenshot
            if screenshot_path:
                page.screenshot(path=screenshot_path, full_page=False)
                if verbose:
                    print(f"  Screenshot saved: {screenshot_path}")

            browser.close()

    except Exception as e:
        result["error"] = str(e)

    return result


def export_cookies_for_curl(cookies, domain=None):
    """Convert Playwright cookies to curl -b format.

    Returns string like: "cookie1=val1; cookie2=val2"
    """
    parts = []
    for c in cookies:
        if domain and domain not in c.get("domain", ""):
            continue
        parts.append(f"{c['name']}={c['value']}")
    return "; ".join(parts)


def export_cookies_for_requests(cookies, domain=None):
    """Convert Playwright cookies to Python requests dict format."""
    jar = {}
    for c in cookies:
        if domain and domain not in c.get("domain", ""):
            continue
        jar[c["name"]] = c["value"]
    return jar

"""Domain alive checking using httpx for speed and reliability."""

import httpx
import concurrent.futures


def check_alive(targets, timeout=5, max_workers=30):
    """Check which targets are alive using httpx.

    Args:
        targets: list of domains/URLs
        timeout: request timeout in seconds
        max_workers: thread pool size

    Returns:
        list of dicts: target, alive, status_code, url, redirect, error
    """
    results = []

    def _check_one(target):
        target = target.strip()
        if not target:
            return None

        url = target if target.startswith("http") else f"https://{target}"
        result = {
            "target": target,
            "alive": False,
            "status_code": 0,
            "url": url,
            "final_url": "",
            "redirect": False,
            "title": "",
            "content_length": 0,
            "error": None,
        }

        try:
            with httpx.Client(
                timeout=timeout,
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            ) as client:
                resp = client.get(url)
                result["alive"] = True
                result["status_code"] = resp.status_code
                result["final_url"] = str(resp.url)
                result["redirect"] = str(resp.url) != url
                result["content_length"] = len(resp.content)

                # Extract title
                import re
                title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:5000], re.IGNORECASE | re.DOTALL)
                if title_match:
                    result["title"] = title_match.group(1).strip()[:100]

        except httpx.ConnectError:
            # Try HTTP fallback
            try:
                http_url = target if target.startswith("http://") else f"http://{target}"
                with httpx.Client(
                    timeout=timeout,
                    follow_redirects=True,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                ) as client:
                    resp = client.get(http_url)
                    result["alive"] = True
                    result["status_code"] = resp.status_code
                    result["url"] = http_url
                    result["final_url"] = str(resp.url)
                    result["redirect"] = str(resp.url) != http_url
                    result["content_length"] = len(resp.content)

                    import re
                    title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:5000], re.IGNORECASE | re.DOTALL)
                    if title_match:
                        result["title"] = title_match.group(1).strip()[:100]
            except Exception as e:
                result["error"] = str(e)

        except Exception as e:
            result["error"] = str(e)

        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_check_one, t): t for t in targets}
        for future in concurrent.futures.as_completed(futures):
            try:
                r = future.result(timeout=timeout + 5)
                if r:
                    results.append(r)
            except Exception:
                t = futures[future]
                results.append({
                    "target": t, "alive": False, "status_code": 0,
                    "url": "", "final_url": "", "redirect": False,
                    "title": "", "content_length": 0, "error": "timeout",
                })

    # Maintain input order
    order = {t.strip(): i for i, t in enumerate(targets)}
    results.sort(key=lambda r: order.get(r["target"], 999999))
    return results

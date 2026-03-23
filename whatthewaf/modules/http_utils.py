"""HTTP utilities — redirect chain tracking, response hashing, robots.txt parsing."""

import hashlib
import re
import httpx


def trace_redirects(url, timeout=10, max_redirects=10, headers=None, proxy=None):
    """Follow redirects and return the full chain.

    Returns list of dicts: url, status_code, location, server
    """
    chain = []
    current_url = url
    seen = set()

    client_kwargs = {
        "timeout": timeout,
        "follow_redirects": False,
        "verify": False,
        "headers": headers or {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
    }
    if proxy:
        client_kwargs["proxy"] = proxy

    try:
        with httpx.Client(**client_kwargs) as client:
            for _ in range(max_redirects):
                if current_url in seen:
                    chain.append({"url": current_url, "status_code": 0, "note": "redirect loop"})
                    break
                seen.add(current_url)

                try:
                    resp = client.get(current_url)
                except Exception as e:
                    chain.append({"url": current_url, "status_code": 0, "error": str(e)})
                    break

                entry = {
                    "url": current_url,
                    "status_code": resp.status_code,
                    "server": resp.headers.get("server", ""),
                }

                if resp.is_redirect:
                    location = resp.headers.get("location", "")
                    # Handle relative redirects
                    if location and not location.startswith("http"):
                        from urllib.parse import urljoin
                        location = urljoin(current_url, location)
                    entry["location"] = location
                    chain.append(entry)
                    current_url = location
                else:
                    entry["final"] = True
                    chain.append(entry)
                    break
    except Exception as e:
        chain.append({"url": current_url, "status_code": 0, "error": str(e)})

    return chain


def hash_response(body):
    """SHA256 hash of response body."""
    if not body:
        return ""
    return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()


def parse_robots_txt(url, timeout=5, proxy=None):
    """Fetch and parse robots.txt for interesting paths.

    Returns dict: raw, disallowed, sitemaps, interesting_paths
    """
    base = url.rstrip("/")
    if not base.startswith("http"):
        base = f"https://{base}"

    # Try to figure out the root URL
    from urllib.parse import urlparse
    parsed = urlparse(base)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

    result = {
        "url": robots_url,
        "exists": False,
        "disallowed": [],
        "sitemaps": [],
        "interesting": [],
    }

    client_kwargs = {
        "timeout": timeout,
        "follow_redirects": True,
        "verify": False,
        "headers": {"User-Agent": "Mozilla/5.0"},
    }
    if proxy:
        client_kwargs["proxy"] = proxy

    try:
        with httpx.Client(**client_kwargs) as client:
            resp = client.get(robots_url)

        if resp.status_code != 200:
            return result

        result["exists"] = True
        body = resp.text

        for line in body.split("\n"):
            line = line.strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    result["disallowed"].append(path)
            elif line.lower().startswith("sitemap:"):
                sitemap = line.split(":", 1)[1].strip()
                # Re-join if split on the http: part
                if sitemap.startswith("//") or sitemap.startswith("http"):
                    pass
                elif ":" in line:
                    sitemap = line.split(" ", 1)[1].strip() if " " in line else sitemap
                result["sitemaps"].append(sitemap)

        # Flag interesting paths
        interesting_patterns = [
            r"/admin", r"/wp-admin", r"/login", r"/api", r"/graphql",
            r"/debug", r"/console", r"/dashboard", r"/phpmyadmin",
            r"/\.env", r"/\.git", r"/backup", r"/config", r"/staging",
            r"/test", r"/dev", r"/private", r"/internal", r"/secret",
            r"/cgi-bin", r"/xmlrpc", r"/server-status", r"/server-info",
        ]
        for path in result["disallowed"]:
            for pattern in interesting_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    if path not in result["interesting"]:
                        result["interesting"].append(path)
                    break

    except Exception:
        pass

    return result


def probe_ports(host, ports=None, timeout=3):
    """HTTP/HTTPS web service probe on common web application ports.

    Unlike nmap TCP connect, this actually makes HTTP(S) requests to confirm
    a real web service is running and grabs the response title + status code.

    Returns list of dicts: port, status_code, title, server, scheme, service
    """
    import concurrent.futures

    if ports is None:
        ports = list(WEB_PORTS.keys())

    results = []

    def _probe_one(port):
        info = WEB_PORTS.get(port, ("unknown", "https" if port != 80 else "http"))
        service_hint, default_scheme = info

        # Try HTTPS first (unless port 80), then HTTP fallback
        schemes = ["https", "http"] if default_scheme == "https" else ["http", "https"]

        for scheme in schemes:
            url = f"{scheme}://{host}:{port}/"
            try:
                with httpx.Client(
                    timeout=timeout,
                    follow_redirects=False,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                ) as client:
                    resp = client.get(url)

                title = ""
                m = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:5000], re.I | re.DOTALL)
                if m:
                    title = m.group(1).strip()[:80]

                server = resp.headers.get("server", "")

                # Try to identify the service from response
                detected = _identify_service(resp, port, service_hint)

                return {
                    "port": port,
                    "status_code": resp.status_code,
                    "title": title,
                    "server": server,
                    "scheme": scheme,
                    "service": detected,
                    "url": url,
                }
            except (httpx.ConnectError, httpx.ConnectTimeout):
                continue
            except Exception:
                continue

        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(_probe_one, p): p for p in ports}
        done, _ = concurrent.futures.wait(futures, timeout=timeout + 5)
        for future in done:
            try:
                r = future.result(timeout=0.1)
                if r:
                    results.append(r)
            except Exception:
                pass

    results.sort(key=lambda r: r["port"])
    return results


# Port -> (service_hint, default_scheme)
WEB_PORTS = {
    80:    ("HTTP", "http"),
    443:   ("HTTPS", "https"),
    # Common alt HTTP/S
    8080:  ("HTTP-Proxy/Alt", "http"),
    8443:  ("HTTPS-Alt", "https"),
    8888:  ("HTTP-Alt", "http"),
    8000:  ("HTTP-Dev", "http"),
    8081:  ("HTTP-Alt", "http"),
    8082:  ("HTTP-Alt", "http"),
    8181:  ("HTTP-Alt", "http"),
    8444:  ("HTTPS-Alt", "https"),
    3000:  ("Grafana/Node/Dev", "http"),
    3001:  ("Dev", "http"),
    # CI/CD & DevOps
    8089:  ("Splunk", "https"),
    9000:  ("SonarQube/Portainer", "http"),
    9090:  ("Prometheus/Cockpit", "http"),
    9091:  ("Prometheus Pushgateway", "http"),
    9093:  ("Alertmanager", "http"),
    9100:  ("Node Exporter", "http"),
    9200:  ("Elasticsearch", "http"),
    9300:  ("Elasticsearch Transport", "http"),
    5601:  ("Kibana", "http"),
    5000:  ("Docker Registry/Flask", "http"),
    5001:  ("Docker Registry", "https"),
    # Databases with web UI
    8086:  ("InfluxDB", "http"),
    8529:  ("ArangoDB", "http"),
    7474:  ("Neo4j Browser", "http"),
    5984:  ("CouchDB", "http"),
    15672: ("RabbitMQ Management", "http"),
    8161:  ("ActiveMQ", "http"),
    # Admin panels
    2082:  ("cPanel", "http"),
    2083:  ("cPanel SSL", "https"),
    2086:  ("WHM", "http"),
    2087:  ("WHM SSL", "https"),
    2095:  ("cPanel Webmail", "http"),
    2096:  ("cPanel Webmail SSL", "https"),
    10000: ("Webmin", "https"),
    # App servers
    4443:  ("HTTPS-Alt", "https"),
    4200:  ("Angular Dev", "http"),
    3443:  ("HTTPS-Alt", "https"),
    9443:  ("HTTPS-Alt/WebSphere", "https"),
    7443:  ("HTTPS-Alt", "https"),
    # Git / Code
    3100:  ("Gitea/Loki", "http"),
    8929:  ("GitLab", "http"),
    # Monitoring
    19999: ("Netdata", "http"),
    8085:  ("Bamboo/Alt", "http"),
    8084:  ("HTTP-Alt", "http"),
    # Misc web apps
    8834:  ("Nessus", "https"),
    9392:  ("OpenVAS/GVM", "https"),
    631:   ("CUPS", "http"),
    8880:  ("HTTP-Alt/Plesk", "http"),
    4848:  ("GlassFish", "https"),
    7001:  ("WebLogic", "http"),
    9060:  ("WebSphere Admin", "https"),
    8500:  ("Consul", "http"),
    8200:  ("Vault", "http"),
    8300:  ("Consul Server", "http"),
}


def _identify_service(resp, port, hint):
    """Try to identify the actual service from response content."""
    server = resp.headers.get("server", "").lower()
    body = resp.text[:5000].lower() if resp.text else ""
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.DOTALL)
    if m:
        title = m.group(1).strip().lower()

    # Service fingerprints: (check, name)
    checks = [
        (lambda: "sonarqube" in body or "sonarqube" in title, "SonarQube"),
        (lambda: "grafana" in body or "grafana" in title, "Grafana"),
        (lambda: "kibana" in body or "kibana" in title, "Kibana"),
        (lambda: "prometheus" in body or "prometheus" in title, "Prometheus"),
        (lambda: "jenkins" in body or "jenkins" in title or "x-jenkins" in [k.lower() for k in resp.headers], "Jenkins"),
        (lambda: "gitlab" in body or "gitlab" in title, "GitLab"),
        (lambda: "gitea" in body or "gitea" in title, "Gitea"),
        (lambda: "gogs" in body or "gogs" in title, "Gogs"),
        (lambda: "portainer" in body or "portainer" in title, "Portainer"),
        (lambda: "nexus" in body or "nexus repository" in title, "Nexus Repository"),
        (lambda: "artifactory" in body or "artifactory" in title, "JFrog Artifactory"),
        (lambda: "elasticsearch" in body or "lucene" in body, "Elasticsearch"),
        (lambda: "rabbitmq" in body or "rabbitmq" in title, "RabbitMQ"),
        (lambda: "couchdb" in body or server.startswith("couchdb"), "CouchDB"),
        (lambda: "consul" in body or "consul" in title, "Consul"),
        (lambda: "vault" in body or "vault" in title, "Vault"),
        (lambda: "webmin" in body or "webmin" in title, "Webmin"),
        (lambda: "cpanel" in body or "cpanel" in title, "cPanel"),
        (lambda: "whm" in title, "WHM"),
        (lambda: "plesk" in body or "plesk" in title, "Plesk"),
        (lambda: "netdata" in body or "netdata" in title, "Netdata"),
        (lambda: "nessus" in body or "nessus" in title or "tenable" in body, "Nessus"),
        (lambda: "openvas" in body or "greenbone" in body, "OpenVAS/GVM"),
        (lambda: "splunk" in body or "splunk" in title, "Splunk"),
        (lambda: "glassfish" in body or "glassfish" in server, "GlassFish"),
        (lambda: "weblogic" in body or "weblogic" in server, "WebLogic"),
        (lambda: "websphere" in body or "websphere" in server, "WebSphere"),
        (lambda: "traefik" in body or "traefik" in title, "Traefik Dashboard"),
        (lambda: "minio" in body or "minio" in title, "MinIO"),
        (lambda: "phpmyadmin" in body or "phpmyadmin" in title, "phpMyAdmin"),
        (lambda: "adminer" in body or "adminer" in title, "Adminer"),
        (lambda: "pgadmin" in body or "pgadmin" in title, "pgAdmin"),
        (lambda: "mailhog" in body or "mailhog" in title, "MailHog"),
        (lambda: "roundcube" in body or "roundcube" in title, "Roundcube"),
        (lambda: "cockpit" in body and "project" in body, "Cockpit"),
        (lambda: "influxdb" in body or "influxdb" in server, "InfluxDB"),
        (lambda: "arangodb" in body or "arango" in server, "ArangoDB"),
        (lambda: "neo4j" in body or "neo4j" in title, "Neo4j"),
        (lambda: "docker" in body and "registry" in body, "Docker Registry"),
        (lambda: "tomcat" in body or "tomcat" in title or "tomcat" in server, "Apache Tomcat"),
        (lambda: "nginx" in server, f"Nginx ({hint})"),
        (lambda: "apache" in server, f"Apache ({hint})"),
    ]

    for check_fn, name in checks:
        try:
            if check_fn():
                return name
        except Exception:
            pass

    return hint

import os
from setuptools import setup, find_packages
from setuptools.command.develop import develop
from setuptools.command.install import install


def _post_install():
    """Create API key config template on install if it doesn't exist."""
    try:
        from whatthewaf.modules.api_keys import init_config
        path = init_config()
        if path:
            print(f"\n  [+] Created API key config: {path}")
            print(f"      Edit it to add your keys, or set environment variables.")
            print(f"      Run: wtw --api-status\n")
    except Exception:
        pass


class PostInstall(install):
    def run(self):
        install.run(self)
        _post_install()


class PostDevelop(develop):
    def run(self):
        develop.run(self)
        _post_install()


setup(
    name="whatthewaf",
    version="3.1.0",
    description="WAF/CDN Detection, Bypass, Origin Discovery & TLS Fingerprint Evasion",
    author="KermitPurple96",
    url="https://github.com/KermitPurple96/WhatTheWAF",
    packages=find_packages(),
    install_requires=[
        "httpx>=0.27.0",
        "dnspython>=2.4.0",
        "cryptography>=41.0.0",
        "requests>=2.28.0",
    ],
    extras_require={
        "full": [
            "mmh3",
            "tls-client",
            "scapy",
            "stem",
            "urwid",
            "h2>=4.0.0",
            "aioquic>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "whatthewaf=whatthewaf.cli:main",
            "wtw=whatthewaf.cli:main",
        ],
    },
    cmdclass={
        "install": PostInstall,
        "develop": PostDevelop,
    },
    python_requires=">=3.8",
)

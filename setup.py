from setuptools import setup, find_packages

setup(
    name="whatthewaf",
    version="1.0.0",
    description="Detect WAF, CDN, technologies, and origin IPs",
    author="KermitPurple96",
    url="https://github.com/KermitPurple96/WhatTheWAF",
    packages=find_packages(),
    install_requires=[
        "httpx>=0.27.0",
        "dnspython>=2.4.0",
        "cryptography>=41.0.0",
    ],
    entry_points={
        "console_scripts": [
            "whatthewaf=whatthewaf.cli:main",
        ],
    },
    python_requires=">=3.8",
)

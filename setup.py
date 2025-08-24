#!/usr/bin/env python3
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="network-security-scanner",
    version="1.0.0",
    author="Alen Pepa",
    author_email="your-email@example.com",
    description="Professional Network Security Scanner Suite",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-username/network-security-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
        "netifaces>=0.11.0",
        "python-nmap>=0.7.1",
        "cryptography>=41.0.7",
        "pyOpenSSL>=23.3.0",
        "matplotlib>=3.7.2",
        "reportlab>=4.0.4",
        "jinja2>=3.1.2",
        "colorama>=0.4.6",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.2",
            "black>=23.9.1",
            "flake8>=6.1.0",
            "pytest-cov>=4.1.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "network-scanner=main:main",
        ],
    },
    package_data={
        "data": ["*.json"],
    },
    include_package_data=True,
)
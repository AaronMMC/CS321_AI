"""
Setup script for Email Security Gateway.
Install with: pip install -e .
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="email-security-gateway",
    version="1.0.0",
    author="Email Security Gateway Team",
    description="AI-Powered Email Security for Philippine Government",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/email-security-gateway",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "email-security-api=src.api.main:main",
            "email-security-dashboard=src.dashboard.app:main",
            "email-security-gateway=src.gateway.smtp_handler:run_gateway",
        ],
    },
)
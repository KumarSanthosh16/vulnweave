"""Deliberately insecure examples for validating VulnWeave's Python Semgrep pack.

Never copy these patterns into application code.
"""

import subprocess

import requests


def inspect_user_command(command: str) -> None:
    subprocess.run(command, shell=True, check=False)


def fetch_external_url(url: str) -> str:
    return requests.get(url, allow_redirects=True, verify=False, timeout=3).text

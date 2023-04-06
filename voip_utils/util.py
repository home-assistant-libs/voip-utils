"""Utilities for VoIP"""
from ipaddress import IPv4Address


def is_ipv4_address(address: str) -> bool:
    """Check if a given string is an IPv4 address."""
    try:
        IPv4Address(address)
    except ValueError:
        return False

    return True

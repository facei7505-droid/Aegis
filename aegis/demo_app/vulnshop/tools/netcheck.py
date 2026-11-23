"""Tiny stand-in for a network diagnostic tool (prints instead of sending packets)."""
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
print(f"netcheck: {target} is reachable")

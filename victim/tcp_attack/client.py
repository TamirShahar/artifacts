#!/usr/bin/env python3
"""TCP client for attack testing: connects to target, sends HTTP GET, returns response.
Mimics a real browser request. Errors are not caught so failures will raise to the caller.
"""

import socket
import time

# Target server (adjust if needed)
HOST_IP = "192.0.2.123"
PORT = 80
TIMEOUT = 5
SUCCESS_MARKER = "hello from attacker"


def get_response():
    """Connect to server, send HTTP GET, return response body.
    Minimal, sterile implementation that mimics a real browser."""
    start = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    s.connect((HOST_IP, PORT))

    local_addr, local_port = s.getsockname()

    req = f"GET / HTTP/1.1\r\nHost: {HOST_IP}\r\nConnection: close\r\n\r\n"
    s.sendall(req.encode("utf-8"))

    resp = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk

    s.close()
    elapsed = time.time() - start
    print(f"Source port: {local_port} | Time: {elapsed:.3f}s")
    print()
    return resp.decode("utf-8", errors="ignore")


def run_attack_loop(iterations=100):
    """Run connection loop, count successes (response contains SUCCESS_MARKER).
    Print success rate at the end."""
    successes = 0
    start = time.time()

    for i in range(iterations):
        try:
            resp = get_response()
            if SUCCESS_MARKER in resp:
                successes += 1
                print(resp)
                print(f"[{i+1}/{iterations}] SUCCESS")
            else:
                print(f"[{i+1}/{iterations}] FAIL (no marker)")
        except Exception as e:
            print(f"[{i+1}/{iterations}] ERROR: {e}")
        time.sleep(0.1)  # small delay between attempts

    elapsed = time.time() - start
    rate = (successes / iterations) * 100
    print(f"\n=== RESULTS ===")
    print(f"Successes: {successes}/{iterations}")
    print(f"Success Rate: {rate:.1f}%")
    print(f"Total time: {elapsed:.3f}s")
    return successes, iterations, rate


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        iterations = int(sys.argv[1])
        run_attack_loop(iterations)
    else:
        resp = get_response()
        print(resp)

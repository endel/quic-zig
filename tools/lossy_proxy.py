#!/usr/bin/env python3
"""UDP relay that drops a fraction of datagrams in both directions.

    lossy_proxy.py <listen_port> <server_port> <loss_pct> [seed]

One client is assumed (the interop clients are single-connection), so the
return path is whatever address last sent us a packet.
"""
import random, socket, sys, threading

listen_port = int(sys.argv[1])
server_port = int(sys.argv[2])
loss = float(sys.argv[3]) / 100.0
rng = random.Random(int(sys.argv[4]) if len(sys.argv) > 4 else 0)

front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
front.bind(("127.0.0.1", listen_port))
back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
back.bind(("127.0.0.1", 0))

client_addr = None
lock = threading.Lock()
stats = {"c2s": 0, "s2c": 0, "drop": 0}

def c2s():
    global client_addr
    while True:
        data, addr = front.recvfrom(65535)
        with lock:
            client_addr = addr
            stats["c2s"] += 1
            if rng.random() < loss:
                stats["drop"] += 1
                continue
        back.sendto(data, ("127.0.0.1", server_port))

def s2c():
    while True:
        data, _ = back.recvfrom(65535)
        with lock:
            stats["s2c"] += 1
            if rng.random() < loss:
                stats["drop"] += 1
                continue
            dst = client_addr
        if dst:
            front.sendto(data, dst)

threading.Thread(target=c2s, daemon=True).start()
threading.Thread(target=s2c, daemon=True).start()
threading.Event().wait()

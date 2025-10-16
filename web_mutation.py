# web_mutation.py
import docker
import re
import time
import random
import string
import socket
import json
from collections import defaultdict
from datetime import datetime

client = docker.from_env()
CONTAINER_NAME = "aass_web_honeypot"
INTERNAL_PORT = 80
MUTATION_LOG = "web_mutations.log"

def now_ts():
    return datetime.utcnow().isoformat() + "Z"

def rand_token(n=6):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(n))

def is_port_free(port, host="0.0.0.0"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((host, port))
        s.close()
        return True
    except OSError:
        return False

def choose_free_port(start=8000, end=9000, max_attempts=200):
    for _ in range(max_attempts):
        p = random.randint(start, end)
        if is_port_free(p):
            return p
    raise RuntimeError("No free port found")

def log_mutation(event_obj):
    with open(MUTATION_LOG, "a") as f:
        f.write(json.dumps(event_obj) + "\n")

def inspect_container(container_name=CONTAINER_NAME):
    c = client.containers.get(container_name)
    attrs = c.attrs
    image = c.image.tags[0] if c.image.tags else c.image.id
    cmd = attrs['Config'].get('Cmd') or None
    entrypoint = attrs['Config'].get('Entrypoint') or None
    env_list = attrs['Config'].get('Env') or []
    env = {}
    for e in env_list:
        if "=" in e:
            k,v = e.split("=",1)
            env[k]=v
    mounts = attrs.get('Mounts') or []
    volumes = {}
    for m in mounts:
        src = m.get('Source'); dst = m.get('Destination'); mode = m.get('Mode') or 'rw'
        if src and dst:
            volumes[src] = {'bind': dst, 'mode': mode}
    ports_mapping = attrs.get('NetworkSettings', {}).get('Ports') or {}
    # get networks and network names
    networks = list(attrs.get('NetworkSettings', {}).get('Networks', {}).keys())
    return {
        'container_obj': c,
        'image': image,
        'cmd': cmd,
        'entrypoint': entrypoint,
        'env': env,
        'volumes': volumes,
        'ports_mapping': ports_mapping,
        'networks': networks
    }

def recreate_web_container(env_overrides=None, new_host_port=None):
    """
    Stop & remove existing web container, recreate it with modified env and optionally mapped to new_host_port.
    """
    info = inspect_container(CONTAINER_NAME)
    c = info['container_obj']
    image = info['image']
    cmd = info['cmd']
    entrypoint = info['entrypoint']
    env = dict(info['env'] or {})
    volumes = info['volumes'] or {}
    networks = info['networks'] or []

    # apply overrides
    if env_overrides:
        env.update(env_overrides)

    # determine host port
    internal_key = f"{INTERNAL_PORT}/tcp"
    current = info['ports_mapping'].get(internal_key)
    host_port = None
    if new_host_port:
        host_port = new_host_port
    elif current and isinstance(current, list) and len(current) > 0:
        host_port = int(current[0].get('HostPort'))

    # stop & remove
    print(f"[mutate] Stopping and removing container {CONTAINER_NAME}...")
    try:
        c.stop(timeout=3)
    except Exception as e:
        print("[mutate] stop error:", e)
    try:
        c.remove()
    except Exception as e:
        print("[mutate] remove error:", e)

    # run new cont
    run_kwargs = {
        'image': image,
        'environment': env,
        'volumes': volumes if volumes else None,
        'ports': {f"{INTERNAL_PORT}/tcp": host_port} if host_port else None,
        'detach': True,
        'name': CONTAINER_NAME,
        'restart_policy': {"Name":"unless-stopped"}
    }
    if cmd:
        run_kwargs['command'] = cmd
    if entrypoint:
        run_kwargs['entrypoint'] = entrypoint

    # filter out None
    run_kwargs = {k:v for k,v in run_kwargs.items() if v is not None}
    # If there was a docker network that existed before, connect after create
    container = client.containers.run(**run_kwargs)
    for net_name in networks:
        try:
            net = client.networks.get(net_name)
            net.connect(container)
        except Exception:
            pass

    print(f"[mutate] Recreated {CONTAINER_NAME} -> host_port={host_port}, env_overrides={env_overrides}")
    event = {
        "ts": now_ts(),
        "action": "recreate_web",
        "host_port": host_port,
        "env_overrides": env_overrides
    }
    log_mutation(event)
    return container

def mutate_banner(suffix=None):
    suffix = suffix or rand_token(5)
    new_banner = f"AASS Web [{suffix}]"
    recreate_web_container(env_overrides={"BANNER": new_banner})
    print(f"[mutate] Banner changed to: {new_banner}")

def mutate_params():
    new_search = "q_" + rand_token(6)
    new_greet = "g_" + rand_token(6)
    recreate_web_container(env_overrides={"SEARCH_PARAM": new_search, "GREET_PARAM": new_greet})
    print(f"[mutate] Param names changed: SEARCH_PARAM={new_search}, GREET_PARAM={new_greet}")

def mutate_port():
    new_port = choose_free_port()
    recreate_web_container(new_host_port=new_port)
    print(f"[mutate] Host port shuffled to: {new_port}")

def mutate_all():
    new_search = "q_" + rand_token(6)
    new_greet = "g_" + rand_token(6)
    new_banner = f"AASS Web [{rand_token(4)}]"
    new_port = choose_free_port()
    recreate_web_container(env_overrides={"SEARCH_PARAM": new_search, "GREET_PARAM": new_greet, "BANNER": new_banner},
                            new_host_port=new_port)
    print(f"[mutate] ALL -> search={new_search}, greet={new_greet}, banner={new_banner}, port={new_port}")

SQL_PATTERNS = [
    re.compile(r"\bUNION\b", re.I),
    re.compile(r"\bSELECT\b", re.I),
    re.compile(r"('|\"|\bOR\b).*(=|LIKE)", re.I),
    re.compile(r"--\s*$"),  # comment at end
    re.compile(r"(?i)information_schema|pg_catalog")
]

XSS_PATTERNS = [
    re.compile(r"<script", re.I),
    re.compile(r"javascript:", re.I),
    re.compile(r"on\w+\s*=" , re.I),
    re.compile(r"<img", re.I)
]

LOGIN_FAILS = defaultdict(list)  # ip -> [timestamps]

def check_sql_payload(s):
    for p in SQL_PATTERNS:
        if p.search(s):
            return True
    return False

def check_xss_payload(s):
    for p in XSS_PATTERNS:
        if p.search(s):
            return True
    return False

def handle_search_event(parsed):
    q = parsed.get('query','')
    src = parsed.get('src','unknown')
    ua = parsed.get('ua','')
    if ua and ("sqlmap" in ua.lower() or "sqlmap" in q.lower()):
        print("[detect] SQLMap UA or signature detected -> mutate_all")
        mutate_all()
        return
    # check payloads
    if check_sql_payload(q):
        print("[detect] SQL-like payload detected -> mutate_params + mutate_banner")
        mutate_params()
        mutate_banner()
        return

def handle_greet_event(parsed):
    name = parsed.get('name','')
    src = parsed.get('src','unknown')
    ua = parsed.get('ua','')
    if check_xss_payload(name) or ("burp" in ua.lower()):
        print("[detect] XSS-like or Burp detected -> mutate_params")
        mutate_params()
        return

def handle_login_event(parsed):
    src = parsed.get('src','unknown')
    ts = time.time()
    LOGIN_FAILS[src].append(ts)
    window = 120
    LOGIN_FAILS[src] = [t for t in LOGIN_FAILS[src] if t > ts - window]
    if len(LOGIN_FAILS[src]) >= 5:
        print(f"[detect] Brute force-ish activity from {src} ({len(LOGIN_FAILS[src])} failures) -> mutate_banner + mutate_port")
        mutate_banner()
        mutate_port()
        LOGIN_FAILS[src].clear()

'''
Expected log formats (from honeypot_web/app.py):
HONEYPOT_SEARCH src=1.2.3.4 param=query query=... ua=...
HONEYPOT_GREET src=1.2.3.4 param=name name=... ua=...
HONEYPOT_LOGIN src=1.2.3.4 user='x' pass='y' ts=... ua=...
'''

SEARCH_RE = re.compile(
    r".*HONEYPOT_SEARCH\s+src=(?P<src>\S+)"
    r"(?:\s+param=(?P<param>\S+))?"
    r"\s+query=(?P<query>.*?)\s+ua=(?P<ua>.*)$"
)

GREET_RE = re.compile(
    r".*HONEYPOT_GREET\s+src=(?P<src>\S+)"
    r"(?:\s+param=(?P<param>\S+))?"
    r"\s+name=(?P<name>.*?)\s+ua=(?P<ua>.*)$"
)

LOGIN_RE = re.compile(
    r".*HONEYPOT_LOGIN\s+src=(?P<src>\S+)\s+user=(?P<user>'.*?'|[^ ]+)\s+pass=(?P<pass>'.*?'|[^ ]+)"
    r"(?:\s+ts=(?P<ts>\S+))?\s+ua=(?P<ua>.*)$"
)

def parse_log_line(line):
    line = line.strip()
    for name, pattern in [("SEARCH", SEARCH_RE), ("GREET", GREET_RE), ("LOGIN", LOGIN_RE)]:
        m = pattern.search(line)
        if m:
            if name == "LOGIN":
                d = m.groupdict()
                d["user"] = d["user"].strip("'\"")
                d["pass"] = d["pass"].strip("'\"")
                return ("login", d)
            return (name.lower(), m.groupdict())
    return (None, None)

def tail_and_detect():
    print(f"[detector] Attaching to container logs: {CONTAINER_NAME}")
    while True:
        try:
            c = client.containers.get(CONTAINER_NAME)
            log_stream = c.logs(stream=True, follow=True, tail=0)
            for raw in log_stream:
                try:
                    line = raw.decode("utf-8", errors="ignore").strip()
                    if not line:
                        continue
                    kind, parsed = parse_log_line(line)
                    print(parsed)
                    if kind:
                        try:
                            if kind == "search":
                                handle_search_event(parsed)
                            elif kind == "greet":
                                handle_greet_event(parsed)
                            elif kind == "login":
                                handle_login_event(parsed)
                        except Exception as e:
                            print(f"[detector] Handler error: {e}")

                        event = {
                            "ts": now_ts(),
                            "type": kind,
                            "parsed": parsed,
                            "raw": line
                        }
                        with open("web_events.log", "a") as f:
                            f.write(json.dumps(event) + "\n")

                except Exception as e:
                    print(f"[detector] Decode error: {e}")
        except docker.errors.NotFound:
            print("[detector] Container not found. Retrying in 5s.")
            time.sleep(5)
        except docker.errors.APIError as e:
            print(f"[detector] Docker API error: {e}. Reconnecting in 5s.")
            time.sleep(5)
        except KeyboardInterrupt:
            print("[detector] Exiting cleanly.")
            break


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Web honeypot detector + mutation agent")
    parser.add_argument("--monitor", action="store_true", help="Monitor logs & react (default)")
    parser.add_argument("--mutate", choices=["banner","params","port","all"], help="Manual trigger")
    args = parser.parse_args()

    if args.mutate:
        if args.mutate == "banner":
            mutate_banner()
        elif args.mutate == "params":
            mutate_params()
        elif args.mutate == "port":
            mutate_port()
        elif args.mutate == "all":
            mutate_all()
    else:
        print("[main] Starting log monitor (reactive mode).")
        tail_and_detect()

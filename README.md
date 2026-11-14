# Network-Check

```
python3 - << 'EOF'
import subprocess, re, glob, os, datetime

def run(cmd):
    return subprocess.run(cmd, shell=True, text=True, capture_output=True).stdout.strip()

# 1. Get all saved Wi-Fi networks in Most-Recently-Used (MRU) order (No password)
pref_out = run("networksetup -listpreferredwirelessnetworks en0").splitlines()[1:]
ssids = [n.strip() for n in pref_out if n.strip()]

# 2. Extract exact Wi-Fi metadata timestamps from Keychain (No password required for metadata)
kc_out = run("security dump-keychain")
kc_times = {}
for block in kc_out.split("keychain: "):
    if '"svce"<blob>="AirPort"' not in block and "AirPort network" not in block:
        continue
    m_acct = re.search(r'"acct"<blob>="([^"]+)"', block)
    dates = []
    for tag in ("mdat", "cdat"):
        m_dt = re.search(rf'"{tag}"<timedate>=0x[0-9A-Fa-f]+\s+"([^"]+)"', block)
        if m_dt:
            t_str = m_dt.group(1).rstrip("Z\0")
            try:
                dt = datetime.datetime.strptime(t_str[:14], "%Y%m%d%H%M%S")
                dates.append(dt.replace(tzinfo=datetime.timezone.utc).astimezone())
            except Exception:
                pass
    if m_acct and dates:
        ssid = m_acct.group(1)
        best = max(dates)
        if ssid not in kc_times or best > kc_times[ssid]:
            kc_times[ssid] = best

# 3. Get recent DHCP connection timestamps per distinct IP (last 24h) + lease file mtimes
log_cmd = (
    "log show --predicate "
    "'(process == \"configd\" AND eventMessage CONTAINS \"DHCP en0:\")' "
    "--info --last 24h --style compact"
)
logs = run(log_cmd)
ip_latest_ts = {}
for line in logs.splitlines():
    m_time = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
    m_ip = re.search(r"(?:setting|switched to lease for IP|BOUND.*?) (\d+\.\d+\.\d+\.\d+)", line)
    if m_time and m_ip:
        dt = datetime.datetime.strptime(m_time.group(1), "%Y-%m-%d %H:%M:%S").astimezone()
        ip_latest_ts[m_ip.group(1)] = dt

for lf in glob.glob("/var/db/dhcpclient/leases/en0*"):
    try:
        mtime = datetime.datetime.fromtimestamp(os.path.getmtime(lf)).astimezone()
        ip_latest_ts[lf] = max(ip_latest_ts.get(lf, mtime), mtime)
    except Exception:
        pass

# Sort distinct recent connection timestamps newest-first to pair with top MRU networks
recent_conn_times = sorted(ip_latest_ts.values(), reverse=True)

rows = []
for idx, ssid in enumerate(ssids):
    candidates = []
    if ssid in kc_times:
        candidates.append(kc_times[ssid])
    if idx < len(recent_conn_times):
        candidates.append(recent_conn_times[idx])
    best_ts = max(candidates) if candidates else None
    rows.append((best_ts, ssid, idx))

# Use Unix epoch (1970) instead of datetime.min to avoid Year 0 underflow in +0530
epoch_zero = datetime.datetime.fromtimestamp(0).astimezone()
rows.sort(key=lambda x: (x[0] is not None, x[0] or epoch_zero, -x[2]), reverse=True)

h1, h2 = "Latest Timestamp (IST)", "Wi-Fi Network Name (SSID)"
print(f"{h1:<26} | {h2}")
print("-" * 65)
for dt, ssid, _ in rows:
    t_str = dt.strftime("%Y-%m-%d %H:%M:%S %z") if dt else "Pre-existing (MRU Ordered)"
    print(f"{t_str:<26} | {ssid}")
EOF
```
# VNC Default
```
log show --last 2h --style compact --info --predicate '(process == "screensharingd") OR (process == "ARDAgent") OR (eventMessage CONTAINS[c] "VNC")' 2>/dev/null
```

# VNC Check

```
cat << 'EOF' > ~/check_remote.py
import sys, json
from datetime import datetime

raw = sys.stdin.read()
start_idx = raw.find("[")
logs = json.loads(raw[start_idx:]) if start_idx != -1 else []

if not logs:
    print("No remote desktop activity found.")
    sys.exit(0)

def detect_service(entry):
    proc = entry.get("processImagePath", "")
    msg = entry.get("eventMessage", "")
    if "ARDAgent" in proc:
        return "Apple Remote Desktop (ARD)"
    if "screensharingd" in proc:
        return "macOS Screen Sharing"
    if "vnc" in msg.lower():
        return f"VNC ({proc.split('/')[-1]})"
    return proc.split("/")[-1] or "Unknown"

def parse_ts(ts_str):
    return datetime.strptime(ts_str[:19], "%Y-%m-%d %H:%M:%S")

sessions = []
for entry in logs:
    ts = parse_ts(entry["timestamp"])
    service = detect_service(entry)
    if sessions and sessions[-1]["service"] == service and (ts - sessions[-1]["end"]).total_seconds() < 300:
        sessions[-1]["end"] = ts
    else:
        sessions.append({"start": ts, "end": ts, "service": service})

print(f"{'Start Time':<21} {'End Time':<21} {'Duration':<10} {'Remote Service'}")
print("-" * 78)
for s in sessions:
    dur = str(s["end"] - s["start"])
    print(f"{str(s['start']):<21} {str(s['end']):<21} {dur:<10} {s['service']}")
EOF
```

```
log show --last 2h --style json --info --predicate '(process == "screensharingd") OR (process == "ARDAgent") OR ((eventMessage CONTAINS[c] "VNC") AND (process != "mobileassetd"))' 2>/dev/null | python3 ~/check_remote.py
```

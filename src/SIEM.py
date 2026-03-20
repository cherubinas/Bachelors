#!/usr/bin/env python3

import os
import json
import time

import pandas as pd

from scapy.all import rdpcap, IP, TCP, UDP, Raw


RULES_FILE = "siem_rules.json"

# Function to choose a file
def choose_file(ext=".pcap"):
    files = [f for f in os.listdir(".") if f.endswith(ext)]
    if not files:
        print(f"No {ext} files found.")
        return None
    for i, f in enumerate(files, 1):
        print(f"{i}) {f}")
    sel = input("Select file number: ").strip() or "1"
    try:
        return files[int(sel)-1]
    except:
        return files[0]
    
# Function to load rules
def load_rules(file=RULES_FILE):
    with open(file) as f:
        return json.load(f)
    
# Function to check if a packet matches rule criteria, this is for expansion of rules, incase a new rule is added it checks if it works with the pcap and can be used 
def packet_matches(pkt, payload, match):
    if not match:
        return True

    if match.get("protocol") and pkt.get("protocol") != match["protocol"]:
        return False

    dp = pkt.get("dst_port")
    if "dst_port" in match and dp != match["dst_port"]:
        return False

    if "dst_ports" in match and dp not in match["dst_ports"]:
        return False
    
    for key in match.get("payload_contains", []):
        if key.encode() not in payload:
            return False

    return True

# Function to evaluate stateful rules, i.e., rules that are triggered not by a single packet, but by patterns over multiple packets.
def evaluate_stateful(df, rule):
    agg = rule.get("aggregate", {})
    group_by = agg.get("group_by", ["src_ip"])
    if isinstance(group_by, str):
        group_by = [group_by]

    if df.empty:
        return set()

    mask = df.apply(
        lambda r: packet_matches(r, r.get("raw_payload", b""), rule.get("match", {})), axis=1
    )
    mdf = df.loc[mask]
    flagged = set()

    for _, g in mdf.groupby(group_by):
        g = g.sort_values("timestamp")
        times = g["timestamp"].tolist()
        idxs = g.index.tolist()
        l = 0
        for i in range(len(times)):
            while times[i] - times[l] > agg.get("time_window", 0):
                l += 1
            if i - l + 1 >= agg.get("threshold", 0):
                flagged.update(idxs[l:i+1])
                break

    return flagged

# Function to display an analysis view
def display_siem_dashboard(df, rules):
    if df.empty:
        print("\nNo suspicious events detected.\n")
        return

    print("\nAnalysis Results\n")
    seen_alerts = set()

    for _, r in df.iterrows():
        for flag in r["flags"]:
            key = (flag, r.get("src_ip"), r.get("dst_ip"))
            if key in seen_alerts:
                continue
            seen_alerts.add(key)

            rule_obj = next((x for x in rules if x.get("name") == flag), None)
            desc = rule_obj.get("description", "N/A") if rule_obj else "N/A"
            magnitude = rule_obj.get("magnitude", "N/A") if rule_obj else "N/A"

            t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["timestamp"]))
            payload_str = r.get("raw_payload", b"").decode(errors="ignore")

            print(f"Event:        {flag}")
            print(f"Description:  {desc}")
            print(f"Magnitude:    {magnitude}")
            print(f"Source IP:    {r['src_ip']}")
            print(f"Destination:  {r['dst_ip']}:{r['dst_port']}")
            print(f"Protocol:     {r['protocol']}")
            print(f"Timestamp:    {t}")
            print(
                f"Payload:      {payload_str[:120]}{'...' if len(payload_str) > 120 else ''}"
            )
            print("-" * 70)

    print("\nOffense raw payload")
    seen = set()
    for _, r in df.iterrows():
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r.get("timestamp")))
        raw = r.get("raw_payload", b"")
        text = raw.decode(errors="ignore") if isinstance(raw, (bytes, bytearray)) else str(raw)
        payload_one = (
            text.replace("\r\n", "\\r\\n").replace("\n", "\\n").replace("\r", "\\r")
        )
        line = f"{ts} {r.get('src_ip','')} {r.get('dst_ip','')} [{','.join(r.get('flags',[]))}] {payload_one}"
        if line not in seen:
            seen.add(line)
            print(line)
            
# Main analysis function           
def analyze(pcap_file):
    
    rules = load_rules()
    pkts = rdpcap(pcap_file)
    events = []

    for pkt in pkts:
        if IP not in pkt or (TCP not in pkt and UDP not in pkt):
            continue

        payload = bytes(pkt[Raw].load) if Raw in pkt else b""
        evt = {
            "timestamp": float(pkt.time),
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "src_port": pkt.sport if TCP in pkt or UDP in pkt else None,
            "dst_port": pkt.dport if TCP in pkt or UDP in pkt else None,
            "protocol": "TCP" if TCP in pkt else "UDP",
            "flags": [],
            "raw_payload": payload,
        }

        for rule in rules:
            if rule.get("type") == "packet" and packet_matches(evt, payload, rule.get("match", {})):
                evt["flags"].append(rule["name"])

        events.append(evt)

    df = pd.DataFrame(events).sort_values("timestamp")

    for rule in (r for r in rules if r.get("type") == "stateful"):
        idxs = evaluate_stateful(df, rule)
        if idxs:
            df.loc[list(idxs), "flags"] = df.loc[list(idxs), "flags"].apply(lambda x: x + [rule["name"]])

    flagged = df[df["flags"].apply(bool)]
    display_siem_dashboard(flagged, rules)
    input("\nPress Enter to return to menu...")
    
# Function to modify rules
def modify_rules():
    try:
        from rules_manager import RuleManager
        RuleManager(RULES_FILE).menu()
        
    except Exception as e:
        print(f"Could not load rule manager: {e}")
        input("Press Enter to return to menu...")
        
# Main menu
def main():
    while True:
        print("\nChoose to analyze the data, modify rules or exit\n1) Analyze Data\n2) Modify Rules\n0) Exit")
        c = input("Press 0, 1, or 2: ").strip()
        if c == "1":
            f = choose_file(".pcap")
            if f: analyze(f)
        elif c == "2":
            modify_rules()
        elif c == "0":
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()

import json
import sys
import re
from collections import defaultdict
import uuid
import time
from datetime import datetime

def format_time(ts):
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


ATTACK_FLOW_ORDER = [
    "Execution",
    "Persistence",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Command and Control"
]


def print_banner():
    print("=" * 40)
    print("   MITRE ATT&CK Log Mapper v1.0")
    print("   Detection Engineering Helper")
    print("=" * 40)

def print_help():
    print("""
Usage:
  python3 mapper.py
      → Interactive single log analysis

  python3 mapper.py --file <filename>
      → Scan multiple log lines from a file

  python3 mapper.py --help
      → Show this help menu
""")

def group_by_host(matches):
    grouped = defaultdict(list)
    for m in matches:
        host = m.get("host", "unknown")
        grouped[host].append(m)
    return grouped

def build_process_tree(log_lines):
    events = [normalize_log(line.strip(), i) for i, line in enumerate(log_lines)]
    tree = defaultdict(list)
    id_map = {e["id"]: e for e in events}

    TIME_WINDOW = 120  # seconds

    for e in events:
        for potential_parent in events:
            if e["parent"] == potential_parent["process"] and e["process"] != e["parent"]:
                time_diff = e["timestamp"] - potential_parent["timestamp"]
                if 0 <= time_diff <= TIME_WINDOW:
                    tree[potential_parent["id"]].append(e["id"])

    return tree, id_map



def analyze_process_chains(tree, process_info, attack_data):
    all_matches = []
    visited = set()

    def dfs(event_id, parent_process=None):
        if event_id in visited:
            return
        visited.add(event_id)

        log = process_info.get(event_id)
        if not log:
            return

        matches = map_to_attack(attack_data, log)

        for m in matches:
            m["process"] = log["process"]
            m["parent"] = parent_process if parent_process else "ROOT"
            m["timestamp"] = log["timestamp"]
            m["host"] = log["host"]
            all_matches.append(m)


        for child in tree.get(event_id, []):
            dfs(child, log["process"])

    # Start DFS from all root events
    roots = set(process_info.keys()) - {child for children in tree.values() for child in children}

    for root in roots:
        dfs(root)

    return all_matches

def normalize_log(raw_log, index=0):
    raw_log_lower = raw_log.lower()

    timestamp = None
    host = "unknown"
    user = "unknown"
    process = ""
    parent = ""
    cmdline = raw_log_lower

    # ---- TIME (supports Time: and Time=) ----
    time_match = re.search(r"time[:=]\s*([0-9t:\-]+)", raw_log_lower)
    if time_match:
        try:
            timestamp = datetime.strptime(time_match.group(1), "%Y-%m-%dT%H:%M:%S").timestamp()
        except:
            timestamp = time.time() + (index * 30)
    else:
        timestamp = time.time() + (index * 30)

    # ---- HOST ----
    host_match = re.search(r"host[:=]\s*([^\s]+)", raw_log_lower)
    if host_match:
        host = host_match.group(1)

    # ---- USER ----
    user_match = re.search(r"user[:=]\s*([^\s]+)", raw_log_lower)
    if user_match:
        user = user_match.group(1)

    # ---- PROCESS (supports Image= or Process=) ----
    process_match = re.search(r"(image|process)[:=]\s*([^\s]+)", raw_log_lower)
    if process_match:
        process = process_match.group(2)

    # ---- PARENT ----
    parent_match = re.search(r"(parentimage|parent)[:=]\s*([^\s]+)", raw_log_lower)
    if parent_match:
        parent = parent_match.group(2)

    # ---- COMMAND LINE ----
    cmd_match = re.search(r'(commandline|cmd)[:=]\s*"?(.+?)"?$', raw_log_lower)
    if cmd_match:
        cmdline = cmd_match.group(2)

    return {
        "id": str(uuid.uuid4())[:8],
        "timestamp": timestamp,
        "host": host,
        "user": user,
        "process": process,
        "parent": parent,
        "cmdline": cmdline,
        "full_text": f"{process} {parent} {cmdline}".lower()
    }


def print_attack_chain(matches):
    if not matches:
        return

    stages_found = set()

    for tech in matches:
        stages_found.add(tech.get("tactic"))

    ordered_stages = [stage for stage in ATTACK_FLOW_ORDER if stage in stages_found]

    if ordered_stages:
        print("\n=== DETECTED ATTACK CHAIN STAGES ===")
        print(" → ".join(ordered_stages))


def load_attack_data():
    with open("attack_data.json", "r") as f:
        return json.load(f)

import re

def get_user_input():
    print("\nPaste full log line OR press Enter to use manual input:")
    raw_log = input("> ").lower()

    if raw_log.strip() == "":
        # Fallback to manual mode
        process = input("Process Name: ").lower()
        parent = input("Parent Process: ").lower()
        cmdline = input("Command Line: ").lower()
    else:
        # Try extracting fields from raw log
        process_match = re.search(r"image:\s*([^\s]+)", raw_log)
        parent_match = re.search(r"parentimage:\s*([^\s]+)", raw_log)
        cmd_match = re.search(r"commandline:\s*(.+)", raw_log)

        process = process_match.group(1) if process_match else ""
        parent = parent_match.group(1) if parent_match else ""
        cmdline = cmd_match.group(1) if cmd_match else raw_log

    return {
        "process": process,
        "parent": parent,
        "cmdline": cmdline,
        "full_text": f"{process} {parent} {cmdline}"
    }
	

def map_to_attack(data, log):
    matches = []

    for technique in data:
        matched_keywords = []
        confidence = 0

        # Basic keyword scoring
        for keyword in technique["keywords"]:
            if keyword in log["full_text"]:
                matched_keywords.append(keyword)
                confidence += 1  # Base weight

        # Behavior-based weighted scoring

        # Office spawning PowerShell = HIGH RISK
        if log["parent"] == "winword.exe" and log["process"] == "powershell.exe":
            if technique["technique_id"] == "T1204":
                matched_keywords.append("Office spawning PowerShell")
                confidence += 3

        # Encoded PowerShell command = HIGH RISK
        if log["process"] == "powershell.exe" and "-enc" in log["cmdline"]:
            if technique["technique_id"] == "T1059.001":
                matched_keywords.append("Encoded PowerShell command")
                confidence += 2

        # LSASS access = VERY HIGH RISK
        if "lsass" in log["full_text"]:
            if technique["technique_id"] == "T1003":
                matched_keywords.append("LSASS access behavior")
                confidence += 3

        if confidence > 0:
            technique_copy = technique.copy()
            technique_copy["matched_keywords"] = matched_keywords
            technique_copy["confidence"] = confidence
            technique_copy["timestamp"] = log.get("timestamp")
            technique_copy["process"] = log.get("process")
            technique_copy["parent"] = log.get("parent")
            matches.append(technique_copy)
            
    return matches

def get_severity(score):
    if score >= 5:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    else:
        return "LOW"

def print_attack_timeline_by_host(matches):
    if not matches:
        return

    grouped = group_by_host(matches)

    for host, host_matches in grouped.items():
        print(f"\n=== ATTACK TIMELINE | HOST: {host.upper()} ===")

        sorted_matches = sorted(host_matches, key=lambda x: x.get("timestamp", 0))

        for tech in sorted_matches:
            time_str = format_time(tech["timestamp"])
            print(f"{time_str} | {tech['tactic']} | {tech['technique_id']} | {tech['process']} ← {tech['parent']}")
            
def print_summary_by_host(matches):
    grouped = group_by_host(matches)

    for host, host_matches in grouped.items():
        tactic_counter = Counter(m["tactic"] for m in host_matches)

        print(f"\n=== MITRE SUMMARY | HOST: {host.upper()} ===")
        for tactic, count in tactic_counter.items():
            print(f"{tactic}: {count}")

def print_attack_chain_by_host(matches):
    grouped = group_by_host(matches)

    for host, host_matches in grouped.items():
        stages_found = {m["tactic"] for m in host_matches}
        ordered = [s for s in ATTACK_FLOW_ORDER if s in stages_found]

        if ordered:
            print(f"\n=== ATTACK CHAIN | HOST: {host.upper()} ===")
            print(" → ".join(ordered))


def print_results(matches):
    if not matches:
        print("\nNo ATT&CK techniques matched.")
        return

    print("\n=== DETECTED TECHNIQUES ===\n")

    for tech in matches:
        time_str = format_time(tech["timestamp"]) if tech.get("timestamp") else "N/A"
        print(f"{time_str} | {tech['technique_id']} | {tech['name']} | {tech.get('process')} ← {tech.get('parent')}")

        
def export_to_json(matches, filename="report.json"):
    report = []

    for tech in matches:
        report.append({
            "timestamp": format_time(tech["timestamp"]) if tech.get("timestamp") else None,
            "technique_id": tech["technique_id"],
            "technique_name": tech["name"],
            "tactic": tech["tactic"],
            "process": tech.get("process"),
            "parent_process": tech.get("parent"),
            "confidence": tech["confidence"],
            "severity": get_severity(tech["confidence"]),
            "matched_indicators": tech["matched_keywords"],
            "detection_notes": tech.get("detection"),
            "possible_false_positives": tech.get("false_positives", [])
})



    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    print(f"\nJSON report saved as {filename}")

def parse_log_line(raw_log, index=0):
    raw_log = raw_log.lower()
    event_id = str(uuid.uuid4())[:8]

    # Fake timeline: each log 30 seconds apart
    timestamp = time.time() + (index * 30)

    process_match = re.search(r"image:\s*([^\s]+)", raw_log)
    parent_match = re.search(r"parentimage:\s*([^\s]+)", raw_log)
    cmd_match = re.search(r"commandline:\s*(.+)", raw_log)

    process = process_match.group(1) if process_match else ""
    parent = parent_match.group(1) if parent_match else ""
    cmdline = cmd_match.group(1) if cmd_match else raw_log

    return {
        "id": event_id,
        "process": process,
        "parent": parent,
        "cmdline": cmdline,
        "timestamp": timestamp,
        "full_text": f"{process} {parent} {cmdline}"
    }


from collections import Counter

def print_mitre_summary(matches):
    if not matches:
        return

    tactic_counter = Counter()

    for tech in matches:
        tactic = tech.get("tactic", "Unknown")
        tactic_counter[tactic] += 1

    print("\n=== MITRE ATT&CK COVERAGE SUMMARY ===")
    for tactic, count in tactic_counter.items():
        print(f"{tactic}: {count}")


def main():
    print_banner()

    if "--help" in sys.argv:
        print_help()
        return
    attack_data = load_attack_data()

    # Check if file mode is used
    if len(sys.argv) > 2 and sys.argv[1] == "--file":
        filename = sys.argv[2]
        all_matches = []

        print(f"\nScanning log file: {filename}\n")

        with open(filename, "r") as f:
            lines = f.readlines()

        tree, process_info = build_process_tree(lines)
        all_matches = analyze_process_chains(tree, process_info, attack_data)
        print_results(all_matches)
        print_summary_by_host(all_matches)
        print_attack_chain_by_host(all_matches)
        print_attack_timeline_by_host(all_matches)

        export_to_json(all_matches, "report.json")


    else:
        # Single log mode
        log_data = get_user_input()
        matches = map_to_attack(attack_data, log_data)
        print_results(matches)
        print_mitre_summary(matches)
        print_attack_chain(matches)
        print_attack_timeline(matches)
        export_to_json(matches)



if __name__ == "__main__":
    main()

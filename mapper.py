import json
import sys
import re

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
            matches.append(technique_copy)

    return matches

def get_severity(score):
    if score >= 5:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    else:
        return "LOW"


def print_results(matches):
    if not matches:
        print("\nNo ATT&CK techniques matched.")
        return

    print("\nMapped MITRE ATT&CK Techniques:\n")

    for tech in matches:
        print(f"{tech['technique_id']} – {tech['name']} ({tech['tactic']})")
        print(f"Matched Indicators: {', '.join(tech['matched_keywords'])}")
        print(f"Confidence Score: {tech['confidence']}")
        print(f"Severity: {get_severity(tech['confidence'])}")
        print("Detection Ideas:")
        for d in tech["detection"]:
            print(f"  - {d}")
        if "false_positives" in tech:
            print("Possible False Positives:")
            for fp in tech["false_positives"]:
                print(f"  - {fp}")
        print("-" * 50)
        
def export_to_json(matches, filename="report.json"):
    report = []

    for tech in matches:
        report.append({
    	    "technique_id": tech["technique_id"],
            "technique_name": tech["name"],
    	    "tactic": tech["tactic"],
            "confidence": tech["confidence"],
            "severity": get_severity(tech["confidence"]),
            "matched_indicators": tech["matched_keywords"],
            "possible_false_positives": tech.get("false_positives", [])
})


    with open(filename, "w") as f:
        json.dump(report, f, indent=4)

    print(f"\nJSON report saved as {filename}")

def parse_log_line(raw_log):
    raw_log = raw_log.lower()

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
            for line in f:
                log_data = parse_log_line(line.strip())
                matches = map_to_attack(attack_data, log_data)

                if matches:
                    print(f"\nLog: {line.strip()}")
                    print_results(matches)
                    all_matches.extend(matches)
        print_mitre_summary(all_matches)
        export_to_json(all_matches, "report.json")

    else:
        # Single log mode
        log_data = get_user_input()
        matches = map_to_attack(attack_data, log_data)
        print_results(matches)
        print_mitre_summary(matches)
        export_to_json(matches)



if __name__ == "__main__":
    main()

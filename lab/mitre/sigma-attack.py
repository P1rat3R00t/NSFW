# Map detections to MITRE ATT&CK framework for S0ngb1rd scenario

SONGBIRD_ATTACK_TECHNIQUES = {
    "T1566.001": "Spearphishing Attachment (Malicious PDF/7zip Dropper)",
    "T1027": "Obfuscated Files or Information (Encoded Dropper)",
    "T1204.002": "User Execution: Malicious File",
    "T1055.002": "Reflective DLL Injection (nsfw.dll)",
    "T1211": "Exploitation for Defense Evasion (HiveNightmare/CVE-2021-36934)",
    "T1003.001": "LSASS Memory (Credential Dumping via LOLBins)",
    "T1003.003": "OS Credential Dumping: NTDS",
    "T1105": "Ingress Tool Transfer (Dropper, 7zip Archive)",
    "T1036": "Masquerading (LOLbins for Cred Dump)",
    "T1059": "Command and Scripting Interpreter (Used by LOLBins)",
}

# Example detection events for this scenario
detection_events = [
    {"event": "Malicious encoded dropper delivered via PDF/7zip", "technique": "T1566.001"},
    {"event": "Dropper decoded and written to disk", "technique": "T1027"},
    {"event": "User opened malicious attachment", "technique": "T1204.002"},
    {"event": "HiveNightmare exploit executed", "technique": "T1211"},
    {"event": "LOLBin tool used for LSASS dump", "technique": "T1003.001"},
    {"event": "LOLBin tool used for OS credentials dump", "technique": "T1003.003"},
    {"event": "Reflective DLL injection of nsfw.dll", "technique": "T1055.002"},
    {"event": "Dropper/7zip archive transferred", "technique": "T1105"},
    {"event": "Credential dumping tools masqueraded as system binaries", "technique": "T1036"},
    {"event": "Command interpreter used for execution", "technique": "T1059"},
]

def map_events_to_mitre(events):
    mapped = []
    for event in events:
        tech_id = event.get("technique")
        mitre_desc = SONGBIRD_ATTACK_TECHNIQUES.get(tech_id, "Unknown Technique")
        mapped.append({
            "event": event["event"],
            "mitre_technique_id": tech_id,
            "mitre_description": mitre_desc
        })
    return mapped

if __name__ == "__main__":
    mapped_results = map_events_to_mitre(detection_events)
    print("Mapped Detection Events to MITRE ATT&CK (S0ngb1rd):")
    for res in mapped_results:
        print(f"- Event: {res['event']}")
        print(f"  Technique: {res['mitre_technique_id']} ({res['mitre_description']})")
        print()

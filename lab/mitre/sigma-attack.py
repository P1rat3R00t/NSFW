# Map detections to MITRE ATT&CK framework
# Map detections to MITRE ATT&CK framework (NotPetya example)
# Source: https://attack.mitre.org/software/S0368/

NOTPETYA_ATTCK_TECHNIQUES = {
    "T1021.002": "SMB/Windows Admin Shares",             # Lateral Movement via SMB
    "T1069.001": "Local Account Discovery",
    "T1087.002": "Domain Account Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1055": "Process Injection",
    "T1569.002": "Service Execution",
    "T1105": "Ingress Tool Transfer",
    "T1490": "Inhibit System Recovery",
    "T1486": "Data Encrypted for Impact",
    "T1489": "Service Stop",
    "T1070.004": "File Deletion",
    "T1047": "Windows Management Instrumentation",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1003.001": "LSASS Memory",
    "T1021.001": "Remote Desktop Protocol",
    "T1075": "Pass the Hash",
}

# Example detection events (in reality, you would parse logs or Sigma rules)
detection_events = [
    {"event": "SMB lateral movement detected", "technique": "T1021.002"},
    {"event": "Process injection attempt", "technique": "T1055"},
    {"event": "Volume shadow copy deletion", "technique": "T1490"},
    {"event": "Credential dump via LSASS", "technique": "T1003.001"},
]

def map_events_to_mitre(events):
    mapped = []
    for event in events:
        tech_id = event.get("technique")
        mitre_desc = NOTPETYA_ATTCK_TECHNIQUES.get(tech_id, "Unknown Technique")
        mapped.append({
            "event": event["event"],
            "mitre_technique_id": tech_id,
            "mitre_description": mitre_desc
        })
    return mapped

if __name__ == "__main__":
    mapped_results = map_events_to_mitre(detection_events)
    print("Mapped Detection Events to MITRE ATT&CK (NotPetya):")
    for res in mapped_results:
        print(f"- Event: {res['event']}")
        print(f"  Technique: {res['mitre_technique_id']} ({res['mitre_description']})")
        print()

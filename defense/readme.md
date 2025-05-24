

# Purple Team Exercise Full Setup & Workflow

---

## 1. **Network and VM Setup**

* **Hardware & Network:**

  * Spectrum Modem (EN2251) + SAX1V1K WiFi 6 Router (inactive, isolated network).
  * Connect your host PC to this network or isolate traffic to a virtual network inside VirtualBox.

* **Virtual Machines:**

  * Windows 11 VM: Target system with SMB shares configured.
  * Kali Linux VM: Defensive/offensive toolset, including Snort and Wireshark installed.

* **VirtualBox Network Configuration:**

  * Use **Host-Only Adapter** or **Internal Network** mode to simulate isolated environment.
  * Ensure Kali VM can see all traffic to/from Windows 11 VM for monitoring.

---

## 2. **Windows 11 Target Preparation**

* Configure **SMB shares** accessible by Kali VM. Place the encoded payload (JPG with embedded wiper) here.

* Enable **Windows Event Logging:**

  * Process creation (Sysmon or built-in Windows logs).
  * Network connections and SMB session events.
  * Event log clearing monitoring.

* Apply basic **AppLocker or WDAC policies** to restrict usage of `rundll32.exe` and PowerShell for mitigation testing.

---

## 3. **Snort Setup on Kali VM**

* Install Snort:

  ```bash
  sudo apt update && sudo apt install snort
  ```

* Place the custom ruleset (`purpleteam-fileless-wiper.rules`) into `/etc/snort/rules/`.

* Edit `/etc/snort/snort.conf` to include the rules:

  ```plaintext
  include $RULE_PATH/purpleteam-fileless-wiper.rules
  ```

* Start Snort in IDS mode, listening on the appropriate interface:

  ```bash
  sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
  ```

* Tail the alert logs for matches.

---

## 4. **Wireshark Setup**

* Install Wireshark on host or Kali VM.

* During the exercise, run live capture on the network interface observing Windows VM traffic.

* Use filters such as:

  ```
  smb2.file_name contains ".jpg"
  smb2.cmd == 0x05 and smb2.file_name contains "rundll32"
  smb2.file_name contains "pipe"
  frame contains "powershell"
  ```

* Optionally set color rules for quicker spotting.

---

## 5. **Execute the Fileless Wiper Test**

* From Kali or an authorized host, trigger remote execution of the embedded payload via:

  ```powershell
  rundll32.exe \\windows_vm_ip\share\encoded_payload.jpg,EntryPoint
  ```

* This activates the wiper encoded inside the JPG, executing fileless in Windows memory.

---

## 6. **Detection & Analysis**

* **Snort:**

  * Watch for alerts triggered by SMB file transfers, `rundll32.exe` execution, PowerShell commands, and Named Pipe usage.

* **Wireshark:**

  * Inspect packet captures for unusual SMB file activity, commands referencing `rundll32.exe` or PowerShell, and named pipes.

* **Windows Event Logs:**

  * Confirm process creation logs (`rundll32.exe` launch).
  * Look for suspicious network activity and log clearing attempts.

* Correlate Snort alerts with Wireshark captures and Windows logs to build a timeline and verify detection efficacy.

---

## 7. **Mitigation & Hardening**

* Apply or tune **AppLocker/WDAC** to block unauthorized `rundll32.exe` or PowerShell from SMB shares.

* Enable SMB **signing and encryption** to mitigate tampering.

* Monitor and alert on **event log clearance** or other suspicious system modifications.

---

## 8. **MITRE ATT\&CK Mapping**

| Technique ID | Technique Name                                | Description & Detection                                                                                      |
| ------------ | --------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| T1021.002    | Remote Services: SMB/Windows Admin Shares     | Fileless payload executed via SMB shares (`rundll32.exe`). Snort detects SMB payload and execution attempts. |
| T1059.001    | Command and Scripting Interpreter: PowerShell | Detection of embedded PowerShell commands in traffic and process logs.                                       |
| T1565        | Data Manipulation                             | Wiper activity—file destruction via payload.                                                                 |
| T1562.001    | Impair Defenses: Disable or Modify Tools      | Detection of event log clearing attempts on Windows.                                                         |

---

## Summary

| Step                       | Purpose                                    |
| -------------------------- | ------------------------------------------ |
| VM and network setup       | Isolate and monitor network traffic        |
| Snort deployment           | Automated network intrusion detection      |
| Wireshark live capture     | Deep packet inspection and manual analysis |
| Windows target hardening   | Apply mitigation controls                  |
| Execute test payload       | Validate detection and defense mechanisms  |
| Analyze and correlate logs | Ensure comprehensive visibility            |
| MITRE ATT\&CK mapping      | Structure detection coverage and gaps      |


Certainly. Here's a focused, professional overview covering:

* **Sysmon XML config** tailored for your fileless wiper scenario
* **Wireshark usage** tips for detecting relevant threats
* **Snort deployment** for real-time network detection
* **Mitigations** aligned with findings and MITRE ATT\&CK

---

## 1. Sysmon XML Configuration (Windows 11 Target)

This Sysmon configuration emphasizes:

* Process creation monitoring of `rundll32.exe`, `powershell.exe`
* Network connections
* Event log clearing and tampering
* File and registry operations
* PowerShell script blocks and command line arguments (to catch obfuscated exec)

```xml
<Sysmon schemaversion="4.70">
  <EventFiltering>
    <ProcessCreate onmatch="include">
      <Image condition="contains">rundll32.exe</Image>
      <Image condition="contains">powershell.exe</Image>
      <CommandLine condition="contains">-encodedCommand</CommandLine>
    </ProcessCreate>
    <NetworkConnect onmatch="include" />
    <FileDelete onmatch="include" />
    <RegistryEvent onmatch="include" />
    <ProcessTerminate onmatch="include" />
    <DriverLoad onmatch="include" />
    <EventLog onmatch="include">
      <TargetObject condition="contains">Security</TargetObject>
    </EventLog>
    <ImageLoad onmatch="include">
      <ImageLoaded condition="contains">dll</ImageLoaded>
    </ImageLoad>
  </EventFiltering>
</Sysmon>
```

* **Deploy** with:

  ```
  sysmon -c sysmon-config.xml -i
  ```

* **Review logs** via Event Viewer or forward to your SIEM for correlation.

---

## 2. Wireshark for Threat Detection

* **Capture interface** connected to VM network or bridged interface with visibility to Windows SMB traffic.
* Apply display filters for quick triage:

  * `smb2.file_name contains ".jpg"` — Detect file transfer of suspicious payload carrier
  * `smb2.cmd == 0x05 and smb2.file_name contains "rundll32"` — Remote execution trigger via SMB
  * `frame contains "powershell"` — Detect inline PowerShell commands over network
  * `smb2.file_name contains "pipe"` — IPC abuse via named pipes
* Use **color rules** for these filters to highlight suspicious packets.
* Export suspicious sessions for deeper forensic analysis.

---

## 3. Snort Real-Time Detection

* Configure Snort with your custom rules file (sample rules provided earlier).

* Run in IDS mode on the monitoring interface:

  ```
  sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
  ```

* Monitor alerts for:

  * SMB file transfers of `.jpg` files carrying payload
  * `rundll32.exe` invocation attempts via SMB
  * PowerShell commands over network
  * Named pipe communication anomalies

* **Tune rules** to reduce false positives after initial runs.

---

## 4. Mitigations Aligned with MITRE ATT\&CK

| Threat Vector                         | Mitigation                                                                       | ATT\&CK ID |
| ------------------------------------- | -------------------------------------------------------------------------------- | ---------- |
| Remote file execution via SMB shares  | Enable SMB signing and encryption; restrict SMB share permissions                | T1021.002  |
| Abuse of `rundll32.exe` for execution | Implement AppLocker/WDAC policies blocking unauthorized usage                    | T1218      |
| PowerShell-based fileless attacks     | Constrain PowerShell execution policies; enable logging and script block logging | T1059.001  |
| Event log clearing                    | Monitor event logs for clearance events; alert on suspicious registry changes    | T1562.001  |
| Named pipe abuse for IPC              | Monitor IPC traffic; restrict named pipe permissions                             | T1573      |

---

### Summary

| Tool      | Detection Focus                 | Deployment Key Points                                                |
| --------- | ------------------------------- | -------------------------------------------------------------------- |
| Sysmon    | Process creation, network, logs | Fine-tuned config deployed on target; logs forwarded for correlation |
| Wireshark | Deep packet inspection of SMB   | Live capture + filters for payload and exec command detection        |
| Snort     | Real-time IDS alerting          | Custom rules for SMB and PowerShell detection; run on monitoring VM  |


## OPTIONAL SET UP 

Got it. Here’s a focused, practical blueprint for integrating your purple team setup into a **SIEM** environment, focusing on Windows 11 + Snort + Sysmon + Wireshark data ingestion, correlation, and alerting.

---

# SIEM Integration Blueprint for Purple Team Exercise

### 1. **SIEM Choice & Setup**

* **Elastic Stack (Elasticsearch + Logstash + Kibana)** — open-source, flexible, widely used.
* Alternatives: Splunk, QRadar, or commercial SIEMs — Elastic is recommended for hands-on and customizable setups.

### 2. **Data Sources & Forwarding**

| Source             | Forwarding Agent / Method                                                | Notes                          |
| ------------------ | ------------------------------------------------------------------------ | ------------------------------ |
| Windows 11 Sysmon  | Winlogbeat (Elastic Agent)                                               | Parses and forwards Event Logs |
| Snort Alerts       | Filebeat (reads alert log file)                                          | Ingest Snort alert logs        |
| Wireshark Captures | Use tshark to export PCAP summaries, send via Filebeat or Logstash input | Full packet capture too heavy  |

---

### 3. **Basic Workflow**

#### a. **Install Elastic Stack**

* Deploy Elasticsearch, Logstash, Kibana on dedicated VM or Linux host.
* Allocate sufficient RAM and CPU for log indexing.

#### b. **Configure Winlogbeat on Windows 11**

* Install and configure Winlogbeat with Sysmon module enabled.
* Example winlogbeat.yml snippet:

```yaml
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational
    ignore_older: 72h
```

* Point output to your Elasticsearch endpoint.

#### c. **Configure Filebeat for Snort**

* Set up Filebeat to monitor Snort alert logs (`/var/log/snort/alert`).
* Basic filebeat.yml snippet:

```yaml
filebeat.inputs:
- type: log
  paths:
    - /var/log/snort/alert
  multiline.pattern: '^\[\*\*\]'
  multiline.negate: true
  multiline.match: after
output.elasticsearch:
  hosts: ["http://ELASTIC_HOST:9200"]
```

#### d. **Wireshark/tshark Export**

* Use tshark to export summary info or extract flows (CSV/JSON).
* Ingest those files periodically or stream with Logstash file input.

---

### 4. **Logstash Pipelines**

* **Parsing Snort alerts:** Use grok patterns to extract timestamp, SID, source/destination IP, protocol, message.
* **Parsing Sysmon logs:** Use XML or Winlogbeat pre-parsed JSON logs.
* **Correlate alerts:** By IP, timestamp, process name, and behavior signatures.

Example snippet for Snort parsing with grok:

```
grok {
  match => { "message" => "\[%{DATA:alert_type}\] \[%{NUMBER:sid}:%{NUMBER:rev}:%{NUMBER}\] %{GREEDYDATA:msg}" }
}
```

---

### 5. **Kibana Dashboard Design**

* **Overview Panel:** Total alerts by type (Snort, Sysmon) over time.
* **Threat Timeline:** Event correlation timeline with source/destination IPs and processes involved.
* **Process Creation Alerts:** Filter for `rundll32.exe`, `powershell.exe` executions.
* **Network Traffic Map:** Visualize source/destination IPs for SMB and PowerShell network activity.
* **Anomaly Detection:** Set alerts for unusual spikes in process launches or network connections.

---

### 6. **Alerting & Mitigation**

* Configure alert rules for critical indicators (e.g., rundll32.exe executing with suspicious parameters, SMB file transfers with embedded executables).
* Enable email, Slack, or webhook alerts from Kibana.

---

### 7. **Summary Table**

| Component     | Function                    | Notes                          |
| ------------- | --------------------------- | ------------------------------ |
| Winlogbeat    | Windows Sysmon log shipping | Reliable real-time forwarding  |
| Filebeat      | Snort alert log forwarding  | Tail alert logs for IDS events |
| Logstash      | Parsing and enrichment      | Grok patterns and correlation  |
| Elasticsearch | Storage & indexing          | Scalable and fast queries      |
| Kibana        | Visualization & alerting    | Custom dashboards and alerts   |





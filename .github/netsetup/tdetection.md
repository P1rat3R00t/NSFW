Got it. I’ll provide you with:

* A **custom Sysmon configuration** with extended detection rules tailored to your fileless wiper scenario over SMB + rundll32 execution.
* A **sample ELK (Elasticsearch/Logstash/Kibana) ingestion pipeline config** snippet to parse and filter these events.
* A **Kibana dashboard JSON template** skeleton for monitoring the key indicators.

---

# 1. Extended Sysmon Configuration for Purple Team Fileless Wiper Detection

```xml
<Sysmon schemaversion="4.50">
  <EventFiltering>

    <!-- Process Creation: Rundll32 launching from network shares -->
    <ProcessCreate onmatch="include">
      <Image condition="end with">rundll32.exe</Image>
      <CommandLine condition="contains">\\</CommandLine>
    </ProcessCreate>

    <!-- Process Creation: Suspicious command line invocations -->
    <ProcessCreate onmatch="include">
      <CommandLine condition="contains">powershell</CommandLine>
      <CommandLine condition="contains">Invoke-Expression</CommandLine>
      <CommandLine condition="contains">mshta</CommandLine>
      <CommandLine condition="contains">regsvr32</CommandLine>
      <CommandLine condition="contains">wmic</CommandLine>
    </ProcessCreate>

    <!-- Network Connect for all processes -->
    <NetworkConnect onmatch="include">
      <Image condition="end with">.exe</Image>
    </NetworkConnect>

    <!-- File Creation: Files created on network shares -->
    <FileCreate onmatch="include">
      <TargetFilename condition="contains">\\</TargetFilename>
    </FileCreate>

    <!-- Process Access: Detect code injection / handle manipulation -->
    <ProcessAccess onmatch="include">
      <GrantedAccess condition="contains">0x1F0FFF</GrantedAccess>
    </ProcessAccess>

    <!-- Pipe Created: For IPC detection -->
    <PipeCreated onmatch="include" />

    <!-- Event Log Clearing -->
    <EventLog onmatch="include">
      <EventID>1102</EventID>
    </EventLog>

    <!-- Image Load: Drivers or DLLs loaded in system paths -->
    <ImageLoad onmatch="include">
      <ImageLoaded condition="contains">\\System32\\drivers\\</ImageLoaded>
    </ImageLoad>

  </EventFiltering>
</Sysmon>
```

---

# 2. ELK Pipeline Filter (Logstash) Snippet for Sysmon

```conf
filter {
  if [source] =~ "Sysmon" {
    xml {
      source => "message"
      target => "sysmon"
      store_xml => true
      xpath => [
        "/Event/EventID/text()", "event_id",
        "/Event/System/TimeCreated/@SystemTime", "timestamp",
        "/Event/EventData/Data[@Name='Image']/text()", "process_image",
        "/Event/EventData/Data[@Name='CommandLine']/text()", "command_line",
        "/Event/EventData/Data[@Name='TargetFilename']/text()", "target_filename",
        "/Event/EventData/Data[@Name='GrantedAccess']/text()", "granted_access"
      ]
    }

    mutate {
      convert => {
        "event_id" => "integer"
      }
      lowercase => ["process_image", "command_line", "target_filename"]
    }

    # Detect rundll32 running from network share
    if [event_id] == 1 and [process_image] =~ "rundll32.exe" and [command_line] =~ /\\\\/ {
      mutate { add_tag => ["suspicious_rundll32_network_path"] }
    }

    # Detect suspicious file creation on network shares
    if ([event_id] == 11 or [event_id] == 4663) and [target_filename] =~ /\\\\/ {
      mutate { add_tag => ["file_created_network_share"] }
    }

    # Detect process access indicating injection
    if [event_id] == 10 and [granted_access] == "0x1F0FFF" {
      mutate { add_tag => ["process_injection_detected"] }
    }

    # Detect event log clearing
    if [event_id] == 1102 {
      mutate { add_tag => ["event_log_cleared"] }
    }
  }
}
```

---

# 3. Kibana Dashboard JSON Skeleton

This skeleton includes panels for critical event types:

```json
{
  "title": "Purple Team Fileless Wiper Monitoring",
  "panels": [
    {
      "title": "Rundll32 Execution from Network Share",
      "type": "table",
      "query": "tags:suspicious_rundll32_network_path",
      "fields": ["@timestamp", "host.name", "process_image", "command_line", "user.name"]
    },
    {
      "title": "File Creation on Network Shares",
      "type": "table",
      "query": "tags:file_created_network_share",
      "fields": ["@timestamp", "host.name", "target_filename", "user.name"]
    },
    {
      "title": "Process Injection Events",
      "type": "table",
      "query": "tags:process_injection_detected",
      "fields": ["@timestamp", "host.name", "process_image", "command_line", "user.name"]
    },
    {
      "title": "Event Log Clearing",
      "type": "table",
      "query": "tags:event_log_cleared",
      "fields": ["@timestamp", "host.name", "user.name"]
    }
  ]
}
```

---

# Summary & Next

* Deploy Sysmon with provided XML config on Windows 11 VM.
* Configure your ELK stack with Logstash filter for Sysmon logs ingestion and tagging.
* Import Kibana dashboard JSON to visualize critical indicators.
* Run your wiper test and monitor logs/alerts.



import re
import json
from datetime import datetime

# Adjust to your Snort alert log path
SNORT_LOG_PATH = '/var/log/snort/alert'

class SnortAlertParser:
    def __init__(self, log_path):
        self.log_path = log_path
        self.alerts = []

    def parse_alerts(self):
        current_alert = {}
        with open(self.log_path, 'r') as f:
            for line in f:
                line = line.strip()

                # Start of new alert block
                if line.startswith('[**]'):
                    if current_alert:
                        self.alerts.append(current_alert)
                        current_alert = {}
                    # Extract message
                    msg_match = re.search(r'\]\s(.+?)\s\[', line)
                    if msg_match:
                        current_alert['msg'] = msg_match.group(1)

                # Extract timestamp line (format: MM/DD-HH:MM:SS.mmmmmm)
                elif re.match(r'\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d{6}', line):
                    ts_str = line.split(' ')[0]
                    try:
                        current_alert['timestamp'] = datetime.strptime(ts_str, '%m/%d-%H:%M:%S.%f')
                    except Exception as e:
                        current_alert['timestamp'] = None

                # Extract source and destination IP:Port
                elif '->' in line:
                    parts = line.split(' ')
                    for part in parts:
                        if '->' in part:
                            ips = part.split('->')
                            current_alert['src'] = ips[0]
                            current_alert['dst'] = ips[1]

            # Add last parsed alert
            if current_alert:
                self.alerts.append(current_alert)

    def correlate_alerts(self):
        # Basic correlation by message similarity and time proximity (within 1 min)
        correlated = []
        for i, alert in enumerate(self.alerts):
            group = [alert]
            for j in range(i+1, len(self.alerts)):
                delta = abs((self.alerts[j]['timestamp'] - alert['timestamp']).total_seconds()) if alert.get('timestamp') and self.alerts[j].get('timestamp') else None
                if delta is not None and delta <= 60:
                    if self.alerts[j]['msg'] == alert['msg']:
                        group.append(self.alerts[j])
            correlated.append(group)
        return correlated

    def save_as_json(self, path='snort_alerts.json'):
        with open(path, 'w') as f:
            json.dump(self.alerts, f, default=str, indent=2)

    def print_summary(self):
        for alert in self.alerts:
            ts = alert.get('timestamp')
            ts_str = ts.strftime('%Y-%m-%d %H:%M:%S') if ts else 'N/A'
            print(f"[{ts_str}] Alert: {alert.get('msg')} | Src: {alert.get('src')} -> Dst: {alert.get('dst')}")

def main():
    parser = SnortAlertParser(SNORT_LOG_PATH)
    parser.parse_alerts()
    parser.print_summary()
    parser.save_as_json()

    correlated = parser.correlate_alerts()
    print(f"\n[+] Correlated Alert Groups (by message within 60 sec): {len(correlated)}")
    for idx, group in enumerate(correlated, 1):
        print(f"Group {idx}: {len(group)} alerts")
        for alert in group:
            ts = alert.get('timestamp')
            ts_str = ts.strftime('%Y-%m-%d %H:%M:%S') if ts else 'N/A'
            print(f"  - [{ts_str}] {alert.get('msg')} from {alert.get('src')} to {alert.get('dst')}")

if __name__ == '__main__':
    main()

from flask import Flask, render_template, jsonify, request, Response
import requests
import time
from datetime import datetime, timedelta
from collections import defaultdict
import json
import re

app = Flask(__name__)

# ======================
# CONFIGURATION
# ======================
GRAYLOG_API = "http://192.168.248.132:9000/api"
GRAYLOG_CREDS = ("admin", "admin")  # Replace with your API key
THREAT_IPS = ["192.168.1.45", "185.143.223.10", "45.33.12.89"]  # From threat intel feeds
TRUSTED_USERS = ["admin", "admin"]  # Users with elevated privileges

# MITRE ATT&CK Mappings
MITRE_TACTICS = {
    "brute_force": "TA0006: Credential Access",
    "port_scan": "TA0007: Discovery",
    "data_access": "TA0009: Collection",
    "config_change": "TA0005: Defense Evasion",
    "data_exfil": "TA0010: Exfiltration"
}

# ======================
# HELPER FUNCTIONS
# ======================
def fetch_graylog_logs(query="*", timeframe=15, limit=100):
    """Fetch logs from Graylog API"""
    time_range = f"last_{timeframe}_minutes"
    url = f"{GRAYLOG_API}/search/universal/relative"
    
    params = {
        'query': query,
        'range': time_range,
        'limit': limit,
        'fields': 'source,message,timestamp,level,source_ip,user'
    }
    
    try:
        res = requests.get(
            url,
            auth=GRAYLOG_CREDS,
            params=params,
            timeout=10
        )
        return res.json().get('messages', [])
    except Exception as e:
        app.logger.error(f"Graylog fetch failed: {str(e)}")
        return []

def log_to_graylog(message):
    """Send data back to Graylog"""
    try:
        requests.post(
            f"{GRAYLOG_API}/system/inputs",
            auth=GRAYLOG_CREDS,
            json={
                "message": message,
                "source": "anomaly-detector",
                "timestamp": datetime.utcnow().isoformat()
            }
        )
    except Exception as e:
        app.logger.error(f"Graylog log failed: {str(e)}")

def extract_ips(message):
    """Extract IP addresses from log messages"""
    ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    return re.findall(ip_pattern, message)

def is_threat_ip(ip):
    """Check if IP is in threat intelligence feed"""
    return ip in THREAT_IPS

def detect_anomaly_type(log):
    """Determine the type of security anomaly"""
    msg = log.get('message', '').lower()
    
    if "fail" in msg and ("login" in msg or "password" in msg):
        return "brute_force"
    elif "port" in msg and ("scan" in msg or "probe" in msg):
        return "port_scan"
    elif "transfer" in msg and ("large" in msg or "external" in msg):
        return "data_exfil"
    elif "firewall" in msg and ("change" in msg or "modif" in msg):
        return "config_change"
    elif "access" in msg and ("confidential" in msg or "sensitive" in msg):
        return "data_access"
    return "unknown"

def generate_recommendations(anomaly_type, log):
    """Generate AI-powered recommendations"""
    base_recs = {
        "brute_force": [
            f"Block IP {extract_ips(log.get('message', ''))[0]} temporarily",
            "Enable CAPTCHA for affected accounts",
            "Require MFA for privileged users"
        ],
        "port_scan": [
            f"Investigate source IP {extract_ips(log.get('message', ''))[0]}",
            "Review firewall rules for scanned ports",
            "Consider adding to threat intelligence feed"
        ],
        "data_exfil": [
            "Immediately suspend involved user account",
            "Initiate forensic investigation",
            "Notify data protection officer"
        ],
        "config_change": [
            "Verify change authorization",
            "Review change management logs",
            "Consider rollback if unauthorized"
        ],
        "data_access": [
            "Verify access was authorized",
            "Review user permissions",
            "Check for unusual access patterns"
        ]
    }
    return base_recs.get(anomaly_type, ["Investigate further"])

# ======================
# CORE ANALYSIS
# ======================
def analyze_logs(logs):
    """Main analysis function"""
    anomalies = []
    
    for entry in logs:
        log = entry.get('message', {})
        anomaly_type = detect_anomaly_type(log)
        
        if anomaly_type == "unknown":
            continue
            
        ips = extract_ips(log.get('message', ''))
        threat_ips = [ip for ip in ips if is_threat_ip(ip)]
        
        anomalies.append({
            'id': log.get('_id', ''),
            'timestamp': log.get('timestamp'),
            'source': log.get('source'),
            'message': log.get('message'),
            'type': anomaly_type,
            'severity': get_severity(anomaly_type, log),
            'is_threat': len(threat_ips) > 0,
            'mitre_tactic': MITRE_TACTICS.get(anomaly_type, "Unknown"),
            'recommendations': generate_recommendations(anomaly_type, log),
            'original_log': log
        })
    
    return anomalies

def get_severity(anomaly_type, log):
    """Determine severity level"""
    severity_map = {
        "brute_force": "high",
        "port_scan": "medium",
        "data_exfil": "critical",
        "config_change": "high",
        "data_access": "medium"
    }
    
    # Elevate severity if from threat IP
    if any(is_threat_ip(ip) for ip in extract_ips(log.get('message', ''))):
        return "critical"
    
    # Elevate severity if by non-privileged user
    user = log.get('user', '')
    if anomaly_type == "config_change" and user not in TRUSTED_USERS:
        return "critical"
    
    return severity_map.get(anomaly_type, "medium")

# ======================
# SAMPLE DATA GENERATION
# ======================
def generate_sample_anomalies():
    """Generate realistic test anomalies"""
    base_time = datetime.utcnow()
    
    samples = [
        # Brute Force
        {
            'message': {
                '_id': 'sample_001',
                'timestamp': (base_time - timedelta(minutes=5)).isoformat(),
                'source': 'auth-server-01',
                'message': 'Failed password for admin from 192.168.1.45 port 22 ssh2',
                'level': 5,
                'source_ip': '192.168.1.45',
                'user': 'admin'
            }
        },
        # Port Scan
        {
            'message': {
                '_id': 'sample_002',
                'timestamp': (base_time - timedelta(minutes=15)).isoformat(),
                'source': 'firewall-01',
                'message': 'Dropped inbound connection from 45.33.12.89 to port 22',
                'level': 4,
                'source_ip': '45.33.12.89'
            }
        },
        # Data Exfiltration
        {
            'message': {
                '_id': 'sample_003',
                'timestamp': (base_time - timedelta(minutes=30)).isoformat(),
                'source': 'proxy-01',
                'message': 'Large transfer: 1.2GB to 185.143.223.10 by rwilson',
                'level': 6,
                'user': 'rwilson'
            }
        }
    ]
    
    return analyze_logs(samples)

# ======================
# FLASK ROUTES
# ======================
@app.route('/')
def dashboard():
    """Main dashboard route"""
    # Get real anomalies
    logs = fetch_graylog_logs()
    real_anomalies = analyze_logs(logs)
    
    # Add samples for demonstration
    sample_anomalies = generate_sample_anomalies()
    
    return render_template(
        'index.html',
        anomalies=real_anomalies + sample_anomalies,
        stats=get_stats(real_anomalies + sample_anomalies)
    )

@app.route('/api/anomalies')
def api_anomalies():
    """JSON API endpoint"""
    query = request.args.get('query', '*')
    timeframe = int(request.args.get('timeframe', 15))
    
    logs = fetch_graylog_logs(query, timeframe)
    anomalies = analyze_logs(logs)
    
    return jsonify({
        'anomalies': anomalies,
        'patterns': detect_patterns(anomalies),
        'stats': get_stats(anomalies)
    })

@app.route('/api/stream')
def stream_anomalies():
    """Server-sent events stream"""
    def event_stream():
        last_ids = set()
        
        while True:
            logs = fetch_graylog_logs(timeframe=2)  # Last 2 minutes
            current_anomalies = analyze_logs(logs)
            new_anomalies = [a for a in current_anomalies if a['id'] not in last_ids]
            
            if new_anomalies:
                last_ids.update(a['id'] for a in new_anomalies)
                yield f"data: {json.dumps(new_anomalies)}\n\n"
            
            time.sleep(10)
    
    return Response(event_stream(), mimetype='text/event-stream')

@app.route('/api/feedback', methods=['POST'])
def handle_feedback():
    """Process user feedback on anomalies"""
    data = request.json
    
    log_to_graylog({
        "message": f"User feedback on anomaly {data.get('id')}",
        "action": data.get('action'),
        "user": data.get('user', 'anonymous'),
        "comments": data.get('comments', '')
    })
    
    return jsonify({"status": "success"})

# ======================
# SUPPORTING FUNCTIONS
# ======================
def get_stats(anomalies):
    """Generate statistics for dashboard"""
    severities = defaultdict(int)
    types = defaultdict(int)
    
    for anomaly in anomalies:
        severities[anomaly['severity']] += 1
        types[anomaly['type']] += 1
    
    return {
        'total': len(anomalies),
        'severities': dict(severities),
        'types': dict(types),
        'sla_compliance': 95  # Example value
    }

def detect_patterns(anomalies):
    """Detect common patterns in anomalies"""
    messages = [a['message'] for a in anomalies]
    common_terms = defaultdict(int)
    
    for msg in messages:
        words = re.findall(r'\b\w{4,}\b', msg.lower())
        for word in set(words):  # Count each word only once per message
            common_terms[word] += 1
    
    return sorted(common_terms.items(), key=lambda x: x[1], reverse=True)[:5]

# ======================
# RUN APPLICATION
# ======================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1235, debug=True)
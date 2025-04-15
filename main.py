from flask import Flask, render_template, jsonify, request
from analyzer import LogAnalyzer
from dotenv import load_dotenv
import os
import time
import requests
import hashlib

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Initialize analyzer with rate limiting
analyzer = LogAnalyzer()
analyzer.configure(
    graylog_api=os.getenv("GRAYLOG_API", "http://192.168.249.132:9000/api"),
    graylog_token=os.getenv("GRAYLOG_TOKEN"),
    groq_key=os.getenv("GROQ_API_KEY")
)

@app.route('/')
def dashboard():
    """Render the main dashboard page"""
    return render_template('index.html')

@app.route('/api/get-analysis')
def get_analysis():
    """Endpoint to fetch and analyze logs with caching"""
    try:
        # Get parameters
        query = request.args.get('query', '*').replace('sevverity', 'severity')
        severity = request.args.get('severity', 'all')
        
        # Process logs with caching
        logs = analyzer.process_logs(
            query=query,
            hours=24,
            limit=20
        )
        
        # Apply severity filter if needed
        if severity != 'all':
            logs = [log for log in logs if log.get("severity") == severity]
        
        # Calculate SLA metrics
        high_severity = sum(1 for log in logs if log.get("severity") in ["high", "critical"])
        sla = max(70, 95 - high_severity)

        response = {
            "anomalies": logs,
            "stats": {
                "total": len(logs),
                "sla": sla,
                "high_severity": high_severity,
                "medium_severity": sum(1 for log in logs if log.get("severity") == "medium"),
                "low_severity": sum(1 for log in logs if log.get("severity") == "low")
            },
            "cache_timestamp": int(time.time())
        }
        
        return jsonify(response)
        
    except Exception as e:
        app.logger.error(f"Analysis error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/test-connection')
def test_connection():
    """Test Graylog and Groq connectivity"""
    try:
        # Test Graylog
        gray_test = requests.get(
            f"{analyzer.graylog_api}/system",
            auth=(analyzer.graylog_token, "token"),
            timeout=5,
            verify=False
        )
        gray_ok = gray_test.status_code == 200
        
        # Test Groq
        groq_test = requests.post(
            analyzer.groq_api,
            headers={"Authorization": f"Bearer {analyzer.groq_key}"},
            json={"model": "llama3-70b-8192", "messages": [{"role": "user", "content": "test"}]},
            timeout=5
        )
        groq_ok = groq_test.status_code != 401
        
        return jsonify({
            "graylog": gray_ok,
            "groq": groq_ok,
            "graylog_version": gray_test.json().get("version") if gray_ok else None
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=1235, debug=True)

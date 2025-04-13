from flask import Flask, render_template
from datetime import datetime

app = Flask(__name__)

def prepare_anomalies(anomalies):
    """Ensure all anomalies have required fields and handle None values"""
    for anomaly in anomalies:
        # Set default user if None
        if anomaly.get('user') is None:
            anomaly['user'] = 'System'
        # Ensure all required fields exist
        anomaly.setdefault('icon', 'ℹ️')
        anomaly.setdefault('severity', 'medium')
        anomaly.setdefault('recommendations', [])
    return anomalies

@app.route('/')
def soc_interface():
    # Sample data
    message_count = {
        'id': '2020',
        'dates': ['Apr 12, 2025', 'Jan 10, 2025', 'Feb 11, 2025', 'Mar 14, 2025']
    }
    
    messages = [
        {
            'timestamp': '2020-04-13 12:30:33 LLP',
            'content': '[new_url=(com.google)](https://www.global.com/blog/2019/01/09/2020-04-13-12:30:33-LLP)',
            'details': 'session closed for over one'
        }
    ]
    
    anomalies = [
        {
            'user': 'admin',
            'severity': 'high',
            'icon': '⚠️',
            'title': 'Multiple Failed Logins',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'message': '5 failed login attempts within 2 minutes',
            'recommendations': [
                'Block IP temporarily',
                'Require CAPTCHA',
                'Notify security team'
            ]
        },
        {
            'user': None,  # Will be converted to 'System'
            'severity': 'low',
            'title': 'Configuration Change',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'message': 'Firewall rules modified'
        }
    ]
    
    # Prepare anomalies data
    processed_anomalies = prepare_anomalies(anomalies)
    
    return render_template('index.html',
                         message_count=message_count,
                         messages=messages,
                         anomalies=processed_anomalies)

if __name__ == '__main__':
    app.run(debug=True, port=1235)
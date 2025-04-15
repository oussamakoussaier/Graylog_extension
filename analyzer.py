import requests
import json
import logging
import time
import hashlib
from threading import Lock
from datetime import datetime, timedelta

class LogAnalyzer:
    def __init__(self):
        self.lock = Lock()
        self.setup_logging()
        self.last_api_call = 0
        self.min_call_interval = 1.0  # 1 second between API calls
        self.cache_expiry_hours = 6  # Cache logs for 6 hours
        self._analysis_cache = {}  # Server-side cache storage

    def setup_logging(self):
        self.logger = logging.getLogger('graylog_analyzer')
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)

    def configure(self, graylog_api, graylog_token, groq_key):
        self.graylog_api = graylog_api
        self.graylog_token = graylog_token
        self.groq_api = "https://api.groq.com/openai/v1/chat/completions"
        self.groq_key = groq_key
        
        self.ai_prompt = """Analyze this security log and return JSON with:
        - summary: Brief incident description
        - severity: low/medium/high/critical
        - actions: 3-5 remediation steps
        - threat_intel: Relevant threat context
        Log: {message}"""

    def get_log_hash(self, log_message):
        """Generate consistent hash for log messages"""
        return hashlib.md5(log_message.encode('utf-8')).hexdigest()

    def cache_analysis(self, key, analysis):
        """Cache analysis with timestamp"""
        self._analysis_cache[key] = {
            'analysis': analysis,
            'timestamp': datetime.now().isoformat()
        }

    def get_cached_analysis(self, key):
        """Get cached analysis if valid"""
        if key not in self._analysis_cache:
            return None
            
        cached = self._analysis_cache[key]
        cache_time = datetime.fromisoformat(cached['timestamp'])
        if datetime.now() - cache_time > timedelta(hours=self.cache_expiry_hours):
            del self._analysis_cache[key]  # Expired cache
            return None
            
        return cached['analysis']

    def fetch_logs(self, query="*", time_range=86400, limit=20):
        """Fetch logs from Graylog with enhanced error handling"""
        try:
            response = requests.get(
                f"{self.graylog_api}/search/universal/relative",
                headers={"Accept": "application/json"},
                params={
                    "query": query,
                    "range": time_range,
                    "limit": limit,
                    "filter": ""
                },
                auth=(self.graylog_token, "token"),
                timeout=15,
                verify=False
            )
            
            if response.status_code == 200:
                messages = response.json().get("messages", [])
                self.logger.info(f"Fetched {len(messages)} logs with query: {query}")
                return messages
            else:
                self.logger.error(f"Graylog API error: {response.text}")
                return []
                
        except Exception as e:
            self.logger.error(f"Graylog connection failed: {str(e)}")
            return []

    def analyze_with_ai(self, message, max_retries=3):
        """Analyze log with Groq API with caching and rate limiting"""
        log_hash = self.get_log_hash(message)
        cache_key = f"log_analysis_{log_hash}"
        
        # Check cache first
        cached = self.get_cached_analysis(cache_key)
        if cached:
            return cached
            
        for attempt in range(max_retries):
            try:
                # Enforce rate limiting
                elapsed = time.time() - self.last_api_call
                if elapsed < self.min_call_interval:
                    wait = self.min_call_interval - elapsed
                    time.sleep(wait)
                
                response = requests.post(
                    self.groq_api,
                    json={
                        "model": "llama3-70b-8192",
                        "messages": [{
                            "role": "user",
                            "content": self.ai_prompt.format(message=message)
                        }],
                        "response_format": {"type": "json_object"},
                        "temperature": 0.3
                    },
                    headers={
                        "Authorization": f"Bearer {self.groq_key}",
                        "Content-Type": "application/json"
                    },
                    timeout=20
                )
                
                self.last_api_call = time.time()
                
                if response.status_code == 429:
                    wait_time = min(5 * (attempt + 1), 30)
                    self.logger.warning(f"Rate limited, waiting {wait_time} seconds...")
                    time.sleep(wait_time)
                    continue
                    
                response.raise_for_status()
                result = json.loads(response.json()["choices"][0]["message"]["content"])
                
                # Cache the result before returning
                self.cache_analysis(cache_key, result)
                return result
                
            except Exception as e:
                self.logger.error(f"AI analysis attempt {attempt + 1} failed: {str(e)}")
                if attempt == max_retries - 1:
                    return {"error": str(e)}
                time.sleep(1)
        
        return {"error": "Max retries exceeded"}

    def process_logs(self, query="*", hours=24, limit=20):
        """Process logs with thread safety and caching"""
        with self.lock:
            results = []
            raw_logs = self.fetch_logs(query, hours*3600, limit)
            
            for log in raw_logs:
                msg = log.get("message", {})
                log_message = msg.get("message", "")
                analysis = self.analyze_with_ai(log_message)
                
                if "error" not in analysis:
                    results.append({
                        "id": msg.get("_id"),
                        "raw": log_message,
                        "analysis": analysis,
                        "source": msg.get("source"),
                        "timestamp": msg.get("timestamp"),
                        "severity": analysis.get("severity", "medium")
                    })
            
            self.logger.info(f"Processed {len(results)} anomalies from {len(raw_logs)} logs")
            return results

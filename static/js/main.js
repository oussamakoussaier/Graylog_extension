// Global State
let currentAnomalies = [];
let networkGraph = null;

// DOM Elements
const anomalyContainer = document.getElementById('anomaly-container');
const anomalyCount = document.getElementById('anomaly-count');
const queryInput = document.getElementById('graylog-query');
const applyQueryBtn = document.getElementById('apply-query');
const filterButtons = document.querySelectorAll('.filter-btn');
const tabButtons = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');
const logModal = document.getElementById('log-modal');
const closeModalBtn = document.querySelector('.close-btn');
const logContent = document.getElementById('log-content');

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    // Load initial data
    fetchAnomalies();
    
    // Set up event listeners
    setupEventListeners();
    
    // Initialize network graph
    initNetworkGraph();
    
    // Start live stream
    startLiveStream();
});

// Core Functions
function fetchAnomalies(query = '*') {
    fetch(`/api/anomalies?query=${encodeURIComponent(query)}`)
        .then(res => res.json())
        .then(data => {
            currentAnomalies = data.anomalies;
            updateAnomalyList(currentAnomalies);
            updateStats(data.stats);
            updatePatterns(data.patterns);
            updateNetworkGraph(currentAnomalies);
        })
        .catch(console.error);
}

function updateAnomalyList(anomalies) {
    anomalyContainer.innerHTML = '';
    anomalyCount.textContent = anomalies.length;
    
    anomalies.forEach(anomaly => {
        const card = document.createElement('div');
        card.className = `anomaly-card ${anomaly.severity} ${anomaly.is_threat ? 'threat' : ''}`;
        card.dataset.id = anomaly.id;
        
        card.innerHTML = `
            <div class="anomaly-header">
                <div class="anomaly-title">
                    <span>${anomaly.icon || '⚠️'}</span>
                    ${anomaly.title || 'Security Anomaly'}
                    ${anomaly.mitre_tactic ? `<span class="anomaly-mitre">${anomaly.mitre_tactic}</span>` : ''}
                </div>
                <div class="anomaly-timestamp">${new Date(anomaly.timestamp).toLocaleString()}</div>
            </div>
            <div class="anomaly-details">
                <div class="anomaly-message">${anomaly.message}</div>
                <div class="anomaly-actions">
                    <button class="action-btn false-positive">False Positive</button>
                    <button class="action-btn escalate">Escalate</button>
                    <button class="action-btn resolve">Mark Resolved</button>
                    <button class="action-btn view-log-btn">View Log</button>
                </div>
            </div>
        `;
        
        // Add click handlers
        const header = card.querySelector('.anomaly-header');
        header.addEventListener('click', () => {
            card.classList.toggle('active');
        });
        
        // Add action handlers
        card.querySelector('.false-positive').addEventListener('click', (e) => {
            e.stopPropagation();
            submitFeedback(anomaly.id, 'false_positive');
            card.remove();
        });
        
        card.querySelector('.view-log-btn').addEventListener('click', (e) => {
            e.stopPropagation();
            showLogModal(anomaly.original_log);
        });
        
        anomalyContainer.appendChild(card);
    });
}

function updateStats(stats) {
    // Update SLA display or other stats
    const slaBar = document.querySelector('.sla-bar');
    if (stats.sla_compliance) {
        slaBar.style.width = `${stats.sla_compliance}%`;
        slaBar.textContent = `${stats.sla_compliance}% SLA Compliance`;
    }
}

function updatePatterns(patterns) {
    const patternList = document.getElementById('pattern-list');
    patternList.innerHTML = '';
    
    patterns.forEach(pattern => {
        const li = document.createElement('li');
        li.className = 'pattern-item';
        li.textContent = `${pattern[0]} (${pattern[1]} occurrences)`;
        patternList.appendChild(li);
    });
}

// Visualization Functions
function initNetworkGraph() {
    const container = document.getElementById('ip-relations-graph');
    const nodes = new vis.DataSet();
    const edges = new vis.DataSet();
    
    const data = {
        nodes: nodes,
        edges: edges
    };
    
    const options = {
        nodes: {
            shape: 'dot',
            size: 16,
            font: {
                size: 12,
                color: '#000'
            },
            borderWidth: 2
        },
        edges: {
            width: 2,
            smooth: true
        },
        physics: {
            barnesHut: {
                gravitationalConstant: -2000,
                centralGravity: 0.3
            }
        }
    };
    
    networkGraph = new vis.Network(container, data, options);
}

function updateNetworkGraph(anomalies) {
    if (!networkGraph) return;
    
    const nodes = new vis.DataSet();
    const edges = new vis.DataSet();
    const nodeIds = new Set();
    
    // Extract IPs and build relationships
    anomalies.forEach(anomaly => {
        const ips = extractIPs(anomaly.message);
        
        ips.forEach(ip => {
            if (!nodeIds.has(ip)) {
                nodes.add({
                    id: ip,
                    label: ip,
                    color: anomaly.is_threat ? '#ff6b6b' : '#74b9ff'
                });
                nodeIds.add(ip);
            }
        });
        
        // Create edges between IPs in the same event
        for (let i = 0; i < ips.length; i++) {
            for (let j = i + 1; j < ips.length; j++) {
                edges.add({
                    from: ips[i],
                    to: ips[j],
                    label: anomaly.source,
                    color: getSeverityColor(anomaly.severity)
                });
            }
        }
    });
    
    networkGraph.setData({ nodes, edges });
}

function extractIPs(text) {
    const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
    return [...new Set(text.match(ipRegex) || [])];
}

function getSeverityColor(severity) {
    switch(severity) {
        case 'high': return '#e74c3c';
        case 'medium': return '#f39c12';
        case 'low': return '#2ecc71';
        default: return '#95a5a6';
    }
}

// Event Handlers
function setupEventListeners() {
    // Query controls
    applyQueryBtn.addEventListener('click', () => {
        fetchAnomalies(queryInput.value);
    });
    
    queryInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') fetchAnomalies(queryInput.value);
    });
    
    // Severity filters
    filterButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            filterButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            const severity = btn.dataset.severity;
            filterAnomalies(severity);
        });
    });
    
    // Tab switching
    tabButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            tabButtons.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            const tabId = `${btn.dataset.tab}-tab`;
            tabContents.forEach(content => content.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
        });
    });
    
    // Modal controls
    closeModalBtn.addEventListener('click', () => {
        logModal.style.display = 'none';
    });
    
    window.addEventListener('click', (e) => {
        if (e.target === logModal) {
            logModal.style.display = 'none';
        }
    });
}

function filterAnomalies(severity) {
    if (severity === 'all') {
        updateAnomalyList(currentAnomalies);
        return;
    }
    
    const filtered = currentAnomalies.filter(anomaly => {
        if (severity === 'threat') return anomaly.is_threat;
        return anomaly.severity === severity;
    });
    
    updateAnomalyList(filtered);
}

function showLogModal(logData) {
    logContent.textContent = JSON.stringify(logData, null, 2);
    logModal.style.display = 'flex';
}

// API Communication
function submitFeedback(anomalyId, action) {
    fetch('/api/feedback', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            id: anomalyId,
            action: action
        })
    }).catch(console.error);
}

function startLiveStream() {
    const eventSource = new EventSource('/api/stream');
    
    eventSource.onmessage = (e) => {
        const newAnomalies = JSON.parse(e.data);
        if (newAnomalies.length > 0) {
            showNotification(`${newAnomalies.length} new anomalies detected`);
            currentAnomalies = [...newAnomalies, ...currentAnomalies];
            updateAnomalyList(currentAnomalies);
            updateNetworkGraph(currentAnomalies);
        }
    };
    
    eventSource.onerror = () => {
        console.error('EventSource failed');
        setTimeout(startLiveStream, 5000);
    };
}

// UI Helpers
function showNotification(message, type = 'info') {
    const notif = document.createElement('div');
    notif.className = `notification ${type}`;
    notif.textContent = message;
    document.body.appendChild(notif);
    
    setTimeout(() => {
        notif.style.opacity = '0';
        setTimeout(() => notif.remove(), 300);
    }, 5000);
}
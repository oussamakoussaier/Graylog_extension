document.addEventListener('DOMContentLoaded', function() {
    // Initialize components
    const elements = {
        anomalyContainer: document.getElementById('anomaly-container'),
        anomalyCount: document.getElementById('anomaly-count'),
        slaBar: document.querySelector('.sla-bar'),
        queryInput: document.getElementById('graylog-query'),
        applyQueryBtn: document.getElementById('apply-query'),
        saveQueryBtn: document.getElementById('save-query'),
        filterButtons: document.querySelectorAll('.filter-btn'),
        tabButtons: document.querySelectorAll('.tab-btn'),
        tabContents: document.querySelectorAll('.tab-content'),
        logModal: document.getElementById('log-modal'),
        logContent: document.getElementById('log-content'),
        closeModalBtn: document.querySelector('.close-btn'),
        paginationContainer: document.createElement('div')
    };

    // Visualization instances
    let networkGraph, timeline;
    let currentData = null;
    let currentPage = 1;
    const itemsPerPage = 10;
    let activeSeverity = 'all';

    // Add pagination container to DOM
    elements.paginationContainer.className = 'pagination';
    elements.anomalyContainer.parentNode.insertBefore(
        elements.paginationContainer,
        elements.anomalyContainer.nextSibling
    );

    // Cache functions
    function getCacheKey(query, severity) {
        return `log_analysis_${query}_${severity}`;
    }

    function getCachedData(query, severity) {
        const cacheKey = getCacheKey(query, severity);
        const cached = localStorage.getItem(cacheKey);
        if (!cached) return null;
        
        try {
            const data = JSON.parse(cached);
            if (Date.now() - data.timestamp > 3600000) {
                localStorage.removeItem(cacheKey);
                return null;
            }
            return data.response;
        } catch {
            return null;
        }
    }

    function cacheData(query, severity, response) {
        const cacheKey = getCacheKey(query, severity);
        localStorage.setItem(cacheKey, JSON.stringify({
            response: response,
            timestamp: Date.now()
        }));
    }

    // Initialize network graph
    function initNetworkGraph() {
        const container = document.getElementById('ip-relations-graph');
        if (!container) return null;
        
        const nodes = new vis.DataSet([]);
        const edges = new vis.DataSet([]);
        return new vis.Network(container, { nodes, edges }, {
            nodes: { 
                shape: 'dot',
                size: 16,
                font: { size: 12 }
            },
            edges: { 
                width: 2,
                arrows: { to: { enabled: true, scaleFactor: 0.5 } }
            },
            physics: {
                barnesHut: { gravitationalConstant: -2000 }
            }
        });
    }

    // Initialize timeline
    function initTimeline() {
        const container = document.getElementById('timeline-view');
        if (!container) return null;
        
        const items = new vis.DataSet([]);
        return new vis.Timeline(container, items, {
            showCurrentTime: true,
            zoomable: true,
            margin: { item: 20 }
        });
    }

    // Setup tab switching
    function setupTabs() {
        elements.tabButtons.forEach(btn => {
            btn.addEventListener('click', () => {
                elements.tabButtons.forEach(b => b.classList.remove('active'));
                elements.tabContents.forEach(c => c.classList.remove('active'));
                btn.classList.add('active');
                document.getElementById(`${btn.dataset.tab}-tab`).classList.add('active');
                
                if (btn.dataset.tab === 'network' && !networkGraph) {
                    networkGraph = initNetworkGraph();
                } else if (btn.dataset.tab === 'timeline' && !timeline) {
                    timeline = initTimeline();
                }
            });
        });
        
        document.querySelector('.tab-btn.active')?.click();
    }

    // Create anomaly card HTML
    function createAnomalyCard(anomaly) {
        const card = document.createElement('div');
        card.className = `anomaly-card ${anomaly.severity}`;
        card.dataset.id = anomaly.id;
        
        const actions = anomaly.analysis?.actions || ['No actions recommended'];
        const threatIntel = anomaly.analysis?.threat_intel || 'No threat context available';
        const summary = anomaly.analysis?.summary || 'No analysis available';
        const rawLog = anomaly.raw || 'No log message available';
        const source = anomaly.source || 'Unknown';
        const timestamp = anomaly.timestamp || new Date().toISOString();
        
        card.innerHTML = `
            <div class="anomaly-header">
                <div class="header-content">
                    <div>
                        <span class="severity-badge">${anomaly.severity?.toUpperCase() || 'UNKNOWN'}</span>
                        <span class="source">${source}</span>
                    </div>
                    <div class="raw-log-header" title="${rawLog.replace(/"/g, '&quot;')}">
                        ${rawLog.substring(0, 100)}${rawLog.length > 100 ? '...' : ''}
                    </div>
                </div>
                <span class="timestamp">${new Date(timestamp).toLocaleTimeString()}</span>
            </div>
            <div class="anomaly-content">
                <div class="analysis">
                    <h4>Analysis:</h4>
                    <p>${summary}</p>
                </div>
                <div class="threat-intel">
                    <h4>Threat Context:</h4>
                    <p>${threatIntel}</p>
                </div>
                <div class="recommendations">
                    <h4>Recommended Actions:</h4>
                    <ul>
                        ${actions.map(a => `<li>${a}</li>`).join('')}
                    </ul>
                </div>
                <button class="view-log" data-log='${JSON.stringify(rawLog).replace(/'/g, "\\'")}'>
                    View Full Log
                </button>
            </div>
        `;
        
        card.addEventListener('click', function(e) {
            if (e.target.classList.contains('view-log')) {
                return;
            }
            
            const currentlyExpanded = document.querySelector('.anomaly-card.expanded');
            if (currentlyExpanded && currentlyExpanded !== this) {
                currentlyExpanded.classList.remove('expanded');
            }
            
            this.classList.toggle('expanded');
        });
        
        card.querySelector('.view-log')?.addEventListener('click', (e) => {
            e.stopPropagation();
            elements.logContent.textContent = e.target.dataset.log;
            elements.logModal.style.display = 'block';
        });
        
        return card;
    }

    // Update visualizations
    function updateVisualizations(anomalies) {
        if (networkGraph) {
            const nodes = [];
            const edges = [];
            const nodeIds = new Set();
            
            anomalies.forEach(anomaly => {
                const ips = (anomaly.raw || '').match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) || [];
                const source = anomaly.source || 'Unknown';
                
                ips.forEach(ip => {
                    if (!nodeIds.has(ip)) {
                        nodes.push({ 
                            id: ip, 
                            label: ip,
                            color: anomaly.severity === 'high' ? '#e74c3c' :
                                   anomaly.severity === 'critical' ? '#8e44ad' : '#3498db'
                        });
                        nodeIds.add(ip);
                    }
                });
                
                if (ips.length > 1) {
                    edges.push({ 
                        from: ips[0], 
                        to: ips[1],
                        label: source,
                        arrows: 'to'
                    });
                }
            });
            
            networkGraph.setData({ nodes, edges });
        }
        
        if (timeline) {
            const items = anomalies.map(anomaly => ({
                id: anomaly.id,
                content: `${(anomaly.severity || 'unknown').toUpperCase()}: ${anomaly.source || 'Unknown'}`,
                start: new Date(anomaly.timestamp || new Date()),
                type: 'point',
                className: anomaly.severity || 'unknown'
            }));
            timeline.setItems(items);
        }
        
        const patternList = document.getElementById('pattern-list');
        if (patternList) {
            const patterns = {};
            anomalies.forEach(a => {
                const key = `${a.source || 'Unknown'}-${a.severity || 'unknown'}`;
                patterns[key] = (patterns[key] || 0) + 1;
            });
            
            patternList.innerHTML = Object.entries(patterns)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5)
                .map(([pattern, count]) => `<li><strong>${pattern}</strong> (${count}x)</li>`)
                .join('');
        }
    }

    // Create pagination controls
    function createPagination(totalItems) {
        const totalPages = Math.ceil(totalItems / itemsPerPage);
        elements.paginationContainer.innerHTML = '';

        if (totalPages <= 1) return;

        // Previous button
        const prevButton = document.createElement('button');
        prevButton.innerHTML = '&laquo; Previous';
        prevButton.disabled = currentPage === 1;
        prevButton.addEventListener('click', () => {
            if (currentPage > 1) {
                currentPage--;
                renderAnomalies();
            }
        });
        elements.paginationContainer.appendChild(prevButton);

        // Page indicator
        const pageInfo = document.createElement('span');
        pageInfo.className = 'page-info';
        pageInfo.textContent = ` Page ${currentPage} of ${totalPages} `;
        elements.paginationContainer.appendChild(pageInfo);

        // Next button
        const nextButton = document.createElement('button');
        nextButton.innerHTML = 'Next &raquo;';
        nextButton.disabled = currentPage === totalPages;
        nextButton.addEventListener('click', () => {
            if (currentPage < totalPages) {
                currentPage++;
                renderAnomalies();
            }
        });
        elements.paginationContainer.appendChild(nextButton);
    }

    // Render anomalies for current page
    function renderAnomalies() {
        if (!currentData || !currentData.anomalies) {
            console.error('No data available to render');
            return;
        }
        
        const filteredAnomalies = activeSeverity === 'all' 
            ? currentData.anomalies 
            : currentData.anomalies.filter(a => a.severity === activeSeverity);

        const startIndex = (currentPage - 1) * itemsPerPage;
        const paginatedAnomalies = filteredAnomalies.slice(startIndex, startIndex + itemsPerPage);

        elements.anomalyContainer.innerHTML = '';

        if (paginatedAnomalies.length > 0) {
            paginatedAnomalies.forEach(anomaly => {
                elements.anomalyContainer.appendChild(createAnomalyCard(anomaly));
            });

            if (elements.anomalyCount) {
                elements.anomalyCount.textContent = filteredAnomalies.length;
            }
            
            createPagination(filteredAnomalies.length);
            updateVisualizations(filteredAnomalies);
        } else {
            elements.anomalyContainer.innerHTML = `
                <div class="no-results">
                    <p>No ${activeSeverity === 'all' ? '' : activeSeverity + ' severity'} anomalies detected</p>
                    <p>Try adjusting your query or time range</p>
                </div>
            `;
            elements.paginationContainer.innerHTML = '';
        }
    }

    // Filter anomalies by severity
    function filterAnomalies(severity) {
        activeSeverity = severity;
        currentPage = 1;
        renderAnomalies();
    }

    // Update UI with new data
    function updateUI(data) {
        if (!data || !data.anomalies) {
            console.error('Invalid data received:', data);
            showError({ message: 'Invalid data format received from server' });
            return;
        }

        hideLoading();
        currentData = data;
        currentPage = 1;
        activeSeverity = document.querySelector('.filter-btn.active')?.dataset.severity || 'all';
        renderAnomalies();
        
        if (elements.slaBar && data.stats?.sla) {
            elements.slaBar.style.width = `${data.stats.sla}%`;
            elements.slaBar.textContent = `${data.stats.sla}% SLA`;
        }
    }

    // Show loading indicator
    function showLoading() {
        const loadingIndicator = document.createElement('div');
        loadingIndicator.className = 'loading';
        loadingIndicator.textContent = 'Loading anomalies...';
        loadingIndicator.id = 'loading-indicator';
        elements.anomalyContainer.innerHTML = '';
        elements.anomalyContainer.appendChild(loadingIndicator);
    }

    // Show error message
    function showError(error) {
        hideLoading();
        
        const errorElement = document.createElement('div');
        errorElement.className = 'error';
        errorElement.innerHTML = `
            <p>Error loading anomalies</p>
            <p>${error.message}</p>
            <button onclick="window.refreshData()">Retry</button>
        `;
        elements.anomalyContainer.innerHTML = '';
        elements.anomalyContainer.appendChild(errorElement);
    }

    // Hide loading indicator
    function hideLoading() {
        const loadingElement = document.getElementById('loading-indicator');
        if (loadingElement) loadingElement.remove();
    }

    // Fetch fresh data from server
    function fetchFreshData(query, severity) {
        fetch(`/api/get-analysis?query=${encodeURIComponent(query)}&severity=all`)
            .then(response => {
                if (!response.ok) throw new Error(`Server returned ${response.status}`);
                return response.json();
            })
            .then(data => {
                if (!data?.anomalies) {
                    throw new Error('Invalid data format: missing anomalies array');
                }
                cacheData(query, severity, data);
                updateUI(data);
            })
            .catch(error => {
                console.error('Fetch error:', error);
                showError(error);
            });
    }

    // Refresh data with caching
    function refreshData() {
        const query = elements.queryInput?.value || '*';
        const severity = 'all';
        
        showLoading();
        
        const cached = getCachedData(query, severity);
        if (cached) {
            updateUI(cached);
        }
        
        fetchFreshData(query, severity);
    }

    // Initialize modal
    function setupModal() {
        elements.closeModalBtn?.addEventListener('click', () => {
            elements.logModal.style.display = 'none';
        });
        
        window.addEventListener('click', (e) => {
            if (e.target === elements.logModal) {
                elements.logModal.style.display = 'none';
            }
        });
    }

    // Initialize filter buttons
    function setupFilters() {
        elements.filterButtons?.forEach(btn => {
            btn.addEventListener('click', function() {
                elements.filterButtons.forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                filterAnomalies(this.dataset.severity);
            });
        });
    }

    // Initialize query controls
    function setupQueryControls() {
        elements.applyQueryBtn?.addEventListener('click', refreshData);
        
        elements.saveQueryBtn?.addEventListener('click', () => {
            localStorage.setItem('savedQuery', elements.queryInput.value);
            alert('Query saved to browser storage');
        });
        
        const savedQuery = localStorage.getItem('savedQuery');
        if (savedQuery && elements.queryInput) {
            elements.queryInput.value = savedQuery;
        }
    }

    // Initialize all components
    function initialize() {
        setupTabs();
        setupModal();
        setupFilters();
        setupQueryControls();
        
        refreshData();
        setInterval(refreshData, 30000);
    }

    // Start the application
    initialize();

    // Make refreshData available globally for retry button
    window.refreshData = refreshData;
});

const API_URL = 'http://localhost:8081';
let currentPage = 1;
let currentView = 'home';
let isSearching = false;
let isGithubSearching = false;

// Load homepage on page load
document.addEventListener('DOMContentLoaded', () => {
    loadHomepage();
    loadHeatmap();
});

async function loadHomepage() {
    try {
        const res = await fetch(`${API_URL}/api/home`);
        const data = await res.json();
        
        let html = '<div class="grid grid-cols-1 lg:grid-cols-2 gap-8">';
        
        // NVD Section
        html += '<div>';
        html += '<h2 class="text-2xl font-bold text-gray-900 mb-4">NVD Vulnerabilities</h2>';
        html += '<div class="space-y-3">';
        if (data.nvd && data.nvd.length > 0) {
            data.nvd.forEach(vuln => {
                html += renderVulnerabilityNVD(vuln);
            });
        } else {
            html += '<p class="text-gray-500">No vulnerabilities found. Try syncing NVD data.</p>';
        }
        html += '</div></div>';
        
        // GitHub Section
        html += '<div>';
        html += '<h2 class="text-2xl font-bold text-gray-900 mb-4">GitHub Advisories</h2>';
        html += '<div class="space-y-3">';
        if (data.github && data.github.length > 0) {
            data.github.forEach(advisory => {
                html += renderVulnerabilityGithub(advisory);
            });
        } else {
            html += '<p class="text-gray-500">No advisories found. Try syncing GitHub data.</p>';
        }
        html += '</div></div>';
        
        html += '</div>';
        document.getElementById('container').innerHTML = html;
    } catch (err) {
        showError('Failed to load homepage: ' + err.message);
    }
}

async function loadAllNVD(page = 1) {
    try {
        const limit = 20;
        const res = await fetch(`${API_URL}/api/nvd?page=${page}&limit=${limit}`);
        const data = await res.json();
        
        let html = '<h2 class="text-2xl font-bold text-gray-900 mb-4">All NVD Vulnerabilities</h2>';
        html += '<div class="space-y-3">';
        
        if (data && data.length > 0) {
            data.forEach(vuln => {
                html += renderVulnerabilityNVD(vuln);
            });
        } else {
            html += '<p class="text-gray-500">No vulnerabilities found.</p>';
        }
        
        html += '</div>';
        
        // Pagination controls
        html += '<div class="mt-6 flex justify-center gap-4">';
        if (page > 1) {
            html += `<button onclick="loadAllNVD(${page - 1})" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Previous</button>`;
        }
        html += `<span class="px-4 py-2 text-gray-700">Page ${page}</span>`;
        if (data && data.length >= limit) {
            html += `<button onclick="loadAllNVD(${page + 1})" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Next</button>`;
        }
        html += '</div>';
        
        document.getElementById('container').innerHTML = html;
        currentPage = page;
        currentView = 'nvd';
    } catch (err) {
        showError('Failed to load NVD data: ' + err.message);
    }
}

async function loadAllGithub(page = 1) {
    try {
        const limit = 20;
        const res = await fetch(`${API_URL}/api/github?page=${page}&limit=${limit}`);
        const data = await res.json();
        
        // debugging the frontend
        // console.log('GitHub data:', data);
        // console.log('Data length:', data ? data.length : 'null');
        // console.log('Data is array?', Array.isArray(data));
        // console.log('Limit:', limit);
        // console.log('Should show next?', data && data.length >= limit);
        
        let html = '<h2 class="text-2xl font-bold text-gray-900 mb-4">All GitHub Advisories</h2>';
        html += '<div class="space-y-3">';
        
        if (data && data.length > 0) {
            data.forEach(advisory => {
                html += renderVulnerabilityGithub(advisory);
            });
        } else {
            html += '<p class="text-gray-500">No advisories found.</p>';
        }
        
        html += '</div>';
        
        // Pagination controls
        html += '<div class="mt-6 flex justify-center gap-4">';
        if (page > 1) {
            html += `<button onclick="loadAllGithub(${page - 1})" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Previous</button>`;
        }
        html += `<span class="px-4 py-2 text-gray-700">Page ${page}</span>`;
        if (data && data.length >= limit) {
            html += `<button onclick="loadAllGithub(${page + 1})" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Next</button>`;
        }
        html += '</div>';
        
        document.getElementById('container').innerHTML = html;
        currentPage = page;
        currentView = 'github';
    } catch (err) {
        showError('Failed to load GitHub data: ' + err.message);
    }
}

async function searchNVD(page = 1) {
    if (isSearching) return;
    isSearching = true;
    
    // const query = document.getElementById('nvdSearch').value.trim();
    const searchInput = document.getElementById('nvdSearch').value.trim();
    const [query, version] = searchInput.split(':');
    const limit = 50;
    if (!query) {
        alert('Please enter a search term');
        isSearching = false;
        return;
    }

    try {
        const res = await fetch(`${API_URL}/api/nvd/search?service=${encodeURIComponent(query)}&version=${encodeURIComponent(version || '')}&page=${page}&limit=${limit}`);
        const data = await res.json();
        
        let html = `<h2 class="text-2xl font-bold text-gray-900 mb-4">NVD Search Results for "${query}:v${version || ''}"</h2>`;
        html += '<div class="space-y-3">';
        
        if (data && data.length > 0) {
            data.forEach(vuln => {
                html += renderVulnerabilityNVD(vuln);
            });
        } else {
            html += '<p class="text-gray-500">No results found.</p>';
        }
        

        html += '</div>';



         // Pagination controls
        html += '<div class="mt-6 flex justify-center gap-4">';
        if (page > 1) {
            html += `<button onclick="searchNVD(${page - 1})" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Previous</button>`;
        }
        html += `<span class="px-4 py-2 text-gray-700">Page ${page}</span>`;
        if (data && data.length >= limit) {
            html += `<button onclick="searchNVD(${page + 1})" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Next</button>`;
        }
        html += '</div>';
        
        document.getElementById('container').innerHTML = html;
        currentPage = page;
        currentView = 'nvd';
    } catch (err) {
        showError('Search failed: ' + err.message);
    } finally {
        isSearching = false;
    }
}

async function searchGithub(page = 1) {
    if (isGithubSearching) return;
    isGithubSearching = true;

    const searchInput = document.getElementById('githubSearch').value.trim();
    const [query, version] = searchInput.split(':');
    const limit = 20;
    if (!query) {
        alert('Please enter a search term');
        isGithubSearching = false;
        return;
    }

    try {
        const res = await fetch(`${API_URL}/api/github/search?advisory=${encodeURIComponent(query)}&version=${encodeURIComponent(version || '')}&page=${page}&limit=${limit}`);
        const data = await res.json();
        
        let html = `<h2 class="text-2xl font-bold text-gray-900 mb-4">GitHub Search Results for "${query}:v${version || ''}"</h2>`;
        html += '<div class="space-y-3">';
        
        if (data && data.length > 0) {
            data.forEach(advisory => {
                html += renderVulnerabilityGithub(advisory);
            });
        } else {
            html += '<p class="text-gray-500">No results found.</p>';
        }
        
        html += '</div>';
        // Pagination controls
        html += '<div class="mt-6 flex justify-center gap-4">';
        if (page > 1) {
            html += `<button onclick="searchGithub(${page - 1})" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Previous</button>`;
        }
        html += `<span class="px-4 py-2 text-gray-700">Page ${page}</span>`;
        if (data && data.length >= limit) {
            html += `<button onclick="searchGithub(${page + 1})" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Next</button>`;
        }
        html += '</div>';
        
        document.getElementById('container').innerHTML = html;
        currentPage = page;
        currentView = 'github';
    } catch (err) {
        showError('Search failed: ' + err.message);
    } finally {
        isGithubSearching = false;
    }
        
}

async function syncNVD() {
    try {
        const statusEl = document.getElementById('syncStatus');
        statusEl.textContent = 'Syncing NVD...';
        statusEl.className = 'text-sm text-blue-600 self-center';
        
        const res = await fetch(`${API_URL}/api/sync/nvd`);
        
        if (res.status === 202) {
            statusEl.textContent = 'NVD sync started in background';
            statusEl.className = 'text-sm text-green-600 self-center';
            setTimeout(() => {
                statusEl.textContent = '';
                loadHomepage();
            }, 3000);
        } else {
            throw new Error(`Unexpected status: ${res.status}`);
        }
    } catch (err) {
        showError('Sync failed: ' + err.message);
    }
}

async function syncGithub() {
    try {
        const statusEl = document.getElementById('syncStatus');
        statusEl.textContent = 'Syncing GitHub...';
        statusEl.className = 'text-sm text-blue-600 self-center';
        
        const res = await fetch(`${API_URL}/api/sync/github`);
        
        if (res.status === 202) {
            statusEl.textContent = 'GitHub sync started in background';
            statusEl.className = 'text-sm text-green-600 self-center';
            setTimeout(() => {
                statusEl.textContent = '';
                loadHomepage();
            }, 3000);
        } else {
            throw new Error(`Unexpected status: ${res.status}`);
        }
    } catch (err) {
        showError('Sync failed: ' + err.message);
    }
}

function switchView() {
    const view = document.getElementById('viewSelect').value;
    console.log('switchView called with:', view);
    
    switch (view) {
        case 'home':
            console.log('Loading homepage');
            loadHomepage();
            break;
        case 'nvd':
            console.log('Loading NVD');
            loadAllNVD();
            break;
        case 'github':
            console.log('Loading GitHub');
            loadAllGithub();
            break;
    }
}

// Helper: Render NVD vulnerability card
function renderVulnerabilityNVD(vuln) {
    const severityColor = getSeverityColor(vuln.BaseScore);
    
    return `
        <div class="border border-gray-200 rounded-lg p-4 hover:shadow-lg transition">
            <div class="flex justify-between items-start mb-2">
                <h3 class="font-bold text-lg text-gray-900">${escapeHtml(vuln.CVEID)}</h3>
                <span class="${severityColor} px-3 py-1 rounded-full text-sm font-semibold">
                    ${vuln.BaseScore.toFixed(1)}
                </span>
            </div>
            <p class="text-sm text-gray-600 mb-2">${escapeHtml(vuln.Description || 'No description')}</p>
            <div class="text-xs text-gray-500 space-y-1">
                <p><strong>Source:</strong> ${escapeHtml(vuln.SourceIdentifier)}</p>
                <p><strong>Published:</strong> ${new Date(vuln.Published).toLocaleDateString()}</p>
                <p><strong>Last Modified:</strong> ${new Date(vuln.LastModified).toLocaleDateString()}</p>
            </div>
        </div>
    `;
}

// Helper: Render GitHub advisory card
function renderVulnerabilityGithub(advisory) {
    const severityColor = getSeverityColorGithub(advisory.Severity);
    
    return `
        <div class="border border-gray-200 rounded-lg p-4 hover:shadow-lg transition">
            <div class="flex justify-between items-start mb-2">
                <div>
                    <h3 class="font-bold text-lg text-gray-900">${escapeHtml(advisory.GHSAID)}</h3>
                    ${advisory.CVEID ? `<p class="text-sm text-gray-600">${escapeHtml(advisory.CVEID)}</p>` : ''}
                </div>
                <span class="${severityColor} px-3 py-1 rounded-full text-sm font-semibold">
                    ${advisory.Severity.toUpperCase()}
                </span>
            </div>
            <p class="text-sm font-semibold text-gray-800 mb-1">${escapeHtml(advisory.Summary)}</p>
            <p class="text-sm text-gray-600 mb-2">${escapeHtml(advisory.Description || 'No description')}</p>
            <div class="text-xs text-gray-500">
                <p><strong>Type:</strong> ${escapeHtml(advisory.Type)}</p>
                <p><strong>Published:</strong> ${new Date(advisory.Published).toLocaleDateString()}</p>
            </div>
        </div>
    `;
}

// Helper: Get color by CVSS score
function getSeverityColor(score) {
    if (score >= 9) return 'bg-red-500 text-white';
    if (score >= 7) return 'bg-orange-500 text-white';
    if (score >= 4) return 'bg-yellow-500 text-white';
    return 'bg-green-500 text-white';
}

// Helper: Get color by GitHub severity
function getSeverityColorGithub(severity) {
    switch (severity.toLowerCase()) {
        case 'critical':
            return 'bg-red-600 text-white';
        case 'high':
            return 'bg-red-500 text-white';
        case 'moderate':
            return 'bg-yellow-500 text-white';
        case 'low':
            return 'bg-green-500 text-white';
        default:
            return 'bg-gray-500 text-white';
    }
}

// Helper: Escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Helper: Show error
function showError(message) {
    const container = document.getElementById('container');
    container.innerHTML = `
        <div class="bg-red-50 border border-red-200 text-red-800 px-4 py-3 rounded-lg">
            <p class="font-semibold">Error</p>
            <p class="text-sm">${escapeHtml(message)}</p>
        </div>
    `;
}

// Load heatmap
async function loadHeatmap() {
    try {
        const res = await fetch(`${API_URL}/api/heatmap`);
        const data = await res.json();
        
        const ctx = document.getElementById('heatmapChart').getContext('2d');
        new Chart(ctx, {
            type: 'bubble',
            data: {
                datasets: [{
                    label: 'Vulnerability Severity',
                    data: data.map(p => ({
                        x: p.x,
                        y: p.y,
                        r: Math.max(p.y, 5),
                        cve: p.cve,
                        description: p.description,
                        published: p.published
                    })),
                    backgroundColor: data.map(p => {
                        if (p.y >= 9) return 'rgba(255, 0, 0, 0.7)'; // Red
                        if (p.y >= 7) return 'rgba(255, 127, 0, 0.7)'; // Orange
                        if (p.y >= 4) return 'rgba(255, 255, 0, 0.7)'; // Yellow
                        return 'rgba(0, 255, 0, 0.7)'; // Green
                    })
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        callbacks: {
                            title: (context) => context[0].raw.cve,
                            label: (context) => `Score: ${context.raw.y.toFixed(1)}`,
                            afterLabel: (context) => [
                                `Published: ${new Date(context.raw.published).toISOString().split('T')[0]}`,
                                `${context.raw.description}`
                            ]
                        },
                        padding: 12,
                        backgroundColor: 'rgba(0,0,0,0.8)',
                        displayColors: false
                    }
                }
            }
        });
    } catch (err) {
        console.error('Failed to load heatmap: ' + err.message);
    }
}

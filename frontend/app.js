/**
 * CodeSentinel AI — Dashboard Application Logic
 * Communicates with the Spring Boot backend REST API
 */

const API_BASE = 'http://localhost:8080/api';

// ── Health Check ──────────────────────────────────────────────
async function checkHealth() {
    // Backend
    try {
        const res = await fetch(`${API_BASE}/webhook/health`, { signal: AbortSignal.timeout(3000) });
        if (res.ok) {
            document.getElementById('backend-status').classList.add('online');
            document.getElementById('backend-status').classList.remove('offline');
        }
    } catch {
        document.getElementById('backend-status').classList.add('offline');
        document.getElementById('backend-status').classList.remove('online');
    }

    // AI Engine
    try {
        const res = await fetch('http://localhost:8000/api/health', { signal: AbortSignal.timeout(3000) });
        if (res.ok) {
            document.getElementById('ai-status').classList.add('online');
            document.getElementById('ai-status').classList.remove('offline');
        }
    } catch {
        document.getElementById('ai-status').classList.add('offline');
        document.getElementById('ai-status').classList.remove('online');
    }
}

// Check health every 10s
checkHealth();
setInterval(checkHealth, 10000);

// ── Pipeline Animation ───────────────────────────────────────
const PIPELINE_STEPS = ['webhook', 'static', 'ai-analyzer', 'security', 'fix', 'review'];

function resetPipeline() {
    document.querySelectorAll('.pipeline-step').forEach(step => {
        step.classList.remove('active', 'completed');
        step.querySelector('.step-status').textContent = 'Waiting';
    });
    document.querySelectorAll('.pipeline-connector').forEach(c => {
        c.classList.remove('active');
    });
}

function animatePipelineStep(stepName, status) {
    const step = document.querySelector(`.pipeline-step[data-step="${stepName}"]`);
    if (!step) return;

    if (status === 'active') {
        step.classList.add('active');
        step.classList.remove('completed');
        step.querySelector('.step-status').textContent = 'Processing...';
    } else if (status === 'completed') {
        step.classList.remove('active');
        step.classList.add('completed');
        step.querySelector('.step-status').textContent = 'Done ✓';

        // Activate the connector after this step
        const connectors = document.querySelectorAll('.pipeline-connector');
        const stepIndex = PIPELINE_STEPS.indexOf(stepName);
        if (stepIndex >= 0 && stepIndex < connectors.length) {
            connectors[stepIndex].classList.add('active');
        }
    }
}

async function simulatePipeline() {
    const delays = [300, 600, 800, 700, 600, 500];

    for (let i = 0; i < PIPELINE_STEPS.length; i++) {
        animatePipelineStep(PIPELINE_STEPS[i], 'active');
        await sleep(delays[i]);
        animatePipelineStep(PIPELINE_STEPS[i], 'completed');
    }
}

function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
}

// ── Trigger Review ───────────────────────────────────────────
async function triggerReview() {
    const repo = document.getElementById('repo-input').value.trim();
    const prNumber = document.getElementById('pr-input').value.trim();
    const btn = document.getElementById('trigger-btn');
    const statusEl = document.getElementById('trigger-status');

    if (!repo || !prNumber) {
        showStatus('Please fill in repository and PR number', 'error');
        return;
    }

    // Disable button
    btn.disabled = true;
    btn.classList.add('loading');
    btn.querySelector('.btn-icon').textContent = '⟳';

    // Reset UI
    resetPipeline();
    document.getElementById('results-panel').classList.add('hidden');
    document.getElementById('comment-panel').classList.add('hidden');

    showStatus('Starting security review...', 'loading');

    // Animate pipeline while waiting
    const pipelinePromise = simulatePipeline();

    try {
        const url = `${API_BASE}/reviews/trigger?repo=${encodeURIComponent(repo)}&prNumber=${prNumber}`;
        const res = await fetch(url, { method: 'POST' });
        const data = await res.json();

        await pipelinePromise;

        if (res.ok) {
            showStatus(
                `✓ Review complete! Found ${data.totalVulnerabilities} vulnerabilities. Risk: ${data.riskScore}/100`,
                'success'
            );

            // Fetch full results
            if (data.reviewId && data.reviewId !== 'N/A') {
                await loadReviewResults(data.reviewId);
            }
        } else {
            showStatus(`Error: ${data.error || 'Unknown error'}`, 'error');
        }
    } catch (err) {
        await pipelinePromise;
        showStatus(`Connection error: ${err.message}. Is the backend running on localhost:8080?`, 'error');
    } finally {
        btn.disabled = false;
        btn.classList.remove('loading');
        btn.querySelector('.btn-icon').textContent = '▶';
    }
}

// ── Load Review Results ──────────────────────────────────────
async function loadReviewResults(reviewId) {
    try {
        const res = await fetch(`${API_BASE}/reviews/${reviewId}`);
        const review = await res.json();

        // Show results panel
        const resultsPanel = document.getElementById('results-panel');
        resultsPanel.classList.remove('hidden');

        // Update stats
        document.getElementById('stat-critical').textContent = review.criticalCount || 0;
        document.getElementById('stat-high').textContent = review.highCount || 0;
        document.getElementById('stat-medium').textContent = review.mediumCount || 0;
        document.getElementById('stat-low').textContent = review.lowCount || 0;
        document.getElementById('stat-static').textContent = review.staticFindings || 0;
        document.getElementById('stat-ai').textContent = review.aiFindings || 0;

        // Update risk badge
        const riskBadge = document.getElementById('risk-badge');
        const score = review.overallRiskScore || 0;
        riskBadge.textContent = `${Math.round(score)} / 100`;
        riskBadge.className = 'risk-badge ' + getRiskClass(score);

        // Render vulnerabilities
        renderVulnerabilities(review.vulnerabilities || []);

        // Show PR comment
        if (review.simulatedPrComment) {
            showPrComment(review.simulatedPrComment);
        }

        // Smooth scroll to results
        resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });

    } catch (err) {
        console.error('Failed to load results:', err);
    }
}

function getRiskClass(score) {
    if (score >= 75) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 25) return 'medium';
    return 'low';
}

// ── Render Vulnerabilities ───────────────────────────────────
function renderVulnerabilities(vulns) {
    const container = document.getElementById('vulns-list');
    container.innerHTML = '';

    if (vulns.length === 0) {
        container.innerHTML = '<div class="vuln-card"><p style="text-align:center;color:var(--success)">🎉 No vulnerabilities found!</p></div>';
        return;
    }

    vulns.forEach((v, i) => {
        const card = document.createElement('div');
        card.className = 'vuln-card';
        card.style.animationDelay = `${i * 0.08}s`;

        const severityClass = (v.severity || 'medium').toLowerCase();
        const sourceLabel = v.source === 'AI' ? '🤖 AI' : '🔍 Static';

        card.innerHTML = `
            <div class="vuln-card-header">
                <span class="vuln-title">${escapeHtml(v.vulnerability || 'Unknown')}</span>
                <div class="vuln-badges">
                    <span class="severity-badge ${severityClass}">${v.severity || 'MEDIUM'}</span>
                    <span class="owasp-badge">${escapeHtml(v.owasp || 'N/A')}</span>
                    <span class="source-badge">${sourceLabel}</span>
                </div>
            </div>
            <div class="vuln-file">📄 ${escapeHtml(v.file || 'unknown')}${v.lineNumber ? ` : line ${v.lineNumber}` : ''}</div>
            <div class="vuln-detail"><strong>Issue:</strong> ${escapeHtml(v.issue || '')}</div>
            <div class="vuln-detail"><strong>Explanation:</strong> ${escapeHtml(v.explanation || '')}</div>
            <div class="vuln-fix">💡 <strong>Fix:</strong> ${escapeHtml(v.fix || '')}</div>
        `;

        container.appendChild(card);
    });
}

// ── PR Comment ───────────────────────────────────────────────
function showPrComment(comment) {
    const panel = document.getElementById('comment-panel');
    const preview = document.getElementById('comment-preview');
    panel.classList.remove('hidden');
    preview.textContent = comment;
}

function copyComment() {
    const text = document.getElementById('comment-preview').textContent;
    navigator.clipboard.writeText(text).then(() => {
        const btn = document.querySelector('.comment-panel .btn-secondary');
        btn.textContent = '✓ Copied!';
        setTimeout(() => { btn.textContent = '📋 Copy'; }, 2000);
    });
}

// ── Utilities ────────────────────────────────────────────────
function showStatus(message, type) {
    const el = document.getElementById('trigger-status');
    el.textContent = message;
    el.className = `trigger-status ${type}`;
    el.classList.remove('hidden');
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

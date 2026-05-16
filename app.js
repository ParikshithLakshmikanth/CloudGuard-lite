// ── Element refs ──────────────────────────────────────────────────────────────
const scanBtn          = document.getElementById('scanBtn');
const clearBtn         = document.getElementById('clearBtn');
const configInput      = document.getElementById('configInput');
const resultsSection   = document.getElementById('resultsSection');
const resultsContainer = document.getElementById('resultsContainer');
const resultsLabel     = document.getElementById('resultsLabel');
const scoreRow         = document.getElementById('scoreRow');
const scoreNum         = document.getElementById('scoreNum');
const scoreGrade       = document.getElementById('scoreGrade');
const scoreRing        = document.getElementById('scoreRing');
const scanOverlay      = document.getElementById('scanOverlay');
const scanText         = document.getElementById('scanText');
const scanRule         = document.getElementById('scanRule');
const scanBar          = document.getElementById('scanBar');
const exportBtn        = document.getElementById('exportBtn');
const historySection   = document.getElementById('historySection');
const historyContainer = document.getElementById('historyContainer');
const clearHistoryBtn  = document.getElementById('clearHistoryBtn');
const filterBar        = document.getElementById('filterBar');
const typedText        = document.getElementById('typedText');
const detectedBadge    = document.getElementById('detectedBadge');
const heatmapSection   = document.getElementById('heatmapSection');
const heatmapGrid      = document.getElementById('heatmapGrid');
const cleanSection     = document.getElementById('cleanSection');
const cleanOutput      = document.getElementById('cleanOutput');
const copyCleanBtn     = document.getElementById('copyCleanBtn');
const downloadCleanBtn = document.getElementById('downloadCleanBtn');
const copiedToast      = document.getElementById('copiedToast');

let lastFindings  = [];
let scanHistory   = [];
let activeFilter  = 'all';
let lastConfig    = '';

// ── Typing animation ──────────────────────────────────────────────────────────
const typingPhrases = [
  "exposed credentials...",
  "open firewall rules...",
  "encryption misconfigs...",
  "hardcoded secrets...",
  "public S3 buckets...",
  "disabled MFA...",
  "weak password policies...",
  "unmonitored resources..."
];

let phraseIndex = 0, charIndex = 0, isDeleting = false;

function typeLoop() {
  const current = typingPhrases[phraseIndex];
  charIndex += isDeleting ? -1 : 1;
  typedText.textContent = current.substring(0, charIndex);

  if (!isDeleting && charIndex === current.length) {
    isDeleting = true;
    setTimeout(typeLoop, 1800);
    return;
  }
  if (isDeleting && charIndex === 0) {
    isDeleting = false;
    phraseIndex = (phraseIndex + 1) % typingPhrases.length;
  }
  setTimeout(typeLoop, isDeleting ? 40 : 70);
}
typeLoop();

// ── Format Auto-Detector ──────────────────────────────────────────────────────
function detectFormat(text) {
  if (!text.trim()) return null;
  try { JSON.parse(text); return 'JSON'; } catch {}
  if (/resource\s+"[^"]+"\s+"[^"]+"/.test(text) ||
      /^\s*(variable|output|provider|terraform)\s+/m.test(text)) return 'Terraform';
  if (/^\s*[\w\-]+\s*:/m.test(text)) return 'YAML';
  return 'Unknown';
}

configInput.addEventListener('input', () => {
  const fmt = detectFormat(configInput.value);
  if (fmt) {
    detectedBadge.textContent = `📄 ${fmt}`;
    detectedBadge.classList.add('visible');
  } else {
    detectedBadge.classList.remove('visible');
  }
});

// ── Clear ─────────────────────────────────────────────────────────────────────
clearBtn.addEventListener('click', () => {
  configInput.value = '';
  resultsContainer.innerHTML = '';
  resultsLabel.innerHTML = '';
  scoreRow.classList.add('hidden');
  resultsSection.classList.add('hidden');
  filterBar.classList.add('hidden');
  heatmapSection.classList.add('hidden');
  cleanSection.classList.add('hidden');
  detectedBadge.classList.remove('visible');
  configInput.focus();
});

// ── Scan ──────────────────────────────────────────────────────────────────────
scanBtn.addEventListener('click', () => {
  const config = configInput.value.trim();
  if (!config) { alert('Please paste a config before scanning!'); return; }
  lastConfig = config;
  animateScan(config);
});

function animateScan(config) {
  scanOverlay.classList.remove('hidden');
  scanBar.style.width = '0%';

  const steps = [
    { msg: "Initializing rule engine...",       rule: "" },
    { msg: "Parsing config format...",           rule: "Format detection" },
    ...RULES.slice(0, 6).map(r => ({
      msg:  "Checking rule...",
      rule: `→ ${r.id}: ${r.name}`
    })),
    { msg: "Calculating security score...",      rule: "Scoring engine" },
    { msg: "Generating clean config...",         rule: "Fix generator" },
    { msg: "Scan complete!",                     rule: "" },
  ];

  let step = 0;
  const interval = setInterval(() => {
    if (step < steps.length) {
      scanText.textContent = steps[step].msg;
      scanRule.textContent = steps[step].rule;
      scanBar.style.width  = `${((step + 1) / steps.length) * 100}%`;
      step++;
    } else {
      clearInterval(interval);
      setTimeout(() => {
        scanOverlay.classList.add('hidden');
        runScan(config);
      }, 400);
    }
  }, 280);
}

// ── Run Scan ──────────────────────────────────────────────────────────────────
function runScan(config) {
  const findings = [];
  RULES.forEach(rule => {
    if (rule.pattern.test(config)) findings.push(rule);
  });
  lastFindings = findings;
  activeFilter = 'all';
  renderResults(findings);
  renderHeatmap(findings);
  renderCleanConfig(config, findings);
  addToHistory(findings);
}

// ── Score ─────────────────────────────────────────────────────────────────────
function calcScore(findings) {
  const weights = { critical: 25, high: 15, medium: 8, low: 3 };
  let deduction = 0;
  findings.forEach(f => deduction += (weights[f.severity] || 0));
  return Math.max(0, 100 - deduction);
}

function getGrade(score) {
  if (score >= 90) return { label: "Excellent 🟢", color: "#2ecc71" };
  if (score >= 75) return { label: "Good 🟡",       color: "#f1c40f" };
  if (score >= 50) return { label: "Fair 🟠",        color: "#e67e22" };
  return               { label: "At Risk 🔴",         color: "#e74c3c" };
}

function animateScore(score) {
  const offset = 314 - (score / 100) * 314;
  const grade  = getGrade(score);
  scoreRing.style.stroke           = grade.color;
  scoreRing.style.strokeDashoffset = offset;
  scoreNum.style.color             = grade.color;
  scoreGrade.textContent           = grade.label;
  scoreGrade.style.color           = grade.color;

  let cur = 0;
  const step = Math.ceil(score / 40);
  const t = setInterval(() => {
    cur = Math.min(cur + step, score);
    scoreNum.textContent = cur;
    if (cur >= score) clearInterval(t);
  }, 30);
}

// ── Render Results ────────────────────────────────────────────────────────────
function renderResults(findings) {
  resultsContainer.innerHTML = '';
  scoreRow.classList.remove('hidden');
  resultsSection.classList.remove('hidden');

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach(f => counts[f.severity]++);
  document.getElementById('countCritical').textContent = counts.critical;
  document.getElementById('countHigh').textContent     = counts.high;
  document.getElementById('countMedium').textContent   = counts.medium;
  document.getElementById('countLow').textContent      = counts.low;

  animateScore(calcScore(findings));

  if (findings.length === 0) {
    resultsLabel.innerHTML = '';
    filterBar.classList.add('hidden');
    resultsContainer.innerHTML = `
      <div class="no-issues">✅ No issues detected — your config looks clean!</div>`;
    return;
  }

  filterBar.classList.remove('hidden');
  setActiveFilter('all');
  resultsLabel.innerHTML = `⚠️ ${findings.length} issue${findings.length > 1 ? 's' : ''} found`;
  renderCards(findings, 'all');
}

function renderCards(findings, filter) {
  resultsContainer.innerHTML = '';
  const order  = { critical: 0, high: 1, medium: 2, low: 3 };
  const sorted = [...findings].sort((a, b) => order[a.severity] - order[b.severity]);
  const shown  = filter === 'all' ? sorted : sorted.filter(f => f.severity === filter);

  if (shown.length === 0) {
    resultsContainer.innerHTML = `
      <p style="color:var(--muted);font-size:0.9rem;padding:0.5rem 0">
        No ${filter} issues found.</p>`;
    return;
  }

  shown.forEach((f, i) => {
    const card = document.createElement('div');
    card.className = `result-card ${f.severity}`;
    card.style.animationDelay = `${i * 0.07}s`;
    card.innerHTML = `
      <div class="card-header">
        <div class="card-title-wrap">
          <span class="card-id">${f.id}</span>
          <span class="card-title">${f.name}</span>
        </div>
        <div style="display:flex;align-items:center;gap:0.5rem">
          <span class="badge ${f.severity}">${f.severity}</span>
          <button class="collapse-btn" title="Toggle">▼</button>
        </div>
      </div>
      <div class="card-body">
        <div class="card-fix">
          <div class="card-fix-label">💡 Suggested Fix</div>
          ${f.fix}
        </div>
      </div>`;

    const collapseBtn = card.querySelector('.collapse-btn');
    const cardBody    = card.querySelector('.card-body');
    collapseBtn.addEventListener('click', () => {
      const collapsed = cardBody.classList.toggle('collapsed');
      collapseBtn.classList.toggle('collapsed', collapsed);
    });

    resultsContainer.appendChild(card);
  });
}

// ── Filter ────────────────────────────────────────────────────────────────────
filterBar.addEventListener('click', e => {
  const btn = e.target.closest('.filter-btn');
  if (!btn) return;
  setActiveFilter(btn.dataset.filter);
  renderCards(lastFindings, btn.dataset.filter);
});

function setActiveFilter(filter) {
  activeFilter = filter;
  document.querySelectorAll('.filter-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.filter === filter);
  });
}

// ── Heatmap ───────────────────────────────────────────────────────────────────
function renderHeatmap(findings) {
  heatmapSection.classList.remove('hidden');
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach(f => counts[f.severity]++);

  const total = findings.length || 1;
  const cells = [
    { key: 'critical', label: 'Critical', desc: 'Immediate action required' },
    { key: 'high',     label: 'High',     desc: 'Fix as soon as possible'   },
    { key: 'medium',   label: 'Medium',   desc: 'Should be addressed soon'  },
    { key: 'low',      label: 'Low',      desc: 'Minor improvements needed' },
  ];

  heatmapGrid.innerHTML = '';
  cells.forEach(c => {
    const pct = Math.round((counts[c.key] / total) * 100);
    const cell = document.createElement('div');
    cell.className = `heatmap-cell ${c.key}`;
    cell.innerHTML = `
      <div class="cell-label">${c.label}</div>
      <div class="cell-count">${counts[c.key]}</div>
      <div class="cell-bar-wrap">
        <div class="cell-bar" style="width:0%" data-pct="${pct}"></div>
      </div>
      <div class="cell-desc">${pct}% of issues · ${c.desc}</div>
    `;
    heatmapGrid.appendChild(cell);

    // Animate bar
    setTimeout(() => {
      cell.querySelector('.cell-bar').style.width = `${pct}%`;
    }, 100);
  });
}

// ── Clean Config Generator ────────────────────────────────────────────────────
function renderCleanConfig(config, findings) {
  cleanSection.classList.remove('hidden');

  if (findings.length === 0) {
    cleanOutput.value = config;
    return;
  }

  // Replacements map — pattern → safe placeholder
  const replacements = [
    { pattern: /(\"?password\"?\s*[:=]\s*)["']?[^\s"'\n,}]+["']?/gi,
      replace:  '$1"<USE_ENV_VAR>"' },
    { pattern: /(\"?api[_-]?key\"?\s*[:=]\s*)["']?[^\s"'\n,}]+["']?/gi,
      replace:  '$1"<USE_ENV_VAR>"' },
    { pattern: /(\"?secret[_-]?key\"?\s*[:=]\s*)["']?[^\s"'\n,}]+["']?/gi,
      replace:  '$1"<USE_ENV_VAR>"' },
    { pattern: /(\"?access[_-]?token\"?\s*[:=]\s*)["']?[^\s"'\n,}]+["']?/gi,
      replace:  '$1"<USE_ENV_VAR>"' },
    { pattern: /(\"?admin[_-]?password\"?\s*[:=]\s*)["']?[^\s"'\n,}]+["']?/gi,
      replace:  '$1"<USE_ENV_VAR>"' },
    { pattern: /(\"?public[_-]?access\"?\s*[:=]\s*)true/gi,
      replace:  '$1false' },
    { pattern: /(\"?encrypt(?:ion|ed)?\"?\s*[:=]\s*)["']?false["']?/gi,
      replace:  '$1true' },
    { pattern: /(\"?ssl\"?\s*[:=]\s*)["']?false["']?/gi,
      replace:  '$1true' },
    { pattern: /(\"?tls\"?\s*[:=]\s*)["']?false["']?/gi,
      replace:  '$1true' },
    { pattern: /(\"?logging\"?\s*[:=]\s*)["']?false["']?/gi,
      replace:  '$1true' },
    { pattern: /(\"?enable[_-]?logging\"?\s*[:=]\s*)["']?false["']?/gi,
      replace:  '$1true' },
    { pattern: /(\"?mfa(?:[_-]?enabled)?\"?\s*[:=]\s*)["']?false["']?/gi,
      replace:  '$1true' },
    { pattern: /(\"?monitoring\"?\s*[:=]\s*)["']?false["']?/gi,
      replace:  '$1true' },
    { pattern: /(\"?firewall\"?\s*[:=]\s*)["']?false["']?/gi,
      replace:  '$1true' },
    { pattern: /(\"?backup\"?\s*[:=]\s*)["']?false["']?/gi,
      replace:  '$1true' },
    { pattern: /(\"?debug\"?\s*[:=]\s*)["']?true["']?/gi,
      replace:  '$1false' },
    { pattern: /(\"?cidr\"?\s*[:=]\s*)["']?0\.0\.0\.0\/0["']?/gi,
      replace:  '$1"10.0.0.0/24"' },
    { pattern: /(\"?user\"?\s*[:=]\s*)["']?root["']?/gi,
      replace:  '$1"<IAM_USER>"' },
  ];

  let cleaned = config;
  replacements.forEach(r => {
    cleaned = cleaned.replace(r.pattern, r.replace);
  });

  cleanOutput.value = cleaned;
}

// ── Copy & Download ───────────────────────────────────────────────────────────
function showToast(msg = '✅ Copied to clipboard!') {
  copiedToast.textContent = msg;
  copiedToast.classList.add('show');
  setTimeout(() => copiedToast.classList.remove('show'), 2200);
}

copyCleanBtn.addEventListener('click', () => {
  navigator.clipboard.writeText(cleanOutput.value).then(() => showToast());
});

downloadCleanBtn.addEventListener('click', () => {
  const fmt  = detectFormat(lastConfig);
  const ext  = fmt === 'JSON' ? 'json' : fmt === 'Terraform' ? 'tf' : 'yaml';
  const blob = new Blob([cleanOutput.value], { type: 'text/plain' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `cloudguard-clean.${ext}`;
  a.click();
  URL.revokeObjectURL(url);
  showToast('⬇️ File downloaded!');
});

// ── History ───────────────────────────────────────────────────────────────────
function addToHistory(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach(f => counts[f.severity]++);
  const score = calcScore(findings);
  const grade = getGrade(score);
  const time  = new Date().toLocaleTimeString();
  scanHistory.unshift({ time, score, counts, grade });
  if (scanHistory.length > 5) scanHistory.pop();
  renderHistory();
}

function renderHistory() {
  if (!scanHistory.length) { historySection.classList.add('hidden'); return; }
  historySection.classList.remove('hidden');
  historyContainer.innerHTML = '';
  scanHistory.forEach(h => {
    const item = document.createElement('div');
    item.className = 'history-item';
    item.innerHTML = `
      <span style="color:var(--muted)">${h.time}</span>
      <div class="hist-issues">
        <span class="hist-c">● ${h.counts.critical} Critical</span>
        <span class="hist-h">● ${h.counts.high} High</span>
        <span class="hist-m">● ${h.counts.medium} Medium</span>
        <span class="hist-l">● ${h.counts.low} Low</span>
      </div>
      <span class="hist-score" style="color:${h.grade.color}">Score: ${h.score}/100</span>`;
    historyContainer.appendChild(item);
  });
}

clearHistoryBtn.addEventListener('click', () => {
  scanHistory = [];
  renderHistory();
});

// ── Export PDF ────────────────────────────────────────────────────────────────
exportBtn.addEventListener('click', () => {
  if (!lastFindings.length && scoreNum.textContent === '--') {
    alert('Run a scan first!'); return;
  }

  const { jsPDF } = window.jspdf;
  const doc    = new jsPDF();
  const score  = calcScore(lastFindings);
  const grade  = getGrade(score);
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  lastFindings.forEach(f => counts[f.severity]++);

  doc.setFillColor(15, 37, 64);
  doc.rect(0, 0, 210, 40, 'F');
  doc.setTextColor(59, 191, 191);
  doc.setFontSize(22); doc.setFont('helvetica', 'bold');
  doc.text('CloudGuard Lite', 14, 18);
  doc.setFontSize(10); doc.setTextColor(168, 191, 220);
  doc.text('Security Scan Report', 14, 26);
  doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 33);

  doc.setFillColor(26, 58, 92);
  doc.roundedRect(14, 48, 80, 30, 3, 3, 'F');
  doc.setTextColor(255,255,255); doc.setFontSize(11); doc.setFont('helvetica','bold');
  doc.text('Security Score', 20, 58);
  doc.setFontSize(20); doc.setTextColor(59,191,191);
  doc.text(`${score} / 100`, 20, 70);
  doc.setFontSize(10); doc.setTextColor(168,191,220);
  doc.text(grade.label.replace(/[^\w\s\/]/g,''), 60, 70);

  doc.setFillColor(26,58,92);
  doc.roundedRect(100, 48, 96, 30, 3, 3, 'F');
  doc.setTextColor(255,255,255); doc.setFontSize(10); doc.setFont('helvetica','bold');
  doc.text('Issue Summary', 106, 58);
  doc.setFont('helvetica','normal');
  doc.setTextColor(231,76,60);  doc.text(`Critical: ${counts.critical}`, 106, 66);
  doc.setTextColor(230,126,34); doc.text(`High: ${counts.high}`, 150, 66);
  doc.setTextColor(241,196,15); doc.text(`Medium: ${counts.medium}`, 106, 73);
  doc.setTextColor(46,204,113); doc.text(`Low: ${counts.low}`, 150, 73);

  let y = 92;
  doc.setTextColor(168,191,220); doc.setFontSize(11); doc.setFont('helvetica','bold');
  doc.text('Detected Issues', 14, y); y += 6;

  if (!lastFindings.length) {
    doc.setTextColor(46,204,113); doc.setFont('helvetica','normal');
    doc.text('No issues found - config is clean!', 14, y+6);
  } else {
    const sColors = { critical:[231,76,60], high:[230,126,34], medium:[241,196,15], low:[46,204,113] };
    const order   = { critical:0, high:1, medium:2, low:3 };
    [...lastFindings].sort((a,b)=>order[a.severity]-order[b.severity]).forEach(f => {
      if (y > 260) { doc.addPage(); y = 20; }
      const col = sColors[f.severity];
      doc.setFillColor(26,58,92); doc.roundedRect(14,y,182,22,2,2,'F');
      doc.setFillColor(...col);   doc.roundedRect(14,y,4,22,1,1,'F');
      doc.setTextColor(...col); doc.setFontSize(9); doc.setFont('helvetica','bold');
      doc.text(`[${f.severity.toUpperCase()}] ${f.id} — ${f.name}`, 22, y+8);
      doc.setTextColor(214,228,240); doc.setFont('helvetica','normal'); doc.setFontSize(8);
      doc.text(doc.splitTextToSize(`Fix: ${f.fix}`, 164)[0], 22, y+16);
      y += 26;
    });
  }

  doc.setFillColor(15,37,64); doc.rect(0,285,210,12,'F');
  doc.setTextColor(168,191,220); doc.setFontSize(8);
  doc.text('CloudGuard Lite · Rule-Based Config Scanner · SSN Coding Club', 105, 292, {align:'center'});
  doc.save(`cloudguard-report-${Date.now()}.pdf`);
});
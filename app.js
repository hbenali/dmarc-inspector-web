(function () {
  'use strict';

  // DOM elements
  const domainInput = document.getElementById('domainInput');
  const lookupForm = document.getElementById('lookupForm');
  const checkBtn = document.getElementById('checkBtn');
  const btnText = document.getElementById('btnText');
  const btnLoader = document.getElementById('btnLoader');
  const placeholderState = document.getElementById('placeholderState');
  const recordsContainer = document.getElementById('recordsContainer');
  const errorContainer = document.getElementById('errorContainer');

  // XML Upload elements
  const uploadArea = document.getElementById('uploadArea');
  const fileInput = document.getElementById('fileInput');
  const xmlResults = document.getElementById('xmlResults');

  // Tab elements
  const tabPolicy = document.getElementById('tabPolicy');
  const tabTags = document.getElementById('tabTags');
  const tabReports = document.getElementById('tabReports');
  const tabBestPractices = document.getElementById('tabBestPractices');
  const policyTab = document.getElementById('policyTab');
  const tagsTab = document.getElementById('tagsTab');
  const reportsTab = document.getElementById('reportsTab');
  const bestPracticesTab = document.getElementById('bestPracticesTab');

  // Tab switching
  function switchTab(activeTab, activeContent) {
    [tabPolicy, tabTags, tabReports, tabBestPractices].forEach(t => {
      t.classList.remove('active');
      t.setAttribute('aria-selected', 'false');
    });
    [policyTab, tagsTab, reportsTab, bestPracticesTab].forEach(t => t.classList.remove('active'));

    activeTab.classList.add('active');
    activeTab.setAttribute('aria-selected', 'true');
    activeContent.classList.add('active');
  }

  if (tabPolicy) tabPolicy.addEventListener('click', () => switchTab(tabPolicy, policyTab));
  if (tabTags) tabTags.addEventListener('click', () => switchTab(tabTags, tagsTab));
  if (tabReports) tabReports.addEventListener('click', () => switchTab(tabReports, reportsTab));
  if (tabBestPractices) tabBestPractices.addEventListener('click', () => switchTab(tabBestPractices, bestPracticesTab));

  // Helper functions
  function setActiveView(view) {
    placeholderState.classList.toggle('hidden', view !== 'placeholder');
    recordsContainer.classList.toggle('hidden', view !== 'records');
    errorContainer.classList.toggle('hidden', view !== 'error');
  }

  setActiveView('placeholder');

  // Parse DMARC record tags
  function parseDMARC(record) {
    const tags = [];
    const cleanRecord = record.replace(/^"|"$/g, '');
    const parts = cleanRecord.split(';');

    parts.forEach(part => {
      part = part.trim();
      if (!part) return;

      const match = part.match(/^([a-zA-Z]+)=(.+)$/);
      if (match) {
        tags.push({
          key: match[1],
          value: match[2].trim()
        });
      }
    });

    return tags;
  }

  // Validate DMARC record
  function validateDMARC(tags) {
    const validation = {
      valid: true,
      policy: 'none',
      hasRUA: false,
      hasRUF: false,
      warnings: [],
      errors: []
    };

    const tagMap = {};
    tags.forEach(t => tagMap[t.key] = t.value);

    // Check v= tag
    if (!tagMap.v) {
      validation.valid = false;
      validation.errors.push('Missing v= tag');
    } else if (tagMap.v !== 'DMARC1') {
      validation.valid = false;
      validation.errors.push('v= must be DMARC1');
    }

    // Check p= tag
    if (!tagMap.p) {
      validation.valid = false;
      validation.errors.push('Missing p= tag (policy)');
    } else {
      validation.policy = tagMap.p;
      if (!['none', 'quarantine', 'reject'].includes(tagMap.p)) {
        validation.valid = false;
        validation.errors.push('Invalid policy value');
      }
    }

    // Check reporting
    if (tagMap.rua) validation.hasRUA = true;
    if (tagMap.ruf) validation.hasRUF = true;

    if (!validation.hasRUA) {
      validation.warnings.push('No RUA address - you won\'t receive aggregate reports');
    }

    // Check pct
    if (tagMap.pct) {
      const pct = parseInt(tagMap.pct);
      if (pct < 1 || pct > 100) {
        validation.warnings.push('pct should be between 1-100');
      }
    }

    return validation;
  }

  const POLICY_DETAIL = {
    none: 'Monitoring only. Failing mail is delivered as usual and reports are sent.',
    quarantine: 'Soft enforcement. Failing mail is marked as spam.',
    reject: 'Hard enforcement. Failing mail is rejected completely.'
  };

  function check(cls, word, text) {
    return `<li class="${cls}"><span class="word">${word}</span>${text}</li>`;
  }

  // Render DMARC result. Every DNS-controlled string goes through escapeHtml.
  function renderDMARCResult(domain, record) {
    const tags = parseDMARC(record);
    const validation = validateDMARC(tags);
    const knownPolicy = ['none', 'quarantine', 'reject'].includes(validation.policy);
    const verdictClass = validation.valid ? validation.policy : 'invalid';

    let tagsHtml = '';
    tags.forEach(tag => {
      tagsHtml += `<div class="tag"><span class="tag-key">${escapeHtml(tag.key)}</span><span class="tag-value">${escapeHtml(tag.value)}</span></div>`;
    });

    let checksHtml = '';
    checksHtml += validation.valid
      ? check('ok', 'Valid', 'DMARC record')
      : check('bad', 'Invalid', 'DMARC record');
    checksHtml += check(knownPolicy ? (validation.policy === 'none' ? 'warn' : 'ok') : 'bad', 'Policy', escapeHtml(validation.policy));
    checksHtml += validation.hasRUA
      ? check('ok', 'Configured', 'RUA, aggregate reports')
      : check('warn', 'Not set', 'RUA, aggregate reports');
    checksHtml += validation.hasRUF
      ? check('info', 'Configured', 'RUF, forensic reports')
      : check('info', 'Not set', 'RUF, forensic reports');

    validation.errors.forEach(err => {
      checksHtml += check('bad', 'Error', escapeHtml(err));
    });

    validation.warnings.forEach(warning => {
      checksHtml += check('warn', 'Warning', escapeHtml(warning));
    });

    const detail = knownPolicy ? POLICY_DETAIL[validation.policy] : 'The policy value is not one of none, quarantine or reject.';

    recordsContainer.innerHTML = `
      <div class="verdict ${verdictClass}">
        <p class="kicker">DMARC record for <span class="domain">${escapeHtml(domain)}</span></p>
        <p class="title">${validation.valid ? 'Policy: ' : 'Invalid record, policy: '}${escapeHtml(validation.policy)}</p>
        <p class="detail">${escapeHtml(detail)}</p>
      </div>

      <h3 class="section-title">Checks</h3>
      <ul class="checks">${checksHtml}</ul>

      <h3 class="section-title">Tags</h3>
      <div class="tag-list">${tagsHtml}</div>

      <h3 class="section-title">Record</h3>
      <div class="record-card">${escapeHtml(record)}</div>

      <p class="lookup-note">DNS lookup: <code>_dmarc.${escapeHtml(domain)} IN TXT</code></p>
    `;
  }

  function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return String(unsafe).replace(/[&<>"']/g, function (m) {
      if (m === '&') return '&amp;';
      if (m === '<') return '&lt;';
      if (m === '>') return '&gt;';
      if (m === '"') return '&quot;';
      return '&#39;';
    });
  }

  function renderError(title, message) {
    errorContainer.innerHTML = `
      <div class="verdict error">
        <p class="title">${escapeHtml(title)}</p>
        <p class="detail">${escapeHtml(message)}</p>
      </div>
    `;
  }

  function setLoading(isLoading) {
    checkBtn.disabled = isLoading;
    btnText.textContent = isLoading ? 'Checking' : 'Check DMARC';
    btnLoader.classList.toggle('hidden', !isLoading);
    btnLoader.className = isLoading ? 'spinner' : 'hidden';
  }

  // DMARC lookup function
  async function queryDMARC(domain) {
    let cleanDomain = domain.trim().replace(/\.+$/, '');
    if (!cleanDomain) throw new Error('Please enter a domain');

    const dmarcDomain = `_dmarc.${cleanDomain}`;

    const url = `https://dns.google/resolve?name=${encodeURIComponent(dmarcDomain)}&type=TXT`;

    const response = await fetch(url);
    if (!response.ok) throw new Error(`DNS query failed (HTTP ${response.status})`);

    const data = await response.json();

    if (data.Status === 3) {
      throw new Error(`No DMARC record found for "${dmarcDomain}"`);
    } else if (data.Status !== 0) {
      const reason = data.Comment || `DNS error code ${data.Status}`;
      throw new Error(`DNS lookup error: ${reason}`);
    }

    const answers = data.Answer || [];

    // Find DMARC records (TXT records starting with v=DMARC1)
    const dmarcRecords = answers.filter(r => {
      if (r.type === 16 && r.data) {
        const txt = r.data.replace(/^"|"$/g, '');
        return txt.startsWith('v=DMARC1');
      }
      return false;
    });

    if (dmarcRecords.length === 0) {
      throw new Error(`No DMARC record found for "${dmarcDomain}"`);
    }

    if (dmarcRecords.length > 1) {
      throw new Error(`Multiple DMARC records found - this will cause "permerror"`);
    }

    let record = dmarcRecords[0].data.replace(/^"|"$/g, '');

    return {
      domain: cleanDomain,
      record: record,
      raw: dmarcRecords[0]
    };
  }

  // Main lookup function
  async function performLookup() {
    const domain = domainInput.value.trim();

    if (!domain) {
      renderError('Missing information', 'Please enter a domain');
      setActiveView('error');
      return;
    }

    setLoading(true);
    try {
      const result = await queryDMARC(domain);
      renderDMARCResult(result.domain, result.record);
      setActiveView('records');
    } catch (err) {
      console.error('DMARC lookup error:', err);
      renderError('Error checking DMARC', err.message);
      setActiveView('error');
    } finally {
      setLoading(false);
    }
  }

  // XML Upload handling
  if (uploadArea && fileInput) {
    uploadArea.addEventListener('click', () => fileInput.click());
    uploadArea.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        fileInput.click();
      }
    });

    uploadArea.addEventListener('dragover', (e) => {
      e.preventDefault();
      uploadArea.classList.add('dragover');
    });

    uploadArea.addEventListener('dragleave', () => {
      uploadArea.classList.remove('dragover');
    });

    uploadArea.addEventListener('drop', (e) => {
      e.preventDefault();
      uploadArea.classList.remove('dragover');

      const files = e.dataTransfer.files;
      if (files.length > 0) {
        handleXMLFile(files[0]);
      }
    });

    fileInput.addEventListener('change', (e) => {
      if (e.target.files.length > 0) {
        handleXMLFile(e.target.files[0]);
      }
    });
  }

  function res(pass) {
    return pass ? '<span class="res pass">Pass</span>' : '<span class="res fail">Fail</span>';
  }

  // XML file handler (simplified - real parsing would need XML parser)
  function handleXMLFile(file) {
    const reader = new FileReader();
    reader.onload = function () {
      // In a real implementation, you'd parse the XML
      // For demo, show a message that parsing would happen
      xmlResults.classList.remove('hidden');
      xmlResults.innerHTML = `
        <h3>XML Report Analysis</h3>
        <p class="sample-flag">Sample output. The file is read in your browser but not parsed yet: the figures below are illustrative, not from your report.</p>
        <div class="stats">
          <div class="stat"><div class="stat-number">1,234</div><div class="stat-label">Total Emails</div></div>
          <div class="stat"><div class="stat-number">1,189</div><div class="stat-label">Passed DMARC</div></div>
          <div class="stat"><div class="stat-number">45</div><div class="stat-label">Failed</div></div>
          <div class="stat"><div class="stat-number">3</div><div class="stat-label">Sending IPs</div></div>
        </div>

        <h4>Sending Sources</h4>
        <div class="table-wrap"><table>
          <thead><tr><th>IP Address</th><th>Volume</th><th>SPF</th><th>DKIM</th><th>DMARC</th></tr></thead>
          <tbody>
            <tr><td class="mono">192.0.2.1</td><td>987</td><td>${res(true)}</td><td>${res(true)}</td><td>${res(true)}</td></tr>
            <tr><td class="mono">198.51.100.2</td><td>202</td><td>${res(true)}</td><td>${res(false)}</td><td>${res(false)}</td></tr>
            <tr><td class="mono">203.0.113.3</td><td>45</td><td>${res(false)}</td><td>${res(false)}</td><td>${res(false)}</td></tr>
          </tbody>
        </table></div>

        <div class="caution"><strong>Suspicious Activity:</strong> IP 203.0.113.3 shows 45 failures - possible spoofing attempt</div>

        <p class="lookup-note"><em>Full XML parsing would display real data from your report</em></p>
      `;
    };
    reader.readAsText(file);
  }

  // Event listeners
  lookupForm.addEventListener('submit', (e) => {
    e.preventDefault();
    performLookup();
  });

  // Handle URL parameters
  function handleUrlParameter() {
    const urlParams = new URLSearchParams(window.location.search);
    const domainParam = urlParams.get('domain');

    if (domainParam) {
      domainInput.value = domainParam;
      setTimeout(() => performLookup(), 100);
    }
  }

  window.addEventListener('load', handleUrlParameter);
})();

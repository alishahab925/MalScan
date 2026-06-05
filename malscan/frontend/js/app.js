document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const scanBtn = document.getElementById('scan-btn');
    const selectedFilename = document.getElementById('selected-filename');
    const fileInfo = document.getElementById('file-info');
    const currentStep = document.getElementById('current-step');
    const scanAnotherBtn = document.getElementById('scan-another-btn');

    const states = {
        UPLOAD: 'upload-state',
        LOADING: 'loading-state',
        REPORT: 'report-state'
    };

    let selectedFile = null;

    // State management
    function showState(stateId) {
        document.querySelectorAll('.state').forEach(el => {
            el.classList.remove('active');
        });
        document.getElementById(stateId).classList.add('active');
    }

    // Drag and drop handlers
    dropZone.addEventListener('click', () => fileInput.click());

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
            handleFileSelect(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) {
            handleFileSelect(e.target.files[0]);
        }
    });

    function handleFileSelect(file) {
        selectedFile = file;
        selectedFilename.textContent = `Selected: ${file.name} (${(file.size / 1024 / 1024).toFixed(2)} MB)`;
        fileInfo.classList.remove('hidden');
    }

    // Scan action
    scanBtn.addEventListener('click', async () => {
        if (!selectedFile) return;

        showState(states.LOADING);

        const steps = [
            "Parsing PE headers...",
            "Calculating entropy...",
            "Extracting strings...",
            "Searching for IOCs...",
            "Running AI analysis..."
        ];

        let stepIndex = 0;
        const stepInterval = setInterval(() => {
            if (stepIndex < steps.length) {
                currentStep.textContent = steps[stepIndex];
                stepIndex++;
            }
        }, 1500);

        const formData = new FormData();
        formData.append('file', selectedFile);

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Scan failed');
            }

            const data = await response.json();
            clearInterval(stepInterval);
            renderReport(data);
            showState(states.REPORT);
        } catch (error) {
            clearInterval(stepInterval);
            alert(`Error: ${error.message}`);
            showState(states.UPLOAD);
        }
    });

    scanAnotherBtn.addEventListener('click', () => {
        selectedFile = null;
        fileInput.value = '';
        fileInfo.classList.add('hidden');
        showState(states.UPLOAD);
    });

    function escapeHTML(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function renderReport(data) {
        const { static_analysis, ai_report } = data;

        // Threat Score & Badge
        const score = ai_report.confidence_score || 0;
        const scoreEl = document.getElementById('threat-score');
        scoreEl.textContent = score;

        const badge = document.getElementById('threat-badge');
        badge.textContent = ai_report.threat_classification || 'UNKNOWN';

        if (score > 70) {
            scoreEl.style.color = 'var(--danger-color)';
            badge.className = 'badge red';
        } else if (score > 30) {
            scoreEl.style.color = 'var(--warning-color)';
            badge.className = 'badge yellow';
        } else {
            scoreEl.style.color = 'var(--success-color)';
            badge.className = 'badge green';
        }

        document.getElementById('threat-family').textContent = ai_report.threat_family || 'Generic/Unknown';
        document.getElementById('behavioral_summary').textContent = ai_report.behavioral_summary || 'No summary available.';

        // MITRE Techniques
        const mitreContainer = document.getElementById('mitre-techniques');
        mitreContainer.innerHTML = '';
        if (ai_report.mitre_attack_techniques && ai_report.mitre_attack_techniques.length) {
            ai_report.mitre_attack_techniques.forEach(tech => {
                const div = document.createElement('div');
                div.className = 'technique-item';
                div.innerHTML = `
                    <div class="technique-id">${escapeHTML(tech.id)}</div>
                    <div class="technique-name"><strong>${escapeHTML(tech.name)}</strong></div>
                    <div class="technique-desc">${escapeHTML(tech.description)}</div>
                `;
                mitreContainer.appendChild(div);
            });
        } else {
            mitreContainer.innerHTML = '<p>No MITRE ATT&CK techniques identified.</p>';
        }

        // Entropy Chart
        const ctx = document.getElementById('entropy-chart').getContext('2d');
        const sections = static_analysis.entropy.map(s => s.section_name);
        const scores = static_analysis.entropy.map(s => s.entropy);
        const colors = static_analysis.entropy.map(s => s.is_suspicious ? 'rgba(231, 76, 60, 0.7)' : 'rgba(52, 152, 219, 0.7)');

        if (window.myChart) window.myChart.destroy();
        window.myChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: sections,
                datasets: [{
                    label: 'Entropy',
                    data: scores,
                    backgroundColor: colors
                }]
            },
            options: {
                scales: {
                    y: { beginAtZero: true, max: 8 }
                }
            }
        });

        // IOCs
        const iocContainer = document.getElementById('ioc-tables');
        iocContainer.innerHTML = '';
        const iocs = static_analysis.iocs;

        for (const [type, list] of Object.entries(iocs)) {
            if (list.length > 0) {
                const wrapper = document.createElement('div');
                wrapper.className = 'ioc-table-wrapper';

                const h4 = document.createElement('h4');
                h4.textContent = type.replace('_', ' ').toUpperCase();
                wrapper.appendChild(h4);

                const iocList = document.createElement('div');
                iocList.className = 'ioc-list';

                list.forEach(ioc => {
                    const iocItem = document.createElement('div');
                    iocItem.className = 'ioc-item';

                    const span = document.createElement('span');
                    span.textContent = ioc;
                    iocItem.appendChild(span);

                    const btn = document.createElement('button');
                    btn.className = 'copy-btn';
                    btn.innerHTML = '<i class="fas fa-copy"></i>';
                    btn.addEventListener('click', () => {
                        navigator.clipboard.writeText(ioc);
                    });
                    iocItem.appendChild(btn);
                    iocList.appendChild(iocItem);
                });

                wrapper.appendChild(iocList);
                iocContainer.appendChild(wrapper);
            }
        }

        if (iocContainer.innerHTML === '') {
            iocContainer.innerHTML = '<p>No indicators of compromise found.</p>';
        }

        // Recommended Actions
        const recommendationsContainer = document.getElementById('recommended-actions');
        recommendationsContainer.innerHTML = '';
        if (ai_report.recommended_actions && ai_report.recommended_actions.length) {
            ai_report.recommended_actions.forEach(action => {
                const li = document.createElement('li');
                li.textContent = action;
                recommendationsContainer.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.textContent = 'No specific actions recommended.';
            recommendationsContainer.appendChild(li);
        }

        // Analyst Notes
        const notesContainer = document.getElementById('analyst-notes');
        notesContainer.innerHTML = '';
        const notesP = document.createElement('p');
        notesP.textContent = ai_report.analyst_notes || 'No analyst notes.';
        notesContainer.appendChild(notesP);
    }
});

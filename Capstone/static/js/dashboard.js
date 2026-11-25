// Dashboard JavaScript: Async Scan Execution & Live Polling

document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scanForm');
    const startBtn = document.getElementById('startScanBtn');
    const progressSection = document.getElementById('progressSection');
    const progressBar = document.getElementById('scanProgressBar');
    const currentStepLabel = document.getElementById('currentStepLabel');
    const terminalLogs = document.getElementById('terminalLogs');
    const errorAlert = document.getElementById('errorAlert');

    if (scanForm) {
        scanForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const targetUrl = document.getElementById('targetUrl').value.trim();
            const authConfirmed = document.getElementById('authConfirmed').checked;

            if (!authConfirmed) {
                showError("Authorization Confirmation Required: You must verify that you own or have explicit testing authorization for this target.");
                return;
            }

            hideError();
            setScanningState(true);

            try {
                const response = await fetch('/api/scan/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        target_url: targetUrl,
                        auth_confirmed: authConfirmed ? 1 : 0
                    })
                });

                const data = await response.json();

                if (!data.success) {
                    showError(data.message || "Failed to initiate scan.");
                    setScanningState(false);
                    return;
                }

                // Scan launched successfully - begin polling
                pollScanStatus(data.scan_id);

            } catch (err) {
                showError("Network error while communicating with the scanning server: " + err.message);
                setScanningState(false);
            }
        });
    }

    function setScanningState(isScanning) {
        if (startBtn) {
            startBtn.disabled = isScanning;
            startBtn.innerHTML = isScanning ? 
                '<span class="spinner-border spinner-border-sm me-2"></span>Executing Security Audit...' : 
                '<i class="bi bi-shield-check me-2"></i>Launch Security Assessment';
        }
        if (progressSection) {
            progressSection.classList.toggle('d-none', !isScanning);
        }
        if (isScanning && terminalLogs) {
            terminalLogs.innerHTML = '<div class="terminal-line text-info">Initializing background assessment worker...</div>';
            progressBar.style.width = '5%';
            progressBar.innerText = '5%';
        }
    }

    function pollScanStatus(scanId) {
        const pollInterval = setInterval(async () => {
            try {
                const res = await fetch(`/api/scan/status/${scanId}`);
                const statusData = await res.json();

                if (!statusData.success) {
                    clearInterval(pollInterval);
                    showError("Failed to retrieve scan status.");
                    setScanningState(false);
                    return;
                }

                const { status, progress, current_step, logs } = statusData;

                // Update Progress Bar
                progressBar.style.width = `${progress}%`;
                progressBar.innerText = `${progress}%`;
                if (currentStepLabel) {
                    currentStepLabel.innerText = current_step;
                }

                // Update Terminal Output
                if (terminalLogs && logs) {
                    terminalLogs.innerHTML = logs.map(line => `<div class="terminal-line">${escapeHtml(line)}</div>`).join('');
                    terminalLogs.scrollTop = terminalLogs.scrollHeight;
                }

                // Check Completion
                if (status === 'COMPLETED') {
                    clearInterval(pollInterval);
                    setTimeout(() => {
                        window.location.href = `/scan/${scanId}`;
                    }, 1200);
                } else if (status === 'FAILED') {
                    clearInterval(pollInterval);
                    showError("The security assessment failed or was aborted. Check terminal output.");
                    setScanningState(false);
                }

            } catch (err) {
                console.error("Polling error:", err);
            }
        }, 1200);
    }

    function showError(msg) {
        if (errorAlert) {
            errorAlert.innerText = msg;
            errorAlert.classList.remove('d-none');
        }
    }

    function hideError() {
        if (errorAlert) {
            errorAlert.classList.add('d-none');
        }
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
});

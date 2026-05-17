// ✅ No API key here anymore — it lives safely in Vercel environment variables

// 🔁 Replace this with your actual Vercel deployment URL
const PROXY_URL = "https://virus-scanner-git-main-hariabeys-projects.vercel.app/";

// Utility function to get DOM elements by ID
const getElement = id => document.getElementById(id);

// Updates the result display section with given content
const updateResult = (content, display = true) => {
    const result = getElement('result');
    result.style.display = display ? 'block' : 'none';
    result.innerHTML = content;
};

// Shows a loading spinner and message
const showLoading = message => updateResult(`
        <div class="loading">
            <p>${message}</p>
            <div class="spinner"></div>
        </div>
`);

// Displays an error message
const showError = message => updateResult(`<p class="error">${message}</p>`);

// ✅ Updated: All requests now go through your Vercel proxy instead of VirusTotal directly
async function makeRequest(endpoint, options = {}) {
    const response = await fetch(PROXY_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            endpoint,                               // e.g. "urls", "files", "analyses/xxx"
            method: options.method || "GET",
            body: options.body || null,             // for URL-encoded form data
            isFormData: options.isFormData || false // tells proxy to set correct content-type
        })
    });

    if (!response.ok) {
        const error = await response.json().catch(() => ({ error: { message: response.statusText } }));
        throw new Error(error.error?.message || 'Request failed!');
    }

    return response.json();
}

// ✅ Updated: File uploads go through a separate proxy endpoint
async function makeFileRequest(file) {
    const formData = new FormData();
    formData.append("file", file);

    const response = await fetch(`${PROXY_URL.replace('/api/scan', '')}/api/scan-file`, {
        method: "POST",
        body: formData  // sent as multipart/form-data directly
    });

    if (!response.ok) {
        const error = await response.json().catch(() => ({ error: { message: response.statusText } }));
        throw new Error(error.error?.message || 'File upload failed!');
    }

    return response.json();
}

// Handles the process of scanning a URL using VirusTotal
async function scanURL() {
    const url = getElement('urlInput').value.trim();
    if (!url) return showError("Please enter a URL!");

    try {
        new URL(url); // Validate URL format
    } catch {
        return showError("Please enter a valid URL (e.g., https://example.com)");
    }

    try {
        showLoading("Submitting URL for scanning...");

        const encodedUrl = encodeURIComponent(url);

        // ✅ Now calls proxy with endpoint name instead of full VirusTotal URL
        const submitResult = await makeRequest("urls", {
            method: "POST",
            body: `url=${encodedUrl}`,
            isFormData: true
        });

        if (!submitResult.data?.id) {
            throw new Error("Failed to get analysis ID");
        }

        await new Promise(resolve => setTimeout(resolve, 3000));

        showLoading("Getting scan results...");
        await pollAnalysisResults(submitResult.data.id);
    } catch (error) {
        showError(`Error: ${error.message}`);
    }
}

// Handles the process of scanning a file using VirusTotal
async function scanFile() {
    const file = getElement('fileInput').files[0];
    if (!file) return showError("Please select a file!");
    if (file.size > 32 * 1024 * 1024) return showError("File size exceeds 32MB limit.");

    try {
        showLoading("Uploading file...");

        // ✅ Uses dedicated file upload proxy endpoint
        const uploadResult = await makeFileRequest(file);

        if (!uploadResult.data?.id) {
            throw new Error("Failed to get file ID!");
        }

        await new Promise(resolve => setTimeout(resolve, 3000));

        showLoading("Getting scan results...");

        // ✅ Fetch analysis using the proxy
        const analysisResult = await makeRequest(`analyses/${uploadResult.data.id}`);

        if (!analysisResult.data?.id) {
            throw new Error("Failed to get analysis results!");
        }

        await pollAnalysisResults(analysisResult.data.id, file.name);
    } catch (error) {
        showError(`Error: ${error.message}`);
    }
}

// Polls VirusTotal for analysis results, retrying until complete or timeout
async function pollAnalysisResults(analysisId, fileName = '') {
    const maxAttempts = 20;
    let attempts = 0;
    let interval = 2000;

    while (attempts < maxAttempts) {
        try {
            showLoading(`Analyzing${fileName ? ` ${fileName}` : ''}... (${((maxAttempts - attempts) * interval / 1000).toFixed(0)}s remaining)`);

            // ✅ Now calls proxy with just the endpoint path
            const report = await makeRequest(`analyses/${analysisId}`);
            const status = report.data?.attributes?.status;

            if (!status) throw new Error("Invalid analysis response!");

            if (status === "completed") {
                showFormattedResult(report);
                break;
            }

            if (status === "failed") {
                throw new Error("Analysis failed!");
            }

            if (++attempts >= maxAttempts) {
                throw new Error("Analysis timeout - please try again!");
            }

            interval = Math.min(interval * 1.5, 8000);
            await new Promise(resolve => setTimeout(resolve, interval));
        } catch (error) {
            showError(`Error: ${error.message}`);
            break;
        }
    }
}

// Formats and displays analysis results in the UI
function showFormattedResult(data) {
    if (!data?.data?.attributes?.stats) return showError("Invalid response format!");

    const stats = data.data.attributes.stats;
    const total = Object.values(stats).reduce((sum, val) => sum + val, 0);
    if (!total) return showError("No analysis results available!");

    const getPercent = val => ((val / total) * 100).toFixed(1);

    const categories = {
        malicious: { color: 'malicious', label: 'Malicious' },
        suspicious: { color: 'suspicious', label: 'Suspicious' },
        harmless: { color: 'safe', label: 'Clean' },
        undetected: { color: 'undetected', label: 'Undetected' }
    };

    const percents = Object.keys(categories).reduce((acc, key) => {
        acc[key] = getPercent(stats[key]);
        return acc;
    }, {});

    const verdict = stats.malicious > 0 ? "Malicious" : stats.suspicious > 0 ? "Suspicious" : "Safe";
    const verdictClass = stats.malicious > 0 ? "malicious" : stats.suspicious > 0 ? "suspicious" : "safe";

    updateResult(`
        <h3>Scan Report</h3>
        <div class="scan-stats">
            <p><strong>Verdict:</strong> <span class="${verdictClass}">${verdict}</span></p>
            <div class="progress-section">
                <div class="progress-label">
                    <span>Detection Results</span>
                    <span class="progress-percent">${percents.malicious}% Detection Rate</span>
                </div>
                <div class="progress-stacked">
                    ${Object.entries(categories).map(([key, { color }]) => `
                        <div class="progress-bar ${color}" style="width: ${percents[key]}%" title="${categories[key].label}: ${stats[key]} (${percents[key]}%)">
                            <span class="progress-label-overlay">${stats[key]}</span>
                        </div>
                    `).join('')}
                </div>
                <div class="progress-legend">
                    ${Object.entries(categories).map(([key, { color, label }]) => `
                        <div class="legend-item">
                            <span class="legend-color ${color}"></span>
                            <span>${label} (${percents[key]}%)</span>
                        </div>
                    `).join('')}
                </div>
            </div>
            <div class="detection-details">
                ${Object.entries(categories).map(([key, { color, label }]) => `
                    <div class="detail-item ${color}">
                        <span class="detail-label">${label}</span>
                        <span class="detail-value">${stats[key]}</span>
                        <span class="detail-percent">${percents[key]}%<span>
                    </div>
                `).join('')}
            </div>
        </div>
        <button onclick="showFullReport(this.getAttribute('data-report'))" data-report='${JSON.stringify(data)}'>View Full Report</button>
    `);

    setTimeout(() => getElement('result').querySelector('.progress-stacked').classList.add('animate'), 1000);
}

// Displays a detailed report modal with engine-by-engine detection results
function showFullReport(reportData) {
    const data = typeof reportData === 'string' ? JSON.parse(reportData) : reportData;
    const modal = getElement("fullReportModal");
    const results = data.data?.attributes?.results;

    getElement("fullReportContent").innerHTML = `
        <h3>Full Report Details</h3>
        ${results ? `
            <table>
                <tr><th>Engine</th><th>Result</th></tr>
                ${Object.entries(results).map(([engine, { category }]) => `
                    <tr>
                        <td>${engine}</td>
                        <td class="${category === "malicious" ? "malicious" : category === "suspicious" ? "suspicious" : "safe"}">${category}</td>
                    </tr>
                `).join('')}
            </table>
        ` : '<p>No detailed results available!</p>'}
    `;

    modal.style.display = "block";
    modal.offsetHeight;
    modal.classList.add("show");
}

// Closes the full report modal
const closeModal = () => {
    const modal = getElement("fullReportModal");
    modal.classList.remove("show");
    setTimeout(() => modal.style.display = "none", 300);
}

// Close modal on outside click
window.addEventListener('load', () => {
    const modal = getElement("fullReportModal");
    window.addEventListener('click', e => e.target === modal && closeModal());
});

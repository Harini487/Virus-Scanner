// New proxy request function — replaces makeRequest()
async function makeRequest(endpoint, options = {}) {
    const response = await fetch("https://your-project.vercel.app/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            endpoint,                          // e.g. "urls" or "files"
            method: options.method || "GET",
            body: options.body || null,
            isFormData: options.isFormData || false
        })
    });

    if (!response.ok) {
        const error = await response.json().catch(() => ({ error: { message: response.statusText } }));
        throw new Error(error.error?.message || 'Request failed!');
    }

    return response.json();
}

// Update scanURL() — change only the makeRequest call
async function scanURL() {
    const url = getElement('urlInput').value.trim();
    if (!url) return showError("Please enter a URL!");

    try {
        new URL(url);
    } catch {
        return showError("Please enter a valid URL (e.g., https://example.com)");
    }

    try {
        showLoading("Submitting URL for scanning...");

        const encodedUrl = encodeURIComponent(url);

        // ✅ Now calls your proxy instead of VirusTotal directly
        const submitResult = await makeRequest("urls", {
            method: "POST",
            body: `url=${encodedUrl}`,
            isFormData: true
        });

        if (!submitResult.data?.id) throw new Error("Failed to get analysis ID");

        await new Promise(resolve => setTimeout(resolve, 3000));
        showLoading("Getting scan results...");
        await pollAnalysisResults(submitResult.data.id);
    } catch (error) {
        showError(`Error: ${error.message}`);
    }
}

// Update pollAnalysisResults() — change only the makeRequest call
async function pollAnalysisResults(analysisId, fileName = '') {
    const maxAttempts = 20;
    let attempts = 0;
    let interval = 2000;

    while (attempts < maxAttempts) {
        try {
            showLoading(`Analyzing${fileName ? ` ${fileName}` : ''}... (${((maxAttempts - attempts) * interval / 1000).toFixed(0)}s remaining)`);

            // ✅ Now calls your proxy
            const report = await makeRequest(`analyses/${analysisId}`);
            const status = report.data?.attributes?.status;

            if (!status) throw new Error("Invalid analysis response!");
            if (status === "completed") { showFormattedResult(report); break; }
            if (status === "failed") throw new Error("Analysis failed!");
            if (++attempts >= maxAttempts) throw new Error("Analysis timeout - please try again!");

            interval = Math.min(interval * 1.5, 8000);
            await new Promise(resolve => setTimeout(resolve, interval));
        } catch (error) {
            showError(`Error: ${error.message}`);
            break;
        }
    }
}

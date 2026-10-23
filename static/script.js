const scanForm = document.getElementById("scanForm");
const targetInput = document.getElementById("targetUrl");
const scanButton = document.getElementById("scanButton");
const scanMessage = document.getElementById("scanMessage");
const findingsList = document.getElementById("findingsList");
const findingCount = document.getElementById("findingCount");
const aiResult = document.getElementById("aiResult");

let totalScans = 0;
let totalFindings = 0;
let highFindings = 0;

async function checkBackend() {
    const statusText = document.getElementById("backendStatus");
    const dot = document.getElementById("backendDot");
    const availability = document.getElementById("scannerAvailability");
    try {
        const response = await fetch("/api/health");
        if (!response.ok) throw new Error("Backend unavailable");
        const data = await response.json();
        statusText.textContent = "Backend online";
        dot.className = "status-dot online";
        if (availability && data.tools) {
            availability.textContent =
                `Nuclei: ${data.tools.nuclei ? "available" : "not detected"} · ` +
                `OWASP ZAP: ${data.tools.zap ? "configured" : "not configured"}.`;
        }
    } catch {
        statusText.textContent = "Backend offline";
        dot.className = "status-dot offline";
        if (availability) availability.textContent = "Could not check scanner configuration.";
    }
}

function showMessage(message, isError = false) {
    scanMessage.textContent = message;
    scanMessage.className = "message show" + (isError ? " error" : "");
}

function makeTextElement(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    element.textContent = text ?? "";
    return element;
}

function severityCounts(findings) {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
    findings.forEach((finding) => {
        const value = String(finding.severity || "Informational").toLowerCase();
        if (value === "critical") counts.Critical++;
        else if (value === "high") counts.High++;
        else if (value === "medium") counts.Medium++;
        else if (value === "low") counts.Low++;
        else counts.Informational++;
    });
    return counts;
}

function renderSeverityChart(findings) {
    const chart = document.getElementById("severityChartBars");
    const total = document.getElementById("chartTotal");
    if (!chart || !total) return;

    const counts = severityCounts(findings);
    const entries = [
        ["Critical", counts.Critical, "critical"],
        ["High", counts.High, "high"],
        ["Medium", counts.Medium, "medium"],
        ["Low", counts.Low, "low"],
        ["Informational", counts.Informational, "informational"]
    ];
    const max = Math.max(1, ...entries.map((entry) => entry[1]));
    total.textContent = `${findings.length} finding${findings.length === 1 ? "" : "s"}`;
    chart.replaceChildren();

    entries.forEach(([label, count, className]) => {
        const row = document.createElement("div");
        row.className = "chart-row";
        const labelEl = makeTextElement("span", "chart-label", label);
        const track = document.createElement("div");
        track.className = "chart-track";
        const bar = document.createElement("div");
        bar.className = `chart-bar ${className}`;
        bar.style.width = `${count === 0 ? 0 : Math.max(3, (count / max) * 100)}%`;
        bar.setAttribute("aria-label", `${label}: ${count}`);
        track.appendChild(bar);
        const value = makeTextElement("strong", "chart-value", String(count));
        row.append(labelEl, track, value);
        chart.appendChild(row);
    });
}

function renderFindings(findings) {
    findingsList.replaceChildren();
    findingCount.textContent = `${findings.length} finding${findings.length === 1 ? "" : "s"}`;
    renderSeverityChart(findings);

    if (findings.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty-state";
        empty.append(
            makeTextElement("span", "", "✓"),
            makeTextElement("h3", "", "No findings reported by the selected checks"),
            makeTextElement("p", "", "This does not prove the application is vulnerability-free.")
        );
        findingsList.append(empty);
        return;
    }

    findings.forEach((finding) => {
        const card = document.createElement("article");
        card.className = "finding-card";
        const top = document.createElement("div");
        top.className = "finding-top";
        top.append(
            makeTextElement("h3", "", finding.title),
            makeTextElement("span", "severity " + String(finding.severity || "unknown").toLowerCase(), finding.severity || "Unknown")
        );
        const category = makeTextElement("p", "", "Category: " + (finding.category || "Unclassified"));
        const source = finding.scanner ? makeTextElement("p", "finding-source", "Detected by: " + finding.scanner) : null;
        const evidence = makeTextElement("p", "", "Evidence: " + (finding.evidence || "No evidence provided."));
        const recommendation = makeTextElement("p", "", "Initial recommendation: " + (finding.recommendation || "Review the server configuration."));
        const explainButton = makeTextElement("button", "", "✦ Explain with AI");
        explainButton.type = "button";
        explainButton.addEventListener("click", () => explainFinding(finding, explainButton));
        card.append(top, category);
        if (source) card.append(source);
        card.append(evidence, recommendation, explainButton);
        findingsList.append(card);
    });
}

scanForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const url = targetInput.value.trim();
    const scanners = [...document.querySelectorAll('input[name="scanner"]:checked')].map((input) => input.value);
    if (!url) return showMessage("Enter a target URL.", true);
    if (scanners.length === 0) return showMessage("Select at least one scanner.", true);

    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";
    showMessage("Running selected security checks. Tool scans may take a few minutes.");
    aiResult.replaceChildren(makeTextElement("p", "", "Select a finding to request AI remediation guidance."));

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url, scanners })
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || "Scan request failed.");
        if (result.status !== "completed") throw new Error(result.message || "The scan could not be completed.");

        const findings = result.findings || [];
        totalScans++;
        totalFindings += findings.length;
        highFindings += findings.filter((finding) =>
            ["high", "critical"].includes(String(finding.severity).toLowerCase())
        ).length;

        document.getElementById("totalScans").textContent = totalScans;
        document.getElementById("totalFindings").textContent = totalFindings;
        document.getElementById("highFindings").textContent = highFindings;
        document.getElementById("latestStatus").textContent = "Completed";
        renderFindings(findings);

        let message = `Scan completed. ${findings.length} potential finding(s) identified.`;
        if (result.scanner_status) {
            message += " Scanner status: " + Object.entries(result.scanner_status)
                .map(([name, status]) => `${name} ${status}`).join(", ") + ".";
        }
        if (result.scanner_errors?.length) message += " Some tools reported errors: " + result.scanner_errors.join(" ");
        if (result.redirect_detected) message += " The target returned a redirect; it was not followed.";
        showMessage(message, Boolean(result.scanner_errors?.length));
        await loadScanHistory();
    } catch (error) {
        showMessage(error.message || "Could not complete the scan.", true);
    } finally {
        scanButton.disabled = false;
        scanButton.textContent = "▶  Start Scan";
    }
});

async function explainFinding(finding, button) {
    button.disabled = true;
    button.textContent = "Getting guidance...";
    aiResult.replaceChildren(makeTextElement("p", "", "The AI assistant is preparing remediation guidance..."));
    try {
        const response = await fetch("/api/explain", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ finding })
        });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || "AI request failed.");
        aiResult.replaceChildren(
            makeTextElement("h3", "", finding.title || "Finding explanation"),
            makeTextElement("p", "", result.explanation || "No explanation returned.")
        );
        document.getElementById("remediation").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
        aiResult.replaceChildren(makeTextElement("p", "", error.message || "Could not get AI guidance."));
    } finally {
        button.disabled = false;
        button.textContent = "✦ Explain with AI";
    }
}

const historyBody = document.getElementById("scanHistoryBody");
const refreshHistoryButton = document.getElementById("refreshHistory");
const historyMessage = document.getElementById("historyMessage");

function historyCell(value) {
    const cell = document.createElement("td");
    cell.textContent = value ?? "—";
    return cell;
}

async function loadScanHistory() {
    if (!historyBody) return;
    historyBody.replaceChildren();
    const loadingRow = document.createElement("tr");
    const loadingCell = historyCell("Loading scan history...");
    loadingCell.colSpan = 6;
    loadingRow.appendChild(loadingCell);
    historyBody.appendChild(loadingRow);

    try {
        const response = await fetch("/api/scans");
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "Could not load scan history.");
        const scans = data.scans || [];
        historyBody.replaceChildren();

        if (!scans.length) {
            const row = document.createElement("tr");
            const cell = historyCell("No previous scans yet.");
            cell.colSpan = 6;
            cell.className = "history-empty";
            row.appendChild(cell);
            historyBody.appendChild(row);
        } else {
            scans.forEach((scan) => {
                const row = document.createElement("tr");
                row.append(historyCell(scan.id), historyCell(scan.target));
                const statusCell = historyCell(scan.status);
                statusCell.className = "history-status";
                row.appendChild(statusCell);
                row.appendChild(historyCell(scan.findings_count));
                row.appendChild(historyCell(scan.created_at ? new Date(scan.created_at).toLocaleString() : "—"));
                const actionCell = document.createElement("td");
                const viewButton = document.createElement("button");
                viewButton.type = "button";
                viewButton.textContent = "View";
                viewButton.addEventListener("click", () => viewSavedScan(scan.id));
                actionCell.appendChild(viewButton);
                row.appendChild(actionCell);
                historyBody.appendChild(row);
            });
        }
        historyMessage.textContent = "";
        historyMessage.className = "message";
    } catch (error) {
        historyBody.replaceChildren();
        const row = document.createElement("tr");
        const cell = historyCell("Unable to load scan history.");
        cell.colSpan = 6;
        row.appendChild(cell);
        historyBody.appendChild(row);
        historyMessage.textContent = error.message;
        historyMessage.className = "message show error";
    }
}

async function viewSavedScan(scanId) {
    try {
        const response = await fetch(`/api/scans/${scanId}`);
        const scan = await response.json();
        if (!response.ok) throw new Error(scan.error || "Could not load this scan.");
        const findings = scan.findings || [];
        renderFindings(findings);
        targetInput.value = scan.target;
        showMessage(`Viewing saved scan #${scan.id} for ${scan.target}.`);
        aiResult.replaceChildren(makeTextElement("p", "", "Select “Explain with AI” on a finding to request guidance."));
        document.getElementById("findings").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
        historyMessage.textContent = error.message;
        historyMessage.className = "message show error";
    }
}

if (refreshHistoryButton) refreshHistoryButton.addEventListener("click", loadScanHistory);
checkBackend();
loadScanHistory();

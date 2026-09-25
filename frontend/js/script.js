const API_URL = "http://127.0.0.1:8001";

let currentResult = null;


// ======================================================
// DOM READY
// ======================================================

document.addEventListener("DOMContentLoaded", () => {

    console.log("ThreatLens frontend loaded.");

    setupTabs();
    setupAnalyzeButton();
    setupResetButton();
    setupEMLUpload();
    loadIncidents();
});


// ======================================================
// TAB SYSTEM
// ======================================================

function setupTabs() {

    const tabs = document.querySelectorAll(".tab");
    const panes = document.querySelectorAll(".tab-pane");

    tabs.forEach(tab => {

        tab.addEventListener("click", () => {

            const selectedTab = tab.dataset.tab;

            tabs.forEach(item => {
                item.classList.remove("is-active");
            });

            panes.forEach(pane => {
                pane.classList.remove("is-active");
            });

            tab.classList.add("is-active");

            const selectedPane = document.querySelector(
                `.tab-pane[data-pane="${selectedTab}"]`
            );

            if (selectedPane) {
                selectedPane.classList.add("is-active");
            }

        });

    });

}


// ======================================================
// ANALYZE BUTTON
// ======================================================

function setupAnalyzeButton() {

    const button = document.getElementById("btn-analyze");

    if (!button) {
        console.error("Analyze button not found.");
        return;
    }

    button.addEventListener("click", analyzeThreat);

}


// ======================================================
// MAIN ANALYSIS
// ======================================================

async function analyzeThreat() {

    const sender =
        document.getElementById("in-sender")?.value.trim() || "";

    const subject =
        document.getElementById("in-subject")?.value.trim() || "";

    const body =
        document.getElementById("in-body")?.value.trim() || "";

    const url =
        document.getElementById("in-url")?.value.trim() || "";

    const errorBox =
        document.getElementById("input-error");

    const analyzeButton =
        document.getElementById("btn-analyze");


    // --------------------------------------------------
    // Clear previous error
    // --------------------------------------------------

    if (errorBox) {
        errorBox.textContent = "";
    }


    // --------------------------------------------------
    // Input validation
    // --------------------------------------------------

    if (!sender && !subject && !body && !url) {

        if (errorBox) {
            errorBox.textContent =
                "Please enter an email or URL to analyze.";
        }

        return;
    }


    // --------------------------------------------------
    // Button loading state
    // --------------------------------------------------

    if (analyzeButton) {

        analyzeButton.disabled = true;

        analyzeButton.innerHTML =
            '<span class="btn__icon">◌</span> ANALYZING...';

    }


    // --------------------------------------------------
    // Show pipeline
    // --------------------------------------------------

    showPipeline();


    try {

        // ------------------------------------------------
        // Send request to FastAPI backend
        // ------------------------------------------------

        const response = await fetch(
            `${API_URL}/analyze`,
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    sender: sender,
                    subject: subject,
                    body: body,
                    url: url
                })
            }
        );


        // ------------------------------------------------
        // Check response
        // ------------------------------------------------

        if (!response.ok) {

            throw new Error(
                `Backend returned HTTP ${response.status}`
            );

        }


        // ------------------------------------------------
        // Read JSON response
        // ------------------------------------------------

        const result = await response.json();


        console.log(
            "ThreatLens Backend Result:",
            result
        );


        currentResult = result;


        // ------------------------------------------------
        // Animate pipeline
        // ------------------------------------------------

        await animatePipeline();


        // ------------------------------------------------
        // Display complete analysis
        // ------------------------------------------------

        displayAnalysis(result);


    } catch (error) {

        console.error(
            "ThreatLens API Error:",
            error
        );


        if (errorBox) {

            errorBox.textContent =
                "Unable to connect to ThreatLens backend. " +
                "Make sure FastAPI is running on port 8001.";

        }

    } finally {

        if (analyzeButton) {

            analyzeButton.disabled = false;

            analyzeButton.innerHTML =
                '<span class="btn__icon">▣</span> ANALYZE THREAT';

        }

    }

}


// ======================================================
// SHOW PIPELINE
// ======================================================

function showPipeline() {

    const pipeline =
        document.getElementById("panel-pipeline");

    const results =
        document.getElementById("results");


    if (pipeline) {
        pipeline.classList.remove("is-hidden");
    }

    if (results) {
        results.classList.add("is-hidden");
    }


    // Reset pipeline stages

    document
        .querySelectorAll(".pipeline__stage")
        .forEach(stage => {

            stage.classList.remove(
                "is-active",
                "is-complete"
            );

        });


    const status =
        document.getElementById("pipeline-status");

    if (status) {
        status.textContent = "RUNNING";
    }

}


// ======================================================
// PIPELINE ANIMATION
// ======================================================

async function animatePipeline() {

    const stages =
        document.querySelectorAll(".pipeline__stage");

    const status =
        document.getElementById("pipeline-status");


    for (const stage of stages) {

        stage.classList.add("is-active");

        await sleep(180);

        stage.classList.remove("is-active");

        stage.classList.add("is-complete");

    }


    if (status) {
        status.textContent = "COMPLETE";
    }

}


// ======================================================
// SLEEP HELPER
// ======================================================

function sleep(ms) {

    return new Promise(resolve => {
        setTimeout(resolve, ms);
    });

}


// ======================================================
// DISPLAY COMPLETE ANALYSIS
// ======================================================

function displayAnalysis(result) {

    const results =
        document.getElementById("results");

    if (results) {
        results.classList.remove("is-hidden");
    }


    displayVerdict(result);

    displayAuthentication(result.authentication);

    displayDomainEvidence(result);

    displayURLEvidence(result);

    displayContentEvidence(result);

    displayExplanation(result.explanation);

    displayCampaign(result.campaign);

    displayBlastRadius(result.blast_radius);

    displayPriority(result.priority);

    updateQueue(result);


    // Scroll to results

    setTimeout(() => {

        if (results) {

            results.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });

        }

    }, 100);

}


// ======================================================
// THREAT VERDICT
// ======================================================

function displayVerdict(result) {

    const classification =
        document.getElementById("v-classification");

    const risk =
        document.getElementById("v-risk");

    const riskbar =
        document.getElementById("v-riskbar");

    const confidence =
        document.getElementById("v-confidence");

    const priority =
        document.getElementById("v-priority");


    // Classification

    if (classification) {

        classification.textContent =
            result.classification || "UNKNOWN";

    }


    // Risk score

    if (risk) {

        risk.textContent =
            `${result.risk_score || 0}/100`;

    }


    // Risk bar

    if (riskbar) {

        const score =
            Math.max(
                0,
                Math.min(
                    100,
                    Number(result.risk_score) || 0
                )
            );

        riskbar.style.width =
            `${score}%`;

    }


    // Confidence

    if (confidence) {

        confidence.textContent =
            result.confidence || "—";

        confidence.className =
            "pill " +
            getPillClass(result.confidence);

    }


    // SOC priority

    if (priority) {

        priority.textContent =
            result.priority?.priority_level || "—";

        priority.className =
            "pill " +
            getPillClass(
                result.priority?.priority_level
            );

    }


    // Case ID

    const caseTag =
        document.getElementById("case-id-tag");

    if (caseTag) {

        const campaignId =
            result.campaign?.campaign_id ||
            "TL-CASE";

        caseTag.textContent =
            `CASE — ${campaignId}`;

    }

}


// ======================================================
// AUTHENTICATION EVIDENCE
// ======================================================

function displayAuthentication(auth) {

    const container = document.getElementById("ev-auth");

    if (!container) {
        console.error("Authentication container not found.");
        return;
    }

    if (!auth) {
        container.innerHTML = `
            <div class="kv-row">
                <span class="kv-key">Authentication</span>
                <span class="kv-value">No data</span>
            </div>
        `;
        return;
    }

    const spf = auth.spf || {};
    const dkim = auth.dkim || {};
    const dmarc = auth.dmarc || {};
    const mx = auth.mx || {};

    container.innerHTML = `
        <div class="kv-row">
            <span class="kv-key">Domain</span>
            <span class="kv-value">
                ${escapeHTML(auth.domain || "—")}
            </span>
        </div>

        <div class="kv-row">
            <span class="kv-key">SPF</span>
            <span class="kv-value">
                ${formatAuthStatus(spf)}
            </span>
        </div>

        <div class="kv-row">
            <span class="kv-key">DKIM</span>
            <span class="kv-value">
                ${formatAuthStatus(dkim)}
            </span>
        </div>

        <div class="kv-row">
            <span class="kv-key">DMARC</span>
            <span class="kv-value">
                ${formatAuthStatus(dmarc)}
            </span>
        </div>

        <div class="kv-row">
            <span class="kv-key">MX</span>
            <span class="kv-value">
                ${formatAuthStatus(mx)}
            </span>
        </div>
    `;
}

// ======================================================
// AUTHENTICATION STATUS
// ======================================================

function formatAuthStatus(data) {

    if (!data) {
        return "—";
    }

    if (data.status === "FOUND") {
        return "DNS record found";
    }

    if (data.status === "NOT_FOUND") {
        return "DNS record not found";
    }

    if (data.status === "NOT_CHECKED") {
        return "Not checked";
    }

    if (data.status === "ERROR") {
        return "DNS lookup error";
    }

    return data.status || "Unknown";
}


// ======================================================
// DOMAIN EVIDENCE
// ======================================================

function displayDomainEvidence(result) {

    const container =
        document.getElementById("ev-domain");

    if (!container) return;


    const signals =
        result.signals?.domain || [];


    container.innerHTML = `

        ${createKV(
            "Domain",
            result.parsed_email?.domain || "—"
        )}

        ${createKV(
            "Signals",
            signals.length
                ? `${signals.length} detected`
                : "No suspicious signals"
        )}

        ${createSignalList(signals)}

    `;

}


// ======================================================
// URL EVIDENCE
// ======================================================

function displayURLEvidence(result) {

    const container =
        document.getElementById("ev-url");

    if (!container) return;


    const signals =
        result.signals?.url || [];


    const urls =
        result.parsed_email?.urls || [];


    container.innerHTML = `

        ${createKV(
            "URLs detected",
            urls.length
        )}

        ${createKV(
            "Signals",
            signals.length
                ? `${signals.length} detected`
                : "No suspicious signals"
        )}

        ${createSignalList(signals)}

    `;

}


// ======================================================
// CONTENT EVIDENCE
// ======================================================

function displayContentEvidence(result) {

    const container =
        document.getElementById("ev-content");

    if (!container) return;


    const signals =
        result.signals?.content || [];


    container.innerHTML = `

        ${createKV(
            "Signals",
            signals.length
                ? `${signals.length} detected`
                : "No suspicious signals"
        )}

        ${createSignalList(signals)}

    `;

}


// ======================================================
// SIGNAL LIST
// ======================================================

function createSignalList(signals) {

    if (!signals || signals.length === 0) {

        return `
            <div class="kv-row">

                <span class="kv-key">
                    Status
                </span>

                <span class="kv-value">
                    No suspicious signals
                </span>

            </div>
        `;

    }


    return signals.map(signal => {

        // ----------------------------------------------
        // Get detected value
        // ----------------------------------------------

        let detectedValue =
            signal.value;


        // ----------------------------------------------
        // Convert arrays to readable text
        // Example:
        // ["urgent", "immediately"]
        // becomes:
        // urgent, immediately
        // ----------------------------------------------

        if (Array.isArray(detectedValue)) {

            detectedValue =
                detectedValue.join(", ");

        }


        // ----------------------------------------------
        // Handle missing value
        // ----------------------------------------------

        if (
            detectedValue === undefined ||
            detectedValue === null ||
            detectedValue === ""
        ) {

            detectedValue =
                "Detected";

        }


        return `

            <div class="kv-row">

                <span class="kv-key">

                    ${escapeHTML(
                        signal.type || "Signal"
                    )}

                </span>


                <span class="kv-value">

                    <strong>
                        Detected:
                        ${escapeHTML(
                            String(detectedValue)
                        )}
                    </strong>

                    <br>

                    <span class="signal-explanation">

                        ${escapeHTML(
                            signal.explanation || ""
                        )}

                    </span>

                </span>

            </div>

        `;

    }).join("");

}


// ======================================================
// EXPLANATION
// ======================================================

function displayExplanation(explanations) {

    const list =
        document.getElementById("reason-list");

    const count =
        document.getElementById("explain-count");


    if (!list) return;


    if (
        !explanations ||
        explanations.length === 0
    ) {

        list.innerHTML =
            "<li>No suspicious reasons detected.</li>";

        if (count) {
            count.textContent = "0 reasons";
        }

        return;

    }


    list.innerHTML =
        explanations.map(reason => {

            return `
                <li class="reason-list__item">
                    ${escapeHTML(reason)}
                </li>
            `;

        }).join("");


    if (count) {

        count.textContent =
            `${explanations.length} ${
                explanations.length === 1
                    ? "reason"
                    : "reasons"
            }`;

    }

}


// ======================================================
// CAMPAIGN INTELLIGENCE
// ======================================================

function displayCampaign(campaign) {

    const grid =
        document.getElementById("campaign-grid");

    const status =
        document.getElementById("campaign-status");


    if (!grid) return;


    if (!campaign) {

        grid.innerHTML =
            "<div>No campaign data.</div>";

        return;

    }


    if (status) {

        status.textContent =
            campaign.status ||
            (
                campaign.is_campaign
                    ? "CAMPAIGN DETECTED"
                    : "NO CAMPAIGN"
            );

    }


    grid.innerHTML = `

        ${createKV(
            "Campaign ID",
            campaign.campaign_id || "—"
        )}

        ${createKV(
            "Name",
            campaign.name || "—"
        )}

        ${createKV(
            "Related cases",
            campaign.related_cases ?? "—"
        )}

        ${createKV(
            "Recipients",
            campaign.recipients ?? "—"
        )}

        ${createKV(
            "Departments",
            campaign.departments?.join(", ") || "—"
        )}

        ${createKV(
            "Status",
            campaign.status || "—"
        )}

    `;

}


// ======================================================
// BLAST RADIUS
// ======================================================

function displayBlastRadius(blast) {

    const grid =
        document.getElementById("blast-grid");

    const departments =
        document.getElementById("blast-departments");


    if (!grid) return;


    if (!blast) {

        grid.innerHTML =
            "<div>No exposure data.</div>";

        return;

    }


    grid.innerHTML = `

        ${createKV(
            "Employees exposed",
            blast.employees_exposed ?? 0
        )}

        ${createKV(
            "Emails delivered",
            blast.emails_delivered ?? 0
        )}

        ${createKV(
            "Opened",
            blast.opened ?? 0
        )}

        ${createKV(
            "Clicked",
            blast.clicked ?? 0
        )}

        ${createKV(
            "Credential attempts",
            blast.credential_attempts ?? 0
        )}

    `;


    if (departments) {

        departments.innerHTML =
            (
                blast.departments_affected || []
            ).map(department => {

                return `
                    <span class="chip">
                        ${escapeHTML(
                            department
                        )}
                    </span>
                `;

            }).join("");

    }

}


// ======================================================
// SOC PRIORITY
// ======================================================

function displayPriority(priority) {

    const formula =
        document.getElementById("priority-formula");

    const level =
        document.getElementById("priority-level");

    const action =
        document.getElementById("priority-action");


    if (!priority) return;


    if (formula) {

        formula.innerHTML = `

            <div class="kv-row">

                <span class="kv-key">
                    Priority score
                </span>

                <span class="kv-value">
                    ${priority.priority_score ?? 0}/100
                </span>

            </div>

        `;

    }


    if (level) {

        level.textContent =
            priority.priority_level || "—";

    }


    if (action) {

        action.textContent =
            priority.recommended_action || "—";

    }

}


// ======================================================
// SOC QUEUE
// ======================================================

function updateQueue(result) {

    const queueBody =
        document.getElementById("queue-body");

    const capacity =
        document.getElementById("queue-capacity");


    if (!queueBody) return;


    const priority =
        result.priority?.priority_level ||
        "LOW";


    const risk =
        result.risk_score ??
        0;


    const exposure =
        result.blast_radius?.employees_exposed ??
        0;


    const campaign =
        result.campaign?.campaign_id ||
        "—";


    const caseId =
        result.campaign?.campaign_id ||
        "TL-CASE-001";


    queueBody.innerHTML = `

        <tr>

            <td>

                <span class="pill ${getPillClass(priority)}">

                    ${escapeHTML(priority)}

                </span>

            </td>


            <td>
                ${escapeHTML(caseId)}
            </td>


            <td>
                ${escapeHTML(campaign)}
            </td>


            <td>
                ${exposure}
            </td>


            <td>
                ${risk}/100
            </td>


            <td>

                <span class="queue-status">
                    NEW
                </span>

            </td>


            <td>

                <button
                    class="btn btn--ghost btn--small"
                    onclick="scrollToResults()"
                >
                    INVESTIGATE
                </button>

            </td>

        </tr>

    `;


    if (capacity) {

        capacity.textContent =
            "1 / 5 analyst slots used";

    }

}


// ======================================================
// RESET WORKSPACE
// ======================================================

function setupResetButton() {

    const button =
        document.getElementById("btn-reset");

    if (!button) return;


    button.addEventListener(
        "click",
        resetWorkspace
    );

}


function resetWorkspace() {

    document
        .querySelectorAll(
            "#in-sender, #in-subject, #in-body, #in-url"
        )
        .forEach(input => {

            input.value = "";

        });


    const errorBox =
        document.getElementById("input-error");

    if (errorBox) {
        errorBox.textContent = "";
    }


    const results =
        document.getElementById("results");

    if (results) {
        results.classList.add("is-hidden");
    }


    const pipeline =
        document.getElementById("panel-pipeline");

    if (pipeline) {
        pipeline.classList.add("is-hidden");
    }


    currentResult = null;


    console.log(
        "ThreatLens workspace reset."
    );

}


// ======================================================
// EML UPLOAD
// ======================================================

function setupEMLUpload() {

    const fileInput =
        document.getElementById("in-eml");

    const filename =
        document.getElementById("eml-filename");


    if (!fileInput) return;


    fileInput.addEventListener(
        "change",
        () => {

            if (!fileInput.files.length) {

                if (filename) {

                    filename.textContent =
                        "No file selected — headers and body will be parsed automatically.";

                }

                return;

            }


            const file =
                fileInput.files[0];


            if (filename) {

                filename.textContent =
                    `${file.name} selected — .eml backend parsing will be added next.`;

            }


            console.log(
                "Selected EML file:",
                file.name
            );

        }
    );

}


// ======================================================
// KEY-VALUE HTML HELPER
// ======================================================

function createKV(key, value) {

    return `

        <div class="kv-row">

            <span class="kv-key">

                ${escapeHTML(
                    String(key)
                )}

            </span>


            <span class="kv-value">

                ${escapeHTML(
                    String(value)
                )}

            </span>

        </div>

    `;

}


// ======================================================
// PILL CLASS HELPER
// ======================================================

function getPillClass(value) {

    if (!value) {
        return "";
    }


    const normalized =
        String(value).toLowerCase();


    if (
        normalized === "critical" ||
        normalized === "phishing" ||
        normalized === "high"
    ) {

        return "pill--danger";

    }


    if (
        normalized === "suspicious" ||
        normalized === "medium"
    ) {

        return "pill--warning";

    }


    if (
        normalized === "safe" ||
        normalized === "low"
    ) {

        return "pill--safe";

    }


    return "";

}


// ======================================================
// HTML ESCAPE
// ======================================================

function escapeHTML(value) {

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");

}


// ======================================================
// INVESTIGATE BUTTON
// ======================================================

function scrollToResults() {

    const results =
        document.getElementById("results");

    if (results) {

        results.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });

    }

}
async function loadIncidents() {

    try {

        const response = await fetch(`${API_URL}/incidents`);

        if (!response.ok) {
            throw new Error("Failed to load incidents");
        }

        const data = await response.json();

        const incidents = data.incidents || [];

        console.log("Previous incidents:", incidents);

        const queueBody = document.getElementById("queue-body");

        if (!queueBody) {
            console.error("queue-body not found.");
            return;
        }

        if (incidents.length === 0) {
            queueBody.innerHTML = `
                <div class="queue-empty">
                    No previous incidents found.
                </div>
            `;
            return;
        }

        queueBody.innerHTML = incidents.map(incident => `
            <div class="queue-item">

                <div>
                    <strong>${escapeHTML(incident.id)}</strong>
                    <div>${escapeHTML(incident.title)}</div>
                </div>

                <div>
                    ${escapeHTML(incident.severity)}
                </div>

                <div>
                    ${escapeHTML(incident.status)}
                </div>

            </div>
        `).join("");

    } catch (error) {

        console.error("Incident loading error:", error);

    }
}

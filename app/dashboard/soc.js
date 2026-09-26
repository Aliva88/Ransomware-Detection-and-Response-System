let currentSystem = null;
let dashboardLoading = false;

function getSavedSystem() {
    try {
        const saved = sessionStorage.getItem(
            "ransomshield_system"
        );

        return saved ? JSON.parse(saved) : null;

    } catch (error) {
        console.error(
            "Saved system read error:",
            error
        );

        return null;
    }
}

function setText(id, value) {
    const element =
        document.getElementById(id);

    if (element) {
        element.textContent =
            value ?? "--";
    }
}

function showToast(message) {
    const toast =
        document.getElementById("toast");

    if (!toast) {
        return;
    }

    toast.textContent = message;
    toast.classList.add("show");

    clearTimeout(window.toastTimer);

    window.toastTimer =
        setTimeout(() => {
            toast.classList.remove("show");
        }, 3000);
}

async function fetchJSON(url) {
    const response =
        await fetch(url, {
            cache: "no-store"
        });

    let data = {};

    try {
        data = await response.json();
    } catch {
        data = {};
    }

    if (!response.ok) {
        throw new Error(
            data.message ||
            `Request failed: ${response.status}`
        );
    }

    return data;
}

function findObject(data, keys) {
    if (!data || typeof data !== "object") {
        return null;
    }

    for (const key of keys) {
        if (
            data[key] &&
            typeof data[key] === "object"
        ) {
            return data[key];
        }
    }

    return data;
}

function extractScore(data) {
    const source =
        findObject(
            data,
            [
                "threat",
                "current_threat",
                "score",
                "data"
            ]
        );

    if (!source) {
        return 0;
    }

    if (typeof source === "number") {
        return source;
    }

    if (
        typeof source.score === "number"
    ) {
        return source.score;
    }

    if (
        typeof source.threat_score === "number"
    ) {
        return source.threat_score;
    }

    return 0;
}

function extractThreatLevel(data, score) {
    const source =
        findObject(
            data,
            [
                "threat",
                "current_threat",
                "data"
            ]
        );

    if (
        source &&
        typeof source.threat_level === "string"
    ) {
        return source.threat_level;
    }

    if (
        source &&
        typeof source.level === "string"
    ) {
        return source.level;
    }

    if (score >= 80) {
        return "CRITICAL";
    }

    if (score >= 60) {
        return "HIGH";
    }

    if (score >= 30) {
        return "MEDIUM";
    }

    return "LOW";
}

function updateThreat(data) {
    const score =
        Math.max(
            0,
            Math.min(
                100,
                Number(
                    extractScore(data)
                ) || 0
            )
        );

    const level =
        extractThreatLevel(
            data,
            score
        );

    setText(
        "threatScore",
        Math.round(score)
    );

    setText(
        "threatLevel",
        level
    );

    const scoreBar =
        document.getElementById(
            "scoreBar"
        );

    if (scoreBar) {
        scoreBar.style.width =
            `${score}%`;

        if (score >= 80) {
            scoreBar.style.background =
                "var(--red)";
        } else if (score >= 60) {
            scoreBar.style.background =
                "var(--orange)";
        } else {
            scoreBar.style.background =
                "var(--green)";
        }
    }
}

function getIncidentArray(data) {
    if (Array.isArray(data)) {
        return data;
    }

    if (!data || typeof data !== "object") {
        return [];
    }

    const possibleKeys = [
        "incidents",
        "data",
        "results",
        "items"
    ];

    for (const key of possibleKeys) {
        if (Array.isArray(data[key])) {
            return data[key];
        }
    }

    return [];
}

function getOpenIncidentCount(incidents) {
    return incidents.filter(
        incident => {
            const status =
                String(
                    incident.status ||
                    ""
                ).toLowerCase();

            return (
                status === "open" ||
                status === "active" ||
                status === "investigating"
            );
        }
    ).length;
}

function severityClass(severity) {
    const value =
        String(
            severity || "low"
        ).toLowerCase();

    if (
        value.includes("critical")
    ) {
        return "critical";
    }

    if (
        value.includes("high")
    ) {
        return "high";
    }

    if (
        value.includes("medium")
    ) {
        return "medium";
    }

    return "low";
}

function formatDate(value) {
    if (!value) {
        return "--";
    }

    const date =
        new Date(value);

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return String(value);
    }

    return date.toLocaleString(
        "en-IN",
        {
            day: "2-digit",
            month: "short",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit"
        }
    );
}

function renderIncidents(incidents) {
    const table =
        document.getElementById(
            "incidentTable"
        );

    if (!table) {
        return;
    }

    const sorted =
        [...incidents].sort(
            (a, b) => {
                return (
                    new Date(
                        b.timestamp || 0
                    ) -
                    new Date(
                        a.timestamp || 0
                    )
                );
            }
        );

    const recent =
        sorted.slice(0, 8);

    if (!recent.length) {
        table.innerHTML = `
            <tr>
                <td colspan="6" class="empty">
                    No security incidents detected.
                </td>
            </tr>
        `;

        return;
    }

    table.innerHTML =
        recent.map(
            incident => {

                const severity =
                    incident.severity ||
                    "Low";

                return `
                    <tr>
                        <td>
                            #${incident.id ?? "--"}
                        </td>

                        <td>
                            ${escapeHTML(
                                incident.incident_type ||
                                incident.alert_type ||
                                "Security Event"
                            )}
                        </td>

                        <td>
                            <span class="severity ${severityClass(
                                severity
                            )}">
                                ${escapeHTML(
                                    severity
                                )}
                            </span>
                        </td>

                        <td>
                            <span class="incident-status">
                                ${escapeHTML(
                                    incident.status ||
                                    "open"
                                )}
                            </span>
                        </td>

                        <td>
                            ${escapeHTML(
                                incident.description ||
                                incident.message ||
                                "Security activity detected"
                            )}
                        </td>

                        <td>
                            ${formatDate(
                                incident.timestamp
                            )}
                        </td>
                    </tr>
                `;
            }
        ).join("");
}

function escapeHTML(value) {
    return String(value ?? "")
        .replace(
            /&/g,
            "&amp;"
        )
        .replace(
            /</g,
            "&lt;"
        )
        .replace(
            />/g,
            "&gt;"
        )
        .replace(
            /"/g,
            "&quot;"
        )
        .replace(
            /'/g,
            "&#039;"
        );
}

function updateIncidentCount(incidents) {
    const count =
        getOpenIncidentCount(
            incidents
        );

    setText(
        "openIncidents",
        count
    );

    setText(
        "incidentNavBadge",
        count
    );
}

function updateSystemInformation(system) {
    if (!system) {
        return;
    }

    currentSystem = system;

    setText(
        "systemName",
        system.system_name ||
        "Protected Endpoint"
    );

    setText(
        "systemId",
        system.system_id
    );

    setText(
        "hostname",
        system.hostname
    );

    setText(
        "operatingSystem",
        system.operating_system
    );

    setText(
        "sideSystemName",
        system.system_name
    );

    setText(
        "sideSystemId",
        system.system_id
    );

    setText(
        "detailHostname",
        system.hostname
    );

    setText(
        "detailIp",
        system.ip_address
    );

    setText(
        "detailOs",
        system.operating_system
    );

    setText(
        "detailEnvironment",
        system.environment ||
        "Workstation"
    );

    setText(
        "detailVerification",
        system.verified
            ? "VERIFIED"
            : "NOT VERIFIED"
    );

    if (system.monitoring) {
        setText(
            "protectionStatus",
            "PROTECTION ACTIVE"
        );

        setText(
            "monitoringStatus",
            "ACTIVE"
        );

        setText(
            "sideProtection",
            "PROTECTION ACTIVE"
        );
    } else {
        setText(
            "protectionStatus",
            "PROTECTION INACTIVE"
        );

        setText(
            "monitoringStatus",
            "INACTIVE"
        );

        setText(
            "sideProtection",
            "PROTECTION INACTIVE"
        );
    }

    setText(
        "lastSeen",
        system.last_seen
            ? `Last seen: ${formatDate(
                system.last_seen
            )}`
            : "Last update: just now"
    );
}

function updateDetectionSignals(data) {
    if (!data) {
        return;
    }

    const detection =
        data.detection ||
        data;

    const process =
        data.process ||
        {};

    setSignal(
        "rapidEncryption",
        detection.modified_count >= 20
    );

    setSignal(
        "massRename",
        detection.rename_count >= 10
    );

    setSignal(
        "highEntropy",
        detection.high_entropy === true
    );

    setSignal(
        "cpuActivity",
        process.combined_process_activity === true ||
        process.cpu_spike === true
    );
}

function setSignal(id, active) {
    const element =
        document.getElementById(id);

    if (!element) {
        return;
    }

    element.textContent =
        active
            ? "DETECTED"
            : "CLEAR";

    element.classList.toggle(
        "alert",
        active
    );
}

async function loadSystem() {
    const saved =
        getSavedSystem();

    if (!saved) {
        console.warn(
            "No saved RansomShield system found."
        );

        return;
    }

    updateSystemInformation(
        saved
    );

    try {
        const data =
            await fetchJSON(
                `/api/systems/${encodeURIComponent(
                    saved.system_id
                )}`
            );

        const system =
            data.system ||
            data;

        if (system) {
            updateSystemInformation(
                system
            );

            sessionStorage.setItem(
                "ransomshield_system",
                JSON.stringify(system)
            );
        }

    } catch (error) {
        console.warn(
            "System API unavailable:",
            error.message
        );
    }
}

async function loadThreat() {
    try {
        const data =
            await fetchJSON(
                "/api/threat"
            );

        updateThreat(data);

        updateDetectionSignals(
            data
        );

    } catch (error) {
        console.warn(
            "Threat API unavailable:",
            error.message
        );
    }
}

async function loadDashboardSummary() {
    try {
        const data =
            await fetchJSON(
                "/api/dashboard"
            );

        updateThreat(
            data
        );

        updateDetectionSignals(
            data
        );

    } catch (error) {
        console.warn(
            "Dashboard API unavailable:",
            error.message
        );
    }
}

async function loadIncidents() {
    try {
        const data =
            await fetchJSON(
                "/api/incidents"
            );

        const incidents =
            getIncidentArray(
                data
            );

        renderIncidents(
            incidents
        );

        updateIncidentCount(
            incidents
        );

    } catch (error) {
        console.error(
            "Incident API error:",
            error
        );

        const table =
            document.getElementById(
                "incidentTable"
            );

        if (table) {
            table.innerHTML = `
                <tr>
                    <td colspan="6" class="empty">
                        Unable to load incident data.
                    </td>
                </tr>
            `;
        }
    }
}

async function loadStatus() {
    try {
        const data =
            await fetchJSON(
                "/api/status"
            );

        const status =
            data.status ||
            data;

        if (
            typeof status === "object" &&
            status
        ) {
            if (
                status.monitoring !==
                undefined &&
                currentSystem
            ) {
                currentSystem.monitoring =
                    status.monitoring;

                updateSystemInformation(
                    currentSystem
                );
            }
        }

    } catch (error) {
        console.warn(
            "Status API unavailable:",
            error.message
        );
    }
}

async function loadDashboard() {
    if (dashboardLoading) {
        return;
    }

    dashboardLoading = true;

    try {
        await Promise.all([
            loadSystem(),
            loadThreat(),
            loadDashboardSummary(),
            loadIncidents(),
            loadStatus()
        ]);

        const now =
            new Date();

        setText(
            "lastSeen",
            `Last update: ${now.toLocaleTimeString(
                "en-IN"
            )}`
        );

    } catch (error) {
        console.error(
            "Dashboard loading error:",
            error
        );

        showToast(
            "Some dashboard data could not be loaded."
        );

    } finally {
        dashboardLoading = false;
    }
}

function setupRefresh() {
    const button =
        document.getElementById(
            "refreshButton"
        );

    if (!button) {
        return;
    }

    button.addEventListener(
        "click",
        async () => {

            button.disabled = true;
            button.textContent =
                "↻ Refreshing...";

            await loadDashboard();

            button.disabled = false;
            button.textContent =
                "↻ Refresh";

            showToast(
                "Dashboard refreshed."
            );
        }
    );
}

document.addEventListener(
    "DOMContentLoaded",
    () => {

        setupRefresh();

        loadDashboard();

        /*
         * Refresh live dashboard data
         * every 5 seconds.
         */
        setInterval(
            loadDashboard,
            5000
        );
    }
);
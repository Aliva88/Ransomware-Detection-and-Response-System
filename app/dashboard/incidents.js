let allIncidents = [];

function setText(id, value) {
    const element = document.getElementById(id);

    if (element) {
        element.textContent = value ?? "--";
    }
}

function escapeHTML(value) {
    return String(value ?? "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function formatDate(value) {
    if (!value) {
        return "--";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return String(value);
    }

    return date.toLocaleString("en-IN", {
        day: "2-digit",
        month: "short",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit"
    });
}

function severityClass(value) {
    const severity =
        String(value || "low").toLowerCase();

    if (severity.includes("critical")) {
        return "critical";
    }

    if (severity.includes("high")) {
        return "high";
    }

    if (severity.includes("medium")) {
        return "medium";
    }

    return "low";
}

function getIncidents(data) {
    if (Array.isArray(data)) {
        return data;
    }

    if (!data || typeof data !== "object") {
        return [];
    }

    if (Array.isArray(data.incidents)) {
        return data.incidents;
    }

    if (Array.isArray(data.data)) {
        return data.data;
    }

    if (Array.isArray(data.results)) {
        return data.results;
    }

    return [];
}

function renderIncidents() {
    const table =
        document.getElementById("incidentTable");

    const filter =
        document.getElementById("severityFilter")
            .value
            .toLowerCase();

    let incidents = [...allIncidents];

    if (filter !== "all") {
        incidents = incidents.filter(
            incident =>
                String(
                    incident.severity || ""
                ).toLowerCase() === filter
        );
    }

    incidents.sort(
        (a, b) =>
            new Date(b.timestamp || 0) -
            new Date(a.timestamp || 0)
    );

    if (!incidents.length) {
        table.innerHTML = `
            <tr>
                <td colspan="7" class="empty">
                    No incidents found.
                </td>
            </tr>
        `;
        return;
    }

    table.innerHTML = incidents.map(
        incident => {

            const severity =
                incident.severity || "Low";

            return `
                <tr>
                    <td>#${incident.id ?? "--"}</td>

                    <td>
                        ${escapeHTML(
                            incident.incident_type ||
                            "Security Incident"
                        )}
                    </td>

                    <td>
                        <span class="severity ${severityClass(
                            severity
                        )}">
                            ${escapeHTML(severity)}
                        </span>
                    </td>

                    <td>
                        <span class="incident-status">
                            ${escapeHTML(
                                incident.status || "open"
                            )}
                        </span>
                    </td>

                    <td>
                        ${incident.threat_score ?? "--"}
                    </td>

                    <td>
                        ${escapeHTML(
                            incident.description ||
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

async function loadIncidents() {
    try {
        const response =
            await fetch("/api/incidents", {
                cache: "no-store"
            });

        if (!response.ok) {
            throw new Error(
                "Incident API request failed."
            );
        }

        const data =
            await response.json();

        allIncidents = getIncidents(data);

        const openCount =
            allIncidents.filter(
                incident => {

                    const status =
                        String(
                            incident.status || ""
                        ).toLowerCase();

                    return (
                        status === "open" ||
                        status === "active" ||
                        status === "investigating"
                    );
                }
            ).length;

        const highCount =
            allIncidents.filter(
                incident => {

                    const severity =
                        String(
                            incident.severity || ""
                        ).toLowerCase();

                    return (
                        severity === "high" ||
                        severity === "critical"
                    );
                }
            ).length;

        setText(
            "totalIncidents",
            allIncidents.length
        );

        setText(
            "openIncidents",
            openCount
        );

        setText(
            "highIncidents",
            highCount
        );

        setText(
            "incidentBadge",
            openCount
        );

        renderIncidents();

    } catch (error) {

        console.error(
            "Incident loading error:",
            error
        );

        document.getElementById(
            "incidentTable"
        ).innerHTML = `
            <tr>
                <td colspan="7" class="empty">
                    Unable to load incident data.
                </td>
            </tr>
        `;
    }
}

function loadSystem() {
    try {
        const saved =
            sessionStorage.getItem(
                "ransomshield_system"
            );

        if (!saved) {
            return;
        }

        const system =
            JSON.parse(saved);

        setText(
            "sideSystemName",
            system.system_name
        );

        setText(
            "sideSystemId",
            system.system_id
        );

    } catch (error) {
        console.error(
            "System information error:",
            error
        );
    }
}

document.addEventListener(
    "DOMContentLoaded",
    () => {

        loadSystem();
        loadIncidents();

        document
            .getElementById("refreshButton")
            .addEventListener(
                "click",
                loadIncidents
            );

        document
            .getElementById("severityFilter")
            .addEventListener(
                "change",
                renderIncidents
            );

        setInterval(
            loadIncidents,
            5000
        );
    }
);
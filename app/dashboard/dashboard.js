async function loadDashboard() {

    try {

        // Get dashboard summary
        const dashboardResponse = await fetch("/api/dashboard");

        if (!dashboardResponse.ok) {
            throw new Error("Dashboard API request failed");
        }

        const dashboardData = await dashboardResponse.json();


        // -----------------------------
        // SYSTEM STATUS
        // -----------------------------

        const systemStatus =
            dashboardData.status || "unknown";

        document.getElementById("statusValue").textContent =
            systemStatus.toUpperCase();

        document.getElementById("systemStatus").textContent =
            systemStatus.toUpperCase();


        // -----------------------------
        // THREAT INFORMATION
        // -----------------------------

        const threat = dashboardData.threat || {};

        const threatScore =
            Number(threat.score || 0);

        const threatLevel =
            threat.level || "Low";


        document.getElementById("threatScore").textContent =
            threatScore;

        document.getElementById("threatLevel").textContent =
            threatLevel.toUpperCase();

        document.getElementById("scoreDisplay").textContent =
            threatScore;

        document.getElementById("threatText").textContent =
            "Threat Level: " + threatLevel.toUpperCase();


        // -----------------------------
        // OPEN INCIDENTS
        // -----------------------------

        const openIncidents =
            Number(dashboardData.open_incidents || 0);

        document.getElementById("openIncidents").textContent =
            openIncidents;


        // -----------------------------
        // SIMULATION MODE
        // -----------------------------

        const simulationMode =
            dashboardData.simulation_mode === true;

        document.getElementById("simulationMode").textContent =
            "Simulation Mode: " +
            (simulationMode ? "ON" : "OFF");


        // -----------------------------
        // LOAD INCIDENTS
        // -----------------------------

        await loadIncidents();


    } catch (error) {

        console.error("Dashboard error:", error);

        document.getElementById("systemStatus").textContent =
            "API ERROR";

        document.getElementById("statusValue").textContent =
            "ERROR";

        document.getElementById("threatScore").textContent =
            "--";

        document.getElementById("threatLevel").textContent =
            "UNKNOWN";

        document.getElementById("scoreDisplay").textContent =
            "0";

        document.getElementById("threatText").textContent =
            "Threat Level: Unknown";

        document.getElementById("openIncidents").textContent =
            "--";

        document.getElementById("simulationMode").textContent =
            "Simulation Mode: --";
    }
}



async function loadIncidents() {

    try {

        // Request incident data from API
        const response =
            await fetch("/api/incidents");


        if (!response.ok) {
            throw new Error("Incident API request failed");
        }


        const incidents =
            await response.json();


        const table =
            document.getElementById("incidentTable");


        // Clear existing rows
        table.innerHTML = "";


        // -----------------------------
        // NO INCIDENTS
        // -----------------------------

        if (!Array.isArray(incidents) || incidents.length === 0) {

            table.innerHTML = `
                <tr>
                    <td colspan="6">
                        No security incidents detected.
                    </td>
                </tr>
            `;

            return;
        }


        // -----------------------------
        // DISPLAY INCIDENTS
        // -----------------------------

        incidents.forEach(incident => {

            const row =
                document.createElement("tr");


            row.innerHTML = `
                <td>${incident.id ?? "--"}</td>

                <td>${incident.incident_type ?? "--"}</td>

                <td>${incident.severity ?? "--"}</td>

                <td>${incident.status ?? "--"}</td>

                <td>${incident.description ?? "--"}</td>

                <td>${incident.timestamp ?? "--"}</td>
            `;


            table.appendChild(row);

        });


    } catch (error) {

        console.error(
            "Incident loading error:",
            error
        );


        document.getElementById("incidentTable").innerHTML = `
            <tr>
                <td colspan="6">
                    Failed to load security incidents.
                </td>
            </tr>
        `;
    }
}



// -------------------------------------
// INITIAL DASHBOARD LOAD
// -------------------------------------

loadDashboard();



// -------------------------------------
// AUTOMATIC REFRESH
// -------------------------------------

setInterval(
    loadDashboard,
    10000
);
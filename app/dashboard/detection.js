function setText(id, value) {
    const element =
        document.getElementById(id);

    if (element) {
        element.textContent =
            value ?? "--";
    }
}

function setSignal(id, detected) {
    const element =
        document.getElementById(id);

    if (!element) {
        return;
    }

    element.textContent =
        detected
            ? "DETECTED"
            : "CLEAR";

    element.classList.toggle(
        "detected",
        detected
    );
}

function extractThreat(data) {
    if (!data || typeof data !== "object") {
        return {};
    }

    if (data.threat) {
        return data.threat;
    }

    if (data.current_threat) {
        return data.current_threat;
    }

    return data;
}

function updateDetection(data) {

    const threat =
        extractThreat(data);

    const detection =
        threat.detection ||
        data.detection ||
        {};

    const process =
        threat.process ||
        data.process ||
        {};

    const score =
        Number(
            threat.score ||
            threat.threat_score ||
            0
        );

    let level =
        threat.threat_level ||
        threat.level;

    if (!level) {
        if (score >= 80) {
            level = "CRITICAL";
        } else if (score >= 60) {
            level = "HIGH";
        } else if (score >= 30) {
            level = "MEDIUM";
        } else {
            level = "LOW";
        }
    }

    /*setText(
        "threatScore",
        Math.round(score)
    );*/
    const roundedScore = Math.max(
    0,
    Math.min(100, Math.round(score))
);

setText(
    "threatScore",
    roundedScore
);

const scoreCircle = document.querySelector(".score-circle");

if (scoreCircle) {
    const degrees = roundedScore * 3.6;

    scoreCircle.style.background =
        `conic-gradient(
            #1769e0 0deg,
            #1769e0 ${degrees}deg,
            #eaf3ff ${degrees}deg,
            #eaf3ff 360deg
        )`;
}

    setText(
        "threatLevel",
        String(level).toUpperCase()
    );

    setText(
        "modifiedCount",
        detection.modified_count || 0
    );

    setText(
        "renameCount",
        detection.rename_count || 0
    );

    setText(
        "extensionCount",
        detection.extension_changes || 0
    );

    setSignal(
        "rapidEncryption",
        Number(
            detection.modified_count || 0
        ) >= 20
    );

    setSignal(
        "massRename",
        Number(
            detection.rename_count || 0
        ) >= 10
    );

    setSignal(
        "extensionChange",
        Number(
            detection.extension_changes || 0
        ) >= 5
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

async function loadDetection() {

    try {

        const threatResponse =
            await fetch(
                "/api/threat",
                {
                    cache: "no-store"
                }
            );

        if (threatResponse.ok) {

            const threatData =
                await threatResponse.json();

            updateDetection(
                threatData
            );

            return;
        }

    } catch (error) {

        console.warn(
            "Threat endpoint unavailable:",
            error
        );
    }

    try {

        const dashboardResponse =
            await fetch(
                "/api/dashboard",
                {
                    cache: "no-store"
                }
            );

        if (!dashboardResponse.ok) {
            throw new Error(
                "Dashboard endpoint unavailable."
            );
        }

        const dashboardData =
            await dashboardResponse.json();

        updateDetection(
            dashboardData
        );

    } catch (error) {

        console.error(
            "Detection loading error:",
            error
        );
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
            "System loading error:",
            error
        );
    }
}

document.addEventListener(
    "DOMContentLoaded",
    () => {

        loadSystem();
        loadDetection();

        document
            .getElementById("refreshButton")
            .addEventListener(
                "click",
                loadDetection
            );

        setInterval(
            loadDetection,
            5000
        );
    }
);
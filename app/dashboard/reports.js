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
            "systemName",
            system.system_name
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
            "protection",
            system.monitoring
                ? "ACTIVE"
                : "INACTIVE"
        );

    } catch (error) {

        console.error(
            "System loading error:",
            error
        );
    }
}

async function downloadReport(
    format
) {

    const endpoint =
        format === "json"
            ? "/api/reports/json"
            : "/api/reports/csv";

    try {

        showToast(
            `Generating ${format.toUpperCase()} report...`
        );

        const response =
            await fetch(
                endpoint,
                {
                    cache: "no-store"
                }
            );

        if (!response.ok) {
            throw new Error(
                "Report generation failed."
            );
        }

        const blob =
            await response.blob();

        const url =
            window.URL.createObjectURL(
                blob
            );

        const link =
            document.createElement("a");

        link.href = url;

        link.download =
            format === "json"
                ? "ransomshield-security-report.json"
                : "ransomshield-security-report.csv";

        document.body.appendChild(
            link
        );

        link.click();

        link.remove();

        window.URL.revokeObjectURL(
            url
        );

        showToast(
            `${format.toUpperCase()} report generated successfully.`
        );

    } catch (error) {

        console.error(
            "Report error:",
            error
        );

        showToast(
            error.message ||
            "Unable to generate report."
        );
    }
}

document.addEventListener(
    "DOMContentLoaded",
    () => {

        loadSystem();

        document
            .getElementById("jsonButton")
            .addEventListener(
                "click",
                () => downloadReport("json")
            );

        document
            .getElementById("csvButton")
            .addEventListener(
                "click",
                () => downloadReport("csv")
            );
    }
);
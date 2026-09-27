let registeredSystem = null;
let existingSystem = false;
let isLoading = false;

function showToast(message) {
    const toast = document.getElementById("toast");

    if (!toast) {
        alert(message);
        return;
    }

    toast.textContent = message;
    toast.classList.add("show");

    clearTimeout(window.toastTimer);

    window.toastTimer = setTimeout(() => {
        toast.classList.remove("show");
    }, 3500);
}

function getValue(id) {
    const element = document.getElementById(id);
    return element ? element.value.trim() : "";
}

function setValue(id, value) {
    const element = document.getElementById(id);

    if (element) {
        element.value = value ?? "";
    }
}

function setText(id, value) {
    const element = document.getElementById(id);

    if (element) {
        element.textContent = value ?? "--";
    }
}

function setButtonLoading(id, loading, loadingText = "Processing...") {
    const button = document.getElementById(id);

    if (!button) {
        return;
    }

    if (loading) {
        if (!button.dataset.originalText) {
            button.dataset.originalText = button.innerHTML;
        }

        button.disabled = true;
        button.innerHTML = loadingText;
    } else {
        button.disabled = false;

        if (button.dataset.originalText) {
            button.innerHTML = button.dataset.originalText;
        }
    }
}

function saveSystemSession(system) {
    if (!system || !system.system_id) {
        return;
    }

    sessionStorage.setItem(
        "ransomshield_system",
        JSON.stringify(system)
    );

    sessionStorage.setItem(
        "ransomshield_system_id",
        system.system_id
    );
}

function loadSavedSystem() {
    const savedSystem =
        sessionStorage.getItem(
            "ransomshield_system"
        );

    if (!savedSystem) {
        return null;
    }

    try {
        return JSON.parse(savedSystem);
    } catch (error) {
        console.error(
            "Unable to restore saved system:",
            error
        );

        sessionStorage.removeItem(
            "ransomshield_system"
        );

        return null;
    }
}

function validateSystemDetails() {
    const systemName = getValue("systemName");
    const hostname = getValue("hostname");
    const ipAddress = getValue("ipAddress");
    const operatingSystem = getValue("operatingSystem");

    if (!systemName) {
        showToast("Please enter the system name.");
        return false;
    }

    if (!hostname) {
        showToast("Please enter the hostname.");
        return false;
    }

    if (!ipAddress) {
        showToast("Please enter the IP address.");
        return false;
    }

    if (!operatingSystem) {
        showToast("Please select the operating system.");
        return false;
    }

    return true;
}

function updateSidePanel() {
    if (!registeredSystem) {
        setText("sideSystemName", "--");
        setText("sideHostname", "--");
        setText("sideOS", "--");
        setText("sideVerification", "Required");
        setText("sideProtection", "Locked");
        return;
    }

    setText(
        "sideSystemName",
        registeredSystem.system_name
    );

    setText(
        "sideHostname",
        registeredSystem.hostname
    );

    setText(
        "sideOS",
        registeredSystem.operating_system
    );

    if (registeredSystem.verified) {
        setText(
            "sideVerification",
            "Verified"
        );
    } else {
        setText(
            "sideVerification",
            "Required"
        );
    }

    if (registeredSystem.monitoring) {
        setText(
            "sideProtection",
            "Active"
        );
    } else if (registeredSystem.verified) {
        setText(
            "sideProtection",
            "Ready"
        );
    } else {
        setText(
            "sideProtection",
            "Locked"
        );
    }
}

function updateProgress(step) {
    setText(
        "currentStep",
        String(step).padStart(2, "0")
    );

    for (let i = 1; i <= 3; i++) {
        const indicator =
            document.getElementById(
                `stepIndicator${i}`
            );

        if (!indicator) {
            continue;
        }

        indicator.classList.remove(
            "active",
            "completed"
        );

        if (i < step) {
            indicator.classList.add(
                "completed"
            );
        }

        if (i === step) {
            indicator.classList.add(
                "active"
            );
        }
    }

    const line1 =
        document.getElementById(
            "progressLine1"
        );

    const line2 =
        document.getElementById(
            "progressLine2"
        );

    if (line1) {
        line1.classList.toggle(
            "active",
            step >= 2
        );
    }

    if (line2) {
        line2.classList.toggle(
            "active",
            step >= 3
        );
    }
}

function showStep(step) {
    document
        .querySelectorAll(".form-step")
        .forEach(element => {
            element.classList.remove(
                "active"
            );
        });

    const selected =
        document.getElementById(
            `step${step}`
        );

    if (selected) {
        selected.classList.add(
            "active"
        );
    }

    updateProgress(step);

    window.scrollTo({
        top: 0,
        behavior: "smooth"
    });
}

function setStatus(
    status,
    type = "pending"
) {
    const statusPill =
        document.getElementById(
            "statusPill"
        );

    if (!statusPill) {
        return;
    }

    statusPill.textContent = status;

    statusPill.className =
        `status-pill ${type}`;
}

function displaySystemInformation(system) {
    if (!system) {
        return;
    }

    registeredSystem = {
        ...registeredSystem,
        ...system
    };

    setText(
        "systemId",
        registeredSystem.system_id
    );

    setText(
        "summaryId",
        registeredSystem.system_id
    );

    setText(
        "summaryHostname",
        registeredSystem.hostname
    );

    setText(
        "summaryOS",
        registeredSystem.operating_system
    );

    setValue(
        "systemName",
        registeredSystem.system_name
    );

    setValue(
        "hostname",
        registeredSystem.hostname
    );

    setValue(
        "ipAddress",
        registeredSystem.ip_address
    );

    setValue(
        "operatingSystem",
        registeredSystem.operating_system
    );

    updateSidePanel();
}

function clearAuthenticatorDisplay() {
    const qrCode =
        document.getElementById(
            "qrCode"
        );

    if (qrCode) {
        qrCode.removeAttribute(
            "src"
        );

        qrCode.style.display =
            "none";
    }

    setText(
        "authenticatorSecret",
        "--"
    );
}

function displayAuthenticator(
    authenticator
) {
    if (!authenticator) {
        return;
    }

    const qrCode =
        document.getElementById(
            "qrCode"
        );

    if (
        qrCode &&
        authenticator.qr_code
    ) {
        qrCode.src =
            authenticator.qr_code;

        qrCode.style.display =
            "block";

        qrCode.alt =
            "RansomShield Authenticator QR Code";
    }

    setText(
        "authenticatorSecret",
        authenticator.secret ||
        "--"
    );
}

function prepareExistingSystemVerification() {
    existingSystem = true;

    clearAuthenticatorDisplay();

    const setupSection =
        document.querySelector(
            ".authenticator-setup"
        );

    if (setupSection) {
        setupSection.style.display =
            "none";
    }

    const existingCard =
        document.getElementById(
            "existingAuthCard"
        );

    if (existingCard) {
        existingCard.style.display =
            "block";
    }

    const title =
        document.getElementById(
            "verificationTitle"
        );

    if (title) {
        title.textContent =
            "Verify Existing System";
    }

    const description =
        document.getElementById(
            "verificationDescription"
        );

    if (description) {
        description.textContent =
            "Authenticate your previously registered endpoint using its System ID and current authenticator code.";
    }

    setStatus(
        "AUTHENTICATION REQUIRED",
        "pending"
    );
}

function prepareNewSystemVerification() {
    existingSystem = false;

    const setupSection =
        document.querySelector(
            ".authenticator-setup"
        );

    if (setupSection) {
        setupSection.style.display =
            "";
    }

    const existingCard =
        document.getElementById(
            "existingAuthCard"
        );

    if (existingCard) {
        existingCard.style.display =
            "none";
    }

    const title =
        document.getElementById(
            "verificationTitle"
        );

    if (title) {
        title.textContent =
            "Authenticator Verification";
    }

    const description =
        document.getElementById(
            "verificationDescription"
        );

    if (description) {
        description.textContent =
            "Connect this endpoint to an authenticator application before protection can be activated.";
    }

    setStatus(
        "PENDING VERIFICATION",
        "pending"
    );
}

/* =========================================
   ALREADY REGISTERED
========================================= */

function openExistingSystemVerification() {
    existingSystem = true;
    registeredSystem = null;

    clearAuthenticatorDisplay();

    const existingCard =
        document.getElementById(
            "existingAuthCard"
        );

    if (existingCard) {
        existingCard.style.display =
            "block";
    }

    const setupSection =
        document.querySelector(
            ".authenticator-setup"
        );

    if (setupSection) {
        setupSection.style.display =
            "none";
    }

    const title =
        document.getElementById(
            "verificationTitle"
        );

    if (title) {
        title.textContent =
            "Verify Existing System";
    }

    const description =
        document.getElementById(
            "verificationDescription"
        );

    if (description) {
        description.textContent =
            "Enter the registered System ID and current 6-digit authenticator code.";
    }

    setText(
        "systemId",
        "RSH-XXXXXX"
    );

    setStatus(
        "AUTHENTICATION REQUIRED",
        "pending"
    );

    clearVerificationCode();

    const systemIdInput =
        document.getElementById(
            "existingSystemId"
        );

    if (systemIdInput) {
        systemIdInput.value = "";

        setTimeout(() => {
            systemIdInput.focus();
        }, 250);
    }

    showStep(2);

    showToast(
        "Enter your registered System ID and authenticator code."
    );
}

/* =========================================
   REGISTER NEW SYSTEM
========================================= */

async function registerSystem() {
    if (isLoading) {
        return;
    }

    if (!validateSystemDetails()) {
        return;
    }

    isLoading = true;

    setButtonLoading(
        "registerButton",
        true,
        "Registering..."
    );

    try {
        const payload = {
            system_name:
                getValue("systemName"),

            hostname:
                getValue("hostname"),

            ip_address:
                getValue("ipAddress"),

            operating_system:
                getValue("operatingSystem"),

            environment:
                getValue("environment") ||
                "Workstation"
        };

        const response =
            await fetch(
                "/api/systems",
                {
                    method: "POST",
                    headers: {
                        "Content-Type":
                            "application/json"
                    },
                    body:
                        JSON.stringify(
                            payload
                        )
                }
            );

        const data =
            await response.json();

        if (!response.ok) {
            throw new Error(
                data.message ||
                data.detail ||
                "System registration failed."
            );
        }

        /*
         * FIX: backend (app/api/routes.py -> create_system)
         * returns "status": "created" on success, not "registered".
         * This mismatch was the reason the flow never moved to Step 2.
         */
        if (
            data.status ===
            "created"
        ) {
            displaySystemInformation(
                data.system
            );

            saveSystemSession(
                data.system
            );

            prepareNewSystemVerification();

            displayAuthenticator(
                data.authenticator
            );

            setStatus(
                "PENDING VERIFICATION",
                "pending"
            );

            showStep(2);

            showToast(
                "System registered. Scan the QR code with your authenticator app."
            );

            return;
        }

        if (
            data.status ===
                "already_registered" ||
            data.status ===
                "registration_pending"
        ) {
            displaySystemInformation(
                data.system
            );

            saveSystemSession(
                data.system
            );

            prepareExistingSystemVerification();

            showStep(2);

            showToast(
                "This system is already registered. Enter the current authenticator code."
            );

            return;
        }

        throw new Error(
            data.message ||
            "Unexpected registration response."
        );

    } catch (error) {
        console.error(
            "Registration error:",
            error
        );

        showToast(
            error.message ||
            "Unable to register the system."
        );

    } finally {
        isLoading = false;

        setButtonLoading(
            "registerButton",
            false
        );
    }
}

/* =========================================
   VERIFY AGAIN / REGENERATE AUTHENTICATOR
========================================= */

async function verifyAgain() {
    if (isLoading) {
        return;
    }

    let systemId = "";

    if (
        registeredSystem &&
        registeredSystem.system_id
    ) {
        systemId =
            registeredSystem.system_id;
    }

    if (!systemId) {
        systemId =
            getValue(
                "existingSystemId"
            ).toUpperCase();
    }

    if (!systemId) {
        showToast(
            "Enter the registered System ID first."
        );

        return;
    }

    isLoading = true;

    const buttonIds = [
        "verifyAgainButton",
        "existingVerifyAgainButton"
    ];

    buttonIds.forEach(id => {
        setButtonLoading(
            id,
            true,
            "Generating..."
        );
    });

    try {
        const response =
            await fetch(
                `/api/systems/${encodeURIComponent(
                    systemId
                )}/authenticator/regenerate`,
                {
                    method: "POST",
                    headers: {
                        "Content-Type":
                            "application/json"
                    }
                }
            );

        const data =
            await response.json();

        if (!response.ok) {
            throw new Error(
                data.message ||
                data.detail ||
                "Authenticator regeneration failed."
            );
        }

        if (
            data.status !==
            "regenerated"
        ) {
            throw new Error(
                data.message ||
                "Unable to regenerate authenticator."
            );
        }

        if (data.system) {
            registeredSystem =
                data.system;
        } else if (!registeredSystem) {
            registeredSystem = {
                system_id: systemId
            };
        }

        existingSystem = false;

        displaySystemInformation(
            data.system
        );

        saveSystemSession(
            registeredSystem
        );

        displayAuthenticator(
            data.authenticator
        );

        const existingCard =
            document.getElementById(
                "existingAuthCard"
            );

        if (existingCard) {
            existingCard.style.display =
                "none";
        }

        const setupSection =
            document.querySelector(
                ".authenticator-setup"
            );

        if (setupSection) {
            setupSection.style.display =
                "";
        }

        const title =
            document.getElementById(
                "verificationTitle"
            );

        if (title) {
            title.textContent =
                "Authenticator Verification";
        }

        const description =
            document.getElementById(
                "verificationDescription"
            );

        if (description) {
            description.textContent =
                "Scan the new QR code with your authenticator application and enter the generated 6-digit code.";
        }

        setStatus(
            "PENDING VERIFICATION",
            "pending"
        );

        clearVerificationCode();

        showStep(2);

        showToast(
            "New authenticator QR generated. Scan it and enter the new 6-digit code."
        );

    } catch (error) {
        console.error(
            "Authenticator regeneration error:",
            error
        );

        showToast(
            error.message ||
            "Unable to regenerate authenticator."
        );

    } finally {
        isLoading = false;

        buttonIds.forEach(id => {
            setButtonLoading(
                id,
                false
            );
        });
    }
}

/* =========================================
   OTP
========================================= */

function getVerificationCode() {
    const inputs =
        document.querySelectorAll(
            ".code-input"
        );

    let code = "";

    inputs.forEach(input => {
        code +=
            input.value.trim();
    });

    return code;
}

function clearVerificationCode() {
    document
        .querySelectorAll(
            ".code-input"
        )
        .forEach(input => {
            input.value = "";
        });
}

/* =========================================
   VERIFY SYSTEM
========================================= */

async function verifySystem() {
    if (isLoading) {
        return;
    }

    if (existingSystem) {
        const existingId =
            getValue(
                "existingSystemId"
            );

        if (!existingId) {
            showToast(
                "Please enter the registered System ID."
            );

            return;
        }

        registeredSystem = {
            ...registeredSystem,
            system_id:
                existingId.toUpperCase()
        };
    }

    if (!registeredSystem) {
        showToast(
            "Register or authenticate the system first."
        );

        return;
    }

    const code =
        getVerificationCode();

    if (
        code.length !== 6 ||
        !/^\d{6}$/.test(code)
    ) {
        showToast(
            "Enter the complete 6-digit authenticator code."
        );

        return;
    }

    isLoading = true;

    setButtonLoading(
        "verifyButton",
        true,
        "Verifying..."
    );

    try {
        const endpoint =
            existingSystem
                ? "/api/systems/authenticate"
                : "/api/systems/verify";

        const payload = {
            system_id:
                registeredSystem.system_id,
            code: code
        };

        const response =
            await fetch(
                endpoint,
                {
                    method: "POST",
                    headers: {
                        "Content-Type":
                            "application/json"
                    },
                    body:
                        JSON.stringify(
                            payload
                        )
                }
            );

        const data =
            await response.json();

        if (!response.ok) {
            throw new Error(
                data.message ||
                data.detail ||
                "Authentication failed."
            );
        }

        if (
            data.status !==
                "verified" &&
            data.status !==
                "authenticated"
        ) {
            throw new Error(
                data.message ||
                "Invalid authenticator code."
            );
        }

        if (data.system) {
            registeredSystem =
                data.system;
        } else {
            registeredSystem.verified =
                true;
        }

        registeredSystem.verified =
            true;

        updateSidePanel();

        setStatus(
            "VERIFIED",
            "verified"
        );

        clearVerificationCode();

        saveSystemSession(
            registeredSystem
        );

        setText(
            "summaryId",
            registeredSystem.system_id
        );

        setText(
            "summaryHostname",
            registeredSystem.hostname
        );

        setText(
            "summaryOS",
            registeredSystem.operating_system
        );

        showStep(3);

        showToast(
            existingSystem
                ? "Existing system authenticated successfully."
                : "System successfully verified."
        );

    } catch (error) {
        console.error(
            "Verification error:",
            error
        );

        clearVerificationCode();

        showToast(
            error.message ||
            "Invalid or expired authenticator code."
        );

    } finally {
        isLoading = false;

        setButtonLoading(
            "verifyButton",
            false
        );
    }
}

/* =========================================
   FETCH FRESH SYSTEM STATE
========================================= */

async function refreshSystemState() {
    if (!registeredSystem ||
        !registeredSystem.system_id) {
        return null;
    }

    try {
        const systemId =
            registeredSystem.system_id;

        const response =
            await fetch(
                `/api/systems/${encodeURIComponent(
                    systemId
                )}`,
                {
                    method: "GET",
                    cache: "no-store"
                }
            );

        if (!response.ok) {
            return null;
        }

        const data =
            await response.json();

        const system =
            data.system || data;

        if (!system) {
            return null;
        }

        registeredSystem = {
            ...registeredSystem,
            ...system
        };

        saveSystemSession(
            registeredSystem
        );

        updateSidePanel();

        return registeredSystem;

    } catch (error) {
        console.error(
            "Unable to refresh system state:",
            error
        );

        return null;
    }
}

/* =========================================
   ACTIVATE PROTECTION
========================================= */

async function activateProtection() {
    if (isLoading) {
        return;
    }

    if (!registeredSystem) {
        showToast(
            "No registered system found."
        );

        return;
    }

    if (!registeredSystem.verified) {
        showToast(
            "System verification is required first."
        );

        return;
    }

    isLoading = true;

    setButtonLoading(
        "protectionButton",
        true,
        "Activating..."
    );

    try {
        const systemId =
            registeredSystem.system_id;

        const response =
            await fetch(
                `/api/systems/${encodeURIComponent(
                    systemId
                )}/protection`,
                {
                    method: "POST",
                    headers: {
                        "Content-Type":
                            "application/json"
                    },
                    cache: "no-store"
                }
            );

        const data =
            await response.json();

        if (!response.ok) {
            throw new Error(
                data.message ||
                data.detail ||
                "Protection activation failed."
            );
        }

        /*
         * FIX: backend (app/api/routes.py -> set_system_protection)
         * returns "status": "active" on success, not "activated".
         * This mismatch was the reason the button never redirected
         * to soc.html.
         */
        if (
            data.status !==
            "active"
        ) {
            throw new Error(
                data.message ||
                "Protection could not be activated."
            );
        }

        if (data.system) {
            registeredSystem = {
                ...registeredSystem,
                ...data.system
            };
        }

        registeredSystem.monitoring =
            true;

        registeredSystem.verified =
            true;

        updateSidePanel();

        setStatus(
            "PROTECTED",
            "verified"
        );

        saveSystemSession(
            registeredSystem
        );

        /*
         * Fetch the latest backend state.
         * This makes sure the frontend does not
         * depend only on the response object.
         */
        await refreshSystemState();

        /*
         * Keep protection state explicitly stored.
         */
        registeredSystem.monitoring =
            true;

        saveSystemSession(
            registeredSystem
        );

        updateSidePanel();

        showToast(
            "RansomShield protection is now active."
        );

        /*
         * Small delay allows the success state
         * to be visible before opening SOC.
         */
        setTimeout(() => {
            window.location.href =
                "/dashboard/soc.html";
        }, 700);

    } catch (error) {
        console.error(
            "Protection activation error:",
            error
        );

        showToast(
            error.message ||
            "Unable to activate RansomShield protection."
        );

    } finally {
        isLoading = false;

        setButtonLoading(
            "protectionButton",
            false
        );
    }
}

/* =========================================
   BACK
========================================= */

function backToDetails() {
    existingSystem = false;

    clearVerificationCode();

    const existingCard =
        document.getElementById(
            "existingAuthCard"
        );

    if (existingCard) {
        existingCard.style.display =
            "none";
    }

    const setupSection =
        document.querySelector(
            ".authenticator-setup"
        );

    if (setupSection) {
        setupSection.style.display =
            "";
    }

    const title =
        document.getElementById(
            "verificationTitle"
        );

    if (title) {
        title.textContent =
            "Authenticator Verification";
    }

    const description =
        document.getElementById(
            "verificationDescription"
        );

    if (description) {
        description.textContent =
            "Connect this endpoint to an authenticator application before protection can be activated.";
    }

    if (
        registeredSystem &&
        registeredSystem.system_id
    ) {
        setValue(
            "systemName",
            registeredSystem.system_name
        );

        setValue(
            "hostname",
            registeredSystem.hostname
        );

        setValue(
            "ipAddress",
            registeredSystem.ip_address
        );

        setValue(
            "operatingSystem",
            registeredSystem.operating_system
        );

        setStatus(
            registeredSystem.verified
                ? "VERIFIED"
                : "PENDING VERIFICATION",
            registeredSystem.verified
                ? "verified"
                : "pending"
        );
    } else {
        setStatus(
            "NOT REGISTERED",
            "pending"
        );
    }

    showStep(1);

    showToast(
        "Returned to system details."
    );
}

/* =========================================
   RESET
========================================= */

function resetForm() {
    const fields = [
        "systemName",
        "hostname",
        "ipAddress",
        "operatingSystem",
        "existingSystemId"
    ];

    fields.forEach(id => {
        const element =
            document.getElementById(id);

        if (element) {
            element.value = "";
        }
    });

    const environment =
        document.getElementById(
            "environment"
        );

    if (environment) {
        environment.value =
            "Workstation";
    }

    clearVerificationCode();

    clearAuthenticatorDisplay();

    registeredSystem = null;

    existingSystem = false;

    isLoading = false;

    sessionStorage.removeItem(
        "ransomshield_system"
    );

    sessionStorage.removeItem(
        "ransomshield_system_id"
    );

    setText(
        "systemId",
        "RSH-XXXXXX"
    );

    setText(
        "summaryId",
        "RSH-XXXXXX"
    );

    setText(
        "summaryHostname",
        "--"
    );

    setText(
        "summaryOS",
        "--"
    );

    setText(
        "sideSystemName",
        "--"
    );

    setText(
        "sideHostname",
        "--"
    );

    setText(
        "sideOS",
        "--"
    );

    setText(
        "sideVerification",
        "Required"
    );

    setText(
        "sideProtection",
        "Locked"
    );

    setStatus(
        "NOT REGISTERED",
        "pending"
    );

    const setupSection =
        document.querySelector(
            ".authenticator-setup"
        );

    if (setupSection) {
        setupSection.style.display =
            "";
    }

    const existingCard =
        document.getElementById(
            "existingAuthCard"
        );

    if (existingCard) {
        existingCard.style.display =
            "none";
    }

    showStep(1);

    showToast(
        "Enrollment form reset."
    );
}

/* =========================================
   OTP INPUT
========================================= */

function setupCodeInputs() {
    const codeInputs =
        document.querySelectorAll(
            ".code-input"
        );

    codeInputs.forEach(
        (input, index) => {

            input.addEventListener(
                "input",
                event => {

                    event.target.value =
                        event.target.value
                            .replace(
                                /\D/g,
                                ""
                            );

                    if (
                        event.target.value &&
                        index <
                            codeInputs.length - 1
                    ) {
                        codeInputs[
                            index + 1
                        ].focus();
                    }
                }
            );

            input.addEventListener(
                "keydown",
                event => {

                    if (
                        event.key ===
                            "Backspace" &&
                        !event.target.value &&
                        index > 0
                    ) {
                        codeInputs[
                            index - 1
                        ].focus();
                    }
                }
            );

            input.addEventListener(
                "paste",
                event => {

                    event.preventDefault();

                    const pasted =
                        event.clipboardData
                            .getData("text")
                            .replace(
                                /\D/g,
                                ""
                            )
                            .slice(
                                0,
                                6
                            );

                    if (!pasted) {
                        return;
                    }

                    codeInputs.forEach(
                        (
                            field,
                            fieldIndex
                        ) => {

                            field.value =
                                pasted[
                                    fieldIndex
                                ] || "";
                        }
                    );

                    const targetIndex =
                        Math.min(
                            pasted.length,
                            codeInputs.length - 1
                        );

                    codeInputs[
                        targetIndex
                    ].focus();
                }
            );
        }
    );
}

/* =========================================
   NAVIGATION
========================================= */

function setupNavigation() {
    document
        .querySelectorAll(
            ".nav-link"
        )
        .forEach(link => {

            link.addEventListener(
                "click",
                event => {

                    const href =
                        link.getAttribute(
                            "href"
                        );

                    if (
                        !href ||
                        href === "#"
                    ) {
                        event.preventDefault();
                    }
                }
            );
        });
}

/* =========================================
   INITIALIZE
========================================= */

document.addEventListener(
    "DOMContentLoaded",
    async () => {

        setupCodeInputs();

        setupNavigation();

        updateProgress(1);

        setStatus(
            "NOT REGISTERED",
            "pending"
        );

        const savedSystem =
            loadSavedSystem();

        if (savedSystem) {
            registeredSystem =
                savedSystem;

            updateSidePanel();

            /*
             * Get the latest status from backend.
             * This is important after protection activation.
             */
            await refreshSystemState();

            if (
                registeredSystem &&
                registeredSystem.monitoring
            ) {
                setStatus(
                    "PROTECTED",
                    "verified"
                );
            }
        }
    }
);
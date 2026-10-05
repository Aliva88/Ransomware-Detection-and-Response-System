let events = [];

let replayIndex = 0;

let replayTimer = null;

let isPlaying = false;

let currentSystem = null;


/* =========================================================
   SYSTEM
========================================================= */

function getSavedSystem() {

    try {

        const saved =
            sessionStorage.getItem(
                "ransomshield_system"
            );

        return saved
            ? JSON.parse(saved)
            : null;

    } catch (error) {

        console.error(
            "Saved system read error:",
            error
        );

        return null;
    }
}


/* =========================================================
   UI HELPERS
========================================================= */

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

    clearTimeout(
        window.toastTimer
    );

    window.toastTimer =
        setTimeout(() => {

            toast.classList.remove(
                "show"
            );

        }, 3000);
}


async function fetchJSON(url) {

    const response =
        await fetch(
            url,
            {
                cache: "no-store"
            }
        );

    let data = {};

    try {

        data =
            await response.json();

    } catch {

        data = {};
    }

    if (!response.ok) {

        throw new Error(
            data.detail ||
            data.message ||
            `Request failed: ${response.status}`
        );
    }

    return data;
}


function escapeHTML(value) {

    return String(
        value ?? ""
    )
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


/* =========================================================
   DATE / TIME
========================================================= */

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
            minute: "2-digit",
            second: "2-digit"
        }
    );
}


function formatTime(value) {

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
        return "--";
    }

    return date.toLocaleTimeString(
        "en-IN",
        {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit"
        }
    );
}


/* =========================================================
   EVENT HELPERS
========================================================= */

function normalizeEventType(eventType) {

    return String(
        eventType || "EVENT"
    )
        .trim()
        .toUpperCase();
}


function eventClass(eventType) {

    const type =
        normalizeEventType(
            eventType
        );

    if (
        type.includes("CREATE")
    ) {
        return "create";
    }

    if (
        type.includes("MODIFY")
    ) {
        return "modify";
    }

    if (
        type.includes("RENAME")
    ) {
        return "rename";
    }

    if (
        type.includes("DELETE")
    ) {
        return "delete";
    }

    return "other";
}


/* =========================================================
   SYSTEM INFORMATION
========================================================= */

function updateSystemInfo() {

    const saved =
        getSavedSystem();

    if (!saved) {

        setText(
            "systemName",
            "Protected Endpoint"
        );

        setText(
            "systemId",
            "--"
        );

        setText(
            "hostname",
            "--"
        );

        return;
    }

    currentSystem = saved;

    setText(
        "systemName",
        saved.system_name ||
        "Protected Endpoint"
    );

    setText(
        "systemId",
        saved.system_id
    );

    setText(
        "hostname",
        saved.hostname
    );

    setText(
        "sideSystemName",
        saved.system_name
    );

    setText(
        "sideSystemId",
        saved.system_id
    );

    setText(
        "sideProtection",
        saved.monitoring
            ? "PROTECTION ACTIVE"
            : "PROTECTION INACTIVE"
    );

    setText(
        "protectionStatus",
        saved.monitoring
            ? "PROTECTION ACTIVE"
            : "PROTECTION INACTIVE"
    );
}


/* =========================================================
   EVENT COUNTERS
========================================================= */

function countEvents() {

    const counts = {
        CREATE: 0,
        MODIFY: 0,
        RENAME: 0,
        DELETE: 0
    };

    events.forEach(
        event => {

            const type =
                normalizeEventType(
                    event.event_type
                );

            if (
                type.includes("CREATE")
            ) {
                counts.CREATE++;
            }

            if (
                type.includes("MODIFY")
            ) {
                counts.MODIFY++;
            }

            if (
                type.includes("RENAME")
            ) {
                counts.RENAME++;
            }

            if (
                type.includes("DELETE")
            ) {
                counts.DELETE++;
            }
        }
    );

    setText(
        "createCount",
        counts.CREATE
    );

    setText(
        "modifyCount",
        counts.MODIFY
    );

    setText(
        "renameCount",
        counts.RENAME
    );

    setText(
        "deleteCount",
        counts.DELETE
    );

    setText(
        "eventCount",
        events.length
    );

    setText(
        "timelineTotal",
        `${events.length} EVENTS`
    );
}


/* =========================================================
   TIMELINE
========================================================= */

function renderTimeline() {

    const timeline =
        document.getElementById(
            "timeline"
        );

    if (!timeline) {
        return;
    }

    if (!events.length) {

        timeline.innerHTML = `
            <div class="timeline-empty">
                No recorded filesystem events found.
            </div>
        `;

        return;
    }

    timeline.innerHTML =
        events.map(
            (event, index) => {

                const type =
                    normalizeEventType(
                        event.event_type
                    );

                const className =
                    eventClass(type);

                return `
                    <div
                        class="timeline-event"
                        id="event-${index}"
                        data-index="${index}"
                    >

                        <span
                            class="timeline-marker"
                        ></span>

                        <span
                            class="timeline-time"
                            title="${escapeHTML(
                                formatDate(
                                    event.timestamp
                                )
                            )}"
                        >
                            ${escapeHTML(
                                formatTime(
                                    event.timestamp
                                )
                            )}
                        </span>

                        <span
                            class="event-type ${className}"
                        >
                            ${escapeHTML(type)}
                        </span>

                        <span
                            class="event-path"
                            title="${escapeHTML(
                                event.file_path
                            )}"
                        >
                            ${escapeHTML(
                                event.file_path
                            )}
                        </span>

                    </div>
                `;
            }
        )
        .join("");
}


/* =========================================================
   REPLAY SCORE
========================================================= */

function calculateReplayScore(index) {

    if (
        index < 0 ||
        !events.length
    ) {

        return {
            score: 0,
            level: "Low",
            modifiedCount: 0,
            renameCount: 0,
            highEntropy: false,
            processActivity: false
        };
    }

    let modifiedCount = 0;

    let renameCount = 0;

    const end =
        Math.min(
            index + 1,
            events.length
        );

    for (
        let i = 0;
        i < end;
        i++
    ) {

        const type =
            normalizeEventType(
                events[i].event_type
            );

        if (
            type.includes("MODIFY")
        ) {

            modifiedCount++;
        }

        if (
            type.includes("RENAME")
        ) {

            renameCount++;
        }
    }

    const rapidEncryption =
        modifiedCount >= 20;

    const massRename =
        renameCount >= 10;

    /*
     * Replay events currently contain
     * filesystem events only.
     *
     * We do NOT fabricate entropy
     * or process signals.
     */

    const highEntropy = false;

    const processActivity = false;

    let score = 0;

    if (rapidEncryption) {
        score += 40;
    }

    if (massRename) {
        score += 30;
    }

    score =
        Math.min(
            score,
            100
        );

    let level = "Low";

    if (score >= 80) {

        level = "Critical";

    } else if (score >= 60) {

        level = "High";

    } else if (score >= 30) {

        level = "Medium";
    }

    return {
        score,
        level,
        modifiedCount,
        renameCount,
        highEntropy,
        processActivity
    };
}


function updateSignal(
    id,
    active
) {

    const element =
        document.getElementById(id);

    if (!element) {
        return;
    }

    element.textContent =
        active
            ? "DETECTED"
            : "OFF";

    const parent =
        element.closest(
            ".signal-item"
        );

    if (parent) {

        parent.classList.toggle(
            "active",
            active
        );
    }
}


function updateReplayScore(index) {

    const result =
        calculateReplayScore(
            index
        );

    setText(
        "replayThreatScore",
        result.score
    );

    setText(
        "replayScoreValue",
        result.score
    );

    setText(
        "replayThreatLevel",
        result.level.toUpperCase()
    );

    if (
        result.score >= 80
    ) {

        setText(
            "replayDetectionState",
            "Critical ransomware behavior"
        );

    } else if (
        result.score >= 60
    ) {

        setText(
            "replayDetectionState",
            "High-risk ransomware behavior"
        );

    } else if (
        result.score >= 30
    ) {

        setText(
            "replayDetectionState",
            "Suspicious file activity"
        );

    } else {

        setText(
            "replayDetectionState",
            "No suspicious activity"
        );
    }

    updateSignal(
        "signalRapid",
        result.modifiedCount >= 20
    );

    updateSignal(
        "signalRename",
        result.renameCount >= 10
    );

    updateSignal(
        "signalEntropy",
        result.highEntropy
    );

    updateSignal(
        "signalProcess",
        result.processActivity
    );

    const circle =
        document.getElementById(
            "replayScoreCircle"
        );

    if (circle) {

        let borderColor =
            "#eaf3ff";

        if (result.score >= 80) {

            borderColor =
                "#dc3545";

        } else if (result.score >= 60) {

            borderColor =
                "#e58a17";

        } else if (result.score >= 30) {

            borderColor =
                "#1769e0";
        }

        circle.style.borderColor =
            borderColor;
    }

    const badge =
        document.getElementById(
            "replayThreatLevel"
        );

    if (badge) {

        if (result.score >= 80) {

            badge.style.background =
                "#fff0f1";

            badge.style.color =
                "#dc3545";

        } else if (result.score >= 60) {

            badge.style.background =
                "#fff5e6";

            badge.style.color =
                "#e58a17";

        } else if (result.score >= 30) {

            badge.style.background =
                "#eaf3ff";

            badge.style.color =
                "#1769e0";

        } else {

            badge.style.background =
                "#e9f8f2";

            badge.style.color =
                "#15966b";
        }
    }
}


/* =========================================================
   PROGRESS
========================================================= */

function updateProgress() {

    const total =
        events.length;

    const completed =
        replayIndex;

    const percentage =
        total > 0
            ? (
                completed /
                total
            ) * 100
            : 0;

    const roundedPercentage =
        percentage.toFixed(1);

    setText(
        "progressText",
        `${completed} / ${total} • ${roundedPercentage}%`
    );

    const bar =
        document.getElementById(
            "progressBar"
        );

    if (bar) {

        bar.style.width =
            `${percentage}%`;
    }
}


/* =========================================================
   CURRENT EVENT
========================================================= */

function updateCurrentEvent(event) {

    if (!event) {

        setText(
            "currentEvent",
            "Ready to replay recorded activity"
        );

        return;
    }

    const container =
        document.getElementById(
            "currentEvent"
        );

    if (!container) {
        return;
    }

    const type =
        normalizeEventType(
            event.event_type
        );

    container.innerHTML = `
        <div class="current-event-icon">

            ${
                type.includes("DELETE")
                    ? "!"
                    : type.includes("RENAME")
                        ? "↔"
                        : type.includes("MODIFY")
                            ? "✎"
                            : "+"
            }

        </div>

        <div>

            <span>
                CURRENT EVENT •
                ${escapeHTML(type)}
            </span>

            <strong>
                ${escapeHTML(
                    event.file_path
                )}
            </strong>

        </div>
    `;
}


/* =========================================================
   ACTIVE TIMELINE EVENT
========================================================= */

function clearActiveEvent() {

    document
        .querySelectorAll(
            ".timeline-event.active"
        )
        .forEach(
            element => {

                element.classList.remove(
                    "active"
                );
            }
        );
}


function highlightEvent(index) {

    clearActiveEvent();

    const element =
        document.getElementById(
            `event-${index}`
        );

    if (!element) {
        return;
    }

    element.classList.add(
        "active"
    );

    element.scrollIntoView({
        behavior: "smooth",
        block: "center"
    });
}


/* =========================================================
   FLOATING STOP BUTTON
========================================================= */

function updateStopButton() {

    const button =
        document.getElementById(
            "stopButton"
        );

    if (!button) {
        return;
    }

    if (isPlaying) {

        button.classList.add(
            "visible"
        );

        button.disabled = false;

    } else {

        button.classList.remove(
            "visible"
        );

        button.disabled = true;
    }
}


/* =========================================================
   STOP / PAUSE
========================================================= */

function stopReplay() {

    if (replayTimer) {

        clearTimeout(
            replayTimer
        );

        replayTimer = null;
    }

    isPlaying = false;

    const button =
        document.getElementById(
            "playButton"
        );

    if (button) {

        button.disabled = false;

        button.textContent =
            replayIndex > 0
                ? "▶ Resume Replay"
                : "▶ Play Replay";
    }

    setText(
        "replayStatus",
        "PAUSED"
    );

    updateStopButton();
}


/* =========================================================
   FINISH
========================================================= */

function finishReplay() {

    if (replayTimer) {

        clearTimeout(
            replayTimer
        );

        replayTimer = null;
    }

    isPlaying = false;

    replayIndex =
        events.length;

    updateProgress();

    updateReplayScore(
        events.length - 1
    );

    const button =
        document.getElementById(
            "playButton"
        );

    if (button) {

        button.disabled = false;

        button.textContent =
            "▶ Play Again";
    }

    setText(
        "replayStatus",
        "COMPLETE"
    );

    updateStopButton();

    showToast(
        "Attack replay completed."
    );
}


/* =========================================================
   PLAY NEXT EVENT
========================================================= */

function playNextEvent() {

    if (!isPlaying) {
        return;
    }

    if (
        replayIndex >=
        events.length
    ) {

        finishReplay();

        return;
    }

    const event =
        events[
            replayIndex
        ];

    highlightEvent(
        replayIndex
    );

    updateCurrentEvent(
        event
    );

    updateReplayScore(
        replayIndex
    );

    replayIndex++;

    updateProgress();

    const speedSelect =
        document.getElementById(
            "speedSelect"
        );

    const delay =
        Number(
            speedSelect?.value ||
            700
        );

    replayTimer =
        setTimeout(
            playNextEvent,
            delay
        );
}


/* =========================================================
   START REPLAY
========================================================= */

function startReplay() {

    if (!events.length) {

        showToast(
            "No events available for replay."
        );

        return;
    }

    if (
        replayIndex >=
        events.length
    ) {

        replayIndex = 0;

        clearActiveEvent();

        updateReplayScore(-1);

        updateProgress();
    }

    isPlaying = true;

    const button =
        document.getElementById(
            "playButton"
        );

    if (button) {

        button.disabled = true;

        button.textContent =
            "▶ Replaying...";
    }

    setText(
        "replayStatus",
        "REPLAYING"
    );

    updateStopButton();

    playNextEvent();
}


/* =========================================================
   RESET
========================================================= */

function resetReplay() {

    stopReplay();

    replayIndex = 0;

    clearActiveEvent();

    updateProgress();

    updateReplayScore(-1);

    updateCurrentEvent(
        null
    );

    setText(
        "replayStatus",
        "READY"
    );

    const button =
        document.getElementById(
            "playButton"
        );

    if (button) {

        button.disabled = false;

        button.textContent =
            "▶ Play Replay";
    }

    updateStopButton();
}


/* =========================================================
   LOAD EVENTS
========================================================= */

async function loadEvents() {

    stopReplay();

    try {

        const saved =
            getSavedSystem();

        const systemId =
            saved?.id;

        let url =
            "/api/attack-replay?limit=200";

        if (systemId) {

            url +=
                `&system_id=${encodeURIComponent(
                    systemId
                )}`;
        }

        const data =
            await fetchJSON(url);

        events =
            Array.isArray(
                data.events
            )
                ? data.events
                : [];

        /*
         * API returns chronological
         * filesystem events.
         */

        events.sort(
            (a, b) => {

                return (
                    new Date(
                        a.timestamp || 0
                    ) -
                    new Date(
                        b.timestamp || 0
                    )
                );
            }
        );

        replayIndex = 0;

        countEvents();

        renderTimeline();

        updateProgress();

        updateReplayScore(-1);

        updateCurrentEvent(
            null
        );

        setText(
            "replayStatus",
            events.length
                ? "READY"
                : "NO EVENTS"
        );

    } catch (error) {

        console.error(
            "Attack Replay API error:",
            error
        );

        events = [];

        countEvents();

        updateReplayScore(-1);

        const timeline =
            document.getElementById(
                "timeline"
            );

        if (timeline) {

            timeline.innerHTML = `
                <div class="timeline-empty">
                    Unable to load recorded event data.
                </div>
            `;
        }

        setText(
            "replayStatus",
            "API ERROR"
        );

        showToast(
            "Unable to load attack replay data."
        );
    }
}


/* =========================================================
   CONTROLS
========================================================= */

function setupControls() {

    const playButton =
        document.getElementById(
            "playButton"
        );

    const resetButton =
        document.getElementById(
            "resetButton"
        );

    const stopButton =
        document.getElementById(
            "stopButton"
        );

    const refreshButton =
        document.getElementById(
            "refreshButton"
        );


    /* PLAY */

    if (playButton) {

        playButton.addEventListener(
            "click",
            () => {

                if (isPlaying) {
                    return;
                }

                startReplay();
            }
        );
    }


    /* RESET */

    if (resetButton) {

        resetButton.addEventListener(
            "click",
            () => {

                resetReplay();

                showToast(
                    "Replay reset."
                );
            }
        );
    }


    /* STOP */

    if (stopButton) {

        stopButton.addEventListener(
            "click",
            () => {

                if (!isPlaying) {
                    return;
                }

                const stoppedAt =
                    replayIndex;

                stopReplay();

                showToast(
                    `Replay paused at ${stoppedAt} / ${events.length}.`
                );
            }
        );
    }


    /* REFRESH */

    if (refreshButton) {

        refreshButton.addEventListener(
            "click",
            async () => {

                refreshButton.disabled =
                    true;

                refreshButton.textContent =
                    "↻ Refreshing...";

                await loadEvents();

                refreshButton.disabled =
                    false;

                refreshButton.textContent =
                    "↻ Refresh";

                showToast(
                    "Attack replay refreshed."
                );
            }
        );
    }
}


/* =========================================================
   INITIALIZE
========================================================= */

document.addEventListener(
    "DOMContentLoaded",
    async () => {

        updateSystemInfo();

        setupControls();

        updateStopButton();

        updateReplayScore(-1);

        await loadEvents();

    }
);
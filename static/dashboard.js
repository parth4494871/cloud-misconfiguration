async function runScan() {
    const button = document.getElementById("scanButton");

    if (button) {
        button.disabled = true;
        button.innerText = "Scanning...";
    }

    try {
        const response = await fetch("/api/scan", {
            method: "POST"
        });

        const data = await response.json();

        if (!data.success) {
            alert("Scan failed: " + data.error);
            return;
        }

        // Reload the dashboard so the new scan appears
        window.location.reload();

    } catch (error) {
        alert("Error while running scan: " + error);
    } finally {
        if (button) {
            button.disabled = false;
            button.innerText = "Run Scan";
        }
    }
}
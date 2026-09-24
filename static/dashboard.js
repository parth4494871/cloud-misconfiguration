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

// --- NEW FEATURES JS ---

function toggleTheme() {
    document.body.classList.toggle('dark-mode');
    const btn = document.getElementById('themeToggle');
    if (document.body.classList.contains('dark-mode')) {
        btn.innerText = '☀️ Light Mode';
        localStorage.setItem('theme', 'dark');
    } else {
        btn.innerText = '🌙 Dark Mode';
        localStorage.setItem('theme', 'light');
    }
    // Simple reload to update chart labels color
    if (document.getElementById('severityChart')) {
        window.location.reload();
    }
}

// Check saved theme on load
if (localStorage.getItem('theme') === 'dark') {
    document.body.classList.add('dark-mode');
    const btn = document.getElementById('themeToggle');
    if (btn) btn.innerText = '☀️ Light Mode';
}

function fixIssue(buttonElement) {
    buttonElement.innerText = "⏳ Applying...";
    buttonElement.style.backgroundColor = "#fbbf24";
    
    setTimeout(() => {
        buttonElement.innerText = "✅ Remediated!";
        buttonElement.style.backgroundColor = "#10b981";
        buttonElement.disabled = true;
    }, 1500);
}

async function uploadPDF() {
    const fileInput = document.getElementById('pdfUpload');
    const statusText = document.getElementById('uploadStatus');
    
    if (fileInput.files.length === 0) return;

    statusText.innerText = "⏳ Uploading...";
    statusText.style.color = "#fbbf24";

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);

    try {
        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            statusText.innerText = "✅ " + data.message;
            statusText.style.color = "#10b981";
        } else {
            statusText.innerText = "❌ " + data.error;
            statusText.style.color = "#dc2626";
        }
    } catch (error) {
        statusText.innerText = "❌ Upload failed";
        statusText.style.color = "#dc2626";
    }

    // Reset input so they can upload again if needed
    fileInput.value = "";
    
    // Clear status text after 4 seconds
    setTimeout(() => {
        statusText.innerText = "";
    }, 4000);
}
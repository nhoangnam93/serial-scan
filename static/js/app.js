/**
 * NAB Serial Scanner v4.0 - Core Intelligence
 */

// ============================================
// State Management
// ============================================
let sock = null;
let scanner = null;
let isScanning = false;
let scanHistory = [];
let cameras = [];
let selectedCam = null;
let userName = localStorage.getItem('nab_scanner_name') || '';
let userPin = ''; // Not stored in local, only used for session
let clientId = localStorage.getItem('nab_scanner_client_id') || getOrGenerateClientId();
let joinPin = localStorage.getItem('nab_scanner_join_pin') || '';
let currentSessionId = '';

let ocrRunning = false;
let ocrTimer = null;
let ocrAwaitingServer = false;
let photoProcessing = false;
let ocrDelayMs = 700;

let currentPinBuffer = '';
const PIN_LENGTH = 4; // We target 4 for simplicity but support more

// ============================================
// Initialization
// ============================================
function getOrGenerateClientId() {
    let id = localStorage.getItem('nab_scanner_client_id');
    if (!id) {
        id = 'cli-' + Math.random().toString(36).substring(2, 15);
        localStorage.setItem('nab_scanner_client_id', id);
    }
    return id;
}

document.addEventListener('DOMContentLoaded', () => {
    initAuthUI();
    bootstrapApp();
});

function bootstrapApp() {
    if (!joinPin && !userPin) {
        showAuthOverlay();
        return;
    }
    
    hideAuthOverlay();
    document.getElementById('mainApp').style.opacity = '1';
    document.getElementById('mainApp').style.pointerEvents = 'all';
    
    if (userName) {
        document.getElementById('userPill').innerHTML = `👤 ${userName}`;
    }
    
    initSocket();
    loadCameras();
    // Chart placeholder
    initCharts();
}

// ============================================
// Authentication & PIN Pad
// ============================================
function initAuthUI() {
    const overlay = document.getElementById('authOverlay');
    const dots = document.querySelectorAll('.dot');
    const buttons = document.querySelectorAll('.pin-btn[data-val]');
    const delBtn = document.getElementById('pinDelBtn');
    
    buttons.forEach(btn => {
        btn.addEventListener('click', () => {
            if (currentPinBuffer.length < 6) {
                currentPinBuffer += btn.dataset.val;
                updatePinDots();
                if (currentPinBuffer.length >= 4) {
                    // Start auto-submit timer or wait for 6?
                    // Let's do a 500ms delay for 4 digits to allow for longer PINs if needed
                    clearTimeout(window.authTimeout);
                    window.authTimeout = setTimeout(submitUnifiedAuth, 400);
                }
            }
        });
    });
    
    delBtn.addEventListener('click', () => {
        currentPinBuffer = currentPinBuffer.slice(0, -1);
        updatePinDots();
    });
}

function updatePinDots() {
    const dots = document.querySelectorAll('.dot');
    dots.forEach((dot, i) => {
        dot.classList.toggle('filled', i < currentPinBuffer.length);
    });
}

function showAuthOverlay() {
    document.getElementById('authOverlay').style.display = 'grid';
}

function hideAuthOverlay() {
    document.getElementById('authOverlay').style.display = 'none';
}

function submitUnifiedAuth() {
    if (currentPinBuffer.length < 4) return;
    
    const pin = currentPinBuffer;
    // We try to authenticate via SocketIO
    if (!sock) {
        // First time initialization
        joinPin = pin; // Assume it's a join pin for now
        initSocket();
    } else {
        sock.emit('authenticate_pin', { pin });
    }
}

function showRegistration() {
    document.getElementById('registrationModal').style.display = 'grid';
}

function finishRegistration() {
    const name = document.getElementById('regNameInput').value.trim();
    if (!name) return;
    userName = name;
    localStorage.setItem('nab_scanner_name', name);
    
    if (currentPinBuffer.length >= 4) {
        sock.emit('register_user', { name, pin: currentPinBuffer, client_id: clientId });
    }
    document.getElementById('registrationModal').style.display = 'none';
}

// ============================================
// Socket Logic
// ============================================
function initSocket() {
    // If already connected with a different pin, we might need to reconnect
    sock = io({
        auth: {
            client_id: clientId,
            pin: joinPin || currentPinBuffer
        }
    });

    sock.on('connect', () => {
        console.log('Connected to NAB backend');
        if (currentPinBuffer) {
            sock.emit('authenticate_pin', { pin: currentPinBuffer });
        }
    });

    sock.on('auth_result', (data) => {
        if (data.success) {
            hideAuthOverlay();
            document.getElementById('mainApp').style.opacity = '1';
            document.getElementById('mainApp').style.pointerEvents = 'all';
            
            if (data.user) {
                userName = data.user.name;
                localStorage.setItem('nab_scanner_name', userName);
                document.getElementById('userPill').innerHTML = `👤 ${userName}`;
            }
            
            if (data.type === 'session') {
                joinPin = currentPinBuffer;
                localStorage.setItem('nab_scanner_join_pin', joinPin);
            }
            
            toast('Welcome, ' + (userName || 'Anonymous'));
        } else {
            // Shake dots
            const dots = document.getElementById('pinDots');
            dots.classList.add('shake');
            setTimeout(() => {
                dots.classList.remove('shake');
                currentPinBuffer = '';
                updatePinDots();
            }, 500);
            toast('Invalid PIN');
        }
    });
    
    sock.on('identity_status', (data) => {
        if (data.verified) {
            userName = data.name;
            document.getElementById('userPill').innerHTML = `👤 ${userName}`;
            hideAuthOverlay();
            document.getElementById('mainApp').style.opacity = '1';
            document.getElementById('mainApp').style.pointerEvents = 'all';
        }
    });

    sock.on('new_scan', (data) => {
        addScanToFeed(data);
        updateDashboardStats(data);
    });
    
    sock.on('ocr_dashboard', (data) => {
        updateRadar(data);
    });
}

// ============================================
// UI Helpers
// ============================================
function toast(msg) {
    const container = document.getElementById('toasts');
    const el = document.createElement('div');
    el.className = 'toast-msg';
    el.textContent = msg;
    container.appendChild(el);
    setTimeout(() => el.remove(), 3000);
}

function updateRadar(data) {
    document.getElementById('mLatency').textContent = `${data.avg_latency_ms || 0}ms`;
    document.getElementById('mMatch').textContent = `${data.avg_confidence_pct || 0}%`;
    document.getElementById('perfLoad').textContent = `${data.inflight || 0}/${data.capacity || 0}`;
    
    const fill = document.getElementById('confBar');
    if (fill) fill.style.width = `${data.avg_confidence_pct || 0}%`;
}

// ============================================
// Camera & OCR Logic
// ============================================
async function loadCameras() {
    try {
        cameras = await Html5Qrcode.getCameras();
        const sel = document.getElementById('cameraSel');
        if (cameras && cameras.length > 0) {
            sel.innerHTML = cameras.map(c => `<option value="${c.id}">${c.label}</option>`).join('');
            selectedCam = cameras[0].id;
        }
    } catch(e) {
        console.error('Camera access denied', e);
    }
}

function startScanner() {
    scanner = new Html5Qrcode("reader");
    const config = { fps: 15, qrbox: { width: 250, height: 150 } };
    
    scanner.start(
        { deviceId: { exact: selectedCam } },
        config,
        (decodedText) => {
            handleScan(decodedText, 'barcode');
        }
    ).then(() => {
        isScanning = true;
        document.getElementById('startBtn').disabled = true;
        document.getElementById('stopBtn').disabled = false;
        document.getElementById('photoBtn').disabled = false;
        sock.emit('scanner_state', { scanning: true });
        loopOcr();
    });
}

function stopScanner() {
    if (scanner) {
        scanner.stop().then(() => {
            isScanning = false;
            document.getElementById('startBtn').disabled = false;
            document.getElementById('stopBtn').disabled = true;
            sock.emit('scanner_state', { scanning: false });
        });
    }
}

function handleScan(text, source) {
    // Normalization and validation logic would go here
    sock.emit('save_scan', {
        serial: text,
        method: source,
        user: userName
    });
    
    // Play sound based on result (mocked here, will be updated by socket results)
    playSuccessSound();
}

function loopOcr() {
    if (!isScanning) return;
    // Capture frame and emit 'process_ocr_frame'
    // To be implemented fully in the next pass 
    setTimeout(loopOcr, ocrDelayMs);
}

// ============================================
// Aesthetics & Polish
// ============================================
function playSuccessSound() {
    document.getElementById('snd-success').play().catch(() => {});
}

function initCharts() {
    const ctx = document.getElementById('metricsChart').getContext('2d');
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['', '', '', '', '', ''],
            datasets: [{
                label: 'OCR Speed',
                data: [400, 450, 420, 380, 410, 390],
                borderColor: '#3B82F6',
                tension: 0.4,
                borderWidth: 2,
                pointRadius: 0
            }]
        },
        options: {
            plugins: { legend: { display: false } },
            scales: {
                x: { display: false },
                y: { display: false }
            }
        }
    });
}

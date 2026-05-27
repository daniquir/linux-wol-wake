document.addEventListener('DOMContentLoaded', () => {
    const scanBtn = document.getElementById('scan-btn');
    const addManualBtn = document.getElementById('add-manual-btn');
    const manualModal = document.getElementById('manual-modal');
    const saveManualBtn = document.getElementById('save-manual');
    const cancelManualBtn = document.getElementById('cancel-manual');
    
    const editModal = document.getElementById('edit-modal');
    const saveEditBtn = document.getElementById('save-edit');
    const cancelEditBtn = document.getElementById('cancel-edit');
    
    const scanStatus = document.getElementById('scan-status');
    const scanIndicator = document.getElementById('scan-indicator');
    const devicesContainer = document.getElementById('devices-container');
    const networkRangeInfo = document.getElementById('network-range-info');
    const toastContainer = document.getElementById('toast-container');
    
    const statTotal = document.getElementById('stat-total');
    const statOnline = document.getElementById('stat-online');
    const statWol = document.getElementById('stat-wol');

    const categories = {
        'PC': { icon: 'fa-desktop', label: 'Computers' },
        'Laptop': { icon: 'fa-laptop', label: 'Laptops' },
        'Server': { icon: 'fa-server', label: 'Servers / NAS' },
        'Media': { icon: 'fa-tv', label: 'Media' },
        'Console': { icon: 'fa-gamepad', label: 'Consoles' },
        'Network': { icon: 'fa-network-wired', label: 'Network devices' },
        'Mobile': { icon: 'fa-mobile-alt', label: 'Mobile' },
        'Tablet': { icon: 'fa-tablet-alt', label: 'Tablets' },
        'Printer': { icon: 'fa-print', label: 'Printers' },
        'Camera': { icon: 'fa-video', label: 'Cameras' },
        'IoT': { icon: 'fa-microchip', label: 'IoT devices' },
        'Other': { icon: 'fa-question-circle', label: 'Other' }
    };

    const showToast = (title, message, type = 'blue') => {
        const toast = document.createElement('div');
        toast.className = `bg-dark-card border-l-4 border-${type}-500 rounded-lg shadow-xl p-4 min-w-[300px] transform transition-all duration-300 translate-x-full border border-dark-border`;
        toast.innerHTML = `
            <div class="flex items-start">
                <div class="flex-shrink-0">
                    <i class="fas ${type === 'red' ? 'fa-exclamation-circle text-red-500' : 'fa-info-circle text-blue-500'}"></i>
                </div>
                <div class="ml-3">
                    <p class="text-sm font-bold text-white">${title}</p>
                    <p class="text-xs text-dark-muted">${message}</p>
                </div>
                <button class="ml-auto text-dark-muted hover:text-white focus:outline-none">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;
        toastContainer.appendChild(toast);
        setTimeout(() => toast.classList.remove('translate-x-full'), 10);
        const close = () => {
            toast.classList.add('translate-x-full');
            setTimeout(() => toast.remove(), 300);
        };
        toast.querySelector('button').onclick = close;
        setTimeout(close, 5000);
    };

    // Redirect to login on session expiry (API returns 401)
    const _apiFetch = async (url, opts) => {
        const r = await fetch(url, opts);
        if (r.status === 401) { window.location.href = '/login'; }
        return r;
    };

    const loadDevices = async () => {
        try {
            const response = await _apiFetch('/api/devices');
            const devices = await response.json();
            
            statTotal.textContent = devices.length;
            statOnline.textContent = devices.filter(d => d.is_online).length;
            statWol.textContent = devices.filter(d => d.wol_enabled).length;

            if (devices.length === 0) {
                devicesContainer.innerHTML = '<div class="flex items-center justify-center h-64 text-dark-muted italic text-sm">No devices yet. Click "Scan Network".</div>';
                return;
            }

            const grouped = {};
            devices.forEach(d => {
                const cat = d.category || 'Other';
                if (!grouped[cat]) grouped[cat] = [];
                grouped[cat].push(d);
            });

            devicesContainer.innerHTML = '';
            const catOrder = ['Network', 'Server', 'PC', 'Laptop', 'Console', 'Media', 'Camera', 'IoT', 'Mobile', 'Tablet', 'Printer', 'Other'];
            
            catOrder.forEach(catKey => {
                if (!grouped[catKey]) return;
                
                const catInfo = categories[catKey];
                const section = document.createElement('div');
                section.className = 'space-y-4';
                
                let cardsHtml = grouped[catKey].map(device => {
                    const statusColor = device.is_online ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]' : 'bg-red-500/50';
                    const statusText = device.is_online ? 'Online' : 'Offline';
                    const displayName = device.alias || device.hostname || 'Unknown';
                    
                    // Puertos/Servicios abiertos
                    let servicesHtml = '';
                    if (device.open_ports) {
                        const ports = device.open_ports.split(',');
                        servicesHtml = '<div class="flex flex-wrap gap-1 mt-2">';
                        ports.forEach(port => {
                            let protocol = 'http';
                            if (port === '443' || port === '8443') protocol = 'https';
                            const url = `${protocol}://${device.ip}:${port}`;
                            const isWeb = ['80', '443', '8080', '8443', '5000'].includes(port);
                            
                            if (isWeb) {
                                servicesHtml += `<a href="${url}" target="_blank" class="text-[9px] bg-green-500/10 text-green-400 px-1.5 py-0.5 rounded border border-green-500/20 hover:bg-green-500/20 transition-colors flex items-center gap-1">
                                    <i class="fas fa-external-link-alt text-[8px]"></i> :${port}
                                </a>`;
                            } else {
                                servicesHtml += `<span class="text-[9px] bg-slate-500/10 text-slate-400 px-1.5 py-0.5 rounded border border-slate-500/20 flex items-center gap-1">
                                    <i class="fas fa-plug text-[8px]"></i> :${port}
                                </span>`;
                            }
                        });
                        servicesHtml += '</div>';
                    }

                    // WoL auto-detection hint when enabled
                    const wolReasonsStr = device.wol_reasons ? `Reasons: ${device.wol_reasons.split(',').join('; ')}` : 'Auto-detected';
                    const wolBadge = device.wol_enabled ? 
                        `<span class="text-[9px] bg-blue-500/20 text-blue-400 px-1 py-0.5 rounded border border-blue-500/30 ml-auto flex items-center gap-1 cursor-help" title="${wolReasonsStr}"><i class="fas fa-bolt text-[8px]"></i> WoL Ready</span>` : '';

                    const onvifBadge = device.is_onvif ? 
                        `<span class="text-[9px] bg-green-500/20 text-green-400 px-1 py-0.5 rounded border border-green-500/30 flex items-center gap-1 ml-1" title="ONVIF camera detected"><i class="fas fa-video text-[8px]"></i> ONVIF</span>` : '';

                    const manualBadge = device.is_manual_category ? 
                        `<span class="text-[8px] bg-amber-500/20 text-amber-500 px-1 py-0.5 rounded border border-amber-500/30 flex items-center gap-1 ml-1" title="Category set manually"><i class="fas fa-user-edit"></i></span>` : '';

                    return `
                        <div class="bg-dark-card border border-dark-border rounded-xl p-4 hover:border-blue-500/50 transition-all duration-200 group">
                            <div class="flex justify-between items-start mb-3">
                                <div class="flex items-center gap-3 overflow-hidden">
                                    <div class="h-2.5 w-2.5 flex-shrink-0 rounded-full ${statusColor}" title="${statusText}"></div>
                                    <div class="overflow-hidden">
                                        <div class="flex items-center gap-2">
                                            <h4 class="font-bold text-white text-sm truncate">${displayName}</h4>
                                            <button onclick="openEditModal(${device.id}, '${device.alias || ''}', '${device.category}', ${device.is_onvif}, '${device.onvif_user || ''}')" class="text-dark-muted hover:text-blue-400 opacity-0 group-hover:opacity-100 transition-opacity">
                                                <i class="fas fa-edit text-[10px]"></i>
                                            </button>
                                        </div>
                                        <p class="text-[10px] text-dark-muted font-mono uppercase tracking-tighter truncate">${device.mac}</p>
                                    </div>
                                </div>
                                <div class="text-right flex-shrink-0">
                                    <p class="text-xs font-bold text-blue-400 font-mono">${device.ip}</p>
                                    <p class="text-[10px] text-dark-muted truncate max-w-[80px]">${device.vendor}</p>
                                </div>
                            </div>

                            <div class="flex items-center mb-1">
                                ${servicesHtml}
                                ${wolBadge}
                                ${onvifBadge}
                                ${manualBadge}
                            </div>
                            
                            <div class="flex items-center justify-between mt-3 pt-3 border-t border-dark-border/50">
                                <div class="flex items-center gap-4">
                                    <label class="flex items-center cursor-pointer gap-2">
                                        <input type="checkbox" class="sr-only peer" ${device.wol_enabled ? 'checked' : ''} onchange="toggleWol(${device.id})">
                                        <div class="w-8 h-4 bg-slate-700 rounded-full peer peer-checked:bg-blue-600 after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:after:translate-x-4 relative"></div>
                                        <span class="text-[10px] font-bold text-dark-muted uppercase">WoL</span>
                                    </label>
                                </div>
                                
                                <div class="flex gap-2">
                                    ${device.is_onvif ? `
                                        <button class="bg-green-600/20 hover:bg-green-600 text-green-400 hover:text-white px-3 py-1 rounded text-[10px] font-bold uppercase transition-all flex items-center gap-1"
                                                onclick="viewCamera(${device.id}, '${(device.alias || device.hostname || device.ip).replace(/'/g, '')}')">
                                            <i class="fas fa-eye"></i> View
                                        </button>
                                    ` : ''}
                                    <button class="bg-blue-600/20 hover:bg-blue-600 text-blue-400 hover:text-white px-3 py-1 rounded text-[10px] font-bold uppercase transition-all flex items-center gap-1 disabled:opacity-30 disabled:pointer-events-none"
                                            onclick="wakeDevice(${device.id}, '${displayName}')"
                                            ${device.wol_enabled ? '' : 'disabled'}>
                                        <i class="fas fa-power-off"></i> Wake
                                    </button>
                                </div>
                            </div>
                        </div>
                    `;
                }).join('');

                const onlineCameras = catKey === 'Camera'
                    ? grouped[catKey].filter(d => d.is_onvif && d.is_online)
                    : [];
                const gridBtn = onlineCameras.length > 0
                    ? `<button onclick="openCameraGrid()" class="ml-auto flex items-center gap-1.5 text-[10px] bg-green-600/20 hover:bg-green-600 text-green-400 hover:text-white border border-green-600/30 px-3 py-1 rounded-lg transition-all font-bold uppercase">
                           <i class="fas fa-th-large"></i> Grid view (${onlineCameras.length})
                       </button>`
                    : `<p class="text-[10px] text-dark-muted italic ml-auto hidden md:block">System-managed category</p>`;

                section.innerHTML = `
                    <div class="flex items-center gap-3 border-b border-dark-border pb-2">
                        <i class="fas ${catInfo.icon} text-blue-500 text-sm"></i>
                        <h3 class="text-sm font-bold text-white uppercase tracking-wider">${catInfo.label}</h3>
                        <span class="bg-dark-border text-dark-muted text-[10px] px-2 py-0.5 rounded-full">${grouped[catKey].length}</span>
                        ${gridBtn}
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        ${cardsHtml}
                    </div>
                `;
                devicesContainer.appendChild(section);
            });

        } catch (error) {
            console.error('Error:', error);
            showToast('Error', 'Could not load devices', 'red');
        }
    };

    window.toggleWol = async (deviceId) => {
        try {
            const response = await fetch(`/api/toggle-wol/${deviceId}`, { method: 'POST' });
            const result = await response.json();
            if (result.status === 'ok') {
                showToast('Updated', `WoL ${result.wol_enabled ? 'enabled' : 'disabled'}`, 'blue');
                loadDevices(); 
            }
        } catch (error) {
            showToast('Error', 'Failed to toggle WoL', 'red');
        }
    };

    window.wakeDevice = async (deviceId, name) => {
        try {
            const response = await fetch(`/api/wake/${deviceId}`, { method: 'POST' });
            const result = await response.json();
            if (result.status === 'ok') {
                showToast('Success', `Waking ${name}...`, 'green');
            } else {
                showToast('Error', result.message || 'Wake failed', 'red');
            }
        } catch (error) {
            showToast('Error', 'Network error', 'red');
        }
    };

    window.openEditModal = (id, alias, category, is_onvif, onvifUser = '') => {
        const editIdEl = document.getElementById('edit-id');
        editIdEl.value = id;
        editIdEl.dataset.hostname = alias || '';
        document.getElementById('edit-alias').value = alias === 'null' ? '' : alias;
        document.getElementById('edit-category').value = category;
        document.getElementById('edit-is-onvif').checked = is_onvif;
        document.getElementById('edit-onvif-user').value = onvifUser;
        document.getElementById('edit-onvif-pass').value = '';

        toggleOnvifFields(category);

        editModal.classList.remove('hidden');
        editModal.classList.add('flex');

        // Focus ONVIF password field if opened from credential flow
        if (is_onvif && _pendingCameraRetry) {
            setTimeout(() => document.getElementById('edit-onvif-pass').focus(), 100);
        }
    };

    window.toggleOnvifFields = (category) => {
        const onvifSettings = document.getElementById('onvif-settings');
        const isOnvifChecked = document.getElementById('edit-is-onvif').checked;
        if (category === 'Camera' || isOnvifChecked) {
            onvifSettings.classList.remove('hidden');
        } else {
            onvifSettings.classList.add('hidden');
        }
    };

    // ── Camera viewer modal ──────────────────────────────────────────────────
    const cameraModal        = document.getElementById('camera-modal');
    const cameraTitle        = document.getElementById('camera-modal-title');
    const cameraStatus       = document.getElementById('camera-modal-status');
    const cameraLoading      = document.getElementById('camera-loading');
    const cameraLoadingText  = document.getElementById('camera-loading-text');
    const cameraError        = document.getElementById('camera-error');
    const cameraErrorMsg     = document.getElementById('camera-error-msg');
    const cameraImg          = document.getElementById('camera-stream-img');
    const cameraRtspUrl      = document.getElementById('camera-rtsp-url');
    const cameraCopyBtn      = document.getElementById('camera-copy-rtsp');
    const cameraRetryBtn     = document.getElementById('camera-retry-btn');
    const cameraManualBtn    = document.getElementById('camera-manual-btn');
    const cameraManualWrap   = document.getElementById('camera-manual-wrap');
    const cameraManualUrlIn  = document.getElementById('camera-manual-url');
    const cameraManualTest   = document.getElementById('camera-manual-test');
    const cameraManualStatus = document.getElementById('camera-manual-status');
    const cameraDiagWrap     = document.getElementById('camera-diag-wrap');
    const cameraDiagToggle   = document.getElementById('camera-diag-toggle');
    const cameraDiagChevron  = document.getElementById('camera-diag-chevron');
    const cameraDiagBody     = document.getElementById('camera-diag-body');
    const camera401Hint      = document.getElementById('camera-401-hint');
    const cameraCredBtn      = document.getElementById('camera-cred-btn');
    const cameraCloseBtn     = document.getElementById('camera-modal-close');

    let _currentCameraId    = null;
    let _pendingCameraRetry = null;
    let _liveTimer         = null;

    const _setStatus = (state) => {
        const map = {
            connecting: { text: 'Connecting...', cls: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
            live:       { text: 'LIVE',          cls: 'bg-green-500/20 text-green-400 border-green-500/30' },
            error:      { text: 'Error',          cls: 'bg-red-500/20 text-red-400 border-red-500/30' },
        };
        const s = map[state] || map.connecting;
        cameraStatus.textContent = s.text;
        cameraStatus.className = `text-[10px] px-2 py-0.5 rounded-full border ${s.cls}`;
    };

    const _showError = (msg, tried) => {
        if (_liveTimer) { clearTimeout(_liveTimer); _liveTimer = null; }
        cameraImg.onload  = null;
        cameraImg.onerror = null;
        cameraImg.src = '';
        cameraImg.classList.add('hidden');
        cameraLoading.classList.add('hidden');
        _setStatus('error');

        // Detect 401 auth errors across tried URLs
        const is401 = tried && tried.some(t => t.error && t.error.includes('401'));
        if (is401) {
            cameraErrorMsg.textContent = 'The camera rejected the connection due to missing or wrong credentials.';
            camera401Hint.classList.remove('hidden');
        } else {
            cameraErrorMsg.textContent = msg;
            camera401Hint.classList.add('hidden');
        }

        cameraError.classList.remove('hidden');
        cameraError.classList.add('flex');

        // Populate diagnostic panel
        if (tried && tried.length > 0) {
            cameraDiagBody.innerHTML = tried.map(t =>
                `<div><span class="text-slate-500">${t.url}</span><br>` +
                `<span class="${t.error.includes('401') ? 'text-amber-400/80' : 'text-red-400/80'}">${t.error}</span></div>`
            ).join('');
            cameraDiagWrap.classList.remove('hidden');
        } else {
            cameraDiagWrap.classList.add('hidden');
        }
    };

    const _showLive = () => {
        if (_liveTimer) { clearTimeout(_liveTimer); _liveTimer = null; }
        cameraLoading.classList.add('hidden');
        cameraImg.classList.remove('hidden');
        _setStatus('live');
    };

    const _startStream = (rtspUrl) => {
        const streamUrl = `/api/camera-stream/${_currentCameraId}?url=${encodeURIComponent(rtspUrl)}&t=${Date.now()}`;

        cameraImg.onload  = () => _showLive();
        cameraImg.onerror = () => _showError('Stream interrupted. The camera closed the connection.');

        // Fallback: algunos navegadores no disparan onload para MJPEG.
        // After 5s without error, assume playback started.
        _liveTimer = setTimeout(() => {
            if (cameraImg.src && cameraError.classList.contains('hidden')) {
                _showLive();
            }
        }, 5000);

        cameraImg.src = streamUrl;
    };

    const _probe = async (deviceId) => {
        cameraLoadingText.textContent = 'Discovering ONVIF / RTSP stream...';
        _setStatus('connecting');
        cameraDiagWrap.classList.add('hidden');
        cameraManualWrap.classList.add('hidden');
        camera401Hint.classList.add('hidden');

        let probeData;
        try {
            const r = await fetch(`/api/camera-probe/${deviceId}`);
            probeData = await r.json();
            if (!r.ok) {
                _showError(probeData.error || 'No stream found.', probeData.tried);
                return;
            }
        } catch (e) {
            _showError('Could not reach the server.');
            return;
        }

        cameraRtspUrl.textContent = probeData.safe_url || probeData.url;
        cameraRtspUrl.dataset.full = probeData.safe_url || probeData.url;
        cameraLoadingText.textContent = 'Stream found, starting video...';
        _startStream(probeData.url);
    };

    // Diagnostic toggle
    cameraDiagToggle.onclick = () => {
        const open = !cameraDiagBody.classList.contains('hidden');
        cameraDiagBody.classList.toggle('hidden', open);
        cameraDiagChevron.className = open ? 'fas fa-chevron-down' : 'fas fa-chevron-up';
    };

    // Manual URL toggle
    cameraManualBtn.onclick = () => {
        cameraManualWrap.classList.toggle('hidden');
        cameraManualStatus.classList.add('hidden');
    };

    // Test manual URL
    cameraManualTest.onclick = async () => {
        const url = cameraManualUrlIn.value.trim();
        if (!url) return;
        cameraManualStatus.textContent = 'Testing...';
        cameraManualStatus.className = 'text-[10px] text-orange-400';
        cameraManualStatus.classList.remove('hidden');
        cameraManualTest.disabled = true;

        try {
            const r = await fetch('/api/camera-test-url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url }),
            });
            const data = await r.json();
            if (data.ok) {
                const videoStream = (data.streams || []).find(s => s.codec_type === 'video');
                const res = videoStream ? ` — ${videoStream.codec_name || ''} ${videoStream.width || ''}x${videoStream.height || ''}` : '';
                cameraManualStatus.textContent = `✓ Stream found${res}. Starting...`;
                cameraManualStatus.className = 'text-[10px] text-green-400';
                cameraRtspUrl.textContent = url.replace(/:[^@]+@/, ':***@');
                cameraRtspUrl.dataset.full = url.replace(/:[^@]+@/, ':***@');

                // Hide error, start stream
                cameraError.classList.add('hidden');
                cameraError.classList.remove('flex');
                cameraLoading.classList.remove('hidden');
                cameraImg.classList.add('hidden');
                _startStream(url);
            } else {
                cameraManualStatus.textContent = `✗ ${data.error}`;
                cameraManualStatus.className = 'text-[10px] text-red-400';
            }
        } catch (e) {
            cameraManualStatus.textContent = '✗ Network error';
            cameraManualStatus.className = 'text-[10px] text-red-400';
        } finally {
            cameraManualTest.disabled = false;
        }
    };

    // Enter key on manual URL input
    cameraManualUrlIn.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') cameraManualTest.click();
    });

    // ── Camera grid ──────────────────────────────────────────────────────────
    const gridModal     = document.getElementById('camera-grid-modal');
    const gridContainer = document.getElementById('camera-grid-container');
    const gridCloseBtn  = document.getElementById('camera-grid-close');
    const gridCount     = document.getElementById('grid-camera-count');

    // Cache: deviceId -> rtspUrl (avoids re-probing when opening full view)
    const _rtspCache = {};

    const _stopAllGridStreams = () => {
        gridContainer.querySelectorAll('img[data-grid-stream]').forEach(img => {
            img.onload = null; img.onerror = null; img.src = '';
        });
    };

    const _createGridCell = (device) => {
        const name = (device.alias || device.hostname || device.ip).replace(/'/g, '');
        const cell = document.createElement('div');
        cell.className = 'relative bg-dark-card border border-dark-border rounded-xl overflow-hidden cursor-pointer group transition-all duration-200 hover:border-green-500/60 hover:shadow-lg hover:shadow-green-900/30';
        cell.style.height = 'min-content';
        cell.innerHTML = `
            <div class="flex items-center justify-between px-3 py-2 bg-dark-card/80 border-b border-dark-border/50">
                <div class="flex items-center gap-2 overflow-hidden">
                    <div id="gs-dot-${device.id}" class="h-1.5 w-1.5 rounded-full flex-shrink-0 bg-orange-400 animate-pulse"></div>
                    <span class="text-[11px] font-bold text-white truncate">${name}</span>
                </div>
                <span class="text-[9px] text-dark-muted font-mono flex-shrink-0 ml-2">${device.ip}</span>
            </div>
            <div class="relative bg-black" style="aspect-ratio:16/9; min-height:169px;">
                <div id="gs-loading-${device.id}" class="absolute inset-0 flex items-center justify-center">
                    <i class="fas fa-circle-notch fa-spin text-blue-400"></i>
                </div>
                <div id="gs-error-${device.id}" class="absolute inset-0 hidden flex-col items-center justify-center gap-1 px-3">
                    <i class="fas fa-exclamation-triangle text-red-500 text-sm"></i>
                    <p id="gs-errmsg-${device.id}" class="text-[9px] text-red-400 text-center"></p>
                </div>
                <img id="gs-img-${device.id}" data-grid-stream="1"
                     class="hidden w-full h-full object-contain"
                     alt="${name}">
                <div class="absolute inset-0 hidden group-hover:flex items-center justify-center pointer-events-none">
                    <div class="bg-black/50 backdrop-blur-sm rounded-full p-3 shadow-xl">
                        <i class="fas fa-expand-alt text-white text-base"></i>
                    </div>
                </div>
            </div>`;
        cell.addEventListener('click', () => _openFullFromGrid(device.id, name));
        return cell;
    };

    const _startGridStream = (deviceId, rtspUrl) => {
        _rtspCache[deviceId] = rtspUrl;
        const img      = document.getElementById(`gs-img-${deviceId}`);
        const loading  = document.getElementById(`gs-loading-${deviceId}`);
        const dot      = document.getElementById(`gs-dot-${deviceId}`);
        const streamUrl = `/api/camera-stream/${deviceId}?url=${encodeURIComponent(rtspUrl)}&t=${Date.now()}`;

        const onLive = () => {
            loading.classList.add('hidden');
            img.classList.remove('hidden');
            dot.className = 'h-1.5 w-1.5 rounded-full flex-shrink-0 bg-green-400 shadow-[0_0_5px_rgba(74,222,128,0.8)]';
        };
        img.onload  = onLive;
        img.onerror = () => {
            img.classList.add('hidden');
            loading.classList.add('hidden');
            const errDiv = document.getElementById(`gs-error-${deviceId}`);
            document.getElementById(`gs-errmsg-${deviceId}`).textContent = 'Stream interrupted';
            errDiv.classList.remove('hidden');
            errDiv.classList.add('flex');
            dot.className = 'h-1.5 w-1.5 rounded-full flex-shrink-0 bg-red-500';
        };
        // Fallback: si en 6 s no hay error, asumimos que reproduce
        setTimeout(() => {
            if (!img.classList.contains('hidden')) return;
            const errDiv = document.getElementById(`gs-error-${deviceId}`);
            if (img.src && errDiv && errDiv.classList.contains('hidden')) onLive();
        }, 6000);

        img.src = streamUrl;
    };

    const _showGridError = (deviceId, msg) => {
        document.getElementById(`gs-loading-${deviceId}`)?.classList.add('hidden');
        const errDiv = document.getElementById(`gs-error-${deviceId}`);
        if (errDiv) { errDiv.classList.remove('hidden'); errDiv.classList.add('flex'); }
        const errMsg = document.getElementById(`gs-errmsg-${deviceId}`);
        if (errMsg) errMsg.textContent = msg.length > 55 ? msg.slice(0, 52) + '…' : msg;
        const dot = document.getElementById(`gs-dot-${deviceId}`);
        if (dot) dot.className = 'h-1.5 w-1.5 rounded-full flex-shrink-0 bg-red-500';
    };

    const _openFullFromGrid = (deviceId, name) => {
        _stopAllGridStreams();
        gridModal.classList.add('hidden');
        gridModal.classList.remove('flex');
        const known = _rtspCache[deviceId];
        if (known) {
            _openSingleModal(deviceId, name, known);
        } else {
            window.viewCamera(deviceId, name);
        }
    };

    gridCloseBtn.onclick = () => {
        _stopAllGridStreams();
        gridModal.classList.add('hidden');
        gridModal.classList.remove('flex');
    };
    gridModal.addEventListener('click', e => { if (e.target === gridModal) gridCloseBtn.onclick(); });

    window.openCameraGrid = async () => {
        let devices;
        try {
            const r = await fetch('/api/devices');
            devices = await r.json();
        } catch (e) {
            showToast('Error', 'Could not load devices', 'red');
            return;
        }
        const cameras = devices.filter(d => d.is_onvif && d.is_online);
        if (cameras.length === 0) {
            showToast('Info', 'No active ONVIF cameras right now', 'blue');
            return;
        }
        gridContainer.innerHTML = '';
        gridCount.textContent = `${cameras.length} camera${cameras.length !== 1 ? 's' : ''}`;
        gridModal.classList.remove('hidden');
        gridModal.classList.add('flex');

        // Probe cameras progressively (no await — let them load independently)
        cameras.forEach(async cam => {
            const cell = _createGridCell(cam);
            gridContainer.appendChild(cell);
            if (_rtspCache[cam.id]) {
                _startGridStream(cam.id, _rtspCache[cam.id]);
                return;
            }
            try {
                const r = await fetch(`/api/camera-probe/${cam.id}`);
                const data = await r.json();
                if (r.ok) _startGridStream(cam.id, data.url);
                else _showGridError(cam.id, data.error || 'No stream');
            } catch (_) {
                _showGridError(cam.id, 'Connection error');
            }
        });
    };

    // ── Single camera modal helpers ───────────────────────────────────────────
    let _resetSingleModal = (deviceId, name) => {
        _currentCameraId = deviceId;
        if (_liveTimer) { clearTimeout(_liveTimer); _liveTimer = null; }
        cameraImg.onload  = null;
        cameraImg.onerror = null;
        cameraImg.src = '';
        cameraImg.classList.add('hidden');
        cameraError.classList.add('hidden');
        cameraError.classList.remove('flex');
        cameraLoading.classList.remove('hidden');
        cameraDiagWrap.classList.add('hidden');
        cameraDiagBody.classList.add('hidden');
        cameraManualWrap.classList.add('hidden');
        camera401Hint.classList.add('hidden');
        cameraManualUrlIn.value = '';
        cameraRtspUrl.textContent = '—';
        delete cameraRtspUrl.dataset.full;
        cameraTitle.textContent = name;
        cameraModal.classList.remove('hidden');
        cameraModal.classList.add('flex');
    };

    const _openSingleModal = (deviceId, name, rtspUrl) => {
        _resetSingleModal(deviceId, name);
        cameraRtspUrl.textContent = rtspUrl.replace(/:[^@]+@/, ':***@');
        cameraRtspUrl.dataset.full = rtspUrl.replace(/:[^@]+@/, ':***@');
        cameraLoadingText.textContent = 'Starting stream...';
        _startStream(rtspUrl);
    };

    window.viewCamera = (deviceId, name) => {
        _resetSingleModal(deviceId, name);
        _probe(deviceId);
    };

    cameraCloseBtn.onclick = () => {
        if (_liveTimer) { clearTimeout(_liveTimer); _liveTimer = null; }
        cameraImg.onload  = null;
        cameraImg.onerror = null;
        cameraImg.src = '';
        cameraModal.classList.add('hidden');
        cameraModal.classList.remove('flex');
        _currentCameraId = null;
    };

    cameraRetryBtn.onclick = () => {
        if (!_currentCameraId) return;
        camera401Hint.classList.add('hidden');
        cameraError.classList.add('hidden');
        cameraError.classList.remove('flex');
        cameraLoading.classList.remove('hidden');
        cameraImg.classList.add('hidden');
        delete _rtspCache[_currentCameraId]; // force re-probe with updated credentials
        _probe(_currentCameraId);
    };

    // Open edit modal pre-focused on ONVIF credentials, retry on save
    cameraCredBtn.onclick = async () => {
        const deviceId = _currentCameraId;
        if (!deviceId) return;
        try {
            const r = await fetch('/api/devices');
            const devices = await r.json();
            const dev = devices.find(d => d.id === deviceId);
            if (!dev) return;
            // Close camera modal, open edit modal with ONVIF section open
            cameraCloseBtn.onclick();
            openEditModal(dev.id, dev.alias || '', dev.category, true, dev.onvif_user || '');
            // Mark that after saving this device we should retry camera
            _pendingCameraRetry = deviceId;
        } catch (_) {}
    };

    cameraCopyBtn.onclick = () => {
        const url = cameraRtspUrl.dataset.full || cameraRtspUrl.textContent;
        if (url && url !== '—') {
            navigator.clipboard.writeText(url)
                .then(() => showToast('Copied', 'RTSP URL copied to clipboard', 'green'));
        }
    };

    cameraModal.addEventListener('click', (e) => {
        if (e.target === cameraModal) cameraCloseBtn.onclick();
    });

    saveEditBtn.onclick = async () => {
        const id = document.getElementById('edit-id').value;
        const alias = document.getElementById('edit-alias').value;
        const category = document.getElementById('edit-category').value;
        const is_onvif = document.getElementById('edit-is-onvif').checked;
        const onvif_user = document.getElementById('edit-onvif-user').value;
        const onvif_password = document.getElementById('edit-onvif-pass').value;
        
        const payload = { alias, category, is_onvif };
        if (category === 'Camera' || is_onvif) {
            if (onvif_user) payload.onvif_user = onvif_user;
            if (onvif_password) payload.onvif_password = onvif_password;
        }

        try {
            const response = await fetch(`/api/update-device/${id}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (response.ok) {
                editModal.classList.add('hidden');
                editModal.classList.remove('flex');
                loadDevices();
                showToast('Success', 'Saved successfully', 'green');
                // If saved from camera credential flow, reopen the camera viewer
                if (_pendingCameraRetry && _pendingCameraRetry === parseInt(id)) {
                    const retryId = _pendingCameraRetry;
                    _pendingCameraRetry = null;
                    delete _rtspCache[retryId];
                    const devName = document.getElementById('edit-alias').value
                        || document.getElementById('edit-id').dataset.hostname
                        || `Camera #${retryId}`;
                    setTimeout(() => window.viewCamera(retryId, devName), 300);
                }
            }
        } catch (error) {
            showToast('Error', 'Save failed', 'red');
        }
    };

    cancelEditBtn.onclick = () => {
        editModal.classList.add('hidden');
        editModal.classList.remove('flex');
    };

    scanBtn.onclick = async () => {
        scanBtn.disabled = true;
        scanBtn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i> Scanning...';
        scanIndicator.classList.remove('hidden');
        scanStatus.textContent = 'Searching...';
        scanStatus.className = 'text-lg font-bold text-orange-400 animate-pulse';
        
        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({})
            });
            
            if (!response.ok) throw new Error('Server error');
            
            const result = await response.json();
            scanStatus.textContent = `Found: ${result.count}`;
            scanStatus.className = 'text-lg font-bold text-green-500';
            showToast('Scan complete', `${result.count} devices found`, 'green');
            loadDevices();
        } catch (error) {
            scanStatus.textContent = 'Failed';
            scanStatus.className = 'text-lg font-bold text-red-500';
            showToast('Error', 'Scan failed (timeout)', 'red');
        } finally {
            scanBtn.disabled = false;
            scanBtn.innerHTML = '<i class="fas fa-search mr-2"></i> Scan Network';
            scanIndicator.classList.add('hidden');
            setTimeout(() => {
                if (scanStatus.textContent !== 'Failed') {
                    scanStatus.textContent = 'Ready';
                    scanStatus.className = 'text-lg font-bold text-blue-500';
                }
            }, 4000);
        }
    };

    addManualBtn.onclick = () => {
        manualModal.classList.remove('hidden');
        manualModal.classList.add('flex');
    };

    cancelManualBtn.onclick = () => {
        manualModal.classList.add('hidden');
        manualModal.classList.remove('flex');
    };

    saveManualBtn.onclick = async () => {
        const ip = document.getElementById('manual-ip').value;
        const mac = document.getElementById('manual-mac').value;
        const alias = document.getElementById('manual-alias-input').value;
        const category = document.getElementById('manual-category').value;
        
        if (!ip || !mac) {
            showToast('Notice', 'Enter IP and MAC', 'red');
            return;
        }

        try {
            const response = await fetch('/api/add-device', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip, mac, alias, category })
            });
            if (response.ok) {
                manualModal.classList.add('hidden');
                manualModal.classList.remove('flex');
                document.getElementById('manual-ip').value = '';
                document.getElementById('manual-mac').value = '';
                document.getElementById('manual-alias-input').value = '';
                loadDevices();
                showToast('Added', 'Device saved manually', 'green');
            } else {
                const res = await response.json();
                showToast('Error', res.message, 'red');
            }
        } catch (error) {
            showToast('Error', 'Connection failed', 'red');
        }
    };

    fetch('/api/network-info').then(r => r.json()).then(data => {
        networkRangeInfo.textContent = `Network: ${data.range}`;
    });

    // ── PTZ Controls ────────────────────────────────────────────────────────
    const ptzPanel = document.getElementById('camera-ptz-panel');
    const ptzBadge = document.getElementById('camera-ptz-badge');
    const ptzStatus = document.getElementById('ptz-status');
    const ptzSpeed = document.getElementById('ptz-speed');
    const ptzSpeedVal = document.getElementById('ptz-speed-val');
    let _ptzSupported = false;

    // Speed slider update
    ptzSpeed.addEventListener('input', () => {
        const val = ptzSpeed.value;
        ptzSpeedVal.textContent = `${val * 10}%`;
    });

    // PTZ API call
    const _sendPtzCommand = async (direction) => {
        if (!_currentCameraId) return;
        const speed = parseInt(ptzSpeed.value) / 10;
        try {
            ptzStatus.textContent = 'Sending...';
            ptzStatus.classList.remove('hidden');
            const r = await fetch(`/api/camera-ptz/${_currentCameraId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ direction, speed })
            });
            const data = await r.json();
            if (r.ok) {
                ptzStatus.textContent = 'Movement sent';
                ptzStatus.className = 'text-[10px] text-green-400 mt-3 text-center';
                setTimeout(() => { ptzStatus.classList.add('hidden'); }, 1000);
            } else {
                ptzStatus.textContent = data.error || 'Error PTZ';
                ptzStatus.className = 'text-[10px] text-red-400 mt-3 text-center';
            }
        } catch (e) {
            ptzStatus.textContent = 'Network error';
            ptzStatus.className = 'text-[10px] text-red-400 mt-3 text-center';
        }
    };

    // Check PTZ support when opening camera
    const _checkPtzSupport = async (deviceId) => {
        try {
            const r = await fetch(`/api/camera-ptz-support/${deviceId}`);
            const data = await r.json();
            _ptzSupported = data.supported;
            if (_ptzSupported) {
                ptzPanel.classList.remove('hidden');
                ptzBadge.classList.remove('hidden');
            } else {
                ptzPanel.classList.add('hidden');
                ptzBadge.classList.add('hidden');
            }
        } catch (e) {
            _ptzSupported = false;
            ptzPanel.classList.add('hidden');
            ptzBadge.classList.add('hidden');
        }
    };

    // PTZ button event listeners
    document.getElementById('ptz-up')?.addEventListener('click', () => _sendPtzCommand('up'));
    document.getElementById('ptz-down')?.addEventListener('click', () => _sendPtzCommand('down'));
    document.getElementById('ptz-left')?.addEventListener('click', () => _sendPtzCommand('left'));
    document.getElementById('ptz-right')?.addEventListener('click', () => _sendPtzCommand('right'));
    document.getElementById('ptz-zoom-in')?.addEventListener('click', () => _sendPtzCommand('zoom_in'));
    document.getElementById('ptz-zoom-out')?.addEventListener('click', () => _sendPtzCommand('zoom_out'));
    document.getElementById('ptz-home')?.addEventListener('click', () => _sendPtzCommand('stop'));

    // Modify _resetSingleModal to also check PTZ support
    const _originalResetSingleModal = _resetSingleModal;
    _resetSingleModal = (deviceId, name) => {
        _originalResetSingleModal(deviceId, name);
        _checkPtzSupport(deviceId);
    };

    loadDevices();
});

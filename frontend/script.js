/**
 * Basic Network Sniffer - Frontend Logic
 * Handles real-time polling, packet table rendering, protocol filtering,
 * modal dissection, and capture controls.
 */

(function () {
  'use strict';

  // Application State
  const state = {
    isCapturing: false,
    lastPacketId: 0,
    packets: [],
    pollingTimer: null,
    autoScroll: true,
    searchQuery: '',
    previousTotal: 0,
    previousTimestamp: Date.now(),
    currentPacketRate: 0,
  };

  // DOM Elements
  const elements = {
    interfaceSelect: document.getElementById('interfaceSelect'),
    protocolFilterSelect: document.getElementById('protocolFilterSelect'),
    startBtn: document.getElementById('startBtn'),
    stopBtn: document.getElementById('stopBtn'),
    clearBtn: document.getElementById('clearBtn'),
    exportBtn: document.getElementById('exportBtn'),
    statusIndicator: document.getElementById('statusIndicator'),
    statusText: document.getElementById('statusText'),
    uptimeDisplay: document.getElementById('uptimeDisplay'),
    uptimeSeconds: document.getElementById('uptimeSeconds'),
    alertBanner: document.getElementById('alertBanner'),
    alertMessage: document.getElementById('alertMessage'),
    alertCloseBtn: document.getElementById('alertCloseBtn'),
    statTotal: document.getElementById('statTotal'),
    statTcp: document.getElementById('statTcp'),
    statUdp: document.getElementById('statUdp'),
    statIcmp: document.getElementById('statIcmp'),
    statBytes: document.getElementById('statBytes'),
    statRate: document.getElementById('statRate'),
    statTcpPct: document.getElementById('statTcpPct'),
    statUdpPct: document.getElementById('statUdpPct'),
    statIcmpPct: document.getElementById('statIcmpPct'),
    statOther: document.getElementById('statOther'),
    searchInput: document.getElementById('searchInput'),
    clearSearchBtn: document.getElementById('clearSearchBtn'),
    autoScrollToggle: document.getElementById('autoScrollToggle'),
    showingCount: document.getElementById('showingCount'),
    tableContainer: document.getElementById('tableContainer'),
    packetTableBody: document.getElementById('packetTableBody'),
    emptyStateRow: document.getElementById('emptyStateRow'),
    // Modal Elements
    packetModal: document.getElementById('packetModal'),
    modalTitle: document.getElementById('modalTitle'),
    modalProtocolBadge: document.getElementById('modalProtocolBadge'),
    modalGeneralGrid: document.getElementById('modalGeneralGrid'),
    modalHeaderGrid: document.getElementById('modalHeaderGrid'),
    modalPayloadAscii: document.getElementById('modalPayloadAscii'),
    modalPayloadHex: document.getElementById('modalPayloadHex'),
    modalCloseBtn: document.getElementById('modalCloseBtn'),
    modalCloseBtnFooter: document.getElementById('modalCloseBtnFooter'),
  };

  // ==========================================================================
  // Initialization & Interface Discovery
  // ==========================================================================

  async function init() {
    setupEventListeners();
    await loadInterfaces();
    await checkInitialStatus();
  }

  async function loadInterfaces() {
    try {
      // Check status to see if Npcap is available
      let hasPcap = false;
      try {
        const statusRes = await fetch('/api/status');
        const statusData = await statusRes.json();
        hasPcap = Boolean(statusData.has_pcap);
      } catch (_) {}

      const res = await fetch('/api/interfaces');
      const data = await res.json();
      const interfaces = data.interfaces || [];

      elements.interfaceSelect.innerHTML = '';

      if (interfaces.length === 0) {
        elements.interfaceSelect.innerHTML = '<option value="default">Default Interface</option>';
        return;
      }

      let simulatedOption = null;
      let realAdapterOption = null;

      interfaces.forEach((iface) => {
        const option = document.createElement('option');
        option.value = iface.id;
        option.textContent = iface.label || iface.name;
        if (iface.id === 'simulated') {
          simulatedOption = option;
        } else if (!realAdapterOption && iface.ip && !iface.ip.startsWith('169.254') && iface.ip !== '0.0.0.0') {
          realAdapterOption = option;
        }
        elements.interfaceSelect.appendChild(option);
      });

      if (!hasPcap && simulatedOption) {
        simulatedOption.selected = true;
        showAlert('Npcap driver not detected on this Windows PC. "Simulated Traffic (Demo Mode)" is selected so you can test packet sniffing and filtering immediately. To sniff real physical interfaces, install Npcap from https://npcap.com.');
      } else if (realAdapterOption) {
        realAdapterOption.selected = true;
      }
    } catch (err) {
      console.error('Failed to load interfaces:', err);
      elements.interfaceSelect.innerHTML = '<option value="simulated">⚡ Simulated Traffic (Demo Mode)</option>';
      showAlert('Could not query network interfaces. Running in simulated demo mode.');
    }
  }

  async function checkInitialStatus() {
    try {
      const res = await fetch('/api/status');
      const data = await res.json();
      updateStatusUI(data.is_running, data);
      if (data.is_running) {
        startPolling();
      }
    } catch (err) {
      console.warn('Initial status fetch failed:', err);
    }
  }

  // ==========================================================================
  // Event Listeners
  // ==========================================================================

  function setupEventListeners() {
    elements.startBtn.addEventListener('click', handleStartCapture);
    elements.stopBtn.addEventListener('click', handleStopCapture);
    elements.clearBtn.addEventListener('click', handleClearCapture);
    elements.exportBtn.addEventListener('click', handleExportCSV);

    elements.alertCloseBtn.addEventListener('click', hideAlert);

    elements.searchInput.addEventListener('input', (e) => {
      state.searchQuery = e.target.value.trim().toLowerCase();
      elements.clearSearchBtn.style.display = state.searchQuery ? 'block' : 'none';
      filterTableRows();
    });

    elements.clearSearchBtn.addEventListener('click', () => {
      elements.searchInput.value = '';
      state.searchQuery = '';
      elements.clearSearchBtn.style.display = 'none';
      filterTableRows();
    });

    elements.autoScrollToggle.addEventListener('change', (e) => {
      state.autoScroll = e.target.checked;
    });

    // Modal Close Events
    elements.modalCloseBtn.addEventListener('click', closeModal);
    elements.modalCloseBtnFooter.addEventListener('click', closeModal);
    elements.packetModal.addEventListener('click', (e) => {
      if (e.target === elements.packetModal) closeModal();
    });
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && elements.packetModal.style.display !== 'none') {
        closeModal();
      }
    });
  }

  // ==========================================================================
  // Capture Controls (Start / Stop / Clear / Export)
  // ==========================================================================

  async function handleStartCapture() {
    hideAlert();
    const selectedIface = elements.interfaceSelect.value;
    const protocolFilter = elements.protocolFilterSelect.value;

    elements.startBtn.disabled = true;

    try {
      const res = await fetch('/api/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          interface: selectedIface,
          protocol_filter: protocolFilter,
        }),
      });

      const data = await res.json();
      if (!res.ok || !data.success) {
        showAlert(data.error || 'Failed to start packet capture.');
        elements.startBtn.disabled = false;
        return;
      }

      updateStatusUI(true, data.status);
      startPolling();
    } catch (err) {
      showAlert(`Network error starting capture: ${err.message}`);
      elements.startBtn.disabled = false;
    }
  }

  async function handleStopCapture() {
    elements.stopBtn.disabled = true;
    try {
      const res = await fetch('/api/stop', { method: 'POST' });
      const data = await res.json();
      updateStatusUI(false, data.status);
      stopPolling();
    } catch (err) {
      showAlert(`Error stopping capture: ${err.message}`);
    } finally {
      elements.stopBtn.disabled = true;
      elements.startBtn.disabled = false;
    }
  }

  async function handleClearCapture() {
    try {
      await fetch('/api/clear', { method: 'POST' });
      state.packets = [];
      state.lastPacketId = 0;
      state.previousTotal = 0;
      elements.packetTableBody.innerHTML = '';
      if (elements.emptyStateRow) {
        elements.packetTableBody.appendChild(elements.emptyStateRow);
        elements.emptyStateRow.style.display = '';
      }
      resetMetrics();
      updateShowingCount();
    } catch (err) {
      showAlert(`Error clearing buffer: ${err.message}`);
    }
  }

  function handleExportCSV() {
    if (state.packets.length === 0) {
      showAlert('No packets captured to export.');
      return;
    }
    // Direct browser download
    window.location.href = '/api/export';
  }

  // ==========================================================================
  // Polling Loop & Metrics Updates
  // ==========================================================================

  function startPolling() {
    if (state.pollingTimer) clearInterval(state.pollingTimer);
    state.pollingTimer = setInterval(pollPackets, 700);
  }

  function stopPolling() {
    if (state.pollingTimer) {
      clearInterval(state.pollingTimer);
      state.pollingTimer = null;
    }
    // Final poll to get trailing packets
    pollPackets();
  }

  async function pollPackets() {
    try {
      const url = `/api/packets?since_id=${state.lastPacketId}&limit=200`;
      const res = await fetch(url);
      if (!res.ok) return;

      const data = await res.json();
      const status = data.status || {};

      // If backend encountered an error and stopped
      if (!status.is_running && status.last_error) {
        showAlert(status.last_error);
        updateStatusUI(false, status);
        stopPolling();
      } else {
        updateStatusUI(status.is_running, status);
      }

      if (data.packets && data.packets.length > 0) {
        appendPackets(data.packets);
      }

      if (status.stats) {
        updateMetrics(status.stats);
      }

      if (status.uptime_seconds !== undefined) {
        elements.uptimeSeconds.textContent = status.uptime_seconds;
      }
    } catch (err) {
      console.warn('Packet polling request failed:', err);
    }
  }

  function appendPackets(newPackets) {
    if (elements.emptyStateRow && elements.emptyStateRow.parentNode) {
      elements.emptyStateRow.remove();
    }

    const fragment = document.createDocumentFragment();

    newPackets.forEach((pkt) => {
      state.packets.push(pkt);
      state.lastPacketId = Math.max(state.lastPacketId, pkt.id);

      const row = createTableRow(pkt);
      fragment.appendChild(row);
    });

    elements.packetTableBody.appendChild(fragment);

    // Filter freshly added rows if a search query is active
    if (state.searchQuery) {
      filterTableRows();
    } else {
      updateShowingCount();
    }

    // Auto-scroll to bottom if enabled
    if (state.autoScroll) {
      elements.tableContainer.scrollTop = elements.tableContainer.scrollHeight;
    }
  }

  // ==========================================================================
  // Safe Table Row Construction
  // ==========================================================================

  function createTableRow(pkt) {
    const tr = document.createElement('tr');
    tr.className = 'packet-row';
    tr.dataset.packetId = pkt.id;

    // ID
    const tdId = document.createElement('td');
    tdId.className = 'packet-id';
    tdId.textContent = pkt.id;
    tr.appendChild(tdId);

    // Time
    const tdTime = document.createElement('td');
    tdTime.className = 'packet-time';
    tdTime.textContent = pkt.timestamp || '-';
    tr.appendChild(tdTime);

    // Protocol Badge
    const tdProto = document.createElement('td');
    const badge = document.createElement('span');
    const protoStr = (pkt.protocol || 'Other').toUpperCase();
    badge.className = `protocol-badge ${getProtocolBadgeClass(protoStr)}`;
    badge.textContent = protoStr;
    tdProto.appendChild(badge);
    tr.appendChild(tdProto);

    // Source IP & Port
    const tdSrc = document.createElement('td');
    tdSrc.className = 'endpoint-cell';
    const srcSpan = document.createElement('span');
    srcSpan.className = 'endpoint-ip';
    srcSpan.textContent = pkt.src_ip || 'N/A';
    tdSrc.appendChild(srcSpan);
    if (pkt.src_port !== null && pkt.src_port !== undefined) {
      const portSpan = document.createElement('span');
      portSpan.className = 'endpoint-port';
      portSpan.textContent = `:${pkt.src_port}`;
      tdSrc.appendChild(portSpan);
    }
    tr.appendChild(tdSrc);

    // Destination IP & Port
    const tdDst = document.createElement('td');
    tdDst.className = 'endpoint-cell';
    const dstSpan = document.createElement('span');
    dstSpan.className = 'endpoint-ip';
    dstSpan.textContent = pkt.dst_ip || 'N/A';
    tdDst.appendChild(dstSpan);
    if (pkt.dst_port !== null && pkt.dst_port !== undefined) {
      const portSpan = document.createElement('span');
      portSpan.className = 'endpoint-port';
      portSpan.textContent = `:${pkt.dst_port}`;
      tdDst.appendChild(portSpan);
    }
    tr.appendChild(tdDst);

    // Length
    const tdLen = document.createElement('td');
    tdLen.className = 'length-cell';
    tdLen.textContent = `${pkt.length || 0} B`;
    tr.appendChild(tdLen);

    // Summary / Info
    const tdInfo = document.createElement('td');
    tdInfo.className = 'info-cell';
    tdInfo.textContent = pkt.info || '-';
    tdInfo.title = pkt.info || '';
    tr.appendChild(tdInfo);

    // Payload Preview
    const tdPayload = document.createElement('td');
    tdPayload.className = 'payload-cell';
    tdPayload.textContent = pkt.payload_preview ? unescapeHtmlEntities(pkt.payload_preview) : '-';
    tr.appendChild(tdPayload);

    // Row Click -> Open Inspector Modal
    tr.addEventListener('click', () => openModal(pkt));

    return tr;
  }

  function getProtocolBadgeClass(proto) {
    if (proto.includes('TCP')) return 'proto-badge-tcp';
    if (proto.includes('UDP')) return 'proto-badge-udp';
    if (proto.includes('ICMP')) return 'proto-badge-icmp';
    if (proto.includes('ARP')) return 'proto-badge-arp';
    return 'proto-badge-other';
  }

  function unescapeHtmlEntities(str) {
    return str
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&amp;/g, '&');
  }

  // ==========================================================================
  // Filtering & Search
  // ==========================================================================

  function filterTableRows() {
    const rows = elements.packetTableBody.querySelectorAll('.packet-row');
    let visibleCount = 0;

    rows.forEach((row) => {
      if (!state.searchQuery) {
        row.style.display = '';
        visibleCount++;
        return;
      }

      const text = row.textContent.toLowerCase();
      if (text.includes(state.searchQuery)) {
        row.style.display = '';
        visibleCount++;
      } else {
        row.style.display = 'none';
      }
    });

    updateShowingCount(visibleCount);
  }

  function updateShowingCount(count = null) {
    if (count === null) {
      const visible = elements.packetTableBody.querySelectorAll('.packet-row:not([style*="display: none"])').length;
      elements.showingCount.textContent = `Showing: ${visible} of ${state.packets.length} packets`;
    } else {
      elements.showingCount.textContent = `Showing: ${count} of ${state.packets.length} packets`;
    }
  }

  // ==========================================================================
  // Metrics & UI State
  // ==========================================================================

  function updateStatusUI(isRunning, statusObj = {}) {
    state.isCapturing = isRunning;
    elements.startBtn.disabled = isRunning;
    elements.stopBtn.disabled = !isRunning;
    elements.interfaceSelect.disabled = isRunning;
    elements.protocolFilterSelect.disabled = isRunning;

    if (isRunning) {
      elements.statusIndicator.className = 'status-badge status-active';
      const iface = statusObj.interface || 'Selected Interface';
      elements.statusText.textContent = `Capturing live traffic on ${iface}`;
      elements.uptimeDisplay.style.display = 'inline-block';
    } else {
      elements.statusIndicator.className = 'status-badge status-idle';
      elements.statusText.textContent = 'Status: Idle';
      elements.uptimeDisplay.style.display = 'none';
    }
  }

  function updateMetrics(stats) {
    const total = stats.total || 0;
    const tcp = stats.tcp || 0;
    const udp = stats.udp || 0;
    const icmp = stats.icmp || 0;
    const other = stats.other || 0;
    const bytes = stats.bytes_total || 0;

    elements.statTotal.textContent = total.toLocaleString();
    elements.statTcp.textContent = tcp.toLocaleString();
    elements.statUdp.textContent = udp.toLocaleString();
    elements.statIcmp.textContent = icmp.toLocaleString();
    elements.statOther.textContent = `Other: ${other.toLocaleString()} pkts`;

    // Percentages
    const tcpPct = total > 0 ? Math.round((tcp / total) * 100) : 0;
    const udpPct = total > 0 ? Math.round((udp / total) * 100) : 0;
    const icmpPct = total > 0 ? Math.round((icmp / total) * 100) : 0;

    elements.statTcpPct.textContent = `${tcpPct}% of total`;
    elements.statUdpPct.textContent = `${udpPct}% of total`;
    elements.statIcmpPct.textContent = `${icmpPct}% of total`;

    // Data Volume formatted
    if (bytes > 1024 * 1024) {
      elements.statBytes.textContent = `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    } else {
      elements.statBytes.textContent = `${(bytes / 1024).toFixed(1)} KB`;
    }

    // Packet Rate calculation
    const now = Date.now();
    const elapsedSec = (now - state.previousTimestamp) / 1000;
    if (elapsedSec >= 1.0) {
      const diff = total - state.previousTotal;
      state.currentPacketRate = Math.max(0, Math.round(diff / elapsedSec));
      state.previousTotal = total;
      state.previousTimestamp = now;
      elements.statRate.textContent = `${state.currentPacketRate} pkts/sec`;
    }
  }

  function resetMetrics() {
    elements.statTotal.textContent = '0';
    elements.statTcp.textContent = '0';
    elements.statUdp.textContent = '0';
    elements.statIcmp.textContent = '0';
    elements.statBytes.textContent = '0 KB';
    elements.statRate.textContent = '0 pkts/sec';
    elements.statTcpPct.textContent = '0% of total';
    elements.statUdpPct.textContent = '0% of total';
    elements.statIcmpPct.textContent = '0% of total';
    elements.statOther.textContent = 'Other: 0 pkts';
  }

  function showAlert(msg) {
    elements.alertMessage.innerHTML = '';
    const spanText = document.createElement('span');
    spanText.textContent = msg;
    elements.alertMessage.appendChild(spanText);

    if (msg.includes('Npcap') || msg.includes('Permission') || msg.includes('Simulated')) {
      const demoBtn = document.createElement('button');
      demoBtn.className = 'btn btn-primary';
      demoBtn.style.padding = '4px 10px';
      demoBtn.style.fontSize = '0.78rem';
      demoBtn.style.marginLeft = '12px';
      demoBtn.textContent = 'Switch to Demo Mode';
      demoBtn.addEventListener('click', () => {
        elements.interfaceSelect.value = 'simulated';
        hideAlert();
        handleStartCapture();
      });
      elements.alertMessage.appendChild(demoBtn);
    }
    elements.alertBanner.style.display = 'flex';
  }

  function hideAlert() {
    elements.alertBanner.style.display = 'none';
  }

  // ==========================================================================
  // Packet Inspector Modal
  // ==========================================================================

  function openModal(pkt) {
    elements.modalTitle.textContent = `Packet #${pkt.id} Inspection`;
    const protoStr = (pkt.protocol || 'Unknown').toUpperCase();
    elements.modalProtocolBadge.textContent = protoStr;
    elements.modalProtocolBadge.className = `protocol-badge ${getProtocolBadgeClass(protoStr)}`;

    // 1. General Grid
    elements.modalGeneralGrid.innerHTML = `
      <div class="detail-item"><span class="detail-label">Packet ID</span><span class="detail-value">#${pkt.id}</span></div>
      <div class="detail-item"><span class="detail-label">Timestamp</span><span class="detail-value">${pkt.timestamp || 'N/A'}</span></div>
      <div class="detail-item"><span class="detail-label">Total Length</span><span class="detail-value">${pkt.length} Bytes</span></div>
      <div class="detail-item"><span class="detail-label">Protocol</span><span class="detail-value">${pkt.protocol}</span></div>
      <div class="detail-item"><span class="detail-label">Source IP</span><span class="detail-value">${pkt.src_ip}</span></div>
      <div class="detail-item"><span class="detail-label">Destination IP</span><span class="detail-value">${pkt.dst_ip}</span></div>
    `;

    // 2. Protocol Header Grid
    const details = pkt.details || {};
    let headerHtml = '';

    if (details.src_mac || details.dst_mac) {
      headerHtml += `
        <div class="detail-item"><span class="detail-label">Source MAC</span><span class="detail-value">${details.src_mac || 'N/A'}</span></div>
        <div class="detail-item"><span class="detail-label">Dest MAC</span><span class="detail-value">${details.dst_mac || 'N/A'}</span></div>
      `;
    }

    if (details.ip_version) {
      headerHtml += `<div class="detail-item"><span class="detail-label">IP Version</span><span class="detail-value">IPv${details.ip_version}</span></div>`;
    }
    if (details.ttl !== undefined && details.ttl !== null) {
      headerHtml += `<div class="detail-item"><span class="detail-label">TTL (Hop Limit)</span><span class="detail-value">${details.ttl}</span></div>`;
    }

    if (pkt.src_port !== null && pkt.src_port !== undefined) {
      headerHtml += `
        <div class="detail-item"><span class="detail-label">Source Port</span><span class="detail-value">${pkt.src_port} ${pkt.src_service ? `(${pkt.src_service})` : ''}</span></div>
        <div class="detail-item"><span class="detail-label">Dest Port</span><span class="detail-value">${pkt.dst_port} ${pkt.dst_service ? `(${pkt.dst_service})` : ''}</span></div>
      `;
    }

    if (details.tcp_flags) {
      headerHtml += `<div class="detail-item"><span class="detail-label">TCP Flags</span><span class="detail-value">${details.tcp_flags}</span></div>`;
    }
    if (details.seq !== undefined) {
      headerHtml += `<div class="detail-item"><span class="detail-label">Seq Number</span><span class="detail-value">${details.seq}</span></div>`;
    }
    if (details.ack !== undefined) {
      headerHtml += `<div class="detail-item"><span class="detail-label">Ack Number</span><span class="detail-value">${details.ack}</span></div>`;
    }
    if (details.icmp_type !== undefined) {
      headerHtml += `<div class="detail-item"><span class="detail-label">ICMP Type / Code</span><span class="detail-value">Type ${details.icmp_type}, Code ${details.icmp_code || 0}</span></div>`;
    }

    elements.modalHeaderGrid.innerHTML = headerHtml || '<div class="detail-item"><span class="detail-value">No additional header details</span></div>';

    // 3. Payload Previews
    elements.modalPayloadAscii.textContent = pkt.payload_preview ? unescapeHtmlEntities(pkt.payload_preview) : 'No payload or empty data segment.';
    elements.modalPayloadHex.textContent = pkt.payload_hex ? pkt.payload_hex : 'No raw byte data.';

    elements.packetModal.style.display = 'flex';
  }

  function closeModal() {
    elements.packetModal.style.display = 'none';
  }

  // Initialize on DOM ready
  document.addEventListener('DOMContentLoaded', init);
})();

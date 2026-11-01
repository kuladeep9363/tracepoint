const API_BASE = 'http://127.0.0.1:8000';

const fileInput = document.querySelector('#file-input');
const dropzone = document.querySelector('#dropzone');
const browseButton = document.querySelector('#browse-button');
const demoButton = document.querySelector('#demo-button');
const clearButton = document.querySelector('#clear-button');
const uploadTitle = document.querySelector('#upload-title');
const uploadSubtitle = document.querySelector('#upload-subtitle');
const uploadProgress = document.querySelector('#upload-progress');
const uploadProgressLabel = document.querySelector('#upload-progress-label');
const inlineAlert = document.querySelector('#inline-alert');
const resultsSection = document.querySelector('#results-section');
const emptyState = document.querySelector('#empty-state');
const eventsBody = document.querySelector('#events-body');
const emptyFilter = document.querySelector('#empty-filter');
const searchInput = document.querySelector('#search-input');
const severityFilter = document.querySelector('#severity-filter');
const protocolFilter = document.querySelector('#protocol-filter');
const sourceFilter = document.querySelector('#source-filter');
const destinationFilter = document.querySelector('#destination-filter');
const timeFromFilter = document.querySelector('#time-from');
const timeToFilter = document.querySelector('#time-to');
const exportButton = document.querySelector('#export-button');
const resetFiltersButton = document.querySelector('#reset-filters');
const modalBackdrop = document.querySelector('#modal-backdrop');
const modal = document.querySelector('#details-modal');
const modalContent = document.querySelector('#modal-content');
const modalTitle = document.querySelector('#modal-title');

let currentEvents = [];
let visibleEvents = [];
let isLoading = false;
let lastFocusedRow = null;

function showError(message) {
  inlineAlert.textContent = message;
  inlineAlert.hidden = false;
}

function setLoading(loading, label = '') {
  isLoading = loading;
  dropzone.classList.toggle('is-loading', loading);
  uploadProgress.hidden = !loading;
  browseButton.disabled = loading;
  demoButton.disabled = loading;
  uploadProgressLabel.textContent = label || (loading ? 'Sending capture to the analysis API…' : 'Your file is sent to the local analysis API.');
  uploadTitle.textContent = loading ? 'Analyzing your capture…' : 'Drop a capture to analyze';
  uploadSubtitle.textContent = loading ? 'Parsing packets and grouping events' : 'PCAP, PCAPNG, or CAP · up to 100 MiB';
}

function formatTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value || '—';
  return new Intl.DateTimeFormat(undefined, { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3, hour12: false }).format(date);
}

function safeClass(value, allowed) {
  return allowed.includes(value) ? value : allowed[0];
}

function packetNumbers(event) {
  const values = event.details?.packet_numbers;
  if (!Array.isArray(values)) return [];
  return [...new Set(values.map(Number).filter((value) => Number.isInteger(value) && value > 0))].sort((a, b) => a - b);
}

function closePacketPopovers(except = null) {
  document.querySelectorAll('.packet-popover-host.is-open').forEach((host) => {
    if (host === except) return;
    host.classList.remove('is-open');
    host.querySelector('.packet-list-trigger')?.setAttribute('aria-expanded', 'false');
    const popover = host.querySelector('.packet-number-popover');
    if (popover) popover.hidden = true;
    window.clearTimeout(host.hideTimer);
  });
}

function formatPacketRange(values) {
  const numbers = [...new Set((values || []).map(Number).filter((value) => Number.isInteger(value) && value > 0))].sort((a, b) => a - b);
  if (!numbers.length) return '—';
  const ranges = [];
  let start = numbers[0];
  let previous = numbers[0];
  for (const number of numbers.slice(1)) {
    if (number === previous + 1) {
      previous = number;
      continue;
    }
    ranges.push(start === previous ? String(start) : `${start}–${previous}`);
    start = previous = number;
  }
  ranges.push(start === previous ? String(start) : `${start}–${previous}`);
  return ranges.join(', ');
}

function rowColor(event) {
  const summary = String(event.summary || '').toLowerCase();
  const protocol = String(event.protocol || '').toUpperCase();
  const backendColor = safeClass(event.color, ['neutral', 'teal', 'amber', 'red']);
  if (backendColor === 'red' || String(event.severity).toLowerCase() === 'high'
      || summary.includes('arp spoof') || summary.includes('dns hijack')
      || summary.includes('dos burst') || summary.includes('ddos')) return 'red';
  if (summary.includes('possible port scan') || summary.includes('rogue dhcp')
      || summary.includes('dhcp attack') || summary.includes('directory scan')) return 'amber';
  if (backendColor === 'amber' || String(event.severity).toLowerCase() === 'medium') return 'amber';
  if (protocol === 'DNS') return 'purple';
  if (protocol === 'HTTP') return 'cyan';
  if (summary.includes('handshake')) return 'teal';
  return backendColor;
}

function makeCell(text, className = '') {
  const cell = document.createElement('td');
  if (className) cell.className = className;
  cell.textContent = text ?? '—';
  if (text !== null && text !== undefined) cell.title = String(text);
  return cell;
}

function makePacketNumberCell(event) {
  const cell = document.createElement('td');
  cell.className = 'packet-number-cell';
  const numbers = packetNumbers(event);
  if (numbers.length <= 3) {
    cell.textContent = formatPacketRange(numbers);
    return cell;
  }

  const host = document.createElement('div');
  host.className = 'packet-popover-host';
  const trigger = document.createElement('button');
  trigger.type = 'button';
  trigger.className = 'packet-list-trigger';
  trigger.textContent = '⋯';
  trigger.setAttribute('aria-label', `Show all ${numbers.length} related packet numbers`);
  trigger.setAttribute('aria-expanded', 'false');
  const popover = document.createElement('div');
  popover.className = 'packet-number-popover';
  popover.hidden = true;
  const title = document.createElement('strong');
  title.textContent = `${numbers.length.toLocaleString()} related packets`;
  const list = document.createElement('ol');
  list.className = 'packet-number-items';
  for (const number of numbers) {
    const item = document.createElement('li');
    item.textContent = String(number);
    list.append(item);
  }
  popover.append(title, list);
  host.append(trigger, popover);

  const close = () => {
    host.classList.remove('is-open');
    trigger.setAttribute('aria-expanded', 'false');
    popover.hidden = true;
  };
  host.addEventListener('pointerenter', () => window.clearTimeout(host.hideTimer));
  host.addEventListener('pointerleave', () => {
    host.hideTimer = window.setTimeout(() => {
      if (!host.contains(document.activeElement)) close();
    }, 180);
  });
  trigger.addEventListener('click', (event) => {
    event.preventDefault();
    event.stopPropagation();
    const open = !host.classList.contains('is-open');
    if (open) closePacketPopovers(host);
    host.classList.toggle('is-open', open);
    trigger.setAttribute('aria-expanded', String(open));
    popover.hidden = !open;
  });
  trigger.addEventListener('keydown', (event) => event.stopPropagation());
  popover.addEventListener('click', (event) => event.stopPropagation());
  cell.append(host);
  return cell;
}

function renderRows() {
  const query = searchInput.value.trim().toLowerCase();
  const severity = severityFilter.value;
  const protocol = protocolFilter.value;
  const source = sourceFilter.value.trim().toLowerCase();
  const destination = destinationFilter.value.trim().toLowerCase();
  const from = timeFromFilter.value ? new Date(timeFromFilter.value).getTime() : null;
  const to = timeToFilter.value ? new Date(timeToFilter.value).getTime() : null;
  const filtered = currentEvents.filter((event) => {
    const timestamp = new Date(event.time).getTime();
    const directions = Array.isArray(event.details?.directions) ? event.details.directions : [];
    const sourceEndpoints = [event.source, ...directions.map((direction) => direction.source_ip)].filter(Boolean).join(' ').toLowerCase();
    const destinationEndpoints = [event.destination, ...directions.map((direction) => direction.destination_ip)].filter(Boolean).join(' ').toLowerCase();
    const searchable = [event.id, event.s_no, event.time, event.source, event.destination, event.protocol, event.summary, event.severity, JSON.stringify(event.details || {})]
      .join(' ').toLowerCase();
    return (!query || searchable.includes(query))
      && (severity === 'all' || event.severity === severity)
      && (protocol === 'all' || event.protocol === protocol)
      && (!source || sourceEndpoints.includes(source))
      && (!destination || destinationEndpoints.includes(destination))
      && (from === null || (Number.isFinite(timestamp) && timestamp >= from))
      && (to === null || (Number.isFinite(timestamp) && timestamp <= to));
  });
  visibleEvents = filtered;

  eventsBody.replaceChildren();
  for (const event of filtered) {
    const color = rowColor(event);
    const row = document.createElement('tr');
    row.className = `event-row row-${color}`;
    row.tabIndex = 0;
    row.setAttribute('aria-label', `${event.protocol}: ${event.summary}. Select for details.`);
    row.append(makeCell(event.s_no, 'number-cell'));
    row.append(makePacketNumberCell(event));
    const timestampCell = makeCell(formatTime(event.time), 'time-cell');
    timestampCell.title = event.time || '';
    row.append(timestampCell);
    row.append(makeCell(event.source, 'address-cell'));
    row.append(makeCell(event.destination, 'address-cell'));

    const protocolCell = document.createElement('td');
    const protocolBadge = document.createElement('span');
    protocolBadge.className = `protocol-badge protocol-${String(event.protocol || 'other').toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
    protocolBadge.textContent = event.protocol || 'OTHER';
    protocolCell.append(protocolBadge);
    row.append(protocolCell);

    const summaryCell = document.createElement('td');
    summaryCell.className = 'summary-cell';
    const summaryText = document.createElement('span');
    summaryText.className = 'summary-text';
    summaryText.textContent = event.summary || 'Packet event';
    summaryCell.append(summaryText);
    const level = String(event.severity || 'info').toLowerCase();
    const severityBadge = document.createElement('span');
    severityBadge.className = `severity-badge severity-${safeClass(level, ['info', 'low', 'medium', 'high'])}`;
    severityBadge.textContent = level;
    summaryCell.append(severityBadge);
    if (event.classification) {
      const classificationBadge = document.createElement('span');
      const classificationValue = String(event.classification).toLowerCase();
      classificationBadge.className = `classification-badge classification-${safeClass(classificationValue.replaceAll(' ', '-'), ['likely-fault', 'possible-attack', 'needs-review'])}`;
      classificationBadge.textContent = classificationValue;
      summaryCell.append(classificationBadge);
    }
    const packetCount = Number(event.details?.packet_count);
    if (Number.isFinite(packetCount) && packetCount > 1) {
      const groupedCount = document.createElement('span');
      groupedCount.className = 'packet-count-badge';
      groupedCount.textContent = `${packetCount.toLocaleString()} packets`;
      summaryCell.append(groupedCount);
    }
    row.append(summaryCell);

    row.addEventListener('click', () => openDetails(event, row));
    row.addEventListener('keydown', (keyboardEvent) => {
      if (keyboardEvent.key === 'Enter' || keyboardEvent.key === ' ') {
        keyboardEvent.preventDefault();
        openDetails(event, row);
      }
    });
    eventsBody.append(row);
  }

  const total = currentEvents.length;
  document.querySelector('#results-count').textContent = `${total} ${total === 1 ? 'event' : 'events'}`;
  document.querySelector('#visible-count').textContent = `Showing ${filtered.length} of ${total} events`;
  emptyFilter.hidden = filtered.length !== 0 || total === 0;
  exportButton.disabled = filtered.length === 0;
}

function populateProtocolFilter(events) {
  protocolFilter.replaceChildren();
  const allOption = document.createElement('option');
  allOption.value = 'all';
  allOption.textContent = 'All protocols';
  protocolFilter.append(allOption);
  const protocols = [...new Set(events.map((event) => String(event.protocol || 'OTHER')))].sort((a, b) => a.localeCompare(b));
  for (const value of protocols) {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = value;
    protocolFilter.append(option);
  }
}

function csvValue(value) {
  let text = value === null || value === undefined ? '' : String(value);
  // Prevent spreadsheet applications from evaluating imported cell values as formulas.
  if (/^\s*[=+@-]/.test(text)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}

function exportVisibleEvents() {
  if (!visibleEvents.length) return;
  const columns = [
    ['s_no', 's_no'], ['packet_no', 'packet_no'], ['time', 'time'], ['source', 'source'], ['destination', 'destination'],
    ['protocol', 'protocol'], ['summary', 'summary'], ['severity', 'severity'], ['color', 'color'], ['details', 'details'],
  ];
  const csv = [columns.map(([, heading]) => csvValue(heading)).join(','), ...visibleEvents.map((event) =>
    columns.map(([key]) => {
      if (key === 'packet_no') return csvValue(formatPacketRange(packetNumbers(event)));
      if (key === 'details') {
        const details = { ...(event.details || {}) };
        if (Array.isArray(details.packet_numbers)) details.packet_numbers = formatPacketRange(details.packet_numbers);
        return csvValue(JSON.stringify(details));
      }
      return csvValue(event[key]);
    }).join(','))].join('\r\n');
  const blob = new Blob([`\uFEFF${csv}`], { type: 'text/csv;charset=utf-8' });
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement('a');
  const captureName = document.querySelector('#capture-name').textContent || 'capture';
  const safeName = captureName.replace(/\.[^.]+$/, '').replace(/[^a-z0-9_-]+/gi, '-').replace(/^-+|-+$/g, '') || 'capture';
  link.href = objectUrl;
  link.download = `${safeName}-analysis.csv`;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
}

function resetFilters() {
  searchInput.value = '';
  protocolFilter.value = 'all';
  severityFilter.value = 'all';
  sourceFilter.value = '';
  destinationFilter.value = '';
  timeFromFilter.value = '';
  timeToFilter.value = '';
  renderRows();
}

function addDetailRow(label, value) {
  const item = document.createElement('div');
  item.className = 'detail-item';
  const term = document.createElement('dt');
  term.textContent = label;
  const definition = document.createElement('dd');
  if (Array.isArray(value)) {
    if (label.toLowerCase().includes('packet number')) {
      const list = document.createElement('span');
      list.className = 'packet-number-list';
      for (const number of value) {
        const chip = document.createElement('span');
        chip.className = 'packet-chip';
        chip.textContent = `#${number}`;
        list.append(chip);
      }
      definition.append(list);
    } else if (value.length && value.every((entry) => entry && typeof entry === 'object')) {
      const list = document.createElement('div');
      list.className = 'direction-list';
      for (const direction of value) {
        const directionItem = document.createElement('div');
        directionItem.className = 'direction-entry';
        const endpoints = document.createElement('span');
        endpoints.textContent = `${direction.source_ip || 'Unknown'} → ${direction.destination_ip || 'Unknown'}`;
        const portCount = document.createElement('span');
        portCount.textContent = `${direction.packet_count ?? '—'} packets · ${direction.unique_destination_ports ?? '—'} unique ports`;
        directionItem.append(endpoints, portCount);
        list.append(directionItem);
      }
      definition.append(list);
    } else {
      definition.textContent = value.join(', ') || '—';
    }
  } else if (value !== null && typeof value === 'object') {
    definition.textContent = JSON.stringify(value);
  } else {
    definition.textContent = value === null || value === undefined || value === '' ? '—' : String(value);
  }
  item.append(term, definition);
  return item;
}

function modalSection(title) {
  const section = document.createElement('section');
  section.className = 'modal-section';
  const heading = document.createElement('h3');
  heading.textContent = title;
  section.append(heading);
  return section;
}

function addSectionNote(section, text) {
  const note = document.createElement('p');
  note.className = 'modal-note';
  note.textContent = text;
  section.append(note);
}

function addHttpMessage(section, title, value) {
  const block = document.createElement('div');
  block.className = 'http-message';
  const heading = document.createElement('h4');
  heading.textContent = title;
  const content = document.createElement('pre');
  content.textContent = value === null || value === undefined || value === ''
    ? 'Not available in parsed packet metadata'
    : (typeof value === 'string' ? value : JSON.stringify(value, null, 2));
  block.append(heading, content);
  section.append(block);
}

function detectionAssessment(event) {
  const summary = String(event.summary || '').toLowerCase();
  const details = event.details || {};
  if (summary.includes('port scan')) {
    const window = details.window_seconds ?? 10;
    const directions = details.directions || [];
    const why = details.bidirectional && directions.length > 1
      ? `${directions.map((direction) => `${direction.source_ip} → ${direction.destination_ip} (${direction.packet_count} packets, ${direction.unique_destination_ports} distinct destination ports)`).join('; ')} within ${window} seconds. Both directions are grouped into one event. This indicates possible scan activity between the hosts; it does not identify which host is the attacker.`
      : `${details.unique_destination_ports ?? 'Multiple'} distinct destination ports were contacted within ${window} seconds. This is a possible scan indicator, not confirmation of malicious intent.`;
    return {
      why,
      suggestions: ['Review the target host’s exposed services.', 'Consider rate limiting repeated connection attempts and tightening firewall rules.', 'Preserve the capture and check whether the source is expected.'],
    };
  }
  if (summary.includes('ddos')) {
    const count = details.packet_count ?? 'A high number of';
    const sources = details.distinct_source_ips ?? 'multiple';
    return {
      why: `${count} packets from ${sources} distinct source IPs reached the same destination during a ${details.window_seconds ?? 5}-second window. This is a possible distributed burst.`,
      suggestions: ['Validate impact on the destination service.', 'Coordinate upstream filtering with the network or hosting provider.', 'Apply service rate limits and retain the capture for incident review.'],
    };
  }
  if (summary.includes('dos burst')) {
    return {
      why: `${details.packet_count ?? 'A high number of'} packets from one source reached the same destination during a ${details.window_seconds ?? 5}-second window.`,
      suggestions: ['Confirm whether the traffic volume affected service availability.', 'Consider rate limits and firewall rules for repeated requests.', 'Check whether the source is a trusted scanner or load test.'],
    };
  }
  if (summary.includes('arp spoof')) {
    return { why: details.evidence || 'The backend marked this event as possible ARP spoofing.', suggestions: ['Verify the gateway IP-to-MAC mapping against a trusted source.', 'Investigate or isolate the suspicious host if the mapping is unexpected.'] };
  }
  if (summary.includes('dns hijack')) {
    return { why: details.evidence || 'The backend marked this event as possible DNS hijacking.', suggestions: ['Verify configured resolver settings.', 'Compare DNS responses with a trusted resolver before changing network rules.'] };
  }
  if (summary.includes('rogue dhcp') || summary.includes('dhcp attack')) {
    return { why: details.evidence || 'The backend marked this event as possible rogue DHCP activity.', suggestions: ['Check that DHCP replies come from authorized servers.', 'Investigate the responding host and isolate it if it is unauthorized.'] };
  }
  if (summary.includes('directory scan')) {
    return { why: details.evidence || 'The backend marked repeated path requests as possible directory scanning.', suggestions: ['Review request rate and affected paths in server logs.', 'Consider rate limits and access controls for exposed routes.'] };
  }
  return null;
}

function addProtocolContext(event, details) {
  const protocol = String(event.protocol || '').toUpperCase();
  const summary = String(event.summary || '').toLowerCase();
  const section = modalSection('Protocol context');
  const list = document.createElement('dl');
  list.className = 'detail-list modal-detail-list';
  if (protocol === 'TCP' && summary.includes('handshake')) {
    list.append(
      addDetailRow('Handshake type', details.handshake_type || 'TCP three-way handshake'),
      addDetailRow('Completed successfully', details.completed === false ? 'No' : 'Yes'),
    );
    addSectionNote(section, 'The event groups the SYN, SYN-ACK, and final ACK packets for this connection.');
  } else if (protocol === 'DNS') {
    const listData = [
      ['Requested domain', details.domain_name || 'Not available in parsed packet metadata'],
      ['Source IP / port', event.source],
      ['Destination DNS server', event.destination],
      ['Response IP', details.response_ip || 'Not available in parsed packet metadata'],
    ];
    for (const [label, value] of listData) list.append(addDetailRow(label, value));
    addSectionNote(section, details.match_basis || 'The backend grouped the DNS exchange from packet endpoint metadata.');
  } else if (protocol === 'HTTP') {
    const httpFields = [
      ['HTTP method', details.method || details.request_method || 'Not available in parsed packet metadata'],
      ['Request path', details.path || details.request_path || 'Not available in parsed packet metadata'],
      ['Request summary', details.request_summary || 'Not available in parsed packet metadata'],
      ['Response status', details.response_status || details.status_code || 'Not available in parsed packet metadata'],
      ['Response summary', details.response_summary || 'Not available in parsed packet metadata'],
    ];
    for (const [label, value] of httpFields) list.append(addDetailRow(label, value));
    addSectionNote(section, details.basis || 'HTTP activity is inferred from TCP ports 80/8080; request and response payloads are not inspected.');
    addHttpMessage(section, 'Full request', details.request ?? details.http_request ?? details.request_text);
    addHttpMessage(section, 'Full response', details.response ?? details.http_response ?? details.response_text);
  } else {
    list.append(addDetailRow('Summary', event.summary));
    list.append(addDetailRow('Packets involved', formatPacketRange(packetNumbers(event))));
  }
  section.append(list);
  return section;
}

function openDetails(event, row) {
  closePacketPopovers();
  lastFocusedRow = row || document.activeElement;
  modalTitle.textContent = event.summary || 'Event details';
  modalContent.replaceChildren();
  const color = rowColor(event);
  const summaryBlock = document.createElement('div');
  summaryBlock.className = `detail-summary row-${color}`;
  const protocol = document.createElement('span');
  protocol.className = `protocol-badge protocol-${String(event.protocol || 'other').toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
  protocol.textContent = event.protocol || 'OTHER';
  const severity = document.createElement('span');
  const level = String(event.severity || 'info').toLowerCase();
  severity.className = `severity-badge severity-${safeClass(level, ['info', 'low', 'medium', 'high'])}`;
  severity.textContent = `${level} severity`;
  const classification = document.createElement('span');
  const classValue = String(event.classification || 'needs review').toLowerCase();
  classification.className = `classification-badge classification-${safeClass(classValue.replaceAll(' ', '-'), ['likely-fault', 'possible-attack', 'needs-review'])}`;
  classification.textContent = classValue;
  summaryBlock.append(protocol, severity, classification);
  modalContent.append(summaryBlock);

  const details = event.details && typeof event.details === 'object' ? event.details : {};
  const mainSection = modalSection('Event overview');
  const mainDetails = document.createElement('dl');
  mainDetails.className = 'detail-list modal-detail-list';
  mainDetails.append(
    addDetailRow('Time', event.time),
    addDetailRow('Source', event.source),
    addDetailRow('Destination', event.destination),
    addDetailRow('Protocol', event.protocol),
    addDetailRow('Packet count', details.packet_count ?? packetNumbers(event).length),
    addDetailRow('Packet numbers', formatPacketRange(packetNumbers(event))),
  );
  mainSection.append(mainDetails);
  modalContent.append(mainSection, addProtocolContext(event, details));

  const explanation = event.explanation && typeof event.explanation === 'object' ? event.explanation : {};
  const section = modalSection('Finding explanation');
  for (const [label, value] of [
    ['What this means', explanation.what_this_means],
    ['Why it was flagged', explanation.why_it_was_flagged],
    ...(explanation.suspicious_reason ? [['Why this may be suspicious', explanation.suspicious_reason]] : []),
    ...(explanation.detection_assessment ? [['Detection assessment', explanation.detection_assessment]] : []),
    ...(explanation.likely_cause ? [['Likely cause', explanation.likely_cause]] : []),
    ...(explanation.troubleshooting_step ? [['Troubleshooting step', explanation.troubleshooting_step]] : []),
    ...(explanation.immediate_action ? [['Immediate action', explanation.immediate_action]] : []),
  ]) {
    if (value) {
      const block = document.createElement('div');
      block.className = 'explanation-item';
      const title = document.createElement('h4');
      title.textContent = label;
      const text = document.createElement('p');
      text.textContent = value;
      block.append(title, text);
      section.append(block);
    }
  }
  const suggestionsData = explanation.suggested_response || detectionAssessment(event)?.suggestions || [];
  if (suggestionsData.length) {
    const suggestionTitle = document.createElement('h4');
    suggestionTitle.className = 'suggestion-title';
    suggestionTitle.textContent = 'Suggested response';
    const suggestions = document.createElement('ul');
    suggestions.className = 'suggestion-list';
    for (const suggestion of suggestionsData) {
      const item = document.createElement('li');
      item.textContent = suggestion;
      suggestions.append(item);
    }
    section.append(suggestionTitle, suggestions);
  }
  modalContent.append(section);

  const detailEntries = Object.entries(details).filter(([key]) => !['packet_numbers', 'packet_count', 'time_bucket'].includes(key));
  if (detailEntries.length) {
    const section = modalSection(Number(details.packet_count) > 1 ? 'Grouped packet context' : 'Packet context');
    const detailList = document.createElement('dl');
    detailList.className = 'detail-list modal-detail-list';
    for (const [key, value] of detailEntries) {
      const label = key.replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());
      detailList.append(addDetailRow(label, value));
    }
    section.append(detailList);
    modalContent.append(section);
  }
  modalBackdrop.hidden = false;
  document.body.classList.add('modal-open');
  document.querySelector('#close-modal').focus();
}

function closeDetails() {
  modalBackdrop.hidden = true;
  document.body.classList.remove('modal-open');
  if (lastFocusedRow?.isConnected) lastFocusedRow.focus();
}

function displayResults(payload, fallbackName) {
  if (!payload || !Array.isArray(payload.events)) throw new Error('The API response did not include an events array.');
  currentEvents = payload.events;
  populateProtocolFilter(currentEvents);
  const capture = payload.capture || {};
  document.querySelector('#capture-name').textContent = capture.filename || fallbackName || 'Analysis results';
  const packetCount = capture.packet_count;
  const skippedCount = capture.skipped_packet_count;
  const metadata = [];
  if (Number.isFinite(packetCount)) metadata.push(`${packetCount.toLocaleString()} packets`);
  if (Number.isFinite(skippedCount) && skippedCount > 0) metadata.push(`${skippedCount.toLocaleString()} skipped`);
  document.querySelector('#capture-meta').textContent = metadata.join(' · ') || `${payload.event_count ?? currentEvents.length} events returned`;
  resultsSection.hidden = false;
  emptyState.hidden = true;
  clearButton.hidden = false;
  searchInput.value = '';
  sourceFilter.value = '';
  destinationFilter.value = '';
  timeFromFilter.value = '';
  timeToFilter.value = '';
  protocolFilter.value = 'all';
  severityFilter.value = 'all';
  renderRows();
  const behavior = window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth';
  resultsSection.scrollIntoView({ behavior, block: 'start' });
}

async function requestJson(url, options = {}) {
  let response;
  try {
    response = await fetch(url, options);
  } catch {
    throw new Error(`Could not reach the backend at ${API_BASE}. Start the FastAPI server and try again.`);
  }
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`The API returned an unreadable response (HTTP ${response.status}).`);
  }
  if (!response.ok) {
    const detail = Array.isArray(payload.detail) ? payload.detail.map((item) => item.msg).join(', ') : payload.detail;
    throw new Error(detail || `Analysis failed (HTTP ${response.status}).`);
  }
  return payload;
}

async function loadDemo() {
  if (isLoading) return;
  inlineAlert.hidden = true;
  setLoading(true, 'Loading demo events from the local API…');
  try {
    const payload = await requestJson(`${API_BASE}/api/events/demo`);
    displayResults(payload, 'Demo capture');
  } catch (error) {
    showError(error.message);
  } finally {
    setLoading(false);
  }
}

async function analyzeFile(file) {
  if (!file || isLoading) return;
  inlineAlert.hidden = true;
  const extension = file.name.split('.').pop().toLowerCase();
  if (!['pcap', 'pcapng', 'cap'].includes(extension)) {
    showError('Choose a PCAP, PCAPNG, or CAP packet capture file.');
    return;
  }
  if (file.size > 100 * 1024 * 1024) {
    showError('This file is larger than the backend limit of 100 MiB.');
    return;
  }
  if (!file.size) {
    showError('This file is empty. Choose another packet capture.');
    return;
  }

  setLoading(true, `Uploading ${file.name}…`);
  const formData = new FormData();
  formData.append('file', file);
  try {
    const payload = await requestJson(`${API_BASE}/api/pcap/analyze`, { method: 'POST', body: formData });
    displayResults(payload, file.name);
  } catch (error) {
    showError(error.message);
  } finally {
    setLoading(false);
    fileInput.value = '';
  }
}

function clearResults() {
  currentEvents = [];
  visibleEvents = [];
  resultsSection.hidden = true;
  emptyState.hidden = false;
  clearButton.hidden = true;
  eventsBody.replaceChildren();
  resetFilters();
  closeDetails();
}

browseButton.addEventListener('click', (event) => { event.stopPropagation(); if (!isLoading) fileInput.click(); });
fileInput.addEventListener('change', () => analyzeFile(fileInput.files?.[0]));
demoButton.addEventListener('click', loadDemo);
clearButton.addEventListener('click', clearResults);
searchInput.addEventListener('input', renderRows);
severityFilter.addEventListener('change', renderRows);
protocolFilter.addEventListener('change', renderRows);
sourceFilter.addEventListener('input', renderRows);
destinationFilter.addEventListener('input', renderRows);
timeFromFilter.addEventListener('input', renderRows);
timeToFilter.addEventListener('input', renderRows);
exportButton.addEventListener('click', exportVisibleEvents);
resetFiltersButton.addEventListener('click', resetFilters);
document.querySelector('#close-modal').addEventListener('click', closeDetails);
modalBackdrop.addEventListener('click', (event) => { if (event.target === modalBackdrop && !modal.contains(event.target)) closeDetails(); });
document.addEventListener('pointerdown', (event) => {
  const host = event.target instanceof Element ? event.target.closest('.packet-popover-host') : null;
  closePacketPopovers(host);
});
document.addEventListener('keydown', (event) => {
  if (event.key !== 'Escape') return;
  if (!modalBackdrop.hidden) closeDetails();
  else closePacketPopovers();
});

dropzone.addEventListener('click', (event) => {
  if (event.target.closest('button') || isLoading) return;
  fileInput.click();
});
dropzone.addEventListener('keydown', (event) => {
  if (event.target !== dropzone || (event.key !== 'Enter' && event.key !== ' ')) return;
  event.preventDefault();
  if (!isLoading) fileInput.click();
});
dropzone.addEventListener('dragenter', (event) => { event.preventDefault(); if (!isLoading) dropzone.classList.add('is-dragging'); });
dropzone.addEventListener('dragover', (event) => { event.preventDefault(); if (!isLoading) dropzone.classList.add('is-dragging'); });
dropzone.addEventListener('dragleave', (event) => {
  if (!dropzone.contains(event.relatedTarget)) dropzone.classList.remove('is-dragging');
});
dropzone.addEventListener('drop', (event) => {
  event.preventDefault();
  dropzone.classList.remove('is-dragging');
  if (!isLoading) analyzeFile(event.dataTransfer?.files?.[0]);
});

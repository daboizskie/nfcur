'use strict';
/* ═══════════════════════════════════════════════════════════════
   NFCUR — NFC Universal Reader & Non-Destructive Editor
   app.js — complete client-side engine
═══════════════════════════════════════════════════════════════ */

// ── State ─────────────────────────────────────────────────────
const state = {
  currentScan: null,       // { uid, records: NDEFRecord[], raw: bytes, timestamp }
  editRecords: [],         // cloned records for edit
  backupRecords: [],       // pre-edit snapshot for restore
  nfcReader: null,
  abortController: null,
  scanActive: false,
  darkMode: false,
  history: [],             // loaded from localStorage
};

// ── DOM helpers ───────────────────────────────────────────────
const $ = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => [...ctx.querySelectorAll(sel)];
const el = id => document.getElementById(id);

// ── Boot ──────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initTabs();
  initCopyButtons();
  initNFC();
  initInspector();
  initEditor();
  initHistory();
  handleLaunchParams();
  renderHistory();
});

// ══════════════════════════════════════════════════════════════
// THEME
// ══════════════════════════════════════════════════════════════
function initTheme() {
  try {
    const saved = localStorage.getItem('nfcur-theme');
    if (saved) applyTheme(saved);
  } catch (_) {}

  el('theme-toggle').addEventListener('click', () => {
    const current = document.documentElement.getAttribute('data-theme');
    applyTheme(current === 'dark' ? 'light' : 'dark');
  });
}

function applyTheme(mode) {
  document.documentElement.setAttribute('data-theme', mode);
  state.darkMode = mode === 'dark';
  try { localStorage.setItem('nfcur-theme', mode); } catch (_) {}
}

// ══════════════════════════════════════════════════════════════
// TABS
// ══════════════════════════════════════════════════════════════
function initTabs() {
  $$('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      $$('.tab').forEach(t => { t.classList.remove('active'); t.setAttribute('aria-selected', 'false'); });
      $$('.tab-panel').forEach(p => p.hidden = true);
      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');
      const panel = el('tab-' + btn.dataset.tab);
      if (panel) panel.hidden = false;
    });
  });
}

// ══════════════════════════════════════════════════════════════
// COPY BUTTONS
// ══════════════════════════════════════════════════════════════
function initCopyButtons() {
  document.addEventListener('click', e => {
    const btn = e.target.closest('[data-copy-id]');
    if (!btn) return;
    const target = el(btn.dataset.copyId);
    if (!target) return;
    copyText(target.textContent.trim(), btn);
  });
}

function copyText(text, btn) {
  if (!text || text === '—') return;
  try {
    navigator.clipboard.writeText(text).then(() => flashCopied(btn)).catch(() => fallbackCopy(text, btn));
  } catch (_) {
    fallbackCopy(text, btn);
  }
}

function fallbackCopy(text, btn) {
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.cssText = 'position:fixed;top:-9999px;left:-9999px;opacity:0';
    document.body.appendChild(ta);
    ta.focus(); ta.select();
    document.execCommand('copy');
    ta.remove();
    flashCopied(btn);
  } catch (_) {}
}

function flashCopied(btn) {
  if (!btn) return;
  const orig = btn.textContent;
  btn.textContent = '✓';
  btn.classList.add('copied');
  setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 1500);
}

// ══════════════════════════════════════════════════════════════
// MANUFACTURER & UID UTILS
// ══════════════════════════════════════════════════════════════
const MFR_MAP = {
  '04': 'NXP Semiconductors',
  '02': 'STMicroelectronics',
  '05': 'Infineon Technologies',
  '07': 'Texas Instruments',
  '08': 'Fujitsu',
  '16': 'Sony',
  '1B': 'Broadcom',
  '28': 'Renesas',
  '38': 'Samsung',
  '3E': 'Motorola',
  '56': 'EM Microelectronic',
  'E0': 'NXP (ISO 15693)',
};

const CHIP_MAP = {
  4: 'MIFARE Classic / MIFARE Mini',
  7: 'NTAG / MIFARE Ultralight / DESFire',
  10: 'Triple UID Extended',
};

function decodeUID(raw) {
  if (!raw) return null;
  const clean = raw.replace(/[:\s-]/g, '').toUpperCase();
  const bytes = clean.match(/.{2}/g) || [];
  const fb = bytes[0] || '00';
  const reversed = [...bytes].reverse().join('');
  let decBE = 0n, decLE = 0n;
  try { decBE = BigInt('0x' + clean); } catch (_) {}
  try { decLE = BigInt('0x' + reversed); } catch (_) {}
  return {
    raw: clean,
    colonSep: bytes.join(':'),
    reversed,
    decBE: decBE.toString(),
    decLE: decLE.toString(),
    byteLen: bytes.length,
    manufacturer: MFR_MAP[fb] || `Unknown (0x${fb})`,
    chipType: CHIP_MAP[bytes.length] || `Unknown (${bytes.length}-byte UID)`,
    firstByte: `0x${fb}`,
  };
}

// ══════════════════════════════════════════════════════════════
// NDEF RECORD PARSING (client-side)
// ══════════════════════════════════════════════════════════════
const URI_PREFIXES = [
  '', 'http://www.', 'https://www.', 'http://', 'https://',
  'tel:', 'mailto:', 'ftp://anonymous:anonymous@', 'ftp://ftp.',
  'ftps://', 'sftp://', 'smb://', 'nfs://', 'ftp://', 'dav://',
  'news:', 'telnet://', 'imap:', 'rtsp://', 'urn:', 'pop:',
  'sip:', 'sips:', 'tftp:', 'btspp://', 'btl2cap://', 'btgoep://',
  'tcpobex://', 'irdaobex://', 'file://', 'urn:epc:id:', 'urn:epc:tag:',
  'urn:epc:pat:', 'urn:epc:raw:', 'urn:epc:', 'urn:nfc:',
];

function parseRecord(rec) {
  /* rec is an NDEFRecord from the Web NFC API */
  const result = {
    recordType: rec.recordType,
    mediaType: rec.mediaType || '',
    id: rec.id || '',
    encoding: rec.encoding || '',
    lang: rec.lang || '',
    raw: rec.data ? new Uint8Array(rec.data.buffer || rec.data) : new Uint8Array(0),
    parsed: null,
  };
  result.hexDump = toHexDump(result.raw);
  result.base64 = uint8ToBase64(result.raw);
  result.payloadHex = Array.from(result.raw).map(b => b.toString(16).padStart(2,'0').toUpperCase()).join('');
  result.ascii = Array.from(result.raw).map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('');
  result.byteSize = result.raw.length;

  try {
    if (rec.recordType === 'text') {
      const decoded = rec.toText ? rec.toText() : decodeTextRecord(result.raw);
      result.parsed = { kind: 'text', text: decoded, lang: rec.lang || '' };
    } else if (rec.recordType === 'url' || rec.recordType === 'absolute-url') {
      const url = rec.toURL ? rec.toURL() : decodeURLRecord(result.raw);
      result.parsed = { kind: 'url', url };
    } else if (rec.recordType === 'smart-poster') {
      result.parsed = parseSmartPoster(result.raw);
    } else if (rec.mediaType === 'text/vcard' || rec.mediaType === 'text/x-vcard') {
      const text = new TextDecoder().decode(result.raw);
      result.parsed = parseVCard(text);
    } else if (rec.mediaType === 'application/vnd.wfa.wsc') {
      result.parsed = parseWiFi(result.raw);
    } else if (rec.mediaType === 'application/json') {
      const text = new TextDecoder().decode(result.raw);
      result.parsed = { kind: 'json', data: JSON.parse(text) };
    } else if (rec.recordType === 'mime') {
      const text = new TextDecoder('utf-8', { fatal: false }).decode(result.raw);
      if (rec.mediaType && rec.mediaType.includes('json')) {
        try { result.parsed = { kind: 'json', data: JSON.parse(text) }; } catch (_) {}
      } else if (rec.mediaType && rec.mediaType.includes('vcard')) {
        result.parsed = parseVCard(text);
      } else {
        result.parsed = { kind: 'text', text, lang: '' };
      }
    }
  } catch (_) {}

  return result;
}

function decodeTextRecord(bytes) {
  if (!bytes.length) return '';
  const status = bytes[0];
  const langLen = status & 0x3F;
  const isUTF16 = (status >> 7) & 1;
  const enc = isUTF16 ? 'utf-16' : 'utf-8';
  const textBytes = bytes.slice(1 + langLen);
  return new TextDecoder(enc).decode(textBytes);
}

function decodeURLRecord(bytes) {
  if (!bytes.length) return '';
  const prefix = URI_PREFIXES[bytes[0]] || '';
  const suffix = new TextDecoder().decode(bytes.slice(1));
  return prefix + suffix;
}

function parseSmartPoster(bytes) {
  // Minimal Smart Poster: parse inner NDEF message
  const result = { kind: 'smart-poster', title: '', uri: '', action: '' };
  try {
    let i = 0;
    while (i < bytes.length) {
      const flags = bytes[i]; i++;
      const me = (flags >> 6) & 1;
      const sr = (flags >> 4) & 1;
      const il = (flags >> 3) & 1;
      const tnf = flags & 0x07;
      const typeLen = bytes[i]; i++;
      const payLen = sr ? bytes[i++] : ((bytes[i]<<24)|(bytes[i+1]<<16)|(bytes[i+2]<<8)|bytes[i+3]) + (i+=4,0);
      const idLen = il ? bytes[i++] : 0;
      const type = String.fromCharCode(...bytes.slice(i, i+typeLen)); i+=typeLen+idLen;
      const payload = bytes.slice(i, i+payLen); i+=payLen;
      if (tnf===1 && type==='T') result.title = decodeTextRecord(payload);
      if (tnf===1 && type==='U') result.uri = decodeURLRecord(payload);
      if (tnf===1 && type==='act') result.action = payload[0]===0?'Open':payload[0]===1?'Save':'Edit';
      if (me) break;
    }
  } catch (_) {}
  return result;
}

function parseVCard(text) {
  const fields = { kind: 'vcard', name: '', phone: '', email: '', org: '', address: '', url: '', note: '' };
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const col = line.indexOf(':');
    if (col < 0) continue;
    const key = line.slice(0, col).toUpperCase().split(';')[0];
    const val = line.slice(col + 1).trim();
    if (key === 'FN' || key === 'N') fields.name = fields.name || val.replace(/;/g, ' ').trim();
    else if (key === 'TEL') fields.phone = fields.phone || val;
    else if (key === 'EMAIL') fields.email = fields.email || val;
    else if (key === 'ORG') fields.org = val;
    else if (key === 'ADR') fields.address = val.replace(/;/g, ', ').trim();
    else if (key === 'URL') fields.url = val;
    else if (key === 'NOTE') fields.note = val;
  }
  return fields;
}

function parseWiFi(bytes) {
  // WPS/WSC TLV minimal parser
  const result = { kind: 'wifi', ssid: '', authType: '', password: '' };
  const AUTH_TYPES = { 0x0001: 'Open', 0x0002: 'WPA-Personal', 0x0004: 'Shared', 0x0008: 'WPA-Enterprise', 0x0010: 'WPA2-Enterprise', 0x0020: 'WPA2-Personal' };
  let i = 0;
  try {
    while (i + 4 <= bytes.length) {
      const attr = (bytes[i] << 8) | bytes[i+1];
      const len = (bytes[i+2] << 8) | bytes[i+3];
      i += 4;
      const val = bytes.slice(i, i+len); i += len;
      if (attr === 0x1045) result.ssid = new TextDecoder().decode(val);
      else if (attr === 0x1003) result.authType = AUTH_TYPES[(val[0]<<8)|val[1]] || 'Unknown';
      else if (attr === 0x1027) result.password = new TextDecoder().decode(val);
    }
  } catch (_) {}
  return result;
}

// ══════════════════════════════════════════════════════════════
// HEX DUMP HELPERS
// ══════════════════════════════════════════════════════════════
function toHexDump(bytes) {
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i+16);
    const hex = Array.from(chunk).map(b=>b.toString(16).padStart(2,'0').toUpperCase()).join(' ');
    const ascii = Array.from(chunk).map(b=>b>=32&&b<127?String.fromCharCode(b):'.').join('');
    lines.push({ offset: i.toString(16).padStart(4,'0').toUpperCase(), hex, ascii });
  }
  return lines;
}

function uint8ToBase64(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function totalPayloadBytes(records) {
  return records.reduce((sum, r) => sum + (r.raw ? r.raw.length : (r.payloadBytes ? r.payloadBytes.length : 0)), 0);
}

// ══════════════════════════════════════════════════════════════
// WEB NFC — SCAN ENGINE
// ══════════════════════════════════════════════════════════════
function initNFC() {
  const btnScan = el('btn-scan');
  const btnStop = el('btn-stop-scan');

  if (!('NDEFReader' in window)) {
    el('nfc-unavailable-notice').hidden = false;
    btnScan.disabled = true;
    btnScan.title = 'Web NFC not supported in this browser';
    setHWBadge('unavailable');
    return;
  }

  btnScan.addEventListener('click', startScan);
  btnStop.addEventListener('click', stopScan);
}

async function startScan() {
  if (state.scanActive) return;
  state.scanActive = true;
  state.abortController = new AbortController();
  state.nfcReader = new NDEFReader();

  setScanStatus('scanning', 'Bring tag close…');
  setHWBadge('scanning');
  el('btn-scan').hidden = true;
  el('btn-stop-scan').hidden = false;

  try {
    await state.nfcReader.scan({ signal: state.abortController.signal });

    state.nfcReader.addEventListener('reading', e => {
      onTagRead(e);
      if (!el('chk-continuous').checked) stopScan();
    });

    state.nfcReader.addEventListener('readingerror', () => {
      setScanStatus('error', 'Read error — try again');
      setHWBadge('error');
    });

  } catch (err) {
    setScanStatus('error', 'Scan failed: ' + friendlyNFCError(err));
    setHWBadge('error');
    resetScanUI();
  }
}

function stopScan() {
  if (state.abortController) {
    try { state.abortController.abort(); } catch (_) {}
  }
  state.scanActive = false;
  state.nfcReader = null;
  setScanStatus('idle', 'Ready to scan');
  setHWBadge('idle');
  resetScanUI();
}

function resetScanUI() {
  el('btn-scan').hidden = false;
  el('btn-stop-scan').hidden = true;
}

function onTagRead(e) {
  setScanStatus('detected', 'Tag detected!');
  setHWBadge('active');

  const uid = e.serialNumber || '';
  const uidInfo = decodeUID(uid);
  const records = [];
  let totalBytes = 0;

  for (const rec of e.message.records) {
    const parsed = parseRecord(rec);
    records.push(parsed);
    totalBytes += parsed.byteSize;
  }

  const scan = {
    uid,
    uidInfo,
    records,
    totalBytes,
    timestamp: new Date().toISOString(),
    writable: true, // assume writable; caught on write
    rawMessage: e.message,
  };

  state.currentScan = scan;
  state.editRecords = deepCloneRecords(records);
  state.backupRecords = deepCloneRecords(records);

  renderScanResult(scan);
  addToHistory(scan);
  updateEditor(scan);
}

function setScanStatus(type, text) {
  const ring = el('pulse-ring');
  const statusText = el('scan-status-text');
  ring.className = 'pulse-ring ' + (type === 'idle' ? '' : type);
  statusText.textContent = text;
}

function setHWBadge(state) {
  const badge = el('hw-badge');
  const map = {
    idle:        ['badge--idle',     '● Idle'],
    scanning:    ['badge--scanning', '◉ Scanning'],
    active:      ['badge--active',   '✓ Tag Detected'],
    error:       ['badge--error',    '✕ Error'],
    unavailable: ['badge--warn',     '⚠ Unavailable'],
  };
  const [cls, text] = map[state] || map.idle;
  badge.className = 'badge ' + cls;
  badge.textContent = text;
}

function friendlyNFCError(err) {
  if (err.name === 'NotAllowedError') return 'Permission denied — allow NFC in browser settings';
  if (err.name === 'NotSupportedError') return 'NFC not supported on this device';
  if (err.name === 'NetworkError') return 'Tag moved too fast — hold still';
  return err.message || err.name || 'Unknown error';
}

// ══════════════════════════════════════════════════════════════
// RENDER SCAN RESULT
// ══════════════════════════════════════════════════════════════
function renderScanResult(scan) {
  el('empty-state').hidden = true;

  // Telemetry bar
  const tb = el('telemetry-bar');
  tb.hidden = false;
  el('t-uid').textContent   = scan.uidInfo ? scan.uidInfo.colonSep || '—' : scan.uid || '—';
  el('t-mfr').textContent   = scan.uidInfo ? scan.uidInfo.manufacturer : '—';
  el('t-chip').textContent  = scan.uidInfo ? scan.uidInfo.chipType : '—';
  el('t-recs').textContent  = scan.records.length;
  el('t-bytes').textContent = scan.totalBytes;
  el('t-writable').textContent = scan.writable ? 'Yes' : 'Read-only';
  el('t-time').textContent  = new Date(scan.timestamp).toLocaleTimeString();

  // Export buttons
  el('btn-export-json').onclick = () => exportJSON(scan);
  el('btn-export-txt').onclick  = () => exportTXT(scan);

  // UID card
  if (scan.uidInfo) {
    const u = scan.uidInfo;
    el('uid-card').hidden = false;
    el('uid-colon').textContent  = u.colonSep || '—';
    el('uid-raw').textContent    = u.raw || '—';
    el('uid-rev').textContent    = u.reversed || '—';
    el('uid-dec-be').textContent = u.decBE || '—';
    el('uid-dec-le').textContent = u.decLE || '—';
    el('uid-len').textContent    = u.byteLen + ' bytes';
    el('uid-mfr').textContent    = u.manufacturer;
    el('uid-chip').textContent   = u.chipType;
  }

  // Records
  const container = el('records-container');
  container.innerHTML = '';
  if (scan.records.length === 0) {
    container.innerHTML = `
      <div class="card">
        <p style="color:var(--fg-mid);font-size:13px;margin:0">
          This tag has <strong>no NDEF records</strong> (proprietary / locked / blank tag).
          UID telemetry above is complete.
        </p>
      </div>`;
  } else {
    scan.records.forEach((rec, i) => {
      container.appendChild(buildRecordCard(rec, i));
    });
  }
}

function buildRecordCard(rec, index) {
  const card = document.createElement('div');
  card.className = 'record-card';

  // Header
  const header = document.createElement('div');
  header.className = 'record-header';
  header.innerHTML = `
    <div class="record-meta">
      <span class="record-num">REC ${index + 1}</span>
      <span class="tnf-badge">${escHtml(tnfName(rec.recordType))}</span>
      <span class="type-label">${escHtml(rec.recordType)}${rec.mediaType ? ' · ' + rec.mediaType : ''}</span>
      ${rec.id ? `<span class="type-label">id: ${escHtml(rec.id)}</span>` : ''}
      ${rec.lang ? `<span class="lang-badge">${escHtml(rec.lang)}</span>` : ''}
    </div>
    <div class="record-view-toggle">
      <button class="view-btn active" data-view="smart">Smart</button>
      <button class="view-btn" data-view="raw">Raw</button>
      <button class="view-btn" data-view="hex">Hex</button>
    </div>`;
  card.appendChild(header);

  // Body container
  const body = document.createElement('div');
  body.className = 'record-body';
  card.appendChild(body);

  // Views
  const smartView = buildSmartView(rec);
  const rawView = buildRawView(rec);
  const hexView = buildHexView(rec);

  rawView.hidden = true;
  hexView.hidden = true;
  body.appendChild(smartView);
  body.appendChild(rawView);
  body.appendChild(hexView);

  // Toggle logic
  header.querySelectorAll('.view-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      header.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      smartView.hidden = btn.dataset.view !== 'smart';
      rawView.hidden   = btn.dataset.view !== 'raw';
      hexView.hidden   = btn.dataset.view !== 'hex';
    });
  });

  return card;
}

function tnfName(recordType) {
  const map = {
    'text': 'Well-Known', 'url': 'Well-Known', 'absolute-url': 'Absolute URL',
    'smart-poster': 'Well-Known', 'mime': 'MIME', 'unknown': 'Unknown',
    'empty': 'Empty', 'local': 'Local',
  };
  return map[recordType] || recordType;
}

function buildSmartView(rec) {
  const div = document.createElement('div');
  div.className = 'parsed-view';
  const p = rec.parsed;

  if (!p) {
    div.innerHTML = `<p style="color:var(--fg-mid);font-size:13px;margin:0">No auto-parser for this record type. Use the Raw or Hex view.</p>`;
    return div;
  }

  if (p.kind === 'text') {
    div.innerHTML = `
      <div class="pv-field">
        <span class="pv-label">Text Content</span>
        <span class="pv-value">${p.lang ? `<span class="lang-badge">${escHtml(p.lang)}</span>` : ''}${escHtml(p.text)}</span>
      </div>`;
  } else if (p.kind === 'url') {
    const safe = isSafeURL(p.url);
    div.innerHTML = `
      <div class="pv-field">
        <span class="pv-label">URL</span>
        <a class="pv-value pv-url" href="${escAttr(p.url)}" target="_blank" rel="noopener noreferrer">${escHtml(p.url)}</a>
      </div>
      ${safe ? '' : '<div class="notice notice--warn">⚠ This URL contains unusual characters or an uncommon scheme.</div>'}`;
  } else if (p.kind === 'smart-poster') {
    div.innerHTML = `
      <div class="pv-field"><span class="pv-label">Title</span><span class="pv-value">${escHtml(p.title)}</span></div>
      <div class="pv-field"><span class="pv-label">URI</span><a class="pv-value pv-url" href="${escAttr(p.uri)}" target="_blank" rel="noopener noreferrer">${escHtml(p.uri)}</a></div>
      ${p.action ? `<div class="pv-field"><span class="pv-label">Action</span><span class="pv-value">${escHtml(p.action)}</span></div>` : ''}`;
  } else if (p.kind === 'vcard') {
    div.innerHTML = `<div class="vcard-grid">
      ${vcardRow('Name', p.name)}${vcardRow('Phone', p.phone)}${vcardRow('Email', p.email)}
      ${vcardRow('Org', p.org)}${vcardRow('Address', p.address)}${vcardRow('URL', p.url)}
      ${vcardRow('Note', p.note)}
    </div>`;
  } else if (p.kind === 'wifi') {
    div.innerHTML = `<div class="wifi-fields">
      <div class="wifi-field"><span>SSID</span><strong>${escHtml(p.ssid)}</strong></div>
      <div class="wifi-field"><span>Auth Type</span><span>${escHtml(p.authType)}</span></div>
      <div class="wifi-field"><span>Password</span><span class="wifi-pass">${p.password ? escHtml(p.password) : '(hidden)'}</span></div>
    </div>`;
  } else if (p.kind === 'json') {
    div.innerHTML = `<pre class="json-tree">${escHtml(JSON.stringify(p.data, null, 2))}</pre>`;
  }

  return div;
}

function vcardRow(label, val) {
  if (!val) return '';
  return `<span class="vcard-key">${label}</span><span class="vcard-val">${escHtml(val)}</span>`;
}

function buildRawView(rec) {
  const div = document.createElement('div');
  div.className = 'raw-view';
  div.innerHTML = `
    <div class="raw-row"><span class="raw-label">Hex</span><span class="raw-value">${rec.payloadHex || '(empty)'}</span><button class="copy-micro" onclick="copyText(this.previousElementSibling.textContent,this)">⎘</button></div>
    <div class="raw-row"><span class="raw-label">Base64</span><span class="raw-value">${rec.base64 || ''}</span><button class="copy-micro" onclick="copyText(this.previousElementSibling.textContent,this)">⎘</button></div>
    <div class="raw-row"><span class="raw-label">ASCII</span><span class="raw-value">${escHtml(rec.ascii || '')}</span></div>
    <div class="raw-row"><span class="raw-label">Bytes</span><span class="raw-value">${rec.byteSize}</span></div>`;
  return div;
}

function buildHexView(rec) {
  const div = document.createElement('div');
  div.className = 'hex-view';
  if (!rec.hexDump || !rec.hexDump.length) {
    div.textContent = '(empty payload)';
    return div;
  }
  div.innerHTML = rec.hexDump.map(row =>
    `<div class="hex-row"><span class="hex-offset">${row.offset}</span><span class="hex-bytes">${escHtml(row.hex)}</span><span class="hex-ascii">${escHtml(row.ascii)}</span></div>`
  ).join('');
  return div;
}

function isSafeURL(url) {
  try {
    const u = new URL(url);
    return ['http:', 'https:', 'mailto:', 'tel:'].includes(u.protocol);
  } catch (_) { return false; }
}

// ══════════════════════════════════════════════════════════════
// INSPECTOR TAB
// ══════════════════════════════════════════════════════════════
function initInspector() {
  el('btn-decode-uid').addEventListener('click', () => {
    const uid = el('inp-uid').value.trim();
    if (!uid) return;
    renderInspectorUID(decodeUID(uid));
  });

  el('btn-decode-hex').addEventListener('click', () => {
    const hex = el('inp-hex').value.trim();
    if (!hex) return;
    const clean = hex.replace(/[\s:\-]/g, '');
    renderInspectorHex(parseHexBytes(clean));
  });

  el('btn-decode-server').addEventListener('click', async () => {
    const uid = el('inp-uid').value.trim();
    const hex = el('inp-hex').value.trim();
    if (!uid && !hex) return;
    try {
      const res = await fetch('/api/decode', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ uid: uid || undefined, hex: hex || undefined }),
      });
      const data = await res.json();
      renderServerInspector(data);
    } catch (err) {
      showInspectorError('Server decode failed: ' + err.message);
    }
  });
}

function parseHexBytes(hex) {
  const clean = hex.toUpperCase().replace(/[^0-9A-F]/g, '');
  const bytes = [];
  for (let i = 0; i < clean.length - 1; i += 2) {
    bytes.push(parseInt(clean.substr(i, 2), 16));
  }
  return new Uint8Array(bytes);
}

function renderInspectorUID(info) {
  if (!info) return;
  const result = el('inspector-result');
  result.hidden = false;
  result.innerHTML = `
    <div class="card">
      <h3 class="card-title">UID Decoded</h3>
      <div class="uid-grid">
        ${uidRow('Colon-Separated', info.colonSep)}
        ${uidRow('Raw Hex', info.raw)}
        ${uidRow('Reversed Hex', info.reversed)}
        ${uidRow('Decimal (BE)', info.decBE)}
        ${uidRow('Decimal (LE)', info.decLE)}
        ${uidRow('Byte Length', info.byteLen + ' bytes')}
        ${uidRow('Manufacturer', info.manufacturer)}
        ${uidRow('Chip Type', info.chipType)}
        ${uidRow('First Byte', info.firstByte)}
      </div>
    </div>`;
}

function uidRow(label, val) {
  return `<div class="uid-row"><span>${label}</span><code>${escHtml(String(val))}</code></div>`;
}

function renderInspectorHex(bytes) {
  const result = el('inspector-result');
  result.hidden = false;
  const dump = toHexDump(bytes);
  const b64 = uint8ToBase64(bytes);
  const ascii = Array.from(bytes).map(b=>b>=32&&b<127?String.fromCharCode(b):'.').join('');
  result.innerHTML = `
    <div class="card">
      <h3 class="card-title">Raw Hex Decoded</h3>
      <div class="raw-view">
        <div class="raw-row"><span class="raw-label">Bytes</span><span class="raw-value">${bytes.length}</span></div>
        <div class="raw-row"><span class="raw-label">Base64</span><span class="raw-value">${escHtml(b64)}</span></div>
        <div class="raw-row"><span class="raw-label">ASCII</span><span class="raw-value">${escHtml(ascii)}</span></div>
      </div>
    </div>
    <div class="card">
      <h3 class="card-title">Hex Dump</h3>
      <div class="hex-view">${dump.map(row=>`<div class="hex-row"><span class="hex-offset">${row.offset}</span><span class="hex-bytes">${escHtml(row.hex)}</span><span class="hex-ascii">${escHtml(row.ascii)}</span></div>`).join('')}</div>
    </div>`;
}

function renderServerInspector(data) {
  const result = el('inspector-result');
  result.hidden = false;
  let html = '';

  if (data.error) {
    html = `<div class="notice notice--error">${escHtml(data.error)}</div>`;
  }

  if (data.uid) {
    const u = data.uid;
    html += `<div class="card"><h3 class="card-title">UID (Server)</h3><div class="uid-grid">
      ${uidRow('Colon-Separated', u.colonSeparated)}
      ${uidRow('Raw Hex', u.rawHex)}
      ${uidRow('Reversed', u.reversedHex)}
      ${uidRow('Decimal BE', u.decimalBE)}
      ${uidRow('Decimal LE', u.decimalLE)}
      ${uidRow('Byte Length', u.byteLength)}
      ${uidRow('Manufacturer', u.manufacturer)}
      ${uidRow('Chip Type', u.chipType)}
    </div></div>`;
  }

  if (data.ndef) {
    const n = data.ndef;
    if (n.error) {
      html += `<div class="notice notice--error">${escHtml(n.error)}</div>`;
    } else {
      html += `<div class="card"><h3 class="card-title">NDEF (Server)</h3>
        <div class="raw-view">
          <div class="raw-row"><span class="raw-label">Bytes</span><span class="raw-value">${n.byteLength}</span></div>
          <div class="raw-row"><span class="raw-label">Base64</span><span class="raw-value">${escHtml(n.base64)}</span></div>
          <div class="raw-row"><span class="raw-label">ASCII</span><span class="raw-value">${escHtml(n.ascii)}</span></div>
        </div>
        ${n.ndefRecords && n.ndefRecords.length ? `
          <h4 style="margin:14px 0 10px;font-size:12px;color:var(--fg-mid);text-transform:uppercase;letter-spacing:.4px">NDEF Records</h4>
          ${n.ndefRecords.map((r,i) => `<div class="card" style="margin-bottom:8px">
            <div class="record-header" style="background:var(--bg-elevated);padding:10px 14px;margin:-1px -1px 12px;border-radius:var(--radius) var(--radius) 0 0">
              <span class="tnf-badge">${escHtml(r.tnfName)}</span>
              <span class="type-label">${escHtml(r.type)}</span>
            </div>
            ${r.parsed ? `<p class="pv-value" style="margin:0 0 8px">${r.parsed.text || r.parsed.url || ''}</p>` : ''}
            <div class="hex-view" style="max-height:120px;overflow-y:auto">${r.payloadHex}</div>
          </div>`).join('')}
        ` : ''}
      </div>`;
    }
  }

  result.innerHTML = html;
}

function showInspectorError(msg) {
  const result = el('inspector-result');
  result.hidden = false;
  result.innerHTML = `<div class="notice notice--error">${escHtml(msg)}</div>`;
}

// ══════════════════════════════════════════════════════════════
// EDIT TAB — NON-DESTRUCTIVE EDITOR
// ══════════════════════════════════════════════════════════════
function initEditor() {
  el('btn-add-record').addEventListener('click', () => {
    const type = el('add-type-select').value;
    addEditRecord(type);
  });

  el('btn-write').addEventListener('click', writeTag);
  el('btn-restore').addEventListener('click', restoreOriginal);
}

function updateEditor(scan) {
  el('edit-noscan').hidden = true;
  el('edit-workspace').hidden = false;
  el('write-uid-guard').textContent = scan.uidInfo ? scan.uidInfo.colonSep : scan.uid;
  renderEditRecords();
}

function renderEditRecords() {
  const list = el('edit-records-list');
  list.innerHTML = '';
  state.editRecords.forEach((rec, i) => {
    list.appendChild(buildEditRecord(rec, i));
  });
  updateByteCounter();
}

function buildEditRecord(rec, index) {
  const div = document.createElement('div');
  div.className = 'edit-record';
  div.dataset.index = index;

  const type = rec.recordType === 'text' ? 'text' : rec.recordType === 'url' ? 'url' : 'raw';
  const displayVal = rec.parsed ? (rec.parsed.text || rec.parsed.url || rec.parsed.ssid || '') : (rec.ascii || '');

  div.innerHTML = `
    <div class="edit-record-header">
      <span class="edit-record-label">Record ${index + 1} · <span class="tnf-badge" style="font-size:10px">${escHtml(rec.recordType)}</span></span>
      <div class="edit-record-actions">
        <button class="btn btn--sm btn--ghost" data-action="up" title="Move up">↑</button>
        <button class="btn btn--sm btn--ghost" data-action="down" title="Move down">↓</button>
        <button class="btn btn--sm btn--danger" data-action="remove" title="Remove">✕</button>
      </div>
    </div>
    <div class="edit-field">
      <label>Payload</label>
      <textarea class="rec-payload" rows="2" placeholder="Edit payload…">${escHtml(displayVal)}</textarea>
    </div>
    ${rec.recordType === 'text' ? `<div class="edit-field"><label>Language</label><input type="text" class="rec-lang" value="${escAttr(rec.lang || 'en')}" maxlength="8"></div>` : ''}
    <div class="edit-field"><label>Record ID (optional)</label><input type="text" class="rec-id" value="${escAttr(rec.id || '')}"></div>`;

  // Actions
  div.querySelectorAll('[data-action]').forEach(btn => {
    btn.addEventListener('click', () => {
      const i = parseInt(div.dataset.index);
      if (btn.dataset.action === 'up' && i > 0) {
        [state.editRecords[i-1], state.editRecords[i]] = [state.editRecords[i], state.editRecords[i-1]];
        renderEditRecords();
      } else if (btn.dataset.action === 'down' && i < state.editRecords.length-1) {
        [state.editRecords[i], state.editRecords[i+1]] = [state.editRecords[i+1], state.editRecords[i]];
        renderEditRecords();
      } else if (btn.dataset.action === 'remove') {
        state.editRecords.splice(i, 1);
        renderEditRecords();
      }
    });
  });

  // Live payload sync back to state
  div.querySelector('.rec-payload').addEventListener('input', e => {
    const i = parseInt(div.dataset.index);
    if (state.editRecords[i]) {
      state.editRecords[i]._pendingPayload = e.target.value;
      updateByteCounter();
    }
  });

  return div;
}

function addEditRecord(type) {
  const rec = {
    recordType: type === 'text' ? 'text' : type === 'url' ? 'url' : 'mime',
    mediaType: type === 'json' ? 'application/json' : type === 'raw' ? 'application/octet-stream' : '',
    id: '',
    lang: 'en',
    encoding: 'utf-8',
    raw: new Uint8Array(0),
    payloadHex: '',
    ascii: '',
    base64: '',
    byteSize: 0,
    hexDump: [],
    parsed: null,
    _pendingPayload: '',
    _isNew: true,
  };
  state.editRecords.push(rec);
  renderEditRecords();
}

function updateByteCounter() {
  const total = state.editRecords.reduce((sum, r) => {
    const pending = r._pendingPayload;
    if (pending !== undefined) return sum + new TextEncoder().encode(pending).length;
    return sum + (r.byteSize || 0);
  }, 0);
  const countEl = el('edit-byte-count');
  if (countEl) countEl.textContent = total;
  const warnEl = el('byte-warn');
  if (warnEl) warnEl.hidden = total < 700;
}

async function writeTag() {
  if (!state.currentScan) return;
  if (!('NDEFReader' in window)) {
    setWriteStatus('error', 'Web NFC not available in this browser');
    return;
  }

  setWriteStatus('info', 'Waiting — tap the same tag again…');

  // Build NDEFRecord list from edited state
  const records = buildNDEFRecords(state.editRecords);
  if (!records) {
    setWriteStatus('error', 'Failed to build records');
    return;
  }

  const writer = new NDEFReader();
  const abort = new AbortController();
  const targetUID = state.currentScan.uid;

  try {
    // Scan-then-write UID guard: verify UID before writing
    let verified = false;
    await writer.scan({ signal: abort.signal });

    writer.addEventListener('reading', async e => {
      if (e.serialNumber !== targetUID) {
        setWriteStatus('error', 'Different tag detected — write cancelled. Tap the original tag.');
        return;
      }
      verified = true;
      try {
        await writer.write({ records });
        abort.abort();
        setWriteStatus('ok', `✓ Written to tag ${targetUID}`);
        addToHistory({ ...state.currentScan, records: state.editRecords, timestamp: new Date().toISOString(), edited: true });
      } catch (err) {
        abort.abort();
        setWriteStatus('error', 'Write failed: ' + friendlyNFCError(err));
      }
    });

    // Auto-cancel after 15 s
    setTimeout(() => {
      if (!verified) {
        try { abort.abort(); } catch (_) {}
        setWriteStatus('error', 'Timed out waiting for tag');
      }
    }, 15000);

  } catch (err) {
    setWriteStatus('error', 'Write setup failed: ' + friendlyNFCError(err));
  }
}

function buildNDEFRecords(editRecs) {
  try {
    return editRecs.map(r => {
      const payload = r._pendingPayload !== undefined ? r._pendingPayload : (r.parsed ? (r.parsed.text || r.parsed.url || '') : r.ascii || '');
      if (r.recordType === 'text') {
        return { recordType: 'text', lang: r.lang || 'en', data: payload };
      } else if (r.recordType === 'url' || r.recordType === 'absolute-url') {
        return { recordType: 'url', data: payload };
      } else {
        const enc = new TextEncoder().encode(payload);
        return { recordType: 'mime', mediaType: r.mediaType || 'application/octet-stream', data: enc };
      }
    });
  } catch (_) {
    return null;
  }
}

function restoreOriginal() {
  if (!state.backupRecords.length) return;
  state.editRecords = deepCloneRecords(state.backupRecords);
  renderEditRecords();
  setWriteStatus('info', 'Restored to original — tap Write to apply.');
}

function setWriteStatus(type, msg) {
  const ws = el('write-status');
  ws.className = 'write-status ' + (type === 'ok' ? 'ok' : type === 'error' ? 'error' : '');
  ws.textContent = msg;
}

function deepCloneRecords(records) {
  return records.map(r => ({
    ...r,
    raw: r.raw ? new Uint8Array(r.raw) : new Uint8Array(0),
    parsed: r.parsed ? { ...r.parsed } : null,
    hexDump: r.hexDump ? [...r.hexDump] : [],
  }));
}

// ══════════════════════════════════════════════════════════════
// HISTORY
// ══════════════════════════════════════════════════════════════
function initHistory() {
  try {
    const saved = localStorage.getItem('nfcur-history');
    if (saved) state.history = JSON.parse(saved);
  } catch (_) {}

  el('btn-clear-history').addEventListener('click', () => {
    if (confirm('Clear all scan history?')) {
      state.history = [];
      saveHistory();
      renderHistory();
    }
  });

  el('history-search').addEventListener('input', e => {
    renderHistory(e.target.value.toLowerCase());
  });
}

function addToHistory(scan) {
  const entry = {
    uid: scan.uid,
    uidInfo: scan.uidInfo,
    timestamp: scan.timestamp,
    recordCount: scan.records ? scan.records.length : state.editRecords.length,
    totalBytes: scan.totalBytes,
    summary: buildScanSummary(scan),
    edited: scan.edited || false,
    fullRecords: JSON.stringify(deepCloneRecords(scan.records || state.editRecords).map(serializeRecord)),
  };
  state.history.unshift(entry);
  if (state.history.length > 100) state.history.pop();
  saveHistory();
  renderHistory();
}

function saveHistory() {
  try { localStorage.setItem('nfcur-history', JSON.stringify(state.history)); } catch (_) {}
}

function buildScanSummary(scan) {
  const recs = scan.records || [];
  if (!recs.length) return 'No NDEF records';
  const parts = recs.map(r => {
    if (r.parsed) {
      if (r.parsed.kind === 'text') return 'Text: ' + r.parsed.text.slice(0, 30);
      if (r.parsed.kind === 'url') return 'URL: ' + r.parsed.url.slice(0, 40);
      if (r.parsed.kind === 'vcard') return 'vCard: ' + r.parsed.name;
      if (r.parsed.kind === 'wifi') return 'WiFi: ' + r.parsed.ssid;
    }
    return r.recordType;
  });
  return parts.join(' | ');
}

function serializeRecord(r) {
  return {
    recordType: r.recordType,
    mediaType: r.mediaType,
    id: r.id,
    lang: r.lang,
    payloadHex: r.payloadHex,
    ascii: r.ascii,
    byteSize: r.byteSize,
    parsed: r.parsed,
  };
}

function renderHistory(filter = '') {
  const list = el('history-list');
  const empty = el('history-empty');
  list.innerHTML = '';

  const items = filter
    ? state.history.filter(h =>
        (h.uid && h.uid.toLowerCase().includes(filter)) ||
        (h.summary && h.summary.toLowerCase().includes(filter)))
    : state.history;

  if (!items.length) {
    empty.hidden = false;
    return;
  }
  empty.hidden = true;

  items.forEach((h, i) => {
    const div = document.createElement('div');
    div.className = 'history-item';
    div.innerHTML = `
      <div class="history-item-header">
        <span class="history-uid">${escHtml(h.uidInfo ? h.uidInfo.colonSep : h.uid || 'Unknown UID')}</span>
        <span class="history-time">${new Date(h.timestamp).toLocaleString()}${h.edited ? ' · edited' : ''}</span>
      </div>
      <div class="history-summary">${escHtml(h.summary || '')} · ${h.recordCount} record(s) · ${h.totalBytes} bytes</div>
      ${h.uidInfo ? `<div class="history-summary" style="color:var(--fg-muted)">${escHtml(h.uidInfo.manufacturer)} · ${escHtml(h.uidInfo.chipType)}</div>` : ''}`;
    list.appendChild(div);
  });
}

// ══════════════════════════════════════════════════════════════
// LAUNCH PARAMS (NFC tag → URL mode)
// ══════════════════════════════════════════════════════════════
function handleLaunchParams() {
  const lp = el('launch-params');
  if (!lp) return;
  const uid = lp.dataset.uid;
  const data = lp.dataset.data;
  const type = lp.dataset.type;
  const payload = lp.dataset.payload;

  // Also check hash/query string directly
  const params = new URLSearchParams(location.search);
  const qUid  = params.get('uid') || uid;
  const qData = params.get('data') || data;
  const qType = params.get('type') || type;
  const qPayload = params.get('payload') || payload;

  if (!qUid && !qData && !qPayload) return;

  // Build a synthetic scan object
  const uidInfo = qUid ? decodeUID(qUid) : null;
  const records = [];

  if (qData || qPayload) {
    const rawStr = qData || qPayload;
    const isHex = /^[0-9a-fA-F\s:]+$/.test(rawStr.replace(/\s/g, ''));
    let raw;
    try {
      raw = isHex ? parseHexBytes(rawStr.replace(/[\s:]/g,'')) : new TextEncoder().encode(rawStr);
    } catch (_) {
      raw = new TextEncoder().encode(rawStr);
    }
    // Determine record type from qType hint
    const rt = qType === 'text' ? 'text' : qType === 'url' ? 'url' : 'unknown';
    const fakeRec = {
      recordType: rt,
      mediaType: '',
      id: '',
      lang: '',
      encoding: 'utf-8',
      raw,
      payloadHex: Array.from(raw).map(b=>b.toString(16).padStart(2,'0').toUpperCase()).join(''),
      ascii: Array.from(raw).map(b=>b>=32&&b<127?String.fromCharCode(b):'.').join(''),
      base64: uint8ToBase64(raw),
      byteSize: raw.length,
      hexDump: toHexDump(raw),
      parsed: null,
    };
    // Try auto-parse
    if (rt === 'text') fakeRec.parsed = { kind: 'text', text: new TextDecoder().decode(raw), lang: '' };
    else if (rt === 'url') fakeRec.parsed = { kind: 'url', url: new TextDecoder().decode(raw) };
    else {
      // Try as plain text
      try { fakeRec.parsed = { kind: 'text', text: new TextDecoder('utf-8', {fatal:true}).decode(raw), lang: '' }; } catch (_) {}
    }
    records.push(fakeRec);
  }

  const scan = {
    uid: qUid,
    uidInfo,
    records,
    totalBytes: records.reduce((s,r)=>s+r.byteSize,0),
    timestamp: new Date().toISOString(),
    writable: false,
    isLaunch: true,
  };

  state.currentScan = scan;
  state.editRecords = deepCloneRecords(records);
  state.backupRecords = deepCloneRecords(records);

  renderScanResult(scan);
  updateEditor(scan);
  addToHistory(scan);

  // Show launch notice
  const notice = document.createElement('div');
  notice.className = 'notice notice--info';
  notice.innerHTML = `<strong>Tag-Launch Mode</strong> — Payload decoded from URL parameters.`;
  el('tab-read').prepend(notice);
}

// ══════════════════════════════════════════════════════════════
// EXPORT
// ══════════════════════════════════════════════════════════════
function exportJSON(scan) {
  const data = {
    uid: scan.uid,
    uidInfo: scan.uidInfo,
    timestamp: scan.timestamp,
    records: scan.records.map(serializeRecord),
  };
  downloadFile('nfcur-scan-' + Date.now() + '.json', JSON.stringify(data, null, 2), 'application/json');
}

function exportTXT(scan) {
  const lines = [
    'NFCUR Scan Report',
    '=================',
    `Timestamp: ${scan.timestamp}`,
    `UID: ${scan.uidInfo ? scan.uidInfo.colonSep : scan.uid}`,
    `Manufacturer: ${scan.uidInfo ? scan.uidInfo.manufacturer : '—'}`,
    `Chip: ${scan.uidInfo ? scan.uidInfo.chipType : '—'}`,
    `Records: ${scan.records.length}`,
    `Total Bytes: ${scan.totalBytes}`,
    '',
  ];
  scan.records.forEach((r, i) => {
    lines.push(`--- Record ${i+1} ---`);
    lines.push(`Type: ${r.recordType}`);
    if (r.mediaType) lines.push(`Media: ${r.mediaType}`);
    if (r.parsed) {
      if (r.parsed.text) lines.push(`Text: ${r.parsed.text}`);
      if (r.parsed.url) lines.push(`URL: ${r.parsed.url}`);
    }
    lines.push(`Hex: ${r.payloadHex}`);
    lines.push(`ASCII: ${r.ascii}`);
    lines.push('');
  });
  downloadFile('nfcur-scan-' + Date.now() + '.txt', lines.join('\n'), 'text/plain');
}

function downloadFile(name, content, type) {
  // Build data URL for download (data: URIs in <a> work for direct user interaction)
  const enc = new TextEncoder().encode(content);
  const b64 = uint8ToBase64(enc);
  const url = `data:${type};base64,${b64}`;
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.style.cssText = 'position:fixed;top:-9999px;left:-9999px';
  document.body.appendChild(a);
  a.click();
  setTimeout(() => a.remove(), 500);
}

// ══════════════════════════════════════════════════════════════
// HTML ESCAPE UTILS
// ══════════════════════════════════════════════════════════════
function escHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#039;');
}

function escAttr(str) {
  return escHtml(str);
}

// Expose copyText for inline onclick handlers in dynamically built HTML
window.copyText = copyText;

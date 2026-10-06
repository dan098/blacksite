(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const PROFILE_NAMES = { standard: 'Standard', interactive: 'Interattiva', trace: 'API e kernel', driver: 'Driver / BYOVD' };
  const STATUS_NAMES = {
    queued: 'In coda', static: 'Analisi statica', running: 'In esecuzione', reporting: 'Preparazione report', completed: 'Completata',
    failed: 'Errore', cancelled: 'Annullata', partial: 'Parziale', pending: 'In attesa', booting: 'Avvio VM',
    collecting: 'Raccolta', blocked: 'Bloccata', skipped: 'Non eseguita', available: 'Disponibile',
    unavailable: 'Non disponibile', error: 'Errore', timeout: 'Tempo esaurito', denied: 'Negata',
    verified: 'Verificato', unverified: 'Non verificato', unknown: 'Non verificato', not_run: 'Non eseguito',
    installed: 'Installato', configured: 'Configurato', ready: 'Pronto', disabled: 'Non attivo'
  };
  const ACTIVE = new Set(['queued', 'static', 'running', 'reporting', 'pending', 'booting', 'collecting']);
  const TABS = ['summary', 'timeline', 'processes', 'changes', 'network', 'static', 'api', 'drivers', 'detections', 'artifacts'];
  const SHARED_TABS = new Set(['summary', 'static', 'detections']);
  const state = {
    authenticated: false, shared: false, shareToken: '', job: null, jobs: [], jobId: '', run: '',
    tab: 'summary', routeVersion: 0, refreshBusy: false, eventSequence: 0, offset: 0, total: 0,
    maxUpload: 104857600, sample: null, capabilities: null, renderSignature: '', eventsSignature: '',
    lastAnnouncedStatus: '', route: '', filterQuery: '', filterCategory: '', eventsQuery: '', eventsPendingQuery: '', runtimeBusy: false
  };

  function node(tag, text, className) {
    const el = document.createElement(tag);
    if (text !== undefined && text !== null) el.textContent = textOf(text);
    if (className) el.className = className;
    return el;
  }
  function textOf(value) {
    if (value === undefined || value === null) return 'Non disponibile';
    if (typeof value === 'object') {
      try { return JSON.stringify(value, null, 2); } catch (_) { return 'Dato non leggibile'; }
    }
    return String(value);
  }
  function array(value) { return Array.isArray(value) ? value : []; }
  function object(value) { return value && typeof value === 'object' && !Array.isArray(value) ? value : {}; }
  function clip(value, limit = 1200) { const s = textOf(value); return s.length > limit ? `${s.slice(0, limit)}… [visualizzazione limitata]` : s; }
  function clear(el) { el.replaceChildren(); }
  function announce(text) { $('announcer').textContent = text; }
  function errorText(error) { return error && error.message ? error.message : 'La richiesta non è riuscita. Riprova.'; }
  function setError(id, text) { const el = $(id); el.textContent = text || ''; el.hidden = !text; }
  function message(text, type = 'info') {
    const el = $('global-message'); el.className = `notice ${type}`; el.textContent = text || ''; el.hidden = !text;
  }
  function badge(value, customText) {
    const s = textOf(value).toLowerCase();
    let tone = 'neutral';
    if (['completed', 'available', 'verified', 'ready', 'installed', 'configured'].includes(s)) tone = 'success';
    else if (['running', 'queued', 'static', 'booting', 'collecting'].includes(s)) tone = 'info';
    else if (['failed', 'error', 'blocked', 'denied'].includes(s)) tone = 'error';
    else if (['partial', 'timeout', 'unavailable', 'unverified', 'skipped', 'cancelled', 'unknown'].includes(s)) tone = 'warning';
    return node('span', customText || STATUS_NAMES[s] || clip(value, 100), `chip ${tone}`);
  }
  function date(value) {
    if (!value) return 'Data non disponibile';
    const d = new Date(value); return Number.isNaN(d.getTime()) ? clip(value, 100) : d.toLocaleString('it-IT', { dateStyle: 'short', timeStyle: 'medium' });
  }
  function bytes(value) {
    const n = Number(value); if (!Number.isFinite(n) || n < 0) return 'Dimensione non disponibile';
    if (n < 1024) return `${n} B`;
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KiB`;
    return `${(n / 1048576).toFixed(1)} MiB`;
  }
  function profileId(run) { return typeof run.profile === 'string' ? run.profile : object(run.profile).id || run.id || ''; }
  function profileName(run) { return run.profile_name || object(run.profile).name || PROFILE_NAMES[profileId(run)] || profileId(run) || 'Profilo non specificato'; }
  function selectedRun() { return array(state.job && state.job.runs).find((run) => profileId(run) === state.run) || null; }
  function dynamic() { return object(selectedRun() && selectedRun().dynamic); }
  function scoped(items, always = false) {
    if (state.shared || always || $('include-noise').checked) return array(items);
    return array(items).filter((item) => item && item.related === true);
  }
  function validSegment(value) {
    return typeof value === 'string' && value.length > 0 && value.length <= 250 && !['.', '..'].includes(value)
      && !value.includes('/') && !value.includes(String.fromCharCode(92))
      && !Array.from(value).some((char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127);
  }
  function safeApiPath(...parts) {
    if (!parts.every(validSegment)) throw new Error('Identificativo di analisi o artefatto non valido.');
    return `/api/jobs/${parts.map((p) => encodeURIComponent(p)).join('/')}`;
  }
  function artifactHref(id) { return safeApiPath(state.jobId, 'artifacts', id); }
  async function api(path, options = {}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 120000);
    try {
      const response = await fetch(path, { ...options, credentials: 'same-origin', signal: controller.signal, headers: { Accept: 'application/json', ...(options.headers || {}) } });
      let data = null;
      if (response.headers.get('content-type')?.includes('application/json')) data = await response.json();
      if (!response.ok) {
        const e = new Error(clip(object(data).detail || object(data).error || `Richiesta non riuscita (HTTP ${response.status}).`, 1200));
        e.status = response.status; throw e;
      }
      return data || {};
    } catch (error) {
      if (error.name === 'AbortError') throw new Error('Il server non ha risposto in tempo. Controlla la connessione e riprova.');
      throw error;
    } finally { clearTimeout(timeout); }
  }
  function jsonRequest(method, payload) { return { method, headers: { 'Content-Type': 'application/json' }, ...(payload === undefined ? {} : { body: JSON.stringify(payload) }) }; }
  function showView(id) { ['login-view', 'dashboard-view', 'report-view', 'error-view'].forEach((name) => { $(name).hidden = name !== id; }); }
  function beginReportLoading(shared) {
    state.job = null;
    $('report-title').textContent = shared ? 'Caricamento del report condiviso…' : 'Caricamento del report…';
    $('report-status').replaceWith(Object.assign(badge('pending'), { id: 'report-status' }));
    $('report-date').textContent = ''; $('report-id').textContent = '';
    $('report-actions').hidden = true; $('share-controls').hidden = true;
    $('back-to-jobs').hidden = shared; $('shared-notice').hidden = !shared;
    $('report-loading').hidden = false; $('report-toolbar').hidden = true; $('report-layout').hidden = true;
    clear($('report-warnings'));
    ['summary', 'processes', 'changes', 'network', 'static', 'api', 'drivers', 'detections', 'artifacts'].forEach((name) => clear($(`${name}-content`)));
    clear($('events-content')); $('events-count').textContent = 'In attesa'; $('events-page').textContent = 'In attesa';
    $('events-prev').disabled = true; $('events-next').disabled = true;
    showView('report-view'); $('report-view').setAttribute('aria-busy', 'true');
  }
  function showLogin() {
    state.authenticated = false; state.shared = false; document.body.classList.remove('shared');
    $('private-nav').hidden = true; $('connection-status').replaceWith(Object.assign(badge('unverified', 'Accesso richiesto'), { id: 'connection-status' }));
    $('workspace-label').textContent = 'Accesso al laboratorio'; showView('login-view');
    $('login-token').focus({ preventScroll: true });
  }
  function showError(error, shared = state.shared) {
    showView('error-view'); $('error-home').hidden = shared;
    $('error-title').textContent = shared ? 'Report condiviso non disponibile' : 'Impossibile aprire il report';
    $('error-description').textContent = shared && [403, 404, 410].includes(error.status)
      ? 'Il link non è valido, è scaduto oppure è stato revocato. Richiedi un nuovo link al proprietario del laboratorio.' : errorText(error);
    announce($('error-title').textContent);
  }
  function detail(parent, label, value, key) {
    const el = node('details'); if (key) el.dataset.detailKey = key;
    el.append(node('summary', label));
    const pre = node('pre', clip(value, 80000)); pre.tabIndex = 0; el.append(pre); parent.append(el); return el;
  }
  function empty(parent, heading = 'Nessuna evidenza disponibile', note = 'Il sensore potrebbe non essere disponibile, il campione potrebbe non essere stato eseguito oppure non sono stati raccolti eventi. Questo non è un verdetto di sicurezza.') {
    const el = node('div', null, 'empty-state'); el.append(node('strong', heading), node('p', note)); parent.append(el);
  }
  function card(parent, title, note) {
    const el = node('div', null, 'card'); el.append(node('h2', title)); if (note) el.append(node('p', note, 'evidence-note')); parent.append(el); return el;
  }
  function keyValues(parent, entries) {
    const dl = node('dl', null, 'key-values');
    entries.forEach(([key, value, mono]) => { dl.append(node('dt', key)); dl.append(node('dd', clip(value, 12000), mono ? 'mono' : '')); }); parent.append(dl);
  }
  function recordList(parent, records, titleKeys = ['action', 'name', 'target', 'image'], note) {
    const items = array(records); if (!items.length) { empty(parent, 'Nessun evento in questa vista', note); return; }
    const list = node('div', null, 'data-grid');
    items.slice(0, 300).forEach((record, i) => {
      const item = node('div', null, 'tool-card');
      if (typeof record !== 'object' || record === null) item.append(node('p', clip(record, 2500)));
      else {
        const title = titleKeys.map((key) => record[key]).find((value) => value !== undefined && value !== null && value !== '') || `Evidenza ${i + 1}`;
        const heading = node('div', null, 'tool-heading'); heading.append(node('h3', clip(title, 350)));
        if (record.status) heading.append(badge(record.status));
        else if (record.related === true) heading.append(badge('info', 'Correlato al campione'));
        else if (record.related === false) heading.append(badge('neutral', 'Contesto di sistema'));
        item.append(heading);
        const fields = ['time', 'category', 'action', 'pid', 'tid', 'image', 'target', 'syscall_address', 'ntstatus', 'source', 'destination', 'key', 'value', 'operation', 'service', 'hash', 'sha256'].filter((key) => record[key] !== undefined);
        if (fields.length) keyValues(item, fields.map((key) => [key, record[key], ['image', 'target', 'key', 'hash', 'sha256'].includes(key)]));
        detail(item, 'Espandi evidenza raccolta', record, `record-${i}-${clip(title, 80)}`);
      }
      list.append(item);
    });
    parent.append(list);
    if (items.length > 300) parent.append(node('p', `Mostrate 300 evidenze su ${items.length}. Usa la timeline o gli artefatti grezzi per la raccolta completa.`, 'field-help'));
  }
  function toolResult(parent, name, value) {
    const tool = object(value); const el = node('div', null, 'tool-card'); const heading = node('div', null, 'tool-heading');
    heading.append(node('h3', name), badge(tool.status || 'unavailable')); el.append(heading);
    const description = [tool.detail, tool.coverage, tool.note].find((text) => typeof text === 'string' && text.trim());
    el.append(node('p', description || 'Il backend non ha fornito una descrizione aggiuntiva. Consulta lo stato, gli eventuali risultati e i limiti della raccolta: questo non è un verdetto di sicurezza.'));
    if (tool.result !== undefined && tool.result !== null) detail(el, 'Espandi risultato', tool.result, `tool-${name}`);
    parent.append(el); return el;
  }

  function renderJobs() {
    const body = $('jobs-body'); clear(body); $('jobs-count').textContent = String(state.jobs.length);
    $('jobs-empty').hidden = state.jobs.length > 0; $('jobs-table-wrap').hidden = !state.jobs.length;
    state.jobs.forEach((job) => {
      const row = node('tr'); const sample = node('td'); const link = node('a', job.name || 'Campione senza nome', 'sample-title table-link');
      link.href = `#job/${encodeURIComponent(job.id)}`; sample.append(link);
      if (job.sha256) sample.append(node('span', `SHA-256 ${clip(job.sha256, 16)}`, 'hash-short'));
      row.append(sample); const status = node('td'); status.append(badge(job.status || 'unknown')); row.append(status);
      const options = object(job.options); const profiles = array(options.profiles || job.profiles).map((p) => PROFILE_NAMES[typeof p === 'string' ? p : object(p).id] || textOf(p));
      row.append(node('td', options.static_only || job.static_only ? 'Solo statica' : profiles.join(' · ') || 'Non specificati'), node('td', date(job.created_at)));
      const report = node('td'); const open = node('a', 'Apri report', 'table-link'); open.href = link.href; report.append(open); row.append(report); body.append(row);
    });
  }
  async function fetchJobs() {
    const version = state.routeVersion; const data = await api('/api/jobs');
    if (version !== state.routeVersion || state.shared) return;
    state.jobs = array(data.jobs); renderJobs();
  }
  function renderRuntimeStatus(data) {
    const root = $('runtime-status-content'); clear(root); const status = object(data);
    const privacy = object(status.privacy); const verified = privacy.status === 'verified' && privacy.verified === true;
    const privacyCard = node('div', null, 'capability-card'); const privacyHeading = node('h3', 'Analysis privacy');
    privacyHeading.append(badge(verified ? 'verified' : 'unverified', verified ? 'Base verified' : 'Base unverified')); privacyCard.append(privacyHeading);
    $('privacy-policy-status').replaceWith(Object.assign(badge(verified ? 'verified' : 'unverified', verified ? 'Privacy della base verificata' : 'Privacy non verificata'), { id: 'privacy-policy-status' }));
    keyValues(privacyCard, [
      ['Local Defender', verified ? 'Active: service, antivirus and real-time protection' : 'Not verified'],
      ['Cloud and sample submissions', verified ? 'Defender cloud and automatic tool submissions disabled in base-image evidence' : 'Not verified: no guarantee is inferred'],
      ['Edge', verified ? 'Closed, no authentication stores; sign-in/sync policies configured, runtime adoption not demonstrated' : 'Policies and absence of signed-in accounts not verified'],
      ['VirusTotal / Hybrid Analysis', 'Opt-in SHA-256 lookup only; unknown hashes never trigger sample uploads']
    ]);
    privacyCard.append(node('p', privacy.detail || 'Base-image evidence is unavailable. Each clone must be verified before transferring the sample.'));
    privacyCard.append(node('p', 'Each analysis uses a clean, disposable clone. Base-image privacy evidence does not prove runtime isolation or complete sensor coverage.'));
    root.append(privacyCard);
    $('runtime-status-updated').textContent = status.checked_at ? `Evidence checked: ${date(status.checked_at)}. Refreshed every minute while this panel is visible.` : 'Evidence is unavailable or has not been read yet; no positive verification is inferred.';
  }
  async function loadRuntimeStatus() {
    if (state.shared || !state.authenticated || state.runtimeBusy || document.hidden || $('dashboard-view').hidden) return false;
    const version = state.routeVersion; state.runtimeBusy = true;
    try {
      const data = await api('/api/runtime-status');
      if (version !== state.routeVersion || state.shared || !state.authenticated) return false;
      renderRuntimeStatus(data); return true;
    } catch (error) {
      if (version !== state.routeVersion || state.shared) return false;
      if (error.status === 401) { showLogin(); return false; }
      renderRuntimeStatus({});
      $('runtime-status-updated').textContent = `Evidence unavailable: ${errorText(error)}. Previous status is not presented as current.`;
      return false;
    } finally { state.runtimeBusy = false; }
  }
  function renderCapabilities(data) {
    const root = $('capabilities-content'); clear(root); const caps = object(data);
    renderRuntimeStatus(caps);
    if (Number.isFinite(Number(caps.max_upload)) && Number(caps.max_upload) > 0) { state.maxUpload = Number(caps.max_upload); $('upload-limit').textContent = bytes(state.maxUpload); }
    const isolation = object(caps.isolation); const isoCard = node('div', null, 'capability-card');
    const heading = node('h3', 'Isolamento della VM');
    heading.append(badge(isolation.status || (isolation.verified === true ? 'verified' : 'unverified'))); isoCard.append(heading);
    isoCard.append(node('p', isolation.detail || 'Lo stato effettivo di isolamento deve essere verificato dal runtime prima dell’esecuzione.'));
    if (Object.keys(isolation).length) detail(isoCard, 'Controlli reali del runtime', isolation, 'cap-isolation'); root.append(isoCard);
    if (caps.network_policy) {
      const networkPolicy = object(caps.network_policy);
      const networkTitle = networkPolicy.mode === 'offline' ? 'Rete offline' : networkPolicy.mode === 'public_ipv4_only' ? 'Internet opt-in e blocco LAN/host' : 'Policy di rete non verificata';
      toolResult(root, networkTitle, { status: ['offline', 'public_ipv4_only'].includes(networkPolicy.mode) ? 'configured' : 'unverified', detail: networkPolicy.detail, result: networkPolicy });
    }
    if (caps.kernel) toolResult(root, 'Tracing kernel Microsoft', caps.kernel);
    const profiles = array(caps.profiles); const profileCard = node('div', null, 'capability-card'); profileCard.append(node('h3', 'Base Windows e profili'));
    if (!profiles.length) profileCard.append(node('p', 'Stato dei profili non disponibile. Nessuna VM viene indicata come pronta.'));
    profiles.forEach((profile) => {
      const line = node('p'); line.append(node('span', `${profile.name || PROFILE_NAMES[profile.id] || profile.id} `), badge(profile.status || 'unverified')); profileCard.append(line);
    }); detail(profileCard, 'Configurazione riportata', profiles, 'cap-profiles'); root.append(profileCard);
    const tools = caps.tools;
    const toolEntries = [...(Array.isArray(tools) ? tools.map((t) => [t.name || t.id || 'Strumento', t]) : Object.entries(object(tools))), ...Object.entries(object(caps.integrations))];
    if (!toolEntries.length) {
      const unavailable = node('div', null, 'capability-card'); unavailable.append(node('h3', 'Sensori e strumenti'), badge('unavailable'), node('p', 'Il backend non ha comunicato la disponibilità degli strumenti.')); root.append(unavailable);
    }
    toolEntries.forEach(([name, info]) => {
      const el = node('div', null, 'capability-card'); const value = object(info); const h = node('h3', name); h.append(badge(value.status || 'unverified')); el.append(h, node('p', value.detail || 'Nessun dettaglio di disponibilità fornito.'));
      detail(el, 'Dettagli dello strumento', info, `cap-${name}`); root.append(el);
    });
    if (array(caps.warnings).length) detail(root, 'Avvisi delle capacità', caps.warnings, 'cap-warnings');
  }
  async function loadCapabilities() {
    if (state.shared || !state.authenticated) return;
    const version = state.routeVersion;
    try {
      const data = await api('/api/capabilities');
      if (version !== state.routeVersion || state.shared) return;
      state.capabilities = data; renderCapabilities(data);
    } catch (error) {
      if (version !== state.routeVersion) return;
      if (error.status === 401) { showLogin(); return; }
      clear($('capabilities-content')); empty($('capabilities-content'), 'Capacità non disponibili', errorText(error));
      renderRuntimeStatus({});
      $('runtime-status-updated').textContent = `Lettura non disponibile: ${errorText(error)}.`;
    }
  }
  function setTab(tab, focus = false) {
    state.tab = TABS.includes(tab) && (!state.shared || SHARED_TABS.has(tab)) ? tab : 'summary';
    TABS.forEach((name) => {
      const button = $(`tab-${name}`); const active = name === state.tab;
      button.hidden = state.shared && !SHARED_TABS.has(name); button.setAttribute('aria-selected', String(active)); button.tabIndex = active ? 0 : -1;
      $(`panel-${name}`).hidden = !active;
    });
    $('report-tabs').setAttribute('aria-orientation', matchMedia('(max-width: 900px)').matches ? 'horizontal' : 'vertical');
    if (focus) $(`tab-${state.tab}`).focus();
    if (state.tab === 'timeline' && state.job) loadEvents().catch((error) => setError('events-error', errorText(error)));
  }
  function artifacts() {
    if (state.shared) return [];
    const all = [...array(state.job && state.job.artifacts), ...array(selectedRun() && selectedRun().artifacts)];
    const seen = new Set(); return all.filter((a) => a && validSegment(a.id) && !seen.has(a.id) && seen.add(a.id));
  }
  function renderArtifactList(parent, items, emptyNote) {
    const records = array(items); if (!records.length) { empty(parent, 'Nessun artefatto disponibile', emptyNote || 'Gli artefatti vengono mostrati solo dopo la raccolta reale; la loro assenza non prova che il campione sia sicuro.'); return; }
    const list = node('div', null, 'artifact-list');
    records.forEach((artifact) => {
      const row = node('div', null, 'artifact-row'); const desc = node('div'); desc.append(node('strong', artifact.name || artifact.kind || 'Artefatto'), node('small', `${artifact.kind || 'File'} · ${bytes(artifact.size)}`));
      const link = node('a', 'Scarica', 'button secondary'); link.href = artifactHref(artifact.id); link.setAttribute('download', ''); row.append(desc, link); list.append(row);
    }); parent.append(list);
  }
  function renderWarnings() {
    const root = $('report-warnings'); clear(root);
    const warnings = [...array(state.job.warnings), ...array(selectedRun() && selectedRun().warnings), ...array(dynamic().warnings), ...array(object(state.job.static).warnings)];
    const seen = new Set(); warnings.slice(0, 40).forEach((warning) => {
      const s = clip(typeof warning === 'object' ? warning.detail || warning.message || warning : warning, 1600);
      if (!seen.has(s)) { seen.add(s); root.append(node('div', s, 'notice warning')); }
    });
  }
  function sectionLimit(parent, section) {
    const limit = object(object(dynamic().display_limits)[section]);
    if (!Number.isFinite(Number(limit.total)) || Number(limit.total) <= Number(limit.shown)) return;
    const note = node('div', null, 'notice info section-limit');
    note.append(node('p', `Vista limitata: ${limit.shown}/${limit.total} record ricevuti, prima del filtro di correlazione. Consulta gli eventi paginati o il report JSON completo.`));
    const timeline = node('button', 'Apri timeline paginata', 'button quiet'); timeline.type = 'button';
    timeline.addEventListener('click', () => setTab('timeline')); note.append(timeline);
    const full = artifacts().find((artifact) => artifact.name === 'report.json');
    if (full) { const link = node('a', 'JSON completo', 'button quiet'); link.href = artifactHref(full.id); link.setAttribute('download', ''); note.append(link); }
    parent.append(note);
  }
  function renderSummary() {
    const root = $('summary-content'); clear(root); const run = selectedRun(); const dyn = dynamic(); const counts = object(dyn.counts || (run && run.counts));
    const grid = node('div', null, 'metric-grid');
    [['Processi', 'processes'], ['Eventi', 'events'], ['Eventi di rete raccolti', 'network'], ['Driver raccolti', 'drivers']].forEach(([label, key]) => {
      const items = Array.isArray(dyn[key]) ? scoped(dyn[key], key === 'drivers') : null;
      const relatedKey = !$('include-noise').checked && ['processes', 'events'].includes(key) ? `related_${key}` : key;
      const fallback = counts[relatedKey] ?? counts[key] ?? object(counts.by_category)[key === 'drivers' ? 'driver' : key];
      const count = fallback ?? object(object(dyn.display_limits)[key]).total ?? (items ? items.length : undefined);
      const el = node('div', null, 'metric'); el.append(node('span', Number.isFinite(Number(count)) && count !== undefined && count !== null ? count : '—', 'metric-value'), node('span', label, 'metric-label')); grid.append(el);
    }); root.append(grid);
    root.append(node('p', 'I conteggi del backend coprono la raccolta completa. Processi ed eventi usano il totale correlato quando disponibile; rete e driver riportano il totale raccolto. Le liste di dettaglio possono essere limitate.', 'evidence-note'));
    const summary = card(root, 'Lettura del risultato', 'Un’analisi completata indica che la raccolta è terminata, non che il campione è sicuro. L’assenza di eventi deve essere letta insieme alla copertura dei sensori.');
    if (state.job.summary !== undefined && state.job.summary !== null) {
      if (typeof state.job.summary === 'string') summary.append(node('p', state.job.summary));
      else {
        const obj = object(state.job.summary);
        const readable = obj.description || obj.message || obj.text;
        if (readable) summary.append(node('p', readable));
        detail(summary, 'Riepilogo prodotto dal backend', state.job.summary, 'summary-raw');
      }
    }
    const sample = card(root, 'Identità del campione'); const stat = object(state.job.static); const hashes = object(stat.hashes);
    keyValues(sample, [['Nome', state.job.name || 'Redatto'], ['SHA-256', state.job.sha256 || hashes.sha256, true], ['Dimensione', stat.size === undefined ? 'Non disponibile' : bytes(stat.size)], ['Tipo', object(stat.type).description || stat.type], ['Modalità', object(state.job.options).static_only ? 'Solo analisi statica' : 'Analisi statica e profili dinamici richiesti'], ['Creato', date(state.job.created_at)]]);
    const coverage = card(root, 'Copertura dell’esecuzione', 'Stato e disponibilità sono riportati per questa esecuzione. Un sensore configurato non garantisce che abbia raccolto evidenze.');
    if (!run) { empty(coverage, 'Nessuna esecuzione dinamica', 'Analisi solo statica, esecuzione non ancora avviata oppure base Windows non disponibile. Consulta gli avvisi e i risultati statici.'); }
    else {
      keyValues(coverage, [['Profilo', profileName(run)], ['Stato', STATUS_NAMES[run.status] || run.status], ['Conteggi', counts]]);
      const capabilities = object(dyn.capabilities || run.capabilities);
      if (Object.keys(capabilities).length) detail(coverage, 'Sensori e limiti della raccolta', capabilities, 'summary-capabilities');
      else coverage.append(node('p', 'Disponibilità dei sensori non fornita per questa esecuzione.', 'field-help'));
      if (run.isolation) detail(coverage, 'Isolamento verificato per il profilo', run.isolation, 'run-isolation');
      if (!state.shared && dyn.noise) detail(coverage, 'Correlazione e rumore di sistema', dyn.noise, 'summary-noise');
      if (!state.shared && dyn.display_limits) detail(coverage, 'Limiti delle viste di dettaglio', dyn.display_limits, 'summary-display-limits');
    }
    if (state.shared) root.append(node('div', 'Le sezioni dinamiche grezze sono riservate al proprietario. Questa vista espone soltanto riepilogo, risultati statici redatti e rilevamenti condivisibili.', 'notice info'));
  }
  function renderProcesses() {
    const root = $('processes-content'); clear(root); if (state.shared) return;
    const el = card(root, 'Albero dei processi', 'La relazione segue ProcessGuid e discendenza quando disponibili. Il PID da solo può essere riutilizzato; gli orfani rimangono visibili senza inventare legami.');
    sectionLimit(el, 'processes');
    const processes = scoped(dynamic().processes); if (!processes.length) { empty(el, 'Nessun processo correlato disponibile', 'Abilita il contesto di sistema per ispezionare il rumore oppure verifica gli avvisi di lancio e la disponibilità del sensore.'); return; }
    const byGuid = new Map(processes.filter((p) => p.guid).map((p) => [String(p.guid), p])); const children = new Map(); const roots = [];
    processes.forEach((p) => {
      const parent = p.parent_guid && byGuid.get(String(p.parent_guid));
      if (parent && parent !== p) { if (!children.has(parent)) children.set(parent, []); children.get(parent).push(p); } else roots.push(p);
    });
    const tree = node('ul', null, 'process-tree'); const seen = new Set(); let shown = 0;
    function branch(p, parentList, depth) {
      if (seen.has(p) || shown >= 500) return;
      seen.add(p); shown += 1; const li = node('li'); const box = node('div', null, 'process-node'); const head = node('header');
      head.append(node('strong', clip(p.image || p.name || 'Processo senza immagine', 600)), node('span', `PID ${p.pid ?? '—'}`, 'mono'));
      if (p.related === true) head.append(badge('info', 'Campione / discendente'));
      else head.append(badge('neutral', 'Sistema / non correlato'));
      box.append(head); if (p.command_line) detail(box, 'Comando e identità del processo', { command_line: p.command_line, guid: p.guid, parent_guid: p.parent_guid, ppid: p.ppid }, `process-${p.guid || p.pid}`);
      li.append(box); parentList.append(li);
      const descendants = children.get(p) || [];
      if (descendants.length && depth < 14) { const sub = node('ul'); li.append(sub); descendants.forEach((child) => branch(child, sub, depth + 1)); }
    }
    roots.forEach((p) => branch(p, tree, 0)); processes.forEach((p) => { if (!seen.has(p)) branch(p, tree, 0); }); el.append(tree);
    if (processes.length > shown) el.append(node('p', `Visualizzati ${shown} di ${processes.length} processi. Consulta gli artefatti per il grafo completo.`, 'field-help'));
  }
  function renderChanges() {
    const root = $('changes-content'); clear(root); if (state.shared) return; const dyn = dynamic();
    const reg = card(root, 'Registro di Windows', 'Operazioni osservate; stato, errori e accessi negati restano distinguibili nei dettagli.'); sectionLimit(reg, 'registry'); recordList(reg, scoped(dyn.registry), ['action', 'target', 'key']);
    const files = card(root, 'File e filesystem', 'Operazioni e differenze raccolte nel guest, non accessi al filesystem dell’host.'); sectionLimit(files, 'files'); recordList(files, scoped(dyn.files), ['action', 'target', 'path']);
    const changes = card(root, 'Differenze globali: servizi, attività e baseline', 'Le modifiche globali non vengono nascoste dal filtro dei processi: possono essere rilevanti anche se attribuite a un processo di sistema.');
    ['registry', 'files', 'services', 'tasks'].forEach((category) => sectionLimit(changes, `changes.${category}`));
    if (Object.keys(object(dyn.changes)).length) detail(changes, 'Espandi differenze rispetto alla baseline', dyn.changes, 'global-changes'); else empty(changes, 'Differenze non disponibili');
    const payloads = object(dyn.payloads);
    const secondary = card(root, 'Payload secondari scaricati o creati', 'Solo file correlati al campione/discendenti, con limiti di numero e dimensione. Copie .bin in quarantena privata: mai eseguite sull’host, estratte o caricate automaticamente su servizi esterni.');
    toolResult(secondary, 'Acquisizione payload', { status: payloads.status || 'unavailable', detail: payloads.detail, result: payloads.budgets });
    recordList(secondary, payloads.payloads, ['source_path', 'path', 'name', 'sha256']);
    renderArtifactList(secondary, artifacts().filter((item) => item.kind === 'payload' || item.kind === 'payload_manifest'));
  }
  function renderNetwork() {
    const root = $('network-content'); clear(root); if (state.shared) return;
    const isolation = object(dynamic().isolation);
    const policyDetail = isolation.guest_internet === true
      ? 'Policy Internet IPv4 pubblico: il gateway deve bloccare destinazioni private/riservate, host, LAN, IPv6 e DNS locali, anche dopo redirect o DNS rebinding. La prova runtime indica se questi controlli sono stati verificati.'
      : isolation.guest_internet === false
        ? 'Policy offline o simulata: nessun accesso a Internet reale. Eventuali servizi sintetici sono locali alla rete di analisi. Questa modalità dichiarata non sostituisce le prove runtime di isolamento.'
        : 'Policy di rete non disponibile: non si deduce né accesso a Internet né modalità offline o simulata. Servono le prove runtime per questa esecuzione.';
    const policy = card(root, 'Policy di rete effettiva', policyDetail);
    keyValues(policy, [['Isolamento verificato', isolation.confirmed === true ? 'Sì' : 'Non verificato'],
      ['Internet guest', isolation.guest_internet === true ? 'Internet reale IPv4 pubblico' : isolation.guest_internet === false ? 'Offline / simulato' : 'Non verificato'],
      ['LAN', isolation.guest_lan === false ? 'Bloccata' : 'Non verificata'],
      ['Host', isolation.guest_host === false ? 'Bloccato' : 'Non verificato']]);
    if (Object.keys(isolation).length) detail(policy, 'Prova runtime e policy di rete', isolation, 'network-isolation');
    const el = card(root, 'Attività di rete', 'Destinazioni osservate nella rete isolata. Una richiesta DNS o una connessione tentata non dimostra traffico riuscito verso Internet.'); sectionLimit(el, 'network'); recordList(el, scoped(dynamic().network), ['action', 'target', 'destination', 'query']);
    const pcaps = card(root, 'Cattura PCAP', 'Scaricabile solo dal proprietario. La cattura è disponibile esclusivamente se il runtime l’ha prodotta e registrata come artefatto.');
    renderArtifactList(pcaps, artifacts().filter((a) => /pcap/i.test(textOf(a.kind)) || /\.pcap(?:ng)?$/i.test(textOf(a.name))));
    if (dynamic().pcap) detail(pcaps, 'Analisi flussi, DNS e HTTP dal PCAP', dynamic().pcap, 'network-pcap-summary');
  }
  function renderStatic() {
    const root = $('static-content'); clear(root); const stat = object(state.job.static);
    const info = card(root, 'Identità e struttura statica', 'Nessun risultato statico è prova di esecuzione. Stringhe, import e indicatori vengono mostrati come dati, mai come link attivi.');
    if (!Object.keys(stat).length) { empty(info, 'Analisi statica non ancora disponibile'); return; }
    keyValues(info, [['MD5', object(stat.hashes).md5, true], ['SHA-1', object(stat.hashes).sha1, true], ['SHA-256', object(stat.hashes).sha256 || state.job.sha256, true], ['Dimensione', stat.size === undefined ? 'Non disponibile' : bytes(stat.size)], ['Tipo di file', stat.type]]);
    const sensors = card(root, 'Risultati degli strumenti', '“Completata” descrive lo strumento. “Non disponibile” non viene trasformato in “nessun rilevamento”.');
    const grid = node('div', null, 'data-grid');
    [['pe', 'PE: sezioni, import, export e firma'], ['strings', 'Stringhe estratte'], ['iocs', 'Indicatori (IOC)'], ['yara', 'Regole YARA'], ['capa', 'Capacità · capa'], ['floss', 'Stringhe decodificate · FLOSS'], ['av', 'Antivirus'], ['byovd', 'Indicatori statici BYOVD']].forEach(([key, label]) => toolResult(grid, label, stat[key])); sensors.append(grid);
    if (!state.shared) toolResult(sensors, 'Hybrid Analysis · reputazione hash esterna', stat.hybrid_analysis);
    if (stat.capabilities) detail(sensors, 'Copertura statica e limitazioni', stat.capabilities, 'static-capabilities');
  }
  function renderApi() {
    const root = $('api-content'); clear(root); if (state.shared) return; const dyn = dynamic();
    const kernel = object(dyn.kernel);
    const kernelCard = card(root, 'Syscall e stack · kernel ETW', 'Eventi del kernel Windows tramite Microsoft WPR/ETW, distinti dagli hook Nt* user-mode. Copertura dipendente da buffer, perdita eventi, finestre e decoder; non si presume una traccia totale o uno stack causale completo.');
    toolResult(kernelCard, 'Tracing kernel osservato', object(dyn.capabilities).kernel || { status: 'unavailable', detail: 'Nessuna ricevuta kernel per questa esecuzione.' });
    keyValues(kernelCard, [['Conteggi', kernel.counts], ['Copertura', kernel.coverage], ['Capacità osservate', kernel.capabilities]]);
    sectionLimit(kernelCard, 'kernel.events'); recordList(kernelCard, scoped(kernel.events), ['kind', 'syscall_address', 'name']);
    const pairs = card(root, 'Ingressi/uscite syscall kernel', 'Accoppiamento osservato per thread e cronologia, non deduzione di causalità. I record incompleti restano distinguibili.');
    sectionLimit(pairs, 'kernel.syscall_pairs'); recordList(pairs, scoped(kernel.syscall_pairs), ['syscall_address', 'enter_id', 'tid']);
    if (kernel.receipts) detail(kernelCard, 'Ricevute kernel, perdita eventi e comandi', kernel.receipts, 'kernel-receipts');
    renderArtifactList(kernelCard, artifacts().filter((item) => item.kind === 'kernel'));
    const info = card(root, 'API user-mode e call stack', 'Frida, quando realmente disponibile, osserva hook nel processo. Le chiamate Nt* sono chiamate user-mode: non è una traccia completa dei syscall kernel, né un sensore kernel.');
    const caps = object(dyn.capabilities); const trace = caps.frida || caps.api || caps.trace;
    if (trace !== undefined) toolResult(info, 'Sensore di tracing', typeof trace === 'object' ? trace : { status: 'unknown', detail: textOf(trace) });
    else info.append(node('div', 'Nessuno stato del sensore di tracing fornito. Nessuna copertura viene presunta.', 'notice warning'));
    sectionLimit(info, 'api_calls'); recordList(info, scoped(dyn.api_calls), ['api', 'name', 'function', 'action']);
    const chains = card(root, 'Call chain raccolte', 'Le sequenze riflettono i dati del sensore, non una ricostruzione ipotetica.'); sectionLimit(chains, 'call_chains'); recordList(chains, scoped(dyn.call_chains), ['thread_id', 'name', 'api']);
    const nt = card(root, 'Catene Nt* · user-mode', 'Questa sezione non implica visibilità sulle chiamate dirette al kernel o sui driver.'); sectionLimit(nt, 'syscall_chain'); recordList(nt, scoped(dyn.syscall_chain), ['name', 'api', 'thread_id']);
  }
  function renderDrivers() {
    const root = $('drivers-content'); clear(root); if (state.shared) return;
    const el = card(root, 'Driver caricati e servizi', 'Gli eventi driver non sono esclusi dal filtro del rumore, anche se attribuiti a processi di sistema. Nessun file .sys viene installato automaticamente.'); sectionLimit(el, 'drivers'); recordList(el, dynamic().drivers, ['image', 'target', 'service', 'action']);
    const byovd = card(root, 'Indicatori BYOVD', 'Un hash noto o un driver sospetto è un indicatore; da solo non dimostra sfruttamento, vulnerabilità attiva o disattivazione dei controlli di sicurezza.'); toolResult(byovd, 'Analisi statica dei driver', object(state.job.static).byovd);
    const loaded = object(dynamic().byovd);
    toolResult(byovd, 'Hash dei driver caricati · LOLDrivers', { status: loaded.status, detail: loaded.detail, result: loaded.matches });
  }
  function renderDetections() {
    const root = $('detections-content'); clear(root); const dyn = dynamic(); const run = selectedRun();
    if (!state.shared) {
      const proof = object(dyn.privacy); const summary = object(dyn.privacy_summary);
      const verified = summary.status === 'verified' && summary.verified === true && summary.proof_scope === 'runtime_pretransfer';
      const privacy = card(root, 'Privacy del clone osservato', 'Prova di avvio / prima del trasferimento del campione, distinta dalla base. Non certifica che il campione non abbia comunicato su Internet.');
      privacy.append(badge(verified ? 'verified' : 'unverified', verified ? 'Controllo del clone verificato' : 'Controllo del clone non verificato'));
      privacy.append(node('p', summary.detail || 'Prova assente, incompleta o incoerente: nessuna verifica della privacy viene dedotta dai soli risultati antivirus.'));
      if (Object.keys(proof).length) detail(privacy, 'Prova effettiva del runtime', proof, 'runtime-privacy-proof');
    }
    const defender = card(root, 'Microsoft Defender', 'Defender resta attivo. Blocchi, rilevamenti ed errori sono evidenze distinte; un avvio bloccato non è una detonazione riuscita.');
    const def = dyn.defender || (run && run.defender);
    if (def !== undefined) {
      const value = object(def); if (value.status) defender.append(badge(value.status));
      if (value.detail) defender.append(node('p', value.detail));
      detail(defender, 'Evidenze di Defender', def, 'defender-result');
    } else empty(defender, 'Telemetria Defender non disponibile', 'Non vengono dedotti esiti negativi dalla mancanza di telemetria.');
    const detections = card(root, 'Rilevamenti riportati', 'Eventi di sicurezza non filtrati come rumore di sistema. Dati presentati con la fonte originale, senza inventare punteggi o classificazioni.');
    if (!state.shared) sectionLimit(detections, 'events');
    const records = [...array(state.job.detections), ...array(run && run.detections), ...array(dyn.detections), ...array(dyn.events).filter((e) => ['security', 'defender', 'detection'].includes(e.category))];
    recordList(detections, records, ['name', 'threat', 'action', 'target'], 'Nessun rilevamento riportato in questa vista. Verifica lo stato dei sensori; non significa che il campione sia pulito.');
    const rules = card(root, 'Motori statici', 'Risultati reali degli strumenti, con copertura e stato espliciti.'); toolResult(rules, 'YARA', object(state.job.static).yara); toolResult(rules, 'Antivirus statico', object(state.job.static).av);
    if (!state.shared) {
      const external = card(root, 'Fonti esterne', 'Report già esistenti per lo stesso hash: non sostituiscono la detonazione locale. Nessun file viene caricato automaticamente.');
      toolResult(external, 'Hybrid Analysis', object(state.job.static).hybrid_analysis);
      toolResult(external, 'VirusTotal · hash', object(state.job.static).reputation);
      if (dyn.elastic) toolResult(external, 'Elastic EDR · configurazione richiesta', {status: dyn.elastic.status, detail: dyn.elastic.detail, result: dyn.elastic});
    }
  }
  function renderArtifacts() {
    const root = $('artifacts-content'); clear(root); if (state.shared) return;
    const el = card(root, 'Artefatti della raccolta', 'File grezzi, log e screenshot registrati dal backend. Possono contenere dati ostili: non eseguirli sull’host. I download sono limitati agli endpoint autenticati del laboratorio.'); renderArtifactList(el, artifacts());
  }
  function renderEvidence() {
    const opened = new Set(Array.from(document.querySelectorAll('.evidence-panels details[open]')).map((el) => el.dataset.detailKey).filter(Boolean));
    const focused = document.activeElement;
    const focusedDetail = focused?.closest('.evidence-panels details[data-detail-key]');
    const focusedKey = focusedDetail?.dataset.detailKey;
    const focusedTag = focused?.tagName;
    renderSummary(); renderProcesses(); renderChanges(); renderNetwork(); renderStatic(); renderApi(); renderDrivers(); renderDetections(); renderArtifacts();
    document.querySelectorAll('.evidence-panels details[data-detail-key]').forEach((el) => { if (opened.has(el.dataset.detailKey)) el.open = true; });
    if (focusedKey) {
      const replacement = Array.from(document.querySelectorAll('.evidence-panels details[data-detail-key]')).find((el) => el.dataset.detailKey === focusedKey);
      const target = replacement?.querySelector(focusedTag === 'PRE' ? 'pre' : 'summary');
      if (target) target.focus({ preventScroll: true });
    }
    renderWarnings();
  }
  function renderReport(force = false) {
    if (!state.job) return;
    $('report-loading').hidden = true; $('report-toolbar').hidden = false; $('report-layout').hidden = false;
    $('report-view').removeAttribute('aria-busy');
    const job = state.job; $('report-title').textContent = job.name || 'Report redatto';
    $('report-status').replaceWith(Object.assign(badge(job.status || 'unknown'), { id: 'report-status' }));
    $('report-date').textContent = date(job.created_at); $('report-id').textContent = state.shared ? '' : `ID ${job.id || state.jobId}`;
    $('shared-notice').hidden = !state.shared; $('report-actions').hidden = state.shared; $('back-to-jobs').hidden = state.shared; $('scope-control').hidden = state.shared;
    $('share-controls').hidden = state.shared || $('share-controls').hidden;
    $('pdf-download').href = state.shared ? '#' : safeApiPath(state.jobId, 'report.pdf');
    $('cancel-job').hidden = state.shared || !ACTIVE.has(job.status);
    const select = $('run-select'); const runs = array(job.runs); const prior = state.run;
    if (!runs.some((r) => profileId(r) === state.run)) state.run = runs.length ? profileId(runs[0]) : '';
    clear(select);
    if (!runs.length) { const option = node('option', 'Nessuna esecuzione dinamica'); option.value = ''; select.append(option); }
    runs.forEach((run) => { const option = node('option', `${profileName(run)} · ${STATUS_NAMES[run.status] || run.status || 'Non verificato'}`); option.value = profileId(run); select.append(option); });
    select.value = state.run; select.disabled = !runs.length;
    $('run-status').replaceWith(Object.assign(badge(selectedRun()?.status || 'unavailable'), { id: 'run-status' }));
    const signature = JSON.stringify({ job, run: state.run, noise: $('include-noise').checked, shared: state.shared });
    if (force || signature !== state.renderSignature) { state.renderSignature = signature; renderEvidence(); }
    if (prior !== state.run) { state.offset = 0; state.eventsSignature = ''; }
    setTab(state.tab);
    if (job.status !== state.lastAnnouncedStatus) { announce(`Stato dell’analisi: ${STATUS_NAMES[job.status] || job.status}.`); state.lastAnnouncedStatus = job.status; }
    showView('report-view');
  }

  function renderEvents(items, total) {
    const root = $('events-content');
    const opened = new Set(Array.from(root.querySelectorAll('details[open]')).map((el) => el.dataset.detailKey));
    const focused = document.activeElement; const focusedDetail = focused?.closest('#events-content details[data-detail-key]');
    const focusedKey = focusedDetail?.dataset.detailKey; const focusedTag = focused?.tagName;
    clear(root); const records = array(items); state.total = Number.isFinite(Number(total)) ? Number(total) : records.length;
    $('events-count').textContent = `${state.total} eventi`;
    if (!records.length) empty(root, 'Nessun evento corrisponde ai filtri', 'Modifica ricerca, categoria o filtro di correlazione. La mancanza di eventi non significa campione sicuro.');
    else {
      const list = node('div', null, 'event-list');
      records.forEach((event, i) => {
        const el = node('article', null, 'event-item'); const top = node('div', null, 'event-top'); top.append(node('time', event.time ? date(event.time) : 'Tempo non disponibile', 'event-time'));
        top.append(badge('neutral', event.category || 'Evento'));
        if (event.related === true) top.append(badge('info', 'Campione')); else if (event.related === false) top.append(badge('neutral', 'Sistema'));
        el.append(top, node('div', event.action || 'Operazione non specificata', 'event-title'));
        el.append(node('div', [event.image, event.pid !== undefined ? `PID ${event.pid}` : '', event.target].filter(Boolean).join(' · '), 'event-target'));
        detail(el, 'Dettagli e fonte', event, `event-${event.id || i}`); list.append(el);
      }); root.append(list);
    }
    root.querySelectorAll('details[data-detail-key]').forEach((el) => { if (opened.has(el.dataset.detailKey)) el.open = true; });
    if (focusedKey) {
      const replacement = Array.from(root.querySelectorAll('details[data-detail-key]')).find((el) => el.dataset.detailKey === focusedKey);
      const target = replacement?.querySelector(focusedTag === 'PRE' ? 'pre' : 'summary');
      if (target) target.focus({ preventScroll: true });
    }
    $('events-prev').disabled = state.offset === 0; $('events-next').disabled = state.offset + 200 >= state.total;
    $('events-page').textContent = records.length ? `${state.offset + 1}–${state.offset + records.length} di ${state.total}` : `0 di ${state.total}`;
  }
  async function loadEvents() {
    if (state.shared || !state.jobId || !state.job) return;
    const version = state.routeVersion;
    const params = new URLSearchParams({ run: state.run, related: String(!$('include-noise').checked), offset: String(state.offset), limit: '200' });
    if (state.filterQuery) params.set('q', state.filterQuery); if (state.filterCategory) params.set('category', state.filterCategory);
    const query = `${version}:${state.jobId}?${params}`;
    if (state.eventsPendingQuery === query) return;
    state.eventsPendingQuery = query; const seq = ++state.eventSequence;
    if (query !== state.eventsQuery || !state.eventsSignature) {
      state.eventsQuery = query; state.eventsSignature = ''; clear($('events-content'));
      $('events-content').append(node('p', 'Caricamento degli eventi corrispondenti ai filtri…', 'field-help'));
      $('events-count').textContent = 'Caricamento…'; $('events-page').textContent = 'In attesa';
      $('events-prev').disabled = true; $('events-next').disabled = true;
    }
    $('event-scope-note').textContent = $('include-noise').checked ? 'Tutte le attività raccolte, incluso il contesto di sistema. Driver e sicurezza sono sempre consultabili nelle sezioni dedicate.' : 'Attività correlate al campione e ai suoi discendenti. Driver e sicurezza restano visibili nelle sezioni dedicate.';
    setError('events-error', ''); $('events-content').setAttribute('aria-busy', 'true');
    try {
      const data = await api(`${safeApiPath(state.jobId, 'events')}?${params}`);
      if (seq !== state.eventSequence || version !== state.routeVersion) return;
      const signature = JSON.stringify({ data, params: params.toString() });
      if (signature !== state.eventsSignature) { state.eventsSignature = signature; renderEvents(data.items, data.total); }
    } catch (error) {
      if (seq === state.eventSequence && version === state.routeVersion) {
        if (error.status === 401) showLogin();
        else { state.eventsSignature = ''; setError('events-error', errorText(error)); $('events-count').textContent = 'Non disponibile'; }
      }
    }
    finally {
      if (state.eventsPendingQuery === query) state.eventsPendingQuery = '';
      if (seq === state.eventSequence) $('events-content').removeAttribute('aria-busy');
    }
  }
  function routeData() {
    const sharedPath = location.pathname.match(/^\/s\/([^/]+)\/?$/);
    if (sharedPath) { try { return { kind: 'share', id: decodeURIComponent(sharedPath[1]) }; } catch (_) { return { kind: 'invalid' }; } }
    const hash = location.hash.slice(1); const parts = hash.split('/');
    if (['job', 'share'].includes(parts[0]) && parts[1]) {
      try { const id = decodeURIComponent(parts[1]); return validSegment(id) && parts.length === 2 ? { kind: parts[0], id } : { kind: 'invalid' }; }
      catch (_) { return { kind: 'invalid' }; }
    }
    return { kind: ['new', 'jobs', 'capabilities'].includes(hash) ? hash : 'new' };
  }
  async function navigate() {
    const route = routeData(); const version = ++state.routeVersion; state.route = route.kind;
    message(''); state.eventsSignature = ''; state.eventSequence += 1;
    state.shared = route.kind === 'share'; document.body.classList.toggle('shared', state.shared);
    $('private-nav').hidden = state.shared || !state.authenticated;
    if (state.shared) {
      state.shareToken = route.id; state.jobId = ''; state.tab = 'summary'; state.run = ''; state.lastAnnouncedStatus = '';
      $('workspace-label').textContent = 'BLACKSITE · report condiviso';
      $('connection-status').replaceWith(Object.assign(badge('neutral', 'Sola lettura'), { id: 'connection-status' }));
      $('refresh-status').textContent = ''; beginReportLoading(true);
      try {
        const data = await api(`/api/shared/${encodeURIComponent(route.id)}`);
        if (version !== state.routeVersion) return;
        state.job = object(data.report || data.job || data); state.renderSignature = ''; renderReport(true);
      } catch (error) { if (version === state.routeVersion) showError(error, true); }
      return;
    }
    if (route.kind === 'invalid') { showError(new Error('Indirizzo del report non valido.')); return; }
    if (!state.authenticated) { showLogin(); return; }
    $('workspace-label').textContent = route.kind === 'job' ? 'Report di analisi' : 'Analisi locale';
    $('connection-status').replaceWith(Object.assign(badge('info', 'Sessione locale'), { id: 'connection-status' }));
    ['new', 'jobs', 'capabilities'].forEach((name) => $(`nav-${name}`).classList.toggle('active', route.kind === name));
    if (route.kind === 'job') {
      if (state.jobId !== route.id) {
        state.job = null; state.run = ''; state.tab = 'summary'; state.offset = 0; state.lastAnnouncedStatus = '';
        state.filterQuery = ''; state.filterCategory = ''; $('event-search').value = ''; $('event-category').value = ''; $('include-noise').checked = false;
        $('share-controls').hidden = true; $('share-result').hidden = true; $('share-url').value = ''; $('share-status').textContent = ''; setError('share-error', '');
      }
      state.jobId = route.id; beginReportLoading(false);
      try { const data = await api(safeApiPath(route.id)); if (version !== state.routeVersion) return; state.job = data; renderReport(true); }
      catch (error) { if (version !== state.routeVersion) return; if (error.status === 401) showLogin(); else showError(error); }
      finally { if (version === state.routeVersion) $('report-view').removeAttribute('aria-busy'); }
    } else {
      state.jobId = ''; state.job = null; showView('dashboard-view');
      try { await fetchJobs(); } catch (error) { if (version !== state.routeVersion) return; if (error.status === 401) showLogin(); else message(errorText(error), 'error'); }
      if (version !== state.routeVersion || !state.authenticated) return;
      if (!state.capabilities) await loadCapabilities(); else await loadRuntimeStatus();
      if (version !== state.routeVersion) return;
      if (route.kind !== 'new') $(route.kind === 'jobs' ? 'jobs-section' : 'capabilities-section').scrollIntoView({ block: 'start' });
    }
  }
  async function refresh() {
    if (state.refreshBusy || state.shared || !state.authenticated || document.hidden) return;
    if (!['job', 'new', 'jobs', 'capabilities'].includes(state.route)) return;
    if (state.route === 'job' && !ACTIVE.has(state.job?.status)) return;
    if (state.route !== 'job' && !state.jobs.some((j) => ACTIVE.has(j.status))) return;
    state.refreshBusy = true; const version = state.routeVersion;
    try {
      if (state.route === 'job') {
        const data = await api(safeApiPath(state.jobId));
        if (version !== state.routeVersion) return; state.job = data; renderReport();
      } else await fetchJobs();
      if (version !== state.routeVersion) return;
      $('refresh-status').textContent = `Aggiornato ${new Date().toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}`;
    } catch (error) {
      if (version === state.routeVersion) { if (error.status === 401) showLogin(); else message(`Aggiornamento interrotto: ${errorText(error)}`, 'warning'); }
    } finally { state.refreshBusy = false; }
  }
  function selectFile(file) {
    state.sample = file || null; $('file-selection').textContent = file ? `${file.name} · ${bytes(file.size)}` : 'Nessun file selezionato';
    setError('upload-error', file && file.size > state.maxUpload ? `Il file supera il limite di ${bytes(state.maxUpload)}.` : '');
  }
  function updateStaticMode() {
    const enabled = $('static-only').checked; $('profiles-fieldset').disabled = enabled; $('analysis-duration').disabled = enabled;
    $('analysis-submit').textContent = enabled ? 'Avvia analisi statica' : 'Avvia analisi';
  }
  async function mutateButton(button, operation) {
    if (state.shared || !state.authenticated) return;
    const version = state.routeVersion; const original = button.textContent; button.disabled = true; button.textContent = 'Attendi…';
    try { await operation(); } catch (error) { if (version !== state.routeVersion) return; if (error.status === 401) showLogin(); else message(errorText(error), 'error'); }
    finally { button.disabled = false; button.textContent = original; }
  }

  $('login-form').addEventListener('submit', async (event) => {
    event.preventDefault(); const button = $('login-submit'); setError('login-error', ''); button.disabled = true; button.textContent = 'Accesso in corso…';
    try {
      await api('/api/session', jsonRequest('POST', { token: $('login-token').value })); $('login-token').value = ''; state.authenticated = true;
      $('private-nav').hidden = false; $('connection-status').replaceWith(Object.assign(badge('info', 'Sessione locale'), { id: 'connection-status' }));
      await navigate();
    } catch (error) { setError('login-error', error.status === 401 ? 'Token non valido. Controlla il token locale e riprova.' : errorText(error)); }
    finally { button.disabled = false; button.textContent = 'Accedi al laboratorio'; }
  });
  $('sample-file').addEventListener('change', (event) => selectFile(event.target.files[0]));
  $('static-only').addEventListener('change', updateStaticMode);
  const dropZone = $('drop-zone');
  ['dragenter', 'dragover'].forEach((name) => dropZone.addEventListener(name, (event) => { event.preventDefault(); dropZone.classList.add('dragging'); }));
  ['dragleave', 'drop'].forEach((name) => dropZone.addEventListener(name, (event) => { event.preventDefault(); dropZone.classList.remove('dragging'); }));
  dropZone.addEventListener('drop', (event) => {
    const files = event.dataTransfer.files; if (files.length !== 1) { setError('upload-error', 'Seleziona un solo file per analisi.'); return; }
    try { const transfer = new DataTransfer(); transfer.items.add(files[0]); $('sample-file').files = transfer.files; } catch (_) { $('sample-file').required = false; }
    selectFile(files[0]);
  });
  document.addEventListener('dragover', (event) => { if (event.dataTransfer?.types.includes('Files')) event.preventDefault(); });
  document.addEventListener('drop', (event) => { if (event.dataTransfer?.types.includes('Files')) event.preventDefault(); });
  $('analysis-form').addEventListener('submit', async (event) => {
    event.preventDefault(); setError('upload-error', ''); const file = state.sample || $('sample-file').files[0];
    if (state.shared || !state.authenticated) return;
    if (!file) { setError('upload-error', 'Seleziona un campione prima di avviare l’analisi.'); $('sample-file').focus(); return; }
    if (file.size > state.maxUpload) { setError('upload-error', `Il campione supera il limite di ${bytes(state.maxUpload)}.`); return; }
    const staticOnly = $('static-only').checked; const profiles = Array.from(document.querySelectorAll('input[name="profile"]:checked')).map((el) => el.value);
    if (!staticOnly && !profiles.length) { setError('upload-error', 'Seleziona almeno un profilo oppure abilita la sola analisi statica.'); return; }
    const duration = Number($('analysis-duration').value);
    if (!staticOnly && (!Number.isInteger(duration) || duration < 15 || duration > 600)) { setError('upload-error', 'La durata deve essere un numero intero tra 15 e 600 secondi.'); $('analysis-duration').focus(); return; }
    const form = new FormData(); form.append('file', file, file.name); form.append('profiles', JSON.stringify(staticOnly ? [] : profiles)); form.append('duration', String(staticOnly ? 60 : duration)); form.append('static_only', String(staticOnly));
    const version = state.routeVersion; const button = $('analysis-submit'); button.disabled = true; button.textContent = 'Caricamento locale…';
    try {
      const data = await api('/api/jobs', { method: 'POST', body: form });
      if (version !== state.routeVersion || state.shared) return;
      if (!validSegment(data.id)) throw new Error('Il backend non ha restituito un ID di analisi valido.');
      if (state.sample === file) { $('sample-file').value = ''; $('sample-file').required = true; selectFile(null); }
      announce('Campione caricato. Analisi creata.'); location.hash = `job/${encodeURIComponent(data.id)}`;
    } catch (error) { if (version !== state.routeVersion || state.shared) return; if (error.status === 401) showLogin(); else setError('upload-error', errorText(error)); }
    finally { button.disabled = false; updateStaticMode(); }
  });
  $('refresh-jobs').addEventListener('click', () => mutateButton($('refresh-jobs'), async () => {
    const version = state.routeVersion; await fetchJobs();
    if (version !== state.routeVersion || state.shared || !state.authenticated) return;
    await loadCapabilities();
    if (version === state.routeVersion && !state.shared && state.authenticated) announce('Elenco analisi e capacità aggiornati.');
  }));
  $('refresh-runtime-status').addEventListener('click', () => mutateButton($('refresh-runtime-status'), async () => {
    if (await loadRuntimeStatus()) announce('Privacy dell’analisi aggiornata dalle fonti locali.');
  }));
  $('run-select').addEventListener('change', () => { state.run = $('run-select').value; state.offset = 0; state.eventsSignature = ''; renderReport(true); });
  $('include-noise').addEventListener('change', () => { state.offset = 0; state.eventsSignature = ''; renderReport(true); announce($('include-noise').checked ? 'Attività di sistema incluse.' : 'Vista correlata al campione.'); });
  $('report-tabs').addEventListener('click', (event) => { const button = event.target.closest('[data-tab]'); if (button && !button.hidden) setTab(button.dataset.tab); });
  $('report-tabs').addEventListener('keydown', (event) => {
    const tabs = TABS.filter((name) => !$(`tab-${name}`).hidden); const current = tabs.indexOf(state.tab); let next = current;
    if (['ArrowRight', 'ArrowDown'].includes(event.key)) next = (current + 1) % tabs.length;
    else if (['ArrowLeft', 'ArrowUp'].includes(event.key)) next = (current - 1 + tabs.length) % tabs.length;
    else if (event.key === 'Home') next = 0; else if (event.key === 'End') next = tabs.length - 1; else return;
    event.preventDefault(); setTab(tabs[next], true);
  });
  $('event-filter-form').addEventListener('submit', (event) => { event.preventDefault(); state.filterQuery = $('event-search').value.trim(); state.filterCategory = $('event-category').value; state.offset = 0; loadEvents(); });
  $('event-category').addEventListener('change', () => $('event-filter-form').requestSubmit());
  $('events-prev').addEventListener('click', () => { state.offset = Math.max(0, state.offset - 200); loadEvents(); });
  $('events-next').addEventListener('click', () => { state.offset += 200; loadEvents(); });
  $('cancel-job').addEventListener('click', () => mutateButton($('cancel-job'), async () => {
    if (!confirm('Annullare questa analisi? I risultati già raccolti resteranno disponibili; le esecuzioni successive non verranno avviate.')) return;
    const jobId = state.jobId; const version = state.routeVersion;
    await api(safeApiPath(jobId, 'cancel'), { method: 'POST' });
    if (version !== state.routeVersion) return;
    const data = await api(safeApiPath(jobId));
    if (version !== state.routeVersion) return;
    state.job = data; renderReport(true); message('Annullamento richiesto. La chiusura delle VM può richiedere alcuni secondi.');
  }));
  $('share-job').addEventListener('click', () => { $('share-controls').hidden = !$('share-controls').hidden; if (!$('share-controls').hidden) $('share-hours').focus(); });
  $('close-share').addEventListener('click', () => { $('share-controls').hidden = true; $('share-job').focus(); });
  $('create-share').addEventListener('click', () => mutateButton($('create-share'), async () => {
    setError('share-error', ''); $('share-status').textContent = ''; const hours = Number($('share-hours').value);
    if (!Number.isInteger(hours) || hours < 1 || hours > 168) { setError('share-error', 'La scadenza deve essere un numero intero tra 1 e 168 ore.'); return; }
    const jobId = state.jobId; const version = state.routeVersion;
    try {
      const data = await api(safeApiPath(jobId, 'share'), jsonRequest('POST', { hours }));
      if (version !== state.routeVersion || state.shared) return;
      const url = new URL(data.url, location.origin);
      if (!['https:', 'http:'].includes(url.protocol) || !/^\/s\/[^/]+\/?$/.test(url.pathname) || url.username || url.password) throw new Error('Il backend ha restituito un link di condivisione non valido.');
      $('share-url').value = url.href; $('share-result').hidden = false; $('share-expiry').textContent = `Scadenza: ${date(data.expires_at)}. Accesso limitato alla vista redatta.`;
      $('share-status').textContent = data.public ? 'Link HTTPS pubblico alla sola vista redatta. Chi possiede il link può leggerla fino a scadenza o revoca; l’indirizzo del tunnel temporaneo può cambiare al riavvio.' : 'Link locale creato. Gateway HTTPS pubblico non disponibile in questo momento.';
    } catch (error) { if (version !== state.routeVersion) return; if (error.status === 401) showLogin(); else setError('share-error', errorText(error)); }
  }));
  $('copy-share').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText($('share-url').value); $('share-status').textContent = 'Link copiato.'; }
    catch (_) { $('share-url').focus(); $('share-url').select(); $('share-status').textContent = 'Copia automatica non disponibile. Il link è selezionato: usa il comando Copia del browser.'; }
  });
  $('revoke-share').addEventListener('click', () => mutateButton($('revoke-share'), async () => {
    if (!confirm('Revocare tutti i link condivisi di questa analisi? I link esistenti non funzioneranno più.')) return;
    const jobId = state.jobId; const version = state.routeVersion;
    await api(safeApiPath(jobId, 'share'), { method: 'DELETE' });
    if (version !== state.routeVersion || state.shared) return;
    $('share-result').hidden = true; $('share-url').value = ''; $('share-status').textContent = 'Tutti i link di questa analisi sono stati revocati.'; setError('share-error', ''); announce('Condivisioni revocate.');
  }));
  $('retry-page').addEventListener('click', navigate);
  document.querySelector('.skip-link').addEventListener('click', (event) => {
    event.preventDefault(); $('main').focus({ preventScroll: true }); $('main').scrollIntoView({ block: 'start' });
  });
  window.addEventListener('hashchange', navigate);
  window.addEventListener('resize', () => $('report-tabs').setAttribute('aria-orientation', matchMedia('(max-width: 900px)').matches ? 'horizontal' : 'vertical'));
  document.addEventListener('visibilitychange', () => { if (!document.hidden) { refresh(); loadRuntimeStatus(); } });

  async function start() {
    if (routeData().kind === 'share') { await navigate(); return; }
    let sessionError = '';
    try {
      const session = await api('/api/session'); state.authenticated = session.authenticated === true;
      if (state.authenticated) $('connection-status').replaceWith(Object.assign(badge('info', 'Sessione locale'), { id: 'connection-status' }));
    } catch (error) { sessionError = errorText(error); }
    await navigate();
    if (sessionError && !state.shared) message(`Connessione al laboratorio non disponibile: ${sessionError}`, 'warning');
  }
  updateStaticMode(); start(); setInterval(refresh, 5000); setInterval(loadRuntimeStatus, 60000);
})();

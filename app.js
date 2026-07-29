// Fetches the encrypted snapshot, decrypts it in the browser with a viewer-supplied
// passphrase, and renders the tiles. The passphrase never leaves the page; the server
// (GitHub Pages) only ever holds ciphertext.

const REFRESH_MS = 60_000;
const STORAGE_KEY = 'status-board-passphrase';

const els = {
  html: document.documentElement,
  gateForm: document.getElementById('gate-form'),
  passphrase: document.getElementById('passphrase'),
  remember: document.getElementById('remember'),
  unlock: document.getElementById('unlock'),
  gateError: document.getElementById('gate-error'),
  board: document.getElementById('board'),
  rows: document.getElementById('rows'),
  generated: document.getElementById('meta-generated'),
  refresh: document.getElementById('meta-refresh'),
  failing: document.getElementById('meta-failing'),
  lock: document.getElementById('lock'),
  rowTemplate: document.getElementById('row-template'),
  tileTemplate: document.getElementById('tile-template'),
};

const STATE_WORDS = {
  success: 'Passing',
  running: 'Running',
  failure: 'Failing',
  idle: 'Idle',
  none: 'No runs',
  absent: 'Not wired',
};

const STATE_GLYPHS = {
  success: '✓',
  running: '▸',
  failure: '✕',
  idle: '‖',
  none: '·',
  absent: '·',
};

let passphrase = null;
let refreshTimer = null;
let countdownTimer = null;
let nextRefreshAt = 0;

const b64ToBytes = (value) => Uint8Array.from(atob(value), (c) => c.charCodeAt(0));

async function decryptSnapshot(payload, secret) {
  const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), 'PBKDF2', false, [
    'deriveKey',
  ]);
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: b64ToBytes(payload.kdf.salt),
      iterations: payload.kdf.iterations,
      hash: payload.kdf.hash,
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64ToBytes(payload.iv) },
    key,
    b64ToBytes(payload.ct),
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

async function fetchPayload() {
  const res = await fetch(`data.enc.json?ts=${Date.now()}`, { cache: 'no-store' });
  if (!res.ok) throw new Error(`payload unavailable (${res.status})`);
  return res.json();
}

function relativeTime(iso) {
  if (!iso) return '—';
  const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  const units = [
    ['d', 86_400],
    ['h', 3_600],
    ['m', 60],
  ];
  for (const [suffix, size] of units) {
    if (seconds >= size) return `${Math.floor(seconds / size)}${suffix} ago`;
  }
  return seconds > 5 ? `${seconds}s ago` : 'just now';
}

function duration(run) {
  if (!run?.startedAt) return null;
  const end = run.status === 'completed' ? new Date(run.updatedAt) : new Date();
  const seconds = Math.max(0, Math.round((end - new Date(run.startedAt)) / 1000));
  const minutes = Math.floor(seconds / 60);
  return minutes >= 60
    ? `${Math.floor(minutes / 60)}h${minutes % 60}m`
    : `${minutes}m${String(seconds % 60).padStart(2, '0')}s`;
}

function renderTile(tile) {
  const node = els.tileTemplate.content.firstElementChild.cloneNode(true);
  node.dataset.state = tile.state;
  node.querySelector('.tile__glyph').textContent = STATE_GLYPHS[tile.state] ?? '·';
  node.querySelector('.tile__label').textContent = tile.label;
  node.querySelector('.tile__state').textContent = STATE_WORDS[tile.state] ?? tile.state;

  const detail = node.querySelector('.tile__detail');
  const foot = node.querySelector('.tile__foot');
  const run = tile.run;

  if (!run) {
    detail.textContent = tile.state === 'absent' ? 'No workflow mapped' : 'Never run';
    foot.textContent = '';
    node.removeAttribute('href');
    return node;
  }

  node.href = run.url;
  detail.textContent = run.title ?? '';
  const parts = [
    run.branch ? `${run.branch}@${run.sha ?? '?'}` : run.sha,
    relativeTime(run.status === 'completed' ? run.updatedAt : run.startedAt),
    duration(run),
  ].filter(Boolean);
  foot.textContent = parts.join('  ·  ');
  return node;
}

function render(snapshot) {
  els.rows.replaceChildren();
  let failing = 0;

  snapshot.repos.forEach((repo, index) => {
    const row = els.rowTemplate.content.firstElementChild.cloneNode(true);
    row.style.animationDelay = `${index * 55}ms`;
    row.querySelector('.row__name').textContent = repo.name;
    const link = row.querySelector('.row__link');
    link.href = repo.url;

    const tiles = row.querySelector('.row__tiles');
    for (const tile of repo.tiles) {
      if (tile.state === 'failure') failing += 1;
      tiles.append(renderTile(tile));
    }
    els.rows.append(row);
  });

  els.generated.textContent = relativeTime(snapshot.generatedAt);
  els.failing.textContent = String(failing);
  els.failing.dataset.alarm = String(failing > 0);
  document.title = failing > 0 ? `(${failing}) Status Board` : 'Status Board';
}

function startCountdown() {
  nextRefreshAt = Date.now() + REFRESH_MS;
  clearInterval(countdownTimer);
  countdownTimer = setInterval(() => {
    const seconds = Math.max(0, Math.round((nextRefreshAt - Date.now()) / 1000));
    els.refresh.textContent = `in ${seconds}s`;
  }, 1000);
}

async function load() {
  const snapshot = await decryptSnapshot(await fetchPayload(), passphrase);
  render(snapshot);
  startCountdown();
}

function scheduleRefresh() {
  clearInterval(refreshTimer);
  refreshTimer = setInterval(() => {
    load().catch((error) => {
      els.refresh.textContent = 'stalled';
      console.error(error);
    });
  }, REFRESH_MS);
}

function unlockUI() {
  els.html.dataset.state = 'unlocked';
  els.board.hidden = false;
  scheduleRefresh();
}

async function attempt(secret, { persist }) {
  passphrase = secret;
  await load();
  if (persist) localStorage.setItem(STORAGE_KEY, secret);
  unlockUI();
}

els.gateForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  els.gateError.hidden = true;
  els.unlock.disabled = true;
  els.unlock.textContent = 'Decrypting…';
  try {
    await attempt(els.passphrase.value, { persist: els.remember.checked });
  } catch (error) {
    els.gateError.hidden = false;
    els.gateError.textContent =
      error instanceof Error && /payload/.test(error.message) ? error.message : 'Wrong passphrase — nothing decrypted.';
  } finally {
    els.unlock.disabled = false;
    els.unlock.textContent = 'Decrypt';
  }
});

els.lock.addEventListener('click', () => {
  localStorage.removeItem(STORAGE_KEY);
  location.reload();
});

// Re-read as soon as the tab is looked at again, so a board left open overnight is never stale.
document.addEventListener('visibilitychange', () => {
  if (!document.hidden && els.html.dataset.state === 'unlocked') load().catch(console.error);
});

const stored = localStorage.getItem(STORAGE_KEY);
if (stored) {
  attempt(stored, { persist: true }).catch(() => {
    localStorage.removeItem(STORAGE_KEY);
  });
}

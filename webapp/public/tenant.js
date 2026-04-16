(function () {
  const STORAGE_KEY = 'pcr_tenant';
  const THEME_KEY = 'pcr_theme';
  let tenants = [];
  let currentSlug = localStorage.getItem(STORAGE_KEY) || '';

  function getCurrentTenant() { return currentSlug || 'default'; }

  function setTenant(slug) {
    currentSlug = slug;
    localStorage.setItem(STORAGE_KEY, slug);
  }

  function getTheme() { return localStorage.getItem(THEME_KEY) || 'dark'; }

  function setTheme(theme) {
    localStorage.setItem(THEME_KEY, theme);
    applyTheme(theme);
  }

  function applyTheme(theme) {
    if (theme === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
    const btn = document.getElementById('theme-toggle-btn');
    if (btn) btn.innerHTML = theme === 'light' ? '&#9790;' : '&#9728;';
  }

  function toggleTheme() {
    setTheme(getTheme() === 'dark' ? 'light' : 'dark');
  }

  (function initThemeEarly() {
    applyTheme(getTheme());
  })();

  async function apiFetch(url, opts = {}) {
    opts.headers = opts.headers || {};
    if (typeof opts.headers.set === 'function') {
      opts.headers.set('X-Tenant', getCurrentTenant());
    } else {
      opts.headers['X-Tenant'] = getCurrentTenant();
    }
    return fetch(url, opts);
  }

  function escHtml(s) {
    const d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
  }

  async function initTenantSwitcher() {
    try {
      const resp = await fetch('/api/tenants');
      if (resp.ok) tenants = await resp.json();
    } catch (_) {
      tenants = [];
    }

    if (!tenants.length) return;
    const validSlugs = tenants.map(t => t.slug);
    if (!currentSlug || !validSlugs.includes(currentSlug)) setTenant(tenants[0].slug);

    const slot = document.getElementById('tenant-slot');
    if (!slot) return;

    const options = tenants.map(t =>
      `<option value="${escHtml(t.slug)}"${t.slug === getCurrentTenant() ? ' selected' : ''}>${escHtml(t.name)}</option>`
    ).join('');

    slot.innerHTML = `<div class="nav-tenant">
      <label class="tenant-label">Tenant</label>
      <select class="tenant-select" onchange="TenantCtx.setTenant(this.value);location.reload()">${options}</select>
    </div>`;
  }

  function initThemeToggle() {
    const slot = document.getElementById('theme-slot');
    if (!slot) return;
    const icon = getTheme() === 'light' ? '&#9790;' : '&#9728;';
    slot.innerHTML = `<button class="theme-toggle" id="theme-toggle-btn" onclick="TenantCtx.toggleTheme()" title="Toggle light/dark theme">${icon}</button>`;
  }

  document.addEventListener('DOMContentLoaded', () => {
    initThemeToggle();
    initTenantSwitcher();
  });

  window.TenantCtx = { getCurrentTenant, setTenant, apiFetch, initTenantSwitcher, toggleTheme, getTheme, setTheme };
})();

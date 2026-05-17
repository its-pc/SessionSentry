function updateClock() {
  const el = document.getElementById('topbar-time');
  if (el) {
    const now = new Date();
    el.textContent = now.toLocaleTimeString('en-US', { hour12: false });
  }
}
setInterval(updateClock, 1000);
updateClock();

function toggleSidebar() {
  document.getElementById('sidebar')?.classList.toggle('open');
}

function updateAlertBadge() {
  const badge = document.getElementById('alert-count');
  if (!badge) return;
  fetch('/api/stats')
    .then(r => r.json())
    .then(d => {
      badge.textContent = d.alerts > 0 ? d.alerts : '—';
      badge.style.background = d.alerts > 0 ? 'var(--danger)' : '#eef2f7';
      badge.style.color = d.alerts > 0 ? '#fff' : 'var(--text-dim)';
    })
    .catch(() => {});
}

if (document.getElementById('alert-count')) {
  updateAlertBadge();
  setInterval(updateAlertBadge, 15000);
}

document.querySelectorAll('.flash-msg').forEach(el => {
  setTimeout(() => {
    el.style.transition = 'opacity .5s';
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 500);
  }, 5000);
});

document.querySelectorAll('.stat-value').forEach(el => {
  const target = parseFloat(el.textContent);
  if (isNaN(target) || target === 0) return;
  let start = 0;
  const step = target / 25;
  const timer = setInterval(() => {
    start = Math.min(start + step, target);
    el.textContent = Number.isInteger(target) ? Math.round(start) : start.toFixed(1);
    if (start >= target) clearInterval(timer);
  }, 30);
});

const sessionStatusEl = document.querySelector('.risk-bar-fill');
if (sessionStatusEl && !document.querySelector('.stats-row .stat-card')) {
  setInterval(() => {
    fetch('/api/session-status')
      .then(r => r.json())
      .then(d => {
        const statusCard = document.querySelector('.card-session-status');
        if (!statusCard) return;
        if (d.is_hijacked) {
          statusCard.classList.add('card-danger');
        }
      })
      .catch(() => {});
  }, 10000);
}


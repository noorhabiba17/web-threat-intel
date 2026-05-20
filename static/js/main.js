// ===== Auto-dismiss toasts =====
document.querySelectorAll('.toast').forEach(t => {
  setTimeout(() => {
    try { bootstrap.Toast.getOrCreateInstance(t).hide(); } catch(e) {}
  }, 5000);
});

// ===== Navbar scroll effect =====
const nav = document.querySelector('.wti-nav');
if (nav) {
  window.addEventListener('scroll', () => {
    nav.classList.toggle('scrolled', window.scrollY > 50);
  }, { passive: true });
}

// ===== Stat counter animation =====
function animateCounters() {
  document.querySelectorAll('.card .h3.mb-0').forEach(el => {
    const text = el.textContent.trim();
    const target = parseInt(text);
    if (isNaN(target) || target <= 0) return;
    const suffix = text.replace(/[\d]/g, '');
    const duration = Math.min(1200, target * 20);
    const start = performance.now();
    function update(now) {
      const elapsed = now - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = Math.floor(eased * target);
      el.textContent = current + suffix;
      if (progress < 1) requestAnimationFrame(update);
    }
    requestAnimationFrame(update);
  });
}

// Run counter on pages with stats (dashboard, admin)
if (document.querySelector('.card .h3.mb-0')) {
  if (document.readyState === 'complete') {
    setTimeout(animateCounters, 300);
  } else {
    window.addEventListener('load', () => setTimeout(animateCounters, 300));
  }
}

// ===== Typing effect for hero heading =====
const heroEl = document.querySelector('.hero h1');
if (heroEl && !sessionStorage.getItem('heroTyped')) {
  const original = heroEl.innerHTML;
  // Only apply if the text is short enough (hero page only)
  if (original.length < 120) {
    heroEl.innerHTML = '<span class="typing-cursor">|</span>';
    let idx = 0;
    const chars = original;
    function type() {
      if (idx < chars.length) {
        heroEl.innerHTML = chars.substring(0, idx + 1) + '<span class="typing-cursor">|</span>';
        idx++;
        const delay = chars[idx - 1] === ' ' ? 40 : 25 + Math.random() * 30;
        setTimeout(type, delay);
      } else {
        heroEl.innerHTML = chars;
        sessionStorage.setItem('heroTyped', '1');
      }
    }
    setTimeout(type, 500);
  }
}

// ===== Scan button spinner =====
const scanForm = document.getElementById('scanForm');
const scanBtn = document.getElementById('scanBtn');
const spin = document.getElementById('spin');
if (scanForm && scanBtn) {
  scanForm.addEventListener('submit', () => {
    spin.classList.remove('d-none');
    scanBtn.disabled = true;
  });
}

// ===== History row click =====
document.querySelectorAll('.scan-row').forEach(r => {
  r.addEventListener('click', function() { window.location.href = this.dataset.href; });
});

// ===== Page entrance stagger =====
document.addEventListener('DOMContentLoaded', () => {
  const cards = document.querySelectorAll('.wti-card');
  cards.forEach((card, i) => {
    card.style.animationDelay = `${i * 0.08}s`;
  });
});

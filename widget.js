
(() => {
  const script = document.currentScript;
  const siteKey = script?.dataset?.siteKey;
  const apiBase = script?.dataset?.apiBase || '';

  let mouseMoves = 0;
  let scrollDepth = 0;
  let startedAt = performance.now();
  let lastKey = 0;
  let typingIntervals = [];

  document.addEventListener('mousemove', () => mouseMoves++, { passive: true });
  document.addEventListener('scroll', () => {
    const doc = document.documentElement;
    const max = Math.max(1, doc.scrollHeight - window.innerHeight);
    scrollDepth = Math.max(scrollDepth, Math.min(100, (window.scrollY / max) * 100));
  }, { passive: true });
  document.addEventListener('keydown', () => {
    const now = performance.now();
    if (lastKey) typingIntervals.push(now - lastKey);
    if (typingIntervals.length > 30) typingIntervals.shift();
    lastKey = now;
  });

  function avgTyping() {
    if (!typingIntervals.length) return 0;
    return typingIntervals.reduce((a,b)=>a+b,0) / typingIntervals.length;
  }

  async function send(action, payload = '') {
    const body = {
      siteKey,
      route: location.pathname,
      action,
      payload,
      dwellMs: Math.round(performance.now() - startedAt),
      mouseMoves,
      avgTypingMs: avgTyping(),
      scrollDepth,
      webdriver: !!navigator.webdriver
    };

    const res = await fetch(`${apiBase}/api/intake`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(body)
    });

    return res.json();
  }

  window.AsoProtection = {
    send,
    async protectForm(selector) {
      const form = document.querySelector(selector);
      if (!form) return;
      form.addEventListener('submit', async (e) => {
        const data = new FormData(form);
        const payload = Array.from(data.values()).join(' ');
        const result = await send('form-submit', payload);
        if (result.decision === 'block') {
          e.preventDefault();
          alert('Ação bloqueada por segurança.');
        } else if (result.decision === 'challenge') {
          e.preventDefault();
          alert('Verificação adicional necessária.');
        }
      });
    }
  };
})();


(() => {
  const state = {
    user: null,
    captchaFailures: 0,
    captchaBlockedUntil: 0,
    currentCaptchaAction: null,
    currentChallengeAnswer: '',
    currentChallengeVoice: '',
    currentChallengeType: '',
    captchaToken: '',
    telemetry: {
      startAt: performance.now(),
      mouseMoves: 0,
      scrollDepth: 0,
      keyEvents: 0,
      lastKeyAt: 0,
      typingIntervals: []
    }
  };

  const $ = (id) => document.getElementById(id);

  document.addEventListener('mousemove', () => state.telemetry.mouseMoves++, { passive: true });
  document.addEventListener('scroll', () => {
    const doc = document.documentElement;
    const max = Math.max(1, doc.scrollHeight - window.innerHeight);
    state.telemetry.scrollDepth = Math.max(
      state.telemetry.scrollDepth,
      Math.min(100, (window.scrollY / max) * 100)
    );
  }, { passive: true });
  document.addEventListener('keydown', () => {
    const now = performance.now();
    if (state.telemetry.lastKeyAt) {
      state.telemetry.typingIntervals.push(now - state.telemetry.lastKeyAt);
      if (state.telemetry.typingIntervals.length > 40) state.telemetry.typingIntervals.shift();
    }
    state.telemetry.lastKeyAt = now;
  });

  function avg(arr) {
    if (!arr.length) return 0;
    return arr.reduce((a, b) => a + b, 0) / arr.length;
  }

  function setStatus(id, text, color = '') {
    const el = $(id);
    if (!el) return;
    el.textContent = text;
    el.style.color = color || '';
  }

  async function api(path, method = 'GET', body) {
    const opts = {
      method,
      headers: { 'Accept': 'application/json' },
      credentials: 'same-origin'
    };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    const data = await res.json().catch(() => ({ ok: false, message: 'Resposta inválida.' }));
    if (!res.ok) throw new Error(data.message || 'Erro');
    return data;
  }

  function switchAuthTab(mode) {
    $('loginTab').classList.toggle('active', mode === 'login');
    $('registerTab').classList.toggle('active', mode === 'register');
    $('loginFormWrap').classList.toggle('hidden', mode !== 'login');
    $('registerFormWrap').classList.toggle('hidden', mode !== 'register');
  }

  async function registerUser() {
    try {
      setStatus('registerStatus', 'Criando conta...');
      const data = await api('/api/auth/register', 'POST', {
        email: $('registerEmail').value.trim(),
        password: $('registerPassword').value
      });
      state.user = data.user;
      $('authScreen').classList.add('hidden');
      $('appScreen').classList.remove('hidden');
      renderDashboard();
    } catch (err) {
      setStatus('registerStatus', err.message, '#c53b3b');
    }
  }

  async function loginUser() {
    try {
      setStatus('loginStatus', 'Entrando...');
      const data = await api('/api/auth/login', 'POST', {
        email: $('loginEmail').value.trim(),
        password: $('loginPassword').value
      });
      state.user = data.user;
      $('authScreen').classList.add('hidden');
      $('appScreen').classList.remove('hidden');
      renderDashboard();
    } catch (err) {
      setStatus('loginStatus', err.message, '#c53b3b');
    }
  }

  async function logoutUser() {
    await api('/api/auth/logout', 'POST', {});
    state.user = null;
    location.href = '/';
  }

  function assessBehaviorScore() {
    let score = 0.5;
    const dwell = performance.now() - state.telemetry.startAt;
    if (dwell > 2500) score += 0.12; else score -= 0.08;
    if (state.telemetry.mouseMoves > 10) score += 0.12; else score -= 0.07;
    if (state.telemetry.scrollDepth > 8) score += 0.04;
    const avgTyping = avg(state.telemetry.typingIntervals);
    if (avgTyping > 40 && avgTyping < 450) score += 0.04;
    return Math.max(0, Math.min(1, score));
  }

  function openCaptcha(action) {
    if (Date.now() < state.captchaBlockedUntil) {
      setStatus('keyStatus', 'CAPTCHA temporariamente bloqueado. Aguarde alguns segundos.', '#c53b3b');
      return;
    }
    state.currentCaptchaAction = action;
    $('captchaOverlay').classList.add('open');
    $('challengeWrap').classList.add('hidden');
    $('challengeActions').classList.add('hidden');
    $('challengeInput').value = '';
    $('challengeText').textContent = 'Clique no checkbox para iniciar.';
    $('captchaStatus').textContent = '';
    state.captchaToken = '';
    resetCaptchaCheck();
  }

  function closeCaptcha() {
    $('captchaOverlay').classList.remove('open');
    resetCaptchaCheck();
  }

  function resetCaptchaCheck() {
    const anchor = $('recaptcha-anchor');
    anchor.className = 'recaptcha-checkbox';
    anchor.setAttribute('aria-checked', 'false');
  }

  function randomCaptchaText(len = 5) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    let out = '';
    for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
    return out;
  }

  function drawChallenge(text) {
    const canvas = $('captchaCanvas');
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;

    ctx.clearRect(0, 0, w, h);
    const g = ctx.createLinearGradient(0, 0, w, h);
    g.addColorStop(0, '#081321');
    g.addColorStop(1, '#10203a');
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, w, h);

    for (let i = 0; i < 32; i++) {
      ctx.fillStyle = 'rgba(255,255,255,0.12)';
      ctx.fillRect(Math.random() * w, Math.random() * h, 2, 2);
    }

    for (let i = 0; i < 7; i++) {
      ctx.strokeStyle = 'rgba(255,255,255,0.07)';
      ctx.beginPath();
      ctx.moveTo(Math.random() * w, 0);
      ctx.lineTo(Math.random() * w, h);
      ctx.stroke();
    }

    if (state.currentChallengeType === 'letters') {
      ctx.font = 'bold 58px Arial';
      ctx.textBaseline = 'middle';

      for (let i = 0; i < text.length; i++) {
        const x = 52 + i * 95;
        const y = 92 + (Math.random() * 16 - 8);
        const angle = (Math.random() - 0.5) * 0.45;
        ctx.save();
        ctx.translate(x, y);
        ctx.rotate(angle);
        ctx.fillStyle = '#f3f8ff';
        ctx.shadowColor = '#1a73e8';
        ctx.shadowBlur = 10;
        ctx.fillText(text[i], 0, 0);
        ctx.restore();
      }
    } else {
      ctx.save();
      ctx.translate(w / 2, h / 2);
      ctx.rotate((Math.random() - 0.5) * 0.05);
      ctx.textAlign = 'center';
      ctx.font = 'bold 48px Arial';
      ctx.fillStyle = '#f3f8ff';
      ctx.shadowColor = '#1a73e8';
      ctx.shadowBlur = 12;
      ctx.fillText(text, 0, 12);
      ctx.restore();
    }
  }

  async function runCaptchaAnalysis() {
    if (Date.now() < state.captchaBlockedUntil) {
      setStatus('captchaStatus', 'Bloqueado temporariamente por erros repetidos.', '#c53b3b');
      return;
    }

    const anchor = $('recaptcha-anchor');
    if (anchor.classList.contains('loading') || anchor.classList.contains('done')) return;

    anchor.classList.add('loading');
    await new Promise(r => setTimeout(r, 1200));

    const score = assessBehaviorScore();
    anchor.classList.remove('loading');

    if (score >= 0.78) {
      anchor.classList.add('done');
      anchor.setAttribute('aria-checked', 'true');
      setStatus('captchaStatus', 'Sessão aprovada sem desafio adicional.', '#1f8a5b');
      try {
        const result = await api('/api/captcha/verify', 'POST', {
          challengeType: 'behavior',
          answer: 'OK',
          expected: 'OK'
        });
        state.captchaToken = result.captchaToken;
      } catch (_) {}
      onCaptchaSuccess(score);
      return;
    }

    const useLetters = Math.random() > 0.5;
    if (useLetters) {
      state.currentChallengeType = 'letters';
      state.currentChallengeAnswer = randomCaptchaText();
      state.currentChallengeVoice = state.currentChallengeAnswer.split('').join(' ');
      $('challengeText').textContent = 'Leia as letras da imagem e digite corretamente.';
      drawChallenge(state.currentChallengeAnswer);
    } else {
      state.currentChallengeType = 'math';
      const a = Math.floor(Math.random() * 9) + 1;
      const b = Math.floor(Math.random() * 9) + 1;
      state.currentChallengeAnswer = String(a + b);
      state.currentChallengeVoice = `Quanto é ${a} mais ${b}?`;
      $('challengeText').textContent = `Resolva a conta: ${a} + ${b} = ?`;
      drawChallenge($('challengeText').textContent);
    }

    $('challengeWrap').classList.remove('hidden');
    $('challengeActions').classList.remove('hidden');
    setStatus('captchaStatus', 'Desafio adicional necessário.', '#b7791f');
  }

  function speakChallenge() {
    if (!('speechSynthesis' in window)) {
      setStatus('captchaStatus', 'Seu navegador não suporta áudio.', '#c53b3b');
      return;
    }
    window.speechSynthesis.cancel();
    const u = new SpeechSynthesisUtterance(state.currentChallengeVoice);
    u.lang = 'pt-BR';
    u.rate = 0.92;
    window.speechSynthesis.speak(u);
  }

  async function verifyChallenge() {
    const value = $('challengeInput').value.trim().toUpperCase();

    if (value !== state.currentChallengeAnswer.toUpperCase()) {
      state.captchaFailures++;
      if (state.captchaFailures >= 15) {
        state.captchaBlockedUntil = Date.now() + 5000;
        state.captchaFailures = 0;
        setStatus('captchaStatus', '15 erros. CAPTCHA bloqueado por 5 segundos.', '#c53b3b');
        return;
      }

      setStatus('captchaStatus', `Resposta incorreta. Tentativas acumuladas: ${state.captchaFailures}/15`, '#c53b3b');

      if (state.currentChallengeType === 'letters') {
        state.currentChallengeAnswer = randomCaptchaText();
        state.currentChallengeVoice = state.currentChallengeAnswer.split('').join(' ');
        drawChallenge(state.currentChallengeAnswer);
      } else {
        const a = Math.floor(Math.random() * 9) + 1;
        const b = Math.floor(Math.random() * 9) + 1;
        state.currentChallengeAnswer = String(a + b);
        state.currentChallengeVoice = `Quanto é ${a} mais ${b}?`;
        $('challengeText').textContent = `Resolva a conta: ${a} + ${b} = ?`;
        drawChallenge($('challengeText').textContent);
      }

      $('challengeInput').value = '';
      return;
    }

    try {
      const result = await api('/api/captcha/verify', 'POST', {
        challengeType: state.currentChallengeType,
        answer: value,
        expected: state.currentChallengeAnswer
      });
      state.captchaToken = result.captchaToken;
      setStatus('captchaStatus', 'Desafio concluído com sucesso.', '#1f8a5b');
      onCaptchaSuccess(0.86);
    } catch (err) {
      setStatus('captchaStatus', err.message, '#c53b3b');
    }
  }

  async function createKey() {
    try {
      setStatus('keyStatus', 'Gerando key...');
      const data = await api('/api/keys/create', 'POST', {
        project: $('projectName').value.trim(),
        domain: $('projectDomain').value.trim(),
        captchaToken: state.captchaToken
      });

      $('keysBox').classList.remove('hidden');
      $('siteKeyValue').textContent = data.key.siteKey;
      $('secretKeyValue').textContent = data.key.secretKey;

      $('installSnippet').textContent =
`<script
  src="https://SEU-DOMINIO.com/api/widget.js"
  data-site-key="${data.key.siteKey}"
  data-api-base="https://SEU-DOMINIO.com">
</script>`;

      $('javaSnippet').textContent =
`ShieldVerifier verifier = new ShieldVerifier(
  "https://SEU-DOMINIO.com",
  "${data.key.siteKey}",
  "${data.key.secretKey}"
);

boolean ok = verifier.verify(token, "/login");`;

      setStatus('keyStatus', 'Chaves geradas com sucesso.', '#1f8a5b');
      await renderDashboard();
    } catch (err) {
      setStatus('keyStatus', err.message, '#c53b3b');
    }
  }

  function onCaptchaSuccess() {
    const anchor = $('recaptcha-anchor');
    anchor.classList.add('done');
    anchor.setAttribute('aria-checked', 'true');
    if (state.currentCaptchaAction === 'generateKey') {
      createKey();
    }
    setTimeout(closeCaptcha, 400);
  }

  async function renderDashboard() {
    const data = await api('/api/dashboard');
    state.user = state.user || data.user;
    $('welcomeText').textContent = `Bem-vindo, ${state.user.email}. Gere suas keys e acompanhe requisições, bloqueios e risco.`;

    if (Date.now() < state.user.trialEndsAt) {
      const days = Math.max(0, Math.ceil((state.user.trialEndsAt - Date.now()) / (24 * 60 * 60 * 1000)));
      $('planBadge').textContent = `Trial Pro ativo · ${days} dia(s)`;
      $('planBadge').className = 'badge badge-info';
    } else {
      $('planBadge').textContent = 'Plano Free';
      $('planBadge').className = 'badge badge-warning';
    }

    $('reqCount').textContent = String(data.metrics.requestCount);
    $('blockedCount').textContent = String(data.metrics.blockedCount);
    $('avgScore').textContent = Number(data.metrics.avgScore).toFixed(2);
    $('keyCount').textContent = String(data.metrics.keyCount);

    const keysTable = $('keysTable');
    keysTable.innerHTML = '';
    if (!data.keys.length) {
      keysTable.innerHTML = `<tr><td colspan="4" style="color:#66778c;padding-top:14px">Nenhuma key criada ainda.</td></tr>`;
    } else {
      data.keys.forEach(k => {
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${k.project}</td><td>${k.domain}</td><td>${k.requestCount}</td><td>${k.blockedCount}</td>`;
        keysTable.appendChild(tr);
      });
    }

    const requestsTable = $('requestsTable');
    requestsTable.innerHTML = '';
    if (!data.events.length) {
      requestsTable.innerHTML = `<tr><td colspan="4" style="color:#66778c;padding-top:14px">Sem eventos ainda.</td></tr>`;
    } else {
      data.events.slice(0, 12).forEach(e => {
        const cls = e.decision === 'Liberado' || e.decision === 'allow'
          ? 'badge-success'
          : e.decision === 'Desafio' || e.decision === 'challenge'
            ? 'badge-warning'
            : 'badge-danger';
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${new Date(e.createdAt).toLocaleTimeString('pt-BR')}</td><td>${e.ipMasked || e.ip}</td><td>${e.route}</td><td><span class="badge ${cls}">${e.decision}</span></td>`;
        requestsTable.appendChild(tr);
      });
    }

    const blockedList = $('blockedList');
    blockedList.innerHTML = '';
    if (!data.blocked.length) {
      blockedList.innerHTML = `<div class="list-item"><p>Nenhum IP bloqueado ainda.</p></div>`;
    } else {
      data.blocked.forEach(b => {
        const div = document.createElement('div');
        div.className = 'list-item';
        div.innerHTML = `<div class="list-top"><div class="list-title">${b.ipMasked || b.ip}</div><span class="badge badge-danger">${Math.max(1, Math.floor((b.until - Date.now()) / 60000))} min</span></div><p>${b.reason}</p>`;
        blockedList.appendChild(div);
      });
    }

    const suspectList = $('suspectList');
    suspectList.innerHTML = '';
    const suspects = data.events.filter(e => String(e.decision).toLowerCase() !== 'liberado' && String(e.decision).toLowerCase() !== 'allow').slice(0, 6);
    if (!suspects.length) {
      suspectList.innerHTML = `<div class="list-item"><p>Nenhuma sessão suspeita relevante no momento.</p></div>`;
    } else {
      suspects.forEach(s => {
        const cls = String(s.decision).toLowerCase().includes('bloq') || String(s.decision).toLowerCase() === 'block' ? 'badge-danger' : 'badge-warning';
        const div = document.createElement('div');
        div.className = 'list-item';
        div.innerHTML = `<div class="list-top"><div class="list-title">${s.ipMasked || s.ip} · ${s.route}</div><span class="badge ${cls}">Score ${Number(s.score || 0.5).toFixed(2)}</span></div><p>Motivo: ${s.reason || 'sessão suspeita'}</p>`;
        suspectList.appendChild(div);
      });
    }

    if (data.keys[0]) {
      $('installSnippet').textContent =
`<script
  src="https://SEU-DOMINIO.com/api/widget.js"
  data-site-key="${data.keys[0].siteKey || 'pk_live_exemplo'}"
  data-api-base="https://SEU-DOMINIO.com">
</script>`;
      $('javaSnippet').textContent =
`ShieldVerifier verifier = new ShieldVerifier(
  "https://SEU-DOMINIO.com",
  "${data.keys[0].siteKey || 'pk_live_exemplo'}",
  "secret-real-somente-na-criacao"
);

boolean ok = verifier.verify(token, "/login");`;
    }
  }

  async function bootstrap() {
    try {
      const me = await api('/api/me');
      if (me.ok) {
        state.user = me.user;
        $('authScreen').classList.add('hidden');
        $('appScreen').classList.remove('hidden');
        await renderDashboard();
      }
    } catch (_) {}
  }

  $('loginTab').addEventListener('click', () => switchAuthTab('login'));
  $('registerTab').addEventListener('click', () => switchAuthTab('register'));
  $('registerBtn').addEventListener('click', registerUser);
  $('loginBtn').addEventListener('click', loginUser);
  $('logoutBtn').addEventListener('click', logoutUser);

  $('openCaptchaBtn').addEventListener('click', () => {
    if (!$('projectName').value.trim() || !$('projectDomain').value.trim()) {
      setStatus('keyStatus', 'Preencha o projeto e o domínio antes de continuar.', '#c53b3b');
      return;
    }
    openCaptcha('generateKey');
  });

  $('closeCaptchaBtn').addEventListener('click', closeCaptcha);
  $('recaptcha-anchor').addEventListener('click', runCaptchaAnalysis);
  $('recaptcha-anchor').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      runCaptchaAnalysis();
    }
  });
  $('verifyChallengeBtn').addEventListener('click', verifyChallenge);
  $('speakBtn').addEventListener('click', speakChallenge);
  $('challengeInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') verifyChallenge();
  });

  bootstrap();
})();

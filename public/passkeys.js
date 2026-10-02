/* Native WebAuthn UI. Authentication state stays in app.js's in-memory ticket. */
(() => {
  window.webmuxPasskeys = {
    init({ getToken, absorbTicket, onLogin, onLogout, remember }) {
      // Retire the old credential-ID-derived local secret cache. A real passkey
      // signs a server challenge; the shared secret is never saved in the browser.
      try { localStorage.removeItem('webmux-bio'); } catch {}
      const login = document.querySelector('#passkey-login');
      const dialog = document.querySelector('#passkey-dialog');
      const message = dialog.querySelector('.passkey-message');
      const reauth = dialog.querySelector('.passkey-reauth');
      const form = dialog.querySelector('form');
      const fields = form.querySelector('fieldset');
      const username = form.elements.username;
      const admin = form.elements.admin;
      const list = dialog.querySelector('.passkey-list');
      let config = null;
      let busy = false;
      let view = 0;
      let loginAttempt = 0;

      async function request(url, body, authenticated = false, retry = false) {
        const headers = {};
        if (body !== undefined) headers['Content-Type'] = 'application/json';
        if (authenticated) headers['X-Token'] = getToken();
        const res = await fetch('/api/auth/passkeys' + url, {
          method: body === undefined ? 'GET' : 'POST', headers,
          body: body === undefined ? undefined : JSON.stringify(body),
        });
        if (authenticated) absorbTicket(res);
        if (authenticated && res.status === 401) {
          // A concurrent poll may just have rotated the ticket.
          if (!retry) {
            await new Promise(resolve => setTimeout(resolve, 80));
            return request(url, body, authenticated, true);
          }
          onLogout({ chooseMethod: true });
          throw new Error('Session expired. Sign in again.');
        }
        const data = await res.json().catch(() => null);
        if (!res.ok || !data) {
          const error = new Error(data?.error || 'Passkey service unavailable. Try again.');
          error.status = res.status;
          throw error;
        }
        return { res, data };
      }
      function errorText(e) {
        if (e.name === 'NotAllowedError' || e.name === 'AbortError') return 'Passkey request cancelled or timed out. Try again.';
        return e.message || 'Passkey request failed. Try again.';
      }

      const ready = request('/config').then(({ data }) => {
        config = data;
        const supported = !!(config.enabled && window.isSecureContext && window.PublicKeyCredential && window.SimpleWebAuthnBrowser);
        login.hidden = !supported;
        return supported;
      }).catch(() => false);

      login.addEventListener('click', async () => {
        if (login.disabled) return;
        const attempt = ++loginAttempt;
        const error = document.querySelector('#passkey-login-error');
        error.hidden = true;
        login.disabled = true;
        try {
          const { data: flow } = await request('/login/options', {});
          if (attempt !== loginAttempt) return;
          const response = await SimpleWebAuthnBrowser.startAuthentication({ optionsJSON: flow.options });
          if (attempt !== loginAttempt) return;
          const { res, data } = await request('/login/verify', { requestId: flow.requestId, response });
          if (attempt !== loginAttempt) return;
          absorbTicket(res, data);
          remember('passkey');
          await onLogin();
        } catch (e) {
          if (attempt === loginAttempt) { error.textContent = errorText(e); error.hidden = false; }
        } finally { if (attempt === loginAttempt) login.disabled = false; }
      });

      function cancelLogin() {
        ++loginAttempt;
        window.SimpleWebAuthnBrowser?.WebAuthnAbortService.cancelCeremony();
        login.disabled = false;
      }

      function setBusy(value) {
        busy = value;
        fields.disabled = value;
        list.querySelectorAll('button').forEach(button => { button.disabled = value; });
        dialog.setAttribute('aria-busy', String(value));
      }

      function showError(e, generation) {
        if (generation !== view || !dialog.open) return;
        message.textContent = errorText(e);
        reauth.hidden = e.status !== 403;
      }

      async function refresh(generation, resetUsername = false) {
        const { data } = await request('/credentials', undefined, true);
        if (generation !== view || !dialog.open) return;
        if (!Array.isArray(data.credentials)) throw new Error('Could not load passkeys. Close and try again.');
        username.readOnly = !data.canCreateUsers;
        if (resetUsername) username.value = data.username || '';
        admin.disabled = !data.canCreateUsers;
        admin.closest('label').hidden = !data.canCreateUsers;
        if (resetUsername) admin.checked = !!data.canCreateUsers;
        form.hidden = !data.canCreateUsers && !data.username;
        if (form.hidden) message.textContent = 'An administrator must create a native account for you before you can add passkeys. External accounts are separate.';
        list.textContent = '';
        if (!data.credentials.length) list.textContent = 'No passkeys registered yet.';
        for (const key of data.credentials) {
          const row = document.createElement('div');
          row.className = 'passkey-row';
          const text = document.createElement('span');
          text.textContent = `${key.username} · ${key.label}${key.admin ? ' · admin' : ''}${key.current ? ' · current' : ''}`;
          const remove = document.createElement('button');
          remove.type = 'button';
          remove.textContent = 'Remove';
          remove.addEventListener('click', async () => {
            if (busy) return;
            if (!confirm(`Remove ${key.label} for ${key.username}? Sessions signed in with this key will be revoked.`)) return;
            const generation = view;
            setBusy(true);
            message.textContent = '';
            reauth.hidden = true;
            try {
              const { data: result } = await request('/credentials/delete', { id: key.id }, true);
              if (result.signedOut) return onLogout({ chooseMethod: true });
              if (generation !== view || !dialog.open) return;
              message.textContent = 'Passkey removed.';
              await refresh(generation);
            } catch (e) { showError(e, generation); }
            finally { setBusy(false); }
          });
          row.append(text, remove);
          list.appendChild(row);
        }
        setBusy(busy);
      }

      async function open() {
        const generation = ++view;
        if (!dialog.open) dialog.showModal();
        message.textContent = '';
        reauth.hidden = true;
        form.hidden = true;
        list.textContent = 'Loading passkeys…';
        const supported = await ready;
        if (generation !== view || !dialog.open) return;
        list.textContent = '';
        if (!supported) {
          message.textContent = !config ? 'Could not load passkey settings. Reload the page to try again.' : config.enabled
            ? 'Passkeys require a supported browser and a secure connection.'
            : 'Set WEBMUX_PUBLIC_URL to this site’s HTTPS origin and restart to enable native passkeys.';
          return;
        }
        try { await refresh(generation, true); }
        catch (e) { showError(e, generation); }
      }
      document.querySelectorAll('[data-passkeys]').forEach(button => button.addEventListener('click', open));
      function close() {
        // Invalidate synchronously: a queued native close event can otherwise
        // arrive after the user has reopened the dialog and cancel the new view.
        ++view;
        window.SimpleWebAuthnBrowser?.WebAuthnAbortService.cancelCeremony();
        dialog.close();
      }
      dialog.querySelector('.passkey-close').addEventListener('click', close);
      dialog.addEventListener('cancel', event => { event.preventDefault(); close(); });
      reauth.addEventListener('click', () => onLogout({ chooseMethod: true }));
      form.addEventListener('submit', async event => {
        event.preventDefault();
        if (busy || form.hidden || !dialog.open) return;
        const generation = view;
        setBusy(true);
        message.textContent = '';
        reauth.hidden = true;
        try {
          const { data: flow } = await request('/register/options', {
            username: username.value, label: form.elements.label.value, admin: admin.checked,
          }, true);
          if (generation !== view || !dialog.open) return;
          const response = await SimpleWebAuthnBrowser.startRegistration({ optionsJSON: flow.options });
          if (generation !== view || !dialog.open) return;
          await request('/register/verify', { requestId: flow.requestId, response }, true);
          remember('passkey');
          if (generation !== view || !dialog.open) return;
          message.textContent = 'Passkey saved. You can now sign in with it on the login screen.';
          await refresh(generation);
        } catch (e) { showError(e, generation); }
        finally { setBusy(false); }
      });
      return { ready, open, cancelLogin };
    },
  };
})();

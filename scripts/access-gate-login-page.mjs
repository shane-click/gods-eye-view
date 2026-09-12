/**
 * @module access-gate-login-page
 *
 * The sign-in page served by the access gate. Self-contained HTML with inline
 * styles in the app's console look, so it renders before any app asset is
 * reachable.
 */

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * @param {object} options
 * @param {string} options.loginPath - Form action.
 * @param {string} options.nextPath - Where to go after sign-in.
 * @param {string} [options.error] - Message to show above the field.
 * @returns {string} Full HTML document.
 */
export function renderLoginPage({ loginPath, nextPath, error = '' }) {
  const errorBlock = error
    ? `<p class="error" role="alert">${escapeHtml(error)}</p>`
    : '';
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>God's Eye View</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: grid; place-items: center;
    background: radial-gradient(ellipse at 50% 30%, #0b1a2b 0%, #04070d 65%);
    color: #cfe9ff; font: 15px/1.5 ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  }
  form {
    width: min(360px, calc(100vw - 32px)); padding: 28px 28px 24px;
    border: 1px solid rgba(95, 211, 255, 0.35); border-radius: 6px;
    background: rgba(5, 12, 22, 0.85); box-shadow: 0 0 40px rgba(95, 211, 255, 0.08);
  }
  h1 { margin: 0 0 4px; font-size: 18px; letter-spacing: 0.18em; color: #5fd3ff; }
  .sub { margin: 0 0 22px; font-size: 11px; letter-spacing: 0.22em; color: rgba(207, 233, 255, 0.55); }
  label { display: block; font-size: 11px; letter-spacing: 0.16em; margin-bottom: 8px; color: rgba(207, 233, 255, 0.75); }
  input {
    width: 100%; padding: 11px 12px; font: inherit; color: #e6f4ff;
    background: #050a12; border: 1px solid rgba(95, 211, 255, 0.4); border-radius: 4px; outline: none;
  }
  input:focus { border-color: #5fd3ff; box-shadow: 0 0 0 3px rgba(95, 211, 255, 0.15); }
  button {
    margin-top: 16px; width: 100%; padding: 11px; font: inherit; letter-spacing: 0.2em;
    color: #04070d; background: #5fd3ff; border: 0; border-radius: 4px; cursor: pointer;
  }
  button:hover { background: #8ae0ff; }
  .error { margin: 0 0 14px; padding: 8px 10px; font-size: 12px; color: #ffb4b4;
    border: 1px solid rgba(255, 120, 120, 0.4); border-radius: 4px; background: rgba(120, 20, 20, 0.25); }
</style>
</head>
<body>
<form method="post" action="${escapeHtml(loginPath)}" autocomplete="off">
  <h1>GOD'S EYE VIEW</h1>
  <p class="sub">RESTRICTED // ENTER ACCESS CODE</p>
  ${errorBlock}
  <label for="password">ACCESS CODE</label>
  <input id="password" name="password" type="password" autofocus autocomplete="current-password" required>
  <input type="hidden" name="next" value="${escapeHtml(nextPath)}">
  <button type="submit">ENTER</button>
</form>
</body>
</html>
`;
}

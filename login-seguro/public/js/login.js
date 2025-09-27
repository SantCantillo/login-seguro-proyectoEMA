(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const form       = $("login-form");
  const userInp    = $("username");
  const passInp    = $("password");
  const showPwd    = $("visible");
  const errorMsg   = $("error");
  const loadingMsg = $("loading-msg");
  const submitBtn  = form?.querySelector('button[type="submit"]');

  let inFlight = false; // evita dobles envíos

  // Helpers UI
  const showError = (msg) => {
    if (!errorMsg) return;
    errorMsg.textContent = msg || "Ocurrió un error";
    errorMsg.style.display = "block";
    loadingMsg && (loadingMsg.style.display = "none");
  };
  const hideError = () => {
    if (!errorMsg) return;
    errorMsg.textContent = "";
    errorMsg.style.display = "none";
  };
  const setInvalid = (el, isInvalid) => {
    if (!el) return;
    if (isInvalid) el.setAttribute("aria-invalid", "true");
    else el.removeAttribute("aria-invalid");
  };
  const lockBtn = (locked) => {
    if (!submitBtn) return;
    submitBtn.disabled = locked;
    if (locked) submitBtn.dataset.loading = "true";
    else submitBtn.removeAttribute("data-loading");
  };

  // Mostrar/ocultar contraseña
  showPwd?.addEventListener("change", (e) => {
    passInp.type = e.target.checked ? "text" : "password";
    passInp.focus({ preventScroll: true });
  });

  // Ocultar error al escribir y limpiar aria-invalid
  [userInp, passInp].forEach((el) =>
    el?.addEventListener("input", () => {
      hideError();
      setInvalid(el, false);
    })
  );

  // Utilidad: fetch con timeout
  async function fetchWithTimeout(url, options = {}, timeoutMs = 9000) {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, { ...options, signal: controller.signal });
      return res;
    } finally {
      clearTimeout(t);
    }
  }

  // Envío
  form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!form || !submitBtn || inFlight) return;

    const username = (userInp.value || "").trim();
    const password = passInp.value || "";

    // Validación mínima
    if (!username) {
      showError("Ingresa tu nombre de usuario.");
      setInvalid(userInp, true);
      userInp.focus();
      return;
    }
    if (password.length < 8) {
      showError("La contraseña debe tener al menos 8 caracteres.");
      setInvalid(passInp, true);
      passInp.focus();
      return;
    }

    hideError();
    lockBtn(true);
    inFlight = true;

    try {
      const res = await fetchWithTimeout("/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          // Si usas CSRF, lee el token de una meta y añádelo aquí:
          // "X-CSRF-Token": document.querySelector('meta[name="csrf"]')?.content || ""
        },
        body: JSON.stringify({ username, password }),
        credentials: "same-origin"
      }, 12000);

      // Intenta parsear JSON, incluso si status es de error
      let data = {};
      try { data = await res.json(); } catch { /* no JSON */ }

      if (res.ok && (data.ok ?? true)) {
        loadingMsg && (loadingMsg.style.display = "block");
        submitBtn.textContent = "✔ Éxito";
        setTimeout(() => {
          window.location.href = data.redirect || "/go";
        }, 900);
        return;
      }

      // Mensajes por estado
      if (res.status === 401 || res.status === 403) {
        showError(data.msg || "Credenciales inválidas.");
        setInvalid(passInp, true);
        passInp.focus();
      } else if (res.status >= 500) {
        showError("Servidor ocupado. Inténtalo de nuevo.");
      } else {
        showError(data.msg || "No se pudo iniciar sesión.");
      }

    } catch (err) {
      const aborted = err?.name === "AbortError";
      showError(aborted ? "Tiempo de espera agotado." : "Error de conexión. Inténtalo de nuevo.");
    } finally {
      inFlight = false;
      lockBtn(false);
    }
  });
})();

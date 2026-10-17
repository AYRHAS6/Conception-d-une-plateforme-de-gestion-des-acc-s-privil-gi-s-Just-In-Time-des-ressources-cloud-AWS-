
let keycloak = null;
let currentRequestId = null;

// Elements
const views = {
  login: document.getElementById("viewLogin"),
  form: document.getElementById("viewForm"),
  mfa: document.getElementById("viewMfa"),
  granted: document.getElementById("viewGranted"),
  denied: document.getElementById("viewDenied"),
};

function showView(name) {
  Object.values(views).forEach((el) => (el.hidden = true));
  views[name].hidden = false;
}

function setRailStep(stepName, state) {
  // state: "active" | "done" | "failed"
  const el = document.querySelector(`.rail-step[data-step="${stepName}"]`);
  if (!el) return;
  el.classList.remove("active", "done", "failed");
  el.classList.add(state);
}

function resetRail() {
  document.querySelectorAll(".rail-step").forEach((el) => {
    el.classList.remove("active", "done", "failed");
  });
}

// Authentification Keycloak
async function initKeycloak() {
  keycloak = new Keycloak(KEYCLOAK_CONFIG);

  const authenticated = await keycloak.init({
    onLoad: "check-sso",
    silentCheckSsoRedirectUri: window.location.origin + "/silent-check-sso.html",
    pkceMethod: "S256",
  });

  if (authenticated) {
    onLoggedIn();
  } else {
    showView("login");
  }

  // Rafraichit le token automatiquement avant expiration
  setInterval(() => {
    keycloak.updateToken(30).catch(() => keycloak.login());
  }, 20000);
}

function onLoggedIn() {
  document.getElementById("topbarUser").hidden = false;
  document.getElementById("userEmail").textContent =
    keycloak.tokenParsed?.email || keycloak.tokenParsed?.preferred_username || "";
  showView("form");
}

document.getElementById("loginBtn").addEventListener("click", () => {
  keycloak.login();
});

document.getElementById("logoutBtn").addEventListener("click", () => {
  keycloak.logout({ redirectUri: window.location.origin });
});


// Appels au backend (avec le token Keycloak)
async function apiCall(path, options = {}) {
  await keycloak.updateToken(10).catch(() => keycloak.login());

  const response = await fetch(`${BACKEND_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${keycloak.token}`,
      ...(options.headers || {}),
    },
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const error = new Error(data.detail || data.reason || "Erreur inconnue");
    error.data = data;
    error.status = response.status;
    throw error;
  }

  return data;
}


// Etape 1 : soumission de la demande d'acces
document.getElementById("requestForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const submitBtn = document.getElementById("submitRequestBtn");
  const statusEl = document.getElementById("formStatus");

  const payload = {
    requested_role: document.getElementById("requestedRole").value,
    resource_name: document.getElementById("resourceName").value,
    ticket_id: document.getElementById("ticketId").value,
    duration_minutes: parseInt(document.getElementById("durationMinutes").value, 10),
  };

  submitBtn.disabled = true;
  statusEl.textContent = "Vérification du ticket et de la politique en cours…";
  resetRail();
  setRailStep("ticket", "active");

  try {
    const result = await apiCall("/api/access-requests", {
      method: "POST",
      body: JSON.stringify(payload),
    });

    setRailStep("ticket", "done");
    setRailStep("policy", "done");

    if (result.status === "denied") {
      setRailStep("policy", "failed");
      document.getElementById("deniedReason").textContent =
        result.reason || "La politique de sécurité n'autorise pas cette demande.";
      showView("denied");
      return;
    }

    if (result.status === "mfa_required") {
      currentRequestId = result.request_id;
      await prepareMfaView();
      showView("mfa");
    }
  } catch (err) {
    setRailStep("policy", "failed");
    statusEl.textContent = `Erreur : ${err.message}`;
  } finally {
    submitBtn.disabled = false;
  }
});


// Etape 2 : preparation de la vue MFA (enrolement si besoin)
async function prepareMfaView() {
  setRailStep("mfa", "active");
  document.getElementById("mfaStatus").textContent = "";
  document.getElementById("otpCode").value = "";

  try {
    const enroll = await apiCall("/api/mfa/enroll");
    const enrollBox = document.getElementById("enrollBox");

  if (enroll.provisioning_uri) {
    const container = document.getElementById("qrCanvas");
    container.innerHTML = "";  // vide avant de regenerer, evite les doublons
    new QRCode(container, {
      text: enroll.provisioning_uri,
      width: 220,
      height: 220,
      colorDark: "#0B1220",
      colorLight: "#E8ECF4",
    });
    enrollBox.hidden = false;
  } else {
    enrollBox.hidden = true;
  }
  } catch (err) {
    document.getElementById("mfaStatus").textContent =
      "Impossible de préparer la double authentification.";
  }
}


// Etape 3 : verification du code MFA
document.getElementById("mfaForm").addEventListener("submit", async (e) => {
  e.preventDefault();

  const verifyBtn = document.getElementById("verifyMfaBtn");
  const statusEl = document.getElementById("mfaStatus");
  const otpCode = document.getElementById("otpCode").value;

  verifyBtn.disabled = true;
  statusEl.textContent = "Vérification du code…";

  try {
    const result = await apiCall(`/api/access-requests/${currentRequestId}/verify-mfa`, {
      method: "POST",
      body: JSON.stringify({ request_id: currentRequestId, otp_code: otpCode }),
    });

    setRailStep("mfa", "done");
    setRailStep("granted", "done");

    if (result.status === "granted") {
      statusEl.textContent = "Accès accordé. Ouverture de PowerShell…";
      const agentResponse = await fetch(`${AGENT_URL}/launch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ launch_token: result.launch_token }),
      });
      const agentResult = await agentResponse.json().catch(() => ({}));
      if (!agentResponse.ok) {
        throw new Error(agentResult.detail || "Agent JIT local indisponible");
      }
      displaySession(result.expiration);
      showView("granted");
    }
  } catch (err) {
    setRailStep("mfa", "failed");
    statusEl.textContent = `Code invalide : ${err.message}`;
  } finally {
    verifyBtn.disabled = false;
  }
});

//format de l'affichage de la date 
function formatExpiration(isoString) {
  const date = new Date(isoString);
  return date.toLocaleString("fr-FR", {
    timeZone: "Africa/Casablanca",
    dateStyle: "short",
    timeStyle: "short",
  });
}


function displaySession(expiration) {
  const exp = document.getElementById("credExpiration");
  if (exp) exp.textContent = formatExpiration(expiration);
}


// Reinitialiser pour une nouvelle demande
function resetToForm() {
  currentRequestId = null;
  resetRail();
  document.getElementById("requestForm").reset();
  document.getElementById("durationMinutes").value = 120;
  document.getElementById("formStatus").textContent = "";
  showView("form");
}

document.getElementById("newRequestBtn").addEventListener("click", resetToForm);
document.getElementById("retryBtn").addEventListener("click", resetToForm);


//Demarrage

initKeycloak();
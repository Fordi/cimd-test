const configUrlInput = document.querySelector("#openidConfigUrl");
const getConfigUrl = () => configUrlInput.value.trim() ||
  (localStorage.getItem("openidConfigUrl") ?? "https://api.ion.test:8084/");
configUrlInput.value = getConfigUrl();
const workZone = document.querySelector("#work");
const scope = document.querySelector("#scope");
scope.value ||= localStorage.getItem("scope") ?? "assets:read";
const dcrOptions = document.querySelector("#dcrOptions");
const dcrClientName = document.querySelector("#dcrClientName");
const clientIdInput = document.querySelector('#clientId');
const getClientId = () => clientIdInput.value.trim() || localStorage.getItem("clientId");
const CIMD_CLIENT_ID = "https://fordi.github.io/cimd-test/client.json";

dcrClientName.value =
  localStorage.getItem("dcrClientName") ?? "DCR OAuth2.0 Tester";

function currentMode() {
  return [...document.querySelectorAll('input[type=radio][name=mode]')].find(e => e.checked).value;
}

function updateModeVisibility() {
  for (const radio of document.querySelectorAll('input[type=radio][name=mode]')) {
    const options = document.querySelector(`#${radio.value}Options`)
    if (options) {
      options.style.display = radio.checked ? "" : "none";
    }
  }
}
const configChanged = async (error) => {
  const messages = [];
  const commit = () => {
    workZone.innerHTML = messages.join('\n');
  }
  if (error && typeof error === 'string') {
    messages.push(makeError(error));
  }
  localStorage.setItem("openidConfigUrl", getConfigUrl());
  localStorage.setItem("scope", scope.value);
  localStorage.setItem("clientId", getClientId());
  let authServer;
  try {
    authServer = await discover();
  } catch (e) {
    messages.push(makeError(e.message));
    return commit();
  }
  const { authorization_endpoint, token_endpoint, registration_endpoint } =
    authServer;

  const redirectUri = new URL(".", location).toString();

  let clientId;
  
  if (currentMode() === "dcr") {
    try {
      clientId = await registerDcr(registration_endpoint, {
        clientName: dcrClientName.value,
        redirectUri,
      });
    } catch (e) {
      messages.push(makeError(e.message));
      return commit();
    }
  } else if (currentMode() === "clientId") {
    clientId = clientIdInput.value.trim();
  } else {
    clientId = CIMD_CLIENT_ID;
  }
  
  if (clientId) {
    const [state, code_challenge] = await pkceState({
      openidConfigUrl: getConfigUrl(),
      tokenEndpoint: token_endpoint,
      scopes: scope.value,
      mode: currentMode(),
      clientId,
    });
    const ep = new URL(authorization_endpoint);
    ep.searchParams.append("state", state);
    ep.searchParams.append("code_challenge", code_challenge);
    ep.searchParams.append("code_challenge_method", "S256");
    ep.searchParams.append("response_type", "code");
    ep.searchParams.append("redirect_uri", redirectUri);
    ep.searchParams.append("client_id", clientId);
    ep.searchParams.append(
      "scope",
      scope.value
        .split(",")
        .map((v) => v.trim())
        .join(","),
    );
    commit();
    workZone.appendChild(
      Object.assign(document.createElement("a"), {
        href: ep.toString(),
        textContent: "Click to authenticate",
      }),
    );
  } else {
    commit();
  }
};
configUrlInput.addEventListener("change", configChanged);
clientIdInput.addEventListener("change", configChanged);
const modeChanged = () => {
  const mode = currentMode();
  localStorage.setItem("mode", currentMode());
  updateModeVisibility();
  configChanged();
};
const initialMode = localStorage.getItem("mode") ?? "cimd";
for (const radio of document.querySelectorAll('input[type=radio][name=mode]')) {
  radio.addEventListener('change', modeChanged);
  if (radio.value === initialMode) {
    radio.checked = true;
    modeChanged();
  }
}

dcrClientName.addEventListener("change", () => {
  localStorage.setItem("dcrClientName", dcrClientName.value);
});
const makeError = (error) => `<div style="color: red">${error}</div>`;
const makeMessage = (message) => `<pre>${JSON.stringify(message)}</pre>`;



async function sha256(input) {
  const crypto = globalThis.crypto ?? (await import("node:crypto"))?.webcrypto;
  if (!crypto) {
    throw new Error("WebCrypto not available");
  }
  const result = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input)),
  );
  return result.toBase64({ alphabet: "base64url", omitPadding: true });
}

Uint8Array.prototype.toBase64 ??= function toBase64(options) {
  let result = Buffer.from(this).toString("base64");
  if (options?.alphabet === "base64url") {
    result = result.replace(/\+/g, "-").replace(/\//g, "_");
  }
  if (options?.omitPadding) {
    result = result.replace(/=/g, "");
  }
  return result;
};

const terseRandomUuid = () => {
  return new Uint8Array(
    crypto
      .randomUUID()
      .replace(/-/g, "")
      .match(/../g)
      .map((i) => parseInt(i, 16)),
  ).toBase64({
    alphabet: "base64url",
    omitPadding: true,
  });
};

async function discover() {
  const configUrl = getConfigUrl();
  const mode = currentMode();
  const authServer = await fetch(
    new URL(".well-known/oauth-authorization-server", configUrl),
    { mode: "cors", credentials: "omit" },
  ).then((r) => r.json());
  const {
    authorization_endpoint,
    token_endpoint,
    registration_endpoint,
    client_id_metadata_document_supported: cimdOk,
    grant_types_supported: grantTypes,
    code_challenge_methods_supported: codeChallenge,
    response_types_supported: responseTypes,
  } = authServer;
  const baseSupported =
    responseTypes.includes("code") &&
    grantTypes.includes("authorization_code") &&
    codeChallenge.includes("S256");
  if (mode === "dcr") {
    if (!baseSupported || !registration_endpoint) {
      throw new Error(
        `${configUrl} is not a valid OAuth2.0 server, or does not support Dynamic Client Registration`,
      );
    }
    return { authorization_endpoint, token_endpoint, registration_endpoint };
  }
  if (!baseSupported || !cimdOk) {
    throw new Error(
      `${configUrl} is not a valid OAuth2.0 server, or does not support CIMD`,
    );
  }
  return { authorization_endpoint, token_endpoint };
}

/**
 * Registers this page as an RFC 7591 Dynamic Client Registration public
 * client and returns the issued client_id.
 */
async function registerDcr(registrationEndpoint, { clientName, redirectUri }) {
  const response = await fetch(registrationEndpoint, {
    method: "post",
    mode: "cors",
    credentials: "omit",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      client_name: clientName,
      redirect_uris: [redirectUri],
      token_endpoint_auth_method: "none",
    }),
  });
  const body = await response.json();
  if (!response.ok) {
    throw new Error(body.error_description ?? body.error ?? "unknown error");
  }
  return body.client_id;
}

const MAX_AGE = 60000;
const oldest = Date.now() - MAX_AGE;
const STORAGE_KEY_ROOT = "*STATE*";
// Clean up old states
for (const [key, json] of Object.entries(localStorage)) {
  if (key.startsWith(STORAGE_KEY_ROOT)) {
    const [_, created] = JSON.parse(json);
    if (oldest > created) {
      localStorage.removeItem(key);
    }
  }
}

async function pkceState(metadata = {}) {
  const state = terseRandomUuid();
  const stateKey = `${STORAGE_KEY_ROOT}${state}`;
  const verifier = terseRandomUuid();
  const internalState = [verifier, Date.now(), metadata];
  localStorage.setItem(stateKey, JSON.stringify(internalState));
  return [state, await sha256(verifier)];
}
async function main() {
  const here = new URL(location);
  const returned = Object.fromEntries(here.searchParams.entries());
  here.search = '';
  history.replaceState(null, null, here.toString());
  let stateObj;
  if (returned.state) {
    stateObj = JSON.parse(localStorage.getItem(`${STORAGE_KEY_ROOT}${returned.state}`));
  }
  if (!stateObj) {
    if (returned.error) {
      workZone.innerHTML = `<pre>${JSON.stringify({ error: returned.error, error_description: returned.error_description })}</pre>`;
    } else if (returned.state) {
      configChanged("State was not present in localstorage");
    } else {
      configChanged();
    }
    return;
  }
  const [verifier, created, { tokenEndpoint, openidConfigUrl, scopes, mode, clientId }] = stateObj;
  scope.value = scopes;
  configUrlInput.value = openidConfigUrl;
  localStorage.setItem("scope", scopes);
  console.log("Fuck");
  localStorage.setItem("openidConfigUrl", openidConfigUrl);
  const ep = new URL(tokenEndpoint);
  try {
    const tokenRequest = () => new Request(ep, {
      method: "post",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        grant_type: "authorization_code",
        client_id: clientId ?? CIMD_CLIENT_ID,
        code: returned.code,
        redirect_uri: new URL(".", location).toString(),
        code_verifier: verifier,
      }),
    });
    const tokenInfo = await fetch(tokenRequest()).then((r) => r.json());
    workZone.innerHTML = `<div class="green">First exchange request:</div><pre>${JSON.stringify(tokenInfo, null, 2)}</pre>`;

    await new Promise(r => setTimeout(r, 250));
    try {
      const nextTokenInfo = await fetch(tokenRequest()).then((r) => r.json());
      workZone.innerHTML += `<div class="green">Second exchange request (must fail):</div><pre>${JSON.stringify(nextTokenInfo, null, 2)}</pre>`;
    } catch (e) {
      workZone.innerHTML += makeError(e.message);
    }
    console.log(getConfigUrl());
    const asset = await fetch(new URL("/v1/assets/1", getConfigUrl()), {
      headers: {
        authorization: `Bearer ${tokenInfo.access_token}`,
      },
    }).then(r => r.json());
    workZone.innerHTML += `<div class="green">Asset:</div><pre>${JSON.stringify(asset, null, 2)}</pre>`;
  } catch (e) {
    configChanged(e.message);
  }
}
main();
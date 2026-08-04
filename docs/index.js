const configUrl = document.querySelector('#openidConfigUrl');
configUrl.value ||= localStorage.getItem('openidConfigUrl') ?? "https://api.ion.test:8084/";
const workZone = document.querySelector('#work');
const scope = document.querySelector('#scope');
scope.value ||= localStorage.getItem('scope') ?? "assets:read";
const configChanged = async () => {
  localStorage.setItem('openidConfigUrl', configUrl.value);
  localStorage.setItem('scope', scope.value);
  try { 
    console.log(new URL(configUrl.value));
  } catch {
    return;
  }
  const { authorization_endpoint, token_endpoint } = await discover(configUrl.value);
  const [state, code_challenge] = await pkceState({
    openidConfigUrl: configUrl.value,
    tokenEndpoint: token_endpoint,
    scopes: scope.value,
  });
  const ep = new URL(authorization_endpoint);
  ep.searchParams.append("state", state);
  ep.searchParams.append("code_challenge", code_challenge);
  ep.searchParams.append("code_challenge_method", "S256");
  ep.searchParams.append("response_type", "code");
  ep.searchParams.append("redirect_uri", new URL(".", location).toString());
  ep.searchParams.append("client_id", "https://fordi.github.io/cimd-test/client.json");
  ep.searchParams.append("scope", scope.value.split(',').map(v => v.trim()).join(','));
  workZone.innerHTML='';
  workZone.appendChild(Object.assign(document.createElement('a'), {
    href: ep.toString(),
    textContent: "Click to authenticate",
  }));
};
configUrl.addEventListener('change', configChanged);
configChanged();



async function sha256(input) {
  const crypto = globalThis.crypto ?? (await import('node:crypto'))?.webcrypto;
  if (!crypto) {
    throw new Error("WebCrypto not available");
  }
  const result = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input)));
  return result.toBase64({ alphabet: 'base64url', omitPadding: true });
}

Uint8Array.prototype.toBase64 ??= function toBase64(options) {
  let result = Buffer.from(this).toString('base64');
  if (options?.alphabet === 'base64url') {
    result = result.replace(/\+/g, "-").replace(/\//g, "_");
  }
  if (options?.omitPadding) {
    result = result.replace(/=/g, "");
  }
  return result;
};

const terseRandomUuid = () => {
  return new Uint8Array(
    crypto.randomUUID()
      .replace(/-/g, '')
      .match(/../g)
      .map(i => parseInt(i, 16))
  ).toBase64({
    alphabet: 'base64url',
    omitPadding: true,
  });
}

async function discover(configUrl) {
  const authServer = await fetch(new URL('.well-known/oauth-authorization-server', configUrl), { mode: 'cors', credentials: 'omit' }).then(r => r.json());
  const {
    authorization_endpoint,
    token_endpoint,
    client_id_metadata_document_supported: cimdOk,
    jwks_uri: jwks,
    grant_types_supported: grantTypes,
    code_challenge_methods_supported: codeChallenge,
    response_types_supported: responseTypes,
  } = authServer;
  const supportedServer = cimdOk && responseTypes.includes('code') && grantTypes.includes('authorization_code') && codeChallenge.includes('S256');
  if (supportedServer) {
    return {
      authorization_endpoint,
      token_endpoint,
    }
  }
  throw new Error(`${configUrl} is not a valid OAuth2.0 server, or does not support CIMD`);
}

const MAX_AGE = 60000;
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
  const oldest = Date.now() - MAX_AGE;
  const state = terseRandomUuid();
  const stateKey = `${STORAGE_KEY_ROOT}${state}`;
  const verifier = terseRandomUuid();
  const internalState = [verifier, Date.now(), metadata];
  localStorage.setItem(stateKey, JSON.stringify(internalState));
  return [
    state,
    await sha256(verifier),
  ];
}

const returned = Object.fromEntries(new URL(location).searchParams.entries());
if (returned.state) {
  const [verifier, created, { tokenEndpoint, openidConfigUrl, scopes }] = localStorage.getItem(`${STORAGE_KEY_ROOT}${returned.state}`);
  scope.value = scopes;
  configUrl.value = openidConfigUrl;
  localStorage.setItem('scope', scopes);
  localStorage.setItem('openidConfigUrl', openidConfigUrl);
  const ep = new URL(tokenEndpoint);
  const tokenInfo = await fetch(ep, {
    method: 'post',
    headers:  {
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      grant_type: "authorization_code",
      client_id: "https://fordi.github.io/cimd-test/client.json",
      code: returned.code,
      redirect_uri: new URL(".", location).toString(),
      code_verifier: verifier,
    }),
  }).then(r => r.json());
  workZone.innerHTML = `<pre>${JSON.stringify(tokenInfo)}</pre>`
} else if (returned.error) {
  workZone.innerHTML = `<pre>${JSON.stringify({ error: returned.error, error_description: returned.error_description })}</pre>`;
}
/**
 * Tenant isolation across the entire API surface.
 *
 * Two organizations are created with complete fixtures, then every route that
 * accepts an identifier is called by the WRONG tenant using the RIGHT
 * identifier. Guessing an ID must reveal nothing and change nothing.
 *
 * Two deliberate expectations:
 *
 *  - 404, never 403. A 403 confirms the ID exists, which turns any endpoint
 *    into an oracle for enumerating other tenants' records.
 *  - Writes must be verified as no-ops afterwards. A route can return 404 and
 *    still have mutated something, if the tenant check and the write are
 *    separate statements rather than one scoped query.
 */
const BASE = process.env.RELAY_URL ?? 'http://localhost:3210';

const failures = [];
const check = (ok, description) => {
  process.stdout.write(`  ${ok ? 'PASS' : 'FAIL'}  ${description}\n`);
  if (!ok) failures.push(description);
};

const api = async (method, path, { token, body } = {}) => {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = null; }
  return { status: res.status, body: json };
};

async function provisionTenant(label) {
  const suffix = `${label}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const signup = await api('POST', '/v1/auth/signup', {
    body: {
      organizationName: `Org ${suffix}`,
      email: `owner-${suffix}@isolation.test`,
      password: 'a-sufficiently-long-password',
    },
  });
  if (signup.status !== 201) throw new Error(`signup failed for ${label}: ${JSON.stringify(signup.body)}`);
  const token = signup.body.token;

  const keyRes = await api('POST', '/v1/auth/api-keys', {
    token,
    body: { name: 'isolation', scopes: ['*'] },
  });
  const apiKey = keyRes.body.key;

  const app = await api('POST', '/v1/applications', { token, body: { name: 'app', environment: 'TEST' } });
  const endpoint = await api('POST', '/v1/endpoints', {
    token,
    body: { applicationId: app.body.id, url: 'https://example.com/hook', eventTypes: [] },
  });
  const event = await api('POST', '/v1/events', {
    token,
    body: { applicationId: app.body.id, eventType: 'isolation.test', payload: { secret: `${label}-payload` } },
  });
  const detail = await api('GET', `/v1/events/${event.body.id}`, { token });

  return {
    label,
    token,
    apiKey,
    applicationId: app.body.id,
    endpointId: endpoint.body.id,
    eventId: event.body.id,
    deliveryId: detail.body.deliveries[0]?.id,
  };
}

const victim = await provisionTenant('victim');
const attacker = await provisionTenant('attacker');

process.stdout.write('\n  Reads with a valid ID belonging to another tenant\n');
for (const [label, path] of [
  ['application', `/v1/applications/${victim.applicationId}`],
  ['endpoint', `/v1/endpoints/${victim.endpointId}`],
  ['event', `/v1/events/${victim.eventId}`],
  ['delivery', `/v1/deliveries/${victim.deliveryId}`],
]) {
  const res = await api('GET', path, { token: attacker.token });
  check(res.status === 404, `GET ${label} -> ${res.status} (404 required; 403 would confirm the ID exists)`);
}

process.stdout.write('\n  Writes against another tenant\n');
const writes = [
  ['PATCH', `/v1/applications/${victim.applicationId}`, { name: 'pwned' }, 'rename application'],
  ['PATCH', `/v1/endpoints/${victim.endpointId}`, { url: 'https://attacker.test/steal' }, 'repoint endpoint'],
  ['POST', `/v1/endpoints/${victim.endpointId}/rotate-secret`, undefined, 'rotate signing secret'],
  ['POST', `/v1/deliveries/${victim.deliveryId}/replay`, undefined, 'replay delivery'],
];
for (const [method, path, body, label] of writes) {
  const res = await api(method, path, { token: attacker.token, body });
  check(res.status === 404, `${label} -> ${res.status} (404 required)`);
}

process.stdout.write('\n  Attaching to another tenant\'s application\n');
const attachEndpoint = await api('POST', '/v1/endpoints', {
  token: attacker.token,
  body: { applicationId: victim.applicationId, url: 'https://attacker.test/hook', eventTypes: [] },
});
check(attachEndpoint.status === 404, `create endpoint under victim's app -> ${attachEndpoint.status} (404 required)`);

const injectEvent = await api('POST', '/v1/events', {
  token: attacker.token,
  body: { applicationId: victim.applicationId, eventType: 'injected.event', payload: { evil: true } },
});
check(injectEvent.status === 404, `post event to victim's app -> ${injectEvent.status} (404 required)`);

process.stdout.write('\n  Filters cannot be used to reach across tenants\n');
for (const [label, path] of [
  ['endpoints?applicationId', `/v1/endpoints?applicationId=${victim.applicationId}`],
  ['events?applicationId', `/v1/events?applicationId=${victim.applicationId}`],
  ['deliveries?endpointId', `/v1/deliveries?endpointId=${victim.endpointId}`],
]) {
  const res = await api('GET', path, { token: attacker.token });
  const leaked = (res.body?.data ?? []).length;
  check(leaked === 0, `${label} filtered to victim's ID returns nothing (${leaked} rows)`);
}

process.stdout.write('\n  API-key credentials are scoped the same way as sessions\n');
const viaKey = await api('GET', `/v1/applications/${victim.applicationId}`, { token: attacker.apiKey });
check(viaKey.status === 404, `API key cannot read across tenants -> ${viaKey.status} (404 required)`);

process.stdout.write('\n  Nothing was actually mutated\n');
const app = await api('GET', `/v1/applications/${victim.applicationId}`, { token: victim.token });
check(app.body.name === 'app', `victim's application name unchanged ("${app.body.name}")`);

const endpoint = await api('GET', `/v1/endpoints/${victim.endpointId}`, { token: victim.token });
check(endpoint.body.url === 'https://example.com/hook', `victim's endpoint URL unchanged ("${endpoint.body.url}")`);
check(endpoint.body.secretRotatedAt === null, 'victim\'s signing secret was never rotated');

const events = await api('GET', `/v1/events?applicationId=${victim.applicationId}`, { token: victim.token });
check(events.body.data.length === 1, `no event was injected into victim's app (${events.body.data.length})`);

process.stdout.write(
  failures.length === 0
    ? '\n  PASS: no cross-tenant read, write, or enumeration succeeded\n\n'
    : `\n  FAIL: ${failures.length} isolation assertion(s) failed\n\n`,
);
process.exit(failures.length === 0 ? 0 : 1);

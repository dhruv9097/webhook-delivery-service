/**
 * Seeds a working tenant for local development and manual testing:
 * an organization, an owner, a TEST application, an API key, and an endpoint
 * pointed at the mock receiver.
 *
 * Idempotent — re-running resets the same fixtures rather than accumulating
 * duplicates, so it is safe to run against a database you have been poking at.
 */
import argon2 from 'argon2';
import { prisma } from '../src/db.js';
import { encryptSecret } from '../src/security/secrets.js';
import { generateApiKey, generateSigningSecret } from '../src/services/apiKeys.js';

const EMAIL = process.env.SEED_EMAIL ?? 'dev@relay.local';
const PASSWORD = process.env.SEED_PASSWORD ?? 'development-password';
const RECEIVER_URL = process.env.SEED_RECEIVER_URL ?? 'http://localhost:4210/hook';

async function main() {
  const existing = await prisma.user.findUnique({ where: { email: EMAIL } });
  if (existing) {
    // Cascades to applications, endpoints, events and deliveries.
    await prisma.organization.delete({ where: { id: existing.orgId } });
    process.stdout.write('Removed previous seed data.\n');
  }

  const passwordHash = await argon2.hash(PASSWORD, { type: argon2.argon2id });
  const { plaintext, prefix, keyHash } = generateApiKey('TEST');
  const signingSecret = generateSigningSecret();

  const org = await prisma.organization.create({
    data: {
      name: 'Relay Development',
      slug: `relay-dev-${Date.now().toString(36)}`,
      users: { create: { email: EMAIL, passwordHash, role: 'OWNER' } },
      apiKeys: { create: { name: 'Seed key', prefix, keyHash, scopes: ['*'] } },
      applications: {
        create: {
          name: 'Demo App',
          environment: 'TEST',
          endpoints: {
            create: {
              url: RECEIVER_URL,
              description: 'Local mock receiver',
              eventTypes: [],
              secretCurrent: encryptSecret(signingSecret),
            },
          },
        },
      },
    },
    include: { applications: { include: { endpoints: true } } },
  });

  const application = org.applications[0];
  const endpoint = application.endpoints[0];

  process.stdout.write(
    [
      '',
      'Seed complete.',
      '',
      `  Login           ${EMAIL} / ${PASSWORD}`,
      `  Organization    ${org.id}`,
      `  Application     ${application.id}`,
      `  Endpoint        ${endpoint.id} -> ${endpoint.url}`,
      `  Signing secret  ${signingSecret}`,
      `  API key         ${plaintext}`,
      '',
      'Try it:',
      `  curl -s localhost:3210/v1/applications -H "Authorization: Bearer ${plaintext}" | jq`,
      '',
    ].join('\n'),
  );
}

main()
  .catch((err) => {
    process.stderr.write(`Seed failed: ${err.stack}\n`);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());

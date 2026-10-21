import { expect, sessionFor, test, uid } from './fixtures';

async function zone(api: Awaited<ReturnType<typeof sessionFor>>, name: string): Promise<void> {
  await api.ok('post', '/zones', {
    name,
    default_ttl: 300,
    soa: {
      mname: `ns1.${name}`,
      rname: `h.${name}`,
      refresh: 3600,
      retry: 600,
      expire: 1209600,
      minimum: 300,
    },
    records: [
      { name: '@', type: 'NS', value: `ns1.${name}` },
      { name: 'www', type: 'A', value: '192.0.2.9' },
    ],
  });
}

test('enable signing from the zone tab, copy the DS, start a rollover and confirm the DS', async ({
  page,
  context,
  freshServer,
}) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  const s = await freshServer();
  const api = await sessionFor(page, s.baseURL);
  const name = `sig${uid()}.test.`;
  await zone(api, name);
  await page.goto(`${s.baseURL}/zones/${name}`);
  await page.getByRole('tab', { name: 'DNSSEC' }).click();
  const panel = page.getByRole('tabpanel', { name: 'DNSSEC' });
  await expect(panel.getByRole('heading', { name: 'Sign this zone' })).toBeVisible();

  await panel.getByLabel('Key layout').selectOption('ksk_zsk');
  await panel.getByRole('button', { name: 'Enable DNSSEC signing' }).click();
  const confirm = page.getByRole('dialog', { name: 'Enable DNSSEC signing' });
  await expect(confirm).toContainText('publish the DS record at your registrar');
  await confirm.getByRole('button', { name: 'Enable signing' }).click();

  await expect(panel.getByRole('heading', { name: 'Keys' })).toBeVisible();
  await expect(panel.getByRole('row', { name: /KSK/i }).first()).toBeVisible();
  await expect(panel.getByRole('row', { name: /ZSK/i }).first()).toBeVisible();
  await expect(page.getByText('signed', { exact: true }).first()).toBeVisible();

  // DS for the registrar: copy puts the record text on the clipboard.
  const ds = panel.getByRole('button', { name: /Copy DS record for key \d+ SHA-256/ }).first();
  await ds.click();
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  expect(copied).toMatch(
    new RegExp(
      `^${name.replace(/\./g, '\\.')}\\s+\\d*\\s*IN\\s+DS\\s+\\d+\\s+13\\s+2\\s+[0-9A-F]{64}$`,
      'i',
    ),
  );
  await panel.getByRole('button', { name: 'Copy for registrar (SHA-256)' }).click();
  await expect(panel.getByRole('status')).toContainText(/copied/i);

  // The signed zone export is offered and the zone is served signed.
  await expect(page.getByRole('button', { name: 'Download signed', exact: true })).toBeVisible();

  // Rollover needs an explicit confirmation, then waits for the registrar DS step.
  await panel
    .getByRole('button', { name: /Start rollover of key \d+/ })
    .first()
    .click();
  const rollover = page.getByRole('dialog', { name: /Start rollover of key/ });
  await expect(rollover).toContainText('registrar');
  await rollover.getByRole('button', { name: 'Cancel' }).click();
  await expect(rollover).toBeHidden();

  await panel
    .getByRole('button', { name: /Start rollover of key \d+/ })
    .first()
    .click();
  await page
    .getByRole('dialog', { name: /Start rollover of key/ })
    .getByRole('button', { name: 'Start rollover' })
    .click();
  await expect(panel.getByRole('status').filter({ hasText: /Rollover of the/ })).toBeVisible();
});

test('NSEC3 parameters are validated before enabling', async ({ page, freshServer }) => {
  const s = await freshServer();
  const api = await sessionFor(page, s.baseURL);
  const name = `n3${uid()}.test.`;
  await zone(api, name);
  await page.goto(`${s.baseURL}/zones/${name}`);
  await page.getByRole('tab', { name: 'DNSSEC' }).click();
  const panel = page.getByRole('tabpanel', { name: 'DNSSEC' });
  await panel.getByLabel('Iterations', { exact: true }).fill('10');
  await panel.getByRole('button', { name: 'Enable DNSSEC signing' }).click();
  await expect(panel.getByRole('alert')).toBeVisible();
  await expect(page.getByRole('dialog')).toHaveCount(0);
  await panel.getByLabel('Salt (hex, optional)').fill('zz');
  await panel.getByLabel('Iterations', { exact: true }).fill('0');
  await panel.getByRole('button', { name: 'Enable DNSSEC signing' }).click();
  await expect(panel.getByRole('alert')).toBeVisible();
});

test('disabling signing needs the zone name typed', async ({ page, freshServer }) => {
  const s = await freshServer();
  const api = await sessionFor(page, s.baseURL);
  const name = `off${uid()}.test.`;
  await zone(api, name);
  await api.ok('put', `/zones/${name}/dnssec`, {
    enabled: true,
    algorithm: 13,
    key_layout: 'csk',
    denial: 'nsec',
  });
  await page.goto(`${s.baseURL}/zones/${name}`);
  await page.getByRole('tab', { name: 'DNSSEC' }).click();
  const panel = page.getByRole('tabpanel', { name: 'DNSSEC' });
  await panel.getByRole('button', { name: 'Disable signing' }).click();
  const dialog = page.getByRole('dialog', { name: 'Disable DNSSEC signing' });
  const go = dialog.getByRole('button', { name: 'Disable signing' });
  await expect(go).toBeDisabled();
  await dialog.getByLabel(/Type .* to confirm/).fill(name);
  await go.click();
  await expect(panel.getByRole('heading', { name: 'Sign this zone' })).toBeVisible();
});

test('the validation page lists trust anchors and manages negative trust anchors', async ({
  page,
  freshServer,
}) => {
  const s = await freshServer();
  await sessionFor(page, s.baseURL);
  await page.goto(`${s.baseURL}/dnssec`);
  await expect(page.getByRole('heading', { level: 1, name: 'DNSSEC validation' })).toBeVisible();
  await expect(page.getByRole('region', { name: 'Validation mode' })).toBeVisible();
  const nta = page.getByRole('region', { name: 'Negative trust anchors' });
  await nta.getByLabel('Domain name').fill('broken.example');
  await nta.getByRole('button', { name: 'Add' }).click();
  await expect(nta.getByText('broken.example')).toBeVisible();
  await nta.getByRole('button', { name: 'Remove negative trust anchor broken.example' }).click();
  await page
    .getByRole('dialog', { name: 'Remove negative trust anchor' })
    .getByRole('button', { name: 'Remove' })
    .click();
  await expect(nta.getByText('No negative trust anchors.')).toBeVisible();
});

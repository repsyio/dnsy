import { readFile } from 'node:fs/promises';
import { type Page } from '@playwright/test';
import { query } from './support/dns';
import { expect, heading, roleState, test, uid } from './fixtures';

async function createZoneViaUi(page: Page, name: string): Promise<void> {
  await page.goto('/zones');
  await page.getByRole('button', { name: 'Create zone' }).first().click();
  const dialog = page.getByRole('dialog', { name: 'Create zone' });
  await dialog.getByLabel('Zone name').fill(name);
  await dialog.getByLabel('Name servers').fill(`ns1.${name}`);
  await dialog.getByLabel('SOA primary server').fill(`ns1.${name}`);
  await dialog.getByLabel('SOA contact').fill(`hostmaster.${name}`);
  await dialog.getByRole('button', { name: 'Create', exact: true }).click();
}

function recordForm(page: Page, label: string) {
  return page.getByRole('form', { name: label });
}

async function addRecord(page: Page, name: string, type: string, value: string, ttl = '300') {
  await page.getByRole('button', { name: 'Add record' }).first().click();
  const form = recordForm(page, 'New record');
  await form.getByLabel('Name').fill(name);
  await form.getByLabel('Type').selectOption(type);
  await form.getByLabel('TTL').fill(ttl);
  await form.getByLabel('Value').fill(value);
  await form.getByRole('button', { name: 'Save' }).click();
}

test('create a zone, add, edit and delete records; the DNS server answers from it', async ({
  page,
  server,
}) => {
  const zone = `z${uid()}.test.`;
  await createZoneViaUi(page, zone);
  await expect(page).toHaveURL(new RegExp(`/zones/${zone.replace(/\./g, '\\.')}$`));
  await expect(heading(page, zone)).toBeVisible();

  await addRecord(page, 'www', 'A', '192.0.2.10');
  const row = page.getByRole('row', { name: /www.*A.*192\.0\.2\.10/ });
  await expect(row).toBeVisible();
  await expect
    .poll(async () => (await query(server.dnsPort, `www.${zone}`)).ips)
    .toEqual(['192.0.2.10']);

  await page.getByRole('button', { name: `Edit A record www` }).click();
  const edit = recordForm(page, 'Edit A record www');
  await edit.getByLabel('Value').fill('192.0.2.11');
  await edit.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('row', { name: /www.*192\.0\.2\.11/ })).toBeVisible();
  await expect
    .poll(async () => (await query(server.dnsPort, `www.${zone}`)).ips)
    .toEqual(['192.0.2.11']);

  await page.getByRole('button', { name: 'Delete A record www' }).click();
  const confirm = page.getByRole('dialog', { name: 'Delete record' });
  await expect(confirm).toContainText('192.0.2.11');
  await confirm.getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(page.getByRole('row', { name: /www/ })).toHaveCount(0);
});

test('record validation errors block saving', async ({ page, api }) => {
  const zone = `v${uid()}.test.`;
  await api.ok('post', '/zones', {
    name: zone,
    default_ttl: 300,
    soa: {
      mname: `ns1.${zone}`,
      rname: `h.${zone}`,
      refresh: 3600,
      retry: 600,
      expire: 1209600,
      minimum: 300,
    },
    records: [{ name: '@', type: 'NS', value: `ns1.${zone}` }],
  });
  await page.goto(`/zones/${zone}`);
  await page.getByRole('button', { name: 'Add record' }).first().click();
  const form = recordForm(page, 'New record');
  await form.getByLabel('Name').fill('bad');
  await form.getByLabel('Type').selectOption('A');
  await form.getByLabel('Value').fill('not-an-address');
  await form.getByRole('button', { name: 'Save' }).click();
  await expect(form.locator('.field-error').first()).toBeVisible();
  await form.getByLabel('Value').fill('192.0.2.1');
  await form.getByLabel('TTL').fill('-5');
  await form.getByRole('button', { name: 'Save' }).click();
  await expect(form.locator('.field-error').first()).toBeVisible();
  // Nothing was added besides the NS record.
  await form.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByRole('row', { name: /bad/ })).toHaveCount(0);
});

test('an invalid zone name is rejected in the create dialog', async ({ page }) => {
  await page.goto('/zones');
  await page.getByRole('button', { name: 'Create zone' }).first().click();
  const dialog = page.getByRole('dialog', { name: 'Create zone' });
  await dialog.getByLabel('Zone name').fill('no-trailing-dot');
  await dialog.getByRole('button', { name: 'Create', exact: true }).click();
  await expect(dialog.getByText('Use an absolute name ending in a dot.')).toBeVisible();
  await expect(dialog.getByText('At least one name server is required.')).toBeVisible();
});

test('creating a zone twice shows the server error', async ({ page, api }) => {
  const zone = `d${uid()}.test.`;
  await createZoneViaUi(page, zone);
  await expect(heading(page, zone)).toBeVisible();
  await createZoneViaUi(page, zone);
  await expect(page.getByRole('dialog', { name: 'Create zone' }).getByRole('alert')).toBeVisible();
  expect((await api.get('/zones')).ok()).toBe(true);
});

test('a concurrent change shows the ETag conflict and both resolutions work', async ({
  page,
  api,
}) => {
  const zone = `c${uid()}.test.`;
  await api.ok('post', '/zones', {
    name: zone,
    default_ttl: 300,
    soa: {
      mname: `ns1.${zone}`,
      rname: `h.${zone}`,
      refresh: 3600,
      retry: 600,
      expire: 1209600,
      minimum: 300,
    },
    records: [{ name: '@', type: 'NS', value: `ns1.${zone}` }],
  });
  await page.goto(`/zones/${zone}`);
  await expect(heading(page, zone)).toBeVisible();
  // Someone else changes the zone after the page loaded it.
  await api.ok('post', `/zones/${zone}/records`, {
    name: 'other',
    type: 'A',
    ttl: 300,
    value: '192.0.2.50',
  });

  await addRecord(page, 'mine', 'A', '192.0.2.51');
  const alert = page.getByRole('alert').filter({ hasText: 'changed elsewhere' });
  await expect(alert).toBeVisible();
  await expect(page.getByRole('row', { name: /mine/ })).toHaveCount(0);

  await alert.getByRole('button', { name: 'Overwrite anyway' }).click();
  await expect(page.getByRole('row', { name: /mine.*192\.0\.2\.51/ })).toBeVisible();
  await expect(page.getByRole('row', { name: /other.*192\.0\.2\.50/ })).toBeVisible();

  // Second round: Reload latest drops the pending change.
  await api.ok('post', `/zones/${zone}/records`, {
    name: 'third',
    type: 'A',
    ttl: 300,
    value: '192.0.2.52',
  });
  await addRecord(page, 'fourth', 'A', '192.0.2.53');
  await page.getByRole('button', { name: 'Reload latest' }).click();
  await expect(page.getByRole('row', { name: /third/ })).toBeVisible();
  await expect(page.getByRole('row', { name: /fourth/ })).toHaveCount(0);
});

test('Download BIND saves the zone in master-file format', async ({ page, api }) => {
  const zone = `e${uid()}.test.`;
  await api.ok('post', '/zones', {
    name: zone,
    default_ttl: 300,
    soa: {
      mname: `ns1.${zone}`,
      rname: `h.${zone}`,
      refresh: 3600,
      retry: 600,
      expire: 1209600,
      minimum: 300,
    },
    records: [
      { name: '@', type: 'NS', value: `ns1.${zone}` },
      { name: 'www', type: 'A', value: '192.0.2.77' },
    ],
  });
  await page.goto(`/zones/${zone}`);
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Download BIND' }).click(),
  ]);
  expect(download.suggestedFilename()).toMatch(/\.zone$|\.txt$/);
  const text = await readFile((await download.path()) ?? '', 'utf8');
  expect(text).toContain('SOA');
  expect(text).toMatch(/^www\s+IN\s+A\s+192\.0\.2\.77$/m);
});

test('filter by type, delete the zone with the typed confirmation', async ({ page, api }) => {
  const zone = `f${uid()}.test.`;
  await api.ok('post', '/zones', {
    name: zone,
    default_ttl: 300,
    soa: {
      mname: `ns1.${zone}`,
      rname: `h.${zone}`,
      refresh: 3600,
      retry: 600,
      expire: 1209600,
      minimum: 300,
    },
    records: [
      { name: '@', type: 'NS', value: `ns1.${zone}` },
      { name: 'a', type: 'A', value: '192.0.2.1' },
    ],
  });
  await page.goto(`/zones/${zone}`);
  await page.getByLabel('Filter by type').selectOption('NS');
  await expect(page.getByRole('row', { name: /\bA\b.*192\.0\.2\.1/ })).toHaveCount(0);
  await expect(page.getByRole('row', { name: /NS/ })).toBeVisible();

  await page.getByRole('button', { name: 'Delete zone' }).click();
  const dialog = page.getByRole('dialog', { name: 'Delete zone' });
  const confirm = dialog.getByRole('button', { name: 'Delete', exact: true });
  await expect(confirm).toBeDisabled();
  await dialog.getByLabel(/Type .* to confirm/).fill(zone);
  await confirm.click();
  await expect(page).toHaveURL(/\/zones$/);
  await expect(page.getByRole('link', { name: zone })).toHaveCount(0);
});

test.describe('viewer', () => {
  test.use({ storageState: roleState('viewer') });

  test('can read zones but the server refuses changes', async ({ page, api }) => {
    const zone = `r${uid()}.test.`;
    await api.ok('post', '/zones', {
      name: zone,
      default_ttl: 300,
      soa: {
        mname: `ns1.${zone}`,
        rname: `h.${zone}`,
        refresh: 3600,
        retry: 600,
        expire: 1209600,
        minimum: 300,
      },
      records: [{ name: '@', type: 'NS', value: `ns1.${zone}` }],
    });
    await page.goto(`/zones/${zone}`);
    await expect(heading(page, zone)).toBeVisible();
    await page.getByRole('button', { name: 'Delete zone' }).click();
    const dialog = page.getByRole('dialog', { name: 'Delete zone' });
    await dialog.getByLabel(/Type .* to confirm/).fill(zone);
    await dialog.getByRole('button', { name: 'Delete', exact: true }).click();
    await expect(dialog.getByRole('alert')).toBeVisible();
  });
});

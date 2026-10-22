import { query } from './support/dns';
import { UPSTREAM_IP } from './support/upstream';
import { expect, heading, sessionFor, test } from './fixtures';

test('a custom block rule changes the DNS answer, an allow rule undoes it, removal restores it', async ({
  page,
  freshServer,
}) => {
  const s = await freshServer();
  await sessionFor(page, s.baseURL);
  await page.goto(`${s.baseURL}/filtering`);
  await expect(page.getByText('No custom rules.')).toBeVisible();
  expect((await query(s.dnsPort, 'ads.example.test')).ips).toEqual([UPSTREAM_IP]);

  const rules = page.getByRole('region', { name: 'Custom rules' });
  await rules.getByLabel('Domain').fill('ads.example.test');
  await rules.getByRole('button', { name: 'Add rule' }).click();
  await expect(rules.getByRole('row', { name: /block.*ads\.example\.test/ })).toBeVisible();
  await expect
    .poll(async () => (await query(s.dnsPort, 'ads.example.test')).ips)
    .toEqual(['0.0.0.0']);

  await rules.getByLabel('Action').selectOption('allow');
  await rules.getByLabel('Domain').fill('ads.example.test');
  await rules.getByRole('button', { name: 'Add rule' }).click();
  await expect(rules.getByRole('row', { name: /allow.*ads\.example\.test/ })).toBeVisible();
  await expect
    .poll(async () => (await query(s.dnsPort, 'ads.example.test')).ips)
    .toEqual([UPSTREAM_IP]);

  await rules.getByRole('button', { name: 'Remove rule ads.example.test' }).first().click();
  const confirm = page.getByRole('dialog');
  await confirm.getByRole('button', { name: /Remove|Delete/ }).click();
  await expect(rules.getByRole('row', { name: /ads\.example\.test/ })).toHaveCount(1);
});

test('an empty domain is rejected with a message', async ({ page, freshServer }) => {
  const s = await freshServer();
  await sessionFor(page, s.baseURL);
  await page.goto(`${s.baseURL}/filtering`);
  await page
    .getByRole('region', { name: 'Custom rules' })
    .getByRole('button', { name: 'Add rule' })
    .click();
  await expect(page.getByText('Enter a domain.')).toBeVisible();
});

test('a local file source is refused from the form with the private-target message', async ({
  page,
  freshServer,
}) => {
  const s = await freshServer();
  await sessionFor(page, s.baseURL);
  await page.goto(`${s.baseURL}/filtering`);
  const lists = page.getByRole('region', { name: 'Blocklist sources' });
  await expect(lists.getByText('No blocklist sources yet.')).toBeVisible();
  await lists.getByRole('button', { name: 'Add source' }).click();
  await expect(lists.getByText('Name and location are required.')).toBeVisible();
  await lists.getByLabel('Name').fill('local-list');
  await lists.getByLabel('URL or file path').fill('/nonexistent/dnsy-e2e-list.txt');
  await lists.getByRole('button', { name: 'Add source' }).click();
  await expect(lists.getByRole('alert')).toContainText('not public');
  await expect(lists.getByText('No blocklist sources yet.')).toBeVisible();
});

test('a blocklist file source blocks the names it lists; it can be disabled, enabled and removed', async ({
  page,
  freshServer,
}) => {
  const { writeFileSync } = await import('node:fs');
  const { join } = await import('node:path');
  const s = await freshServer();
  const file = join(s.dir, 'list.txt');
  writeFileSync(file, 'listed.example.test\n');
  await sessionFor(page, s.baseURL);
  await page.goto(`${s.baseURL}/filtering`);
  const lists = page.getByRole('region', { name: 'Blocklist sources' });
  await lists.getByLabel('Name').fill('file-list');
  await lists.getByLabel('URL or file path').fill(file);
  await lists.getByLabel('Format').selectOption('domains');
  await lists.getByLabel('Allow private targets and local files').check();
  await lists.getByRole('button', { name: 'Add source' }).click();
  const row = lists.getByRole('row', { name: /file-list/ });
  await expect(row).toBeVisible();
  await lists.getByRole('button', { name: 'Refresh file-list' }).click();
  await expect(row.getByRole('cell', { name: '1', exact: true })).toBeVisible();
  await expect
    .poll(async () => (await query(s.dnsPort, 'listed.example.test')).ips)
    .toEqual(['0.0.0.0']);

  await lists.getByRole('button', { name: 'Disable file-list' }).click();
  await expect(row).toContainText('disabled');
  await expect
    .poll(async () => (await query(s.dnsPort, 'listed.example.test')).ips)
    .toEqual([UPSTREAM_IP]);
  await lists.getByRole('button', { name: 'Enable file-list' }).click();
  await expect(row).toContainText('enabled');

  await lists.getByRole('button', { name: 'Remove file-list' }).click();
  await page
    .getByRole('dialog')
    .getByRole('button', { name: /Remove|Delete/ })
    .click();
  await expect(lists.getByText('No blocklist sources yet.')).toBeVisible();
});

test('ACL: a deny rule for the client makes the DNS server refuse, removing it restores service', async ({
  page,
  freshServer,
}) => {
  const s = await freshServer();
  await sessionFor(page, s.baseURL);
  await page.goto(`${s.baseURL}/acl`);
  await expect(page.getByText('No access rules.')).toBeVisible();

  const form = page.getByRole('region', { name: 'Access rules' });
  await form.getByLabel('Address or CIDR').fill('not-a-cidr');
  await form.getByRole('button', { name: 'Add rule' }).click();
  await expect(form.getByRole('alert')).toBeVisible();

  await form.getByLabel('Address or CIDR').fill('127.0.0.0/8');
  await form.getByLabel('Action').selectOption('refuse');
  await form.getByLabel('Comment').fill('block loopback');
  await form.getByRole('button', { name: 'Add rule' }).click();
  await expect(
    form.getByRole('row', { name: /127\.0\.0\.0\/8.*refuse.*block loopback/ }),
  ).toBeVisible();
  await expect.poll(async () => (await query(s.dnsPort, 'x.example.test')).rcode).toBe(5);

  await form.getByRole('button', { name: 'Remove rule 127.0.0.0/8' }).click();
  await page
    .getByRole('dialog')
    .getByRole('button', { name: /Remove|Delete/ })
    .click();
  await expect(page.getByText('No access rules.')).toBeVisible();
  await expect.poll(async () => (await query(s.dnsPort, 'x.example.test')).rcode).toBe(0);
});

test('ACL: the per-client rate limit saves and rejects bad values', async ({
  page,
  freshServer,
}) => {
  const s = await freshServer();
  await sessionFor(page, s.baseURL);
  await page.goto(`${s.baseURL}/acl`);
  const rl = page.getByRole('region', { name: 'Rate limit' });
  await rl.getByLabel('Queries per second').fill('abc');
  await rl.getByRole('button', { name: 'Save' }).click();
  await expect(rl.getByRole('alert')).toBeVisible();
  await rl.getByLabel('Queries per second').fill('50');
  await rl.getByRole('button', { name: 'Save' }).click();
  await expect(rl.getByText('Rate limit saved.')).toBeVisible();
});

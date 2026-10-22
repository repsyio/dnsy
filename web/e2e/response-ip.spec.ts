import { query } from './support/dns';
import { UPSTREAM_IP } from './support/upstream';
import { expect, heading, sessionFor, test } from './fixtures';

test('an operator edits the list and the DNS server blocks a response IP, clearing it restores service', async ({
  page,
  freshServer,
}) => {
  const s = await freshServer();
  await sessionFor(page, s.baseURL, 'operator');
  await page.goto(`${s.baseURL}/response-ip`);
  await expect(heading(page, 'Response IP policy')).toBeVisible();
  await expect(page.getByText('No response IPs are blocked.')).toBeVisible();
  expect((await query(s.dnsPort, 'x.example.test')).ips).toEqual([UPSTREAM_IP]);

  const list = page.getByLabel('Addresses or CIDRs, one per line');
  await list.fill('not-an-ip');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('alert')).toContainText('not-an-ip');

  await list.fill('192.0.2.0/24');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('Response IP policy saved.')).toBeVisible();
  await expect
    .poll(async () => (await query(s.dnsPort, 'y.example.test')).ips)
    .not.toEqual([UPSTREAM_IP]);

  await page.reload();
  await expect(list).toHaveValue('192.0.2.0/24');

  await list.fill('');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByText('No response IPs are blocked.')).toBeVisible();
  await expect
    .poll(async () => (await query(s.dnsPort, 'z.example.test')).ips)
    .toEqual([UPSTREAM_IP]);
});

test('a viewer sees the list read-only', async ({ page, freshServer }) => {
  const s = await freshServer();
  const admin = await sessionFor(page, s.baseURL, 'admin');
  await admin.ok('put', '/response-ip', { cidrs: ['10.0.0.0/8'] });
  await sessionFor(page, s.baseURL, 'viewer');
  await page.goto(`${s.baseURL}/response-ip`);
  await expect(page.getByRole('list', { name: 'Blocked response networks' })).toContainText(
    '10.0.0.0/8',
  );
  await expect(page.getByRole('textbox')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Save' })).toHaveCount(0);
});

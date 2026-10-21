import { query } from './support/dns';
import { expect, sessionFor, test } from './fixtures';

test('saving settings applies them: block mode changes the answer for blocked names', async ({
  page,
  freshServer,
}) => {
  const s = await freshServer();
  const api = await sessionFor(page, s.baseURL);
  await api.ok('post', '/rules', { kind: 'block', domain: 'blocked.example.test' });
  expect((await query(s.dnsPort, 'blocked.example.test')).ips).toEqual(['0.0.0.0']);

  await page.goto(`${s.baseURL}/settings`);
  await page.getByLabel('Blocked query response').selectOption('nxdomain');
  await page.getByLabel('Per-client queries per second').fill('0');
  await page.getByLabel('Retention (days)').fill('7');
  await page.getByRole('button', { name: 'Save settings' }).click();
  await expect(page.getByText('Settings saved.')).toBeVisible();
  await expect.poll(async () => (await query(s.dnsPort, 'blocked.example.test')).rcode).toBe(3);

  // The saved values survive a reload.
  await page.reload();
  await expect(page.getByLabel('Blocked query response')).toHaveValue('nxdomain');
  await expect(page.getByLabel('Retention (days)')).toHaveValue('7');
});

test('invalid values show field errors and nothing is saved', async ({ page, freshServer }) => {
  const s = await freshServer();
  await sessionFor(page, s.baseURL);
  await page.goto(`${s.baseURL}/settings`);
  await page.getByLabel('Per-client queries per second').fill('-1');
  await page.getByLabel('Retention (days)').fill('abc');
  await page.getByLabel('Minimum TTL (seconds)').fill('5000');
  await page.getByLabel('Maximum TTL (seconds)').fill('10');
  await page.getByRole('button', { name: 'Save settings' }).click();
  await expect(page.getByRole('alert')).toHaveCount(3);
  await expect(page.getByText('Settings saved.')).toHaveCount(0);
  await expect(page.getByLabel('Per-client queries per second')).toHaveAttribute(
    'aria-invalid',
    'true',
  );
});

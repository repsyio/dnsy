import { query } from './support/dns';
import { expect, sessionFor, test } from './fixtures';

test('statistics reflect traffic; flushing a name and the whole cache sends queries upstream again', async ({
  page,
  freshServer,
}) => {
  const s = await freshServer();
  await sessionFor(page, s.baseURL);
  await query(s.dnsPort, 'one.example.test');
  await query(s.dnsPort, 'one.example.test');
  await query(s.dnsPort, 'sub.two.example.test');
  expect(s.upstream.received).toBe(2);

  await page.goto(`${s.baseURL}/cache`);
  const stats = page.getByRole('region', { name: 'Statistics' });
  await expect(
    stats.locator('dt', { hasText: 'Hits' }).locator('xpath=following-sibling::dd'),
  ).toHaveText('1');
  await expect(
    stats.locator('dt', { hasText: 'Entries' }).locator('xpath=following-sibling::dd'),
  ).toContainText(/^2 \//);

  const flush = page.getByRole('region', { name: 'Flush' });
  await flush.getByLabel('Domain name').fill('one.example.test');
  await flush.getByRole('button', { name: 'Flush name' }).click();
  await expect(flush.getByRole('status')).toContainText('Flushed 1 entry');
  await query(s.dnsPort, 'one.example.test');
  expect(s.upstream.received).toBe(3);

  await flush.getByLabel('Domain name').fill('two.example.test');
  await flush.getByLabel('Include subdomains').check();
  await flush.getByRole('button', { name: 'Flush name' }).click();
  await expect(flush.getByRole('status')).toContainText('Flushed 1 entry');

  await flush.getByRole('button', { name: 'Flush entire cache' }).click();
  const dialog = page.getByRole('dialog', { name: 'Flush entire cache' });
  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(dialog).toBeHidden();
  await flush.getByRole('button', { name: 'Flush entire cache' }).click();
  await page
    .getByRole('dialog', { name: 'Flush entire cache' })
    .getByRole('button', { name: 'Flush cache' })
    .click();
  await expect(flush.getByRole('status')).toContainText(/Flushed \d+ entr/);
  await query(s.dnsPort, 'one.example.test');
  expect(s.upstream.received).toBe(4);
});

test('an empty or invalid name is rejected before any request', async ({ page }) => {
  await page.goto('/cache');
  await page
    .getByRole('region', { name: 'Flush' })
    .getByRole('button', { name: 'Flush name' })
    .click();
  await expect(page.getByRole('region', { name: 'Flush' }).getByRole('alert')).toBeVisible();
});

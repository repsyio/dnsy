import { createHash } from 'node:crypto';
import { expect, heading, sessionFor, test, uid } from './fixtures';

function fingerprint(): string {
  return createHash('sha256').update(uid()).digest('hex');
}

test('allow a client certificate fingerprint, disable, enable and remove it', async ({
  page,
  freshServer,
}) => {
  const s = await freshServer();
  await sessionFor(page, s.baseURL);
  await page.goto(`${s.baseURL}/client-certs`);
  await expect(page.getByText('No client certificates are allowed yet.')).toBeVisible();

  const fp = fingerprint();
  await page.getByLabel('SHA-256 fingerprint').fill(fp);
  await page.getByLabel('Label').fill('laptop');
  await page.getByRole('button', { name: 'Add', exact: true }).click();
  const row = page.getByRole('row', { name: /laptop/ });
  await expect(row).toContainText(fp);

  await page.getByRole('button', { name: 'Disable laptop' }).click();
  await expect(row).toContainText(/disabled/i);
  await page.getByRole('button', { name: 'Enable laptop' }).click();
  await expect(row).not.toContainText(/disabled/i);

  await page.getByRole('button', { name: 'Remove laptop' }).click();
  await page
    .getByRole('dialog', { name: 'Remove client certificate' })
    .getByRole('button', { name: /Remove|Delete/ })
    .click();
  await expect(page.getByText('No client certificates are allowed yet.')).toBeVisible();
});

test('a malformed fingerprint and a missing label are rejected', async ({ page, freshServer }) => {
  const s = await freshServer();
  await sessionFor(page, s.baseURL);
  await page.goto(`${s.baseURL}/client-certs`);
  await expect(heading(page, 'Client certificates')).toBeVisible();
  await page.getByLabel('SHA-256 fingerprint').fill('zz-not-hex');
  await page.getByRole('button', { name: 'Add', exact: true }).click();
  await expect(page.getByRole('alert').first()).toBeVisible();
  await expect(page.getByText('No client certificates are allowed yet.')).toBeVisible();
});

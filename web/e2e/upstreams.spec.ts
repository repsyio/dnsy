import { expect, sessionFor, test, uid } from './fixtures';

test('the default group lists the fake upstream; groups and members can be managed', async ({
  page,
  freshServer,
}) => {
  const s = await freshServer();
  await sessionFor(page, s.baseURL);
  await page.goto(`${s.baseURL}/upstreams`);
  await expect(page.getByRole('heading', { level: 1, name: 'Upstreams' })).toBeVisible();
  await expect(page.getByText(s.upstream.address).first()).toBeVisible();

  const name = `grp-${uid()}`;
  const create = page.getByRole('region', { name: 'New group' });
  await create.getByLabel('Name').fill(name);
  await create.getByLabel('First upstream').fill('udp://203.0.113.9:53');
  await create.getByRole('button', { name: 'Create' }).click();
  const group = page.getByRole('region', { name: name });
  await expect(group.getByText('udp://203.0.113.9:53')).toBeVisible();

  await group.getByLabel('Add upstream').fill('udp://203.0.113.10:53');
  await group.getByRole('button', { name: 'Add member' }).click();
  await expect(group.getByText('udp://203.0.113.10:53')).toBeVisible();

  await group.getByRole('button', { name: `Remove udp://203.0.113.10:53 from ${name}` }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Remove', exact: true }).click();
  await expect(group.getByText('udp://203.0.113.10:53')).toHaveCount(0);

  await page.getByRole('button', { name: `Delete group ${name}` }).click();
  await page
    .getByRole('dialog')
    .getByRole('button', { name: /Delete/ })
    .click();
  await expect(page.getByRole('region', { name })).toHaveCount(0);
});

test('the example in the placeholder is a valid upstream address', async ({
  page,
  freshServer,
}) => {
  const s = await freshServer();
  await sessionFor(page, s.baseURL);
  await page.goto(`${s.baseURL}/upstreams`);
  const create = page.getByRole('region', { name: 'New group' });
  const example =
    (await create.getByLabel('First upstream').getAttribute('placeholder'))?.split(' or ')[0] ?? '';
  const name = `ph-${uid()}`;
  await create.getByLabel('Name').fill(name);
  await create.getByLabel('First upstream').fill(example);
  await create.getByRole('button', { name: 'Create' }).click();
  await expect(page.getByRole('region', { name })).toContainText(example.replace('udp://', ''));
});

test('an invalid upstream address is refused by the server', async ({ page, freshServer }) => {
  const s = await freshServer();
  await sessionFor(page, s.baseURL);
  await page.goto(`${s.baseURL}/upstreams`);
  const create = page.getByRole('region', { name: 'New group' });
  await create.getByLabel('Name').fill(`bad-${uid()}`);
  await create.getByLabel('First upstream').fill('???');
  await create.getByRole('button', { name: 'Create' }).click();
  await expect(page.getByRole('alert').first()).toBeVisible();
});

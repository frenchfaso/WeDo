import { expect, test } from '@playwright/test';

const ADMIN_AGENT_SECRET = process.env.WEDO_ADMIN_AGENT_API_SECRET || 'dev-admin-agent-secret';
const AGENT_SECRET = process.env.WEDO_AGENT_API_SECRET || 'dev-agent-secret';

function uniqueValue(prefix) {
    return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

async function waitForApp(request) {
    await expect
        .poll(
            async () => {
                try {
                    const response = await request.get('/healthz');
                    return response.status();
                } catch {
                    return 0;
                }
            },
            {
                timeout: 30 * 1000,
                intervals: [500, 1000, 2000]
            }
        )
        .toBe(200);
}

async function createUser(request, username) {
    const response = await request.post('/api/agent/admin/users', {
        headers: {
            'X-Agent-Admin-Secret': ADMIN_AGENT_SECRET
        },
        data: { username }
    });

    expect(response.ok()).toBeTruthy();
    const payload = await response.json();
    expect(payload.username).toBe(username);
    expect(payload.temporary_password).toBeTruthy();
    return payload.temporary_password;
}

async function loginAndSetPassword(page, username, temporaryPassword, finalPassword) {
    await page.goto('/');
    await page.getByPlaceholder('Username').fill(username);
    await page.getByPlaceholder('Password').fill(temporaryPassword);
    await page.getByRole('button', { name: 'Log In' }).click();

    await expect(page.getByText(`Benvenuto ${username}`)).toBeVisible();
    await page.getByPlaceholder('Nuova password').fill(finalPassword);
    await page.getByPlaceholder('Conferma password').fill(finalPassword);
    await page.getByRole('button', { name: 'Conferma password' }).click();

    await expect(page.getByPlaceholder('Add a new list...')).toBeVisible();
}

test('sets up a new account and manages lists and todos locally', async ({ page, request }) => {
    await waitForApp(request);

    const username = uniqueValue('ui-user');
    const password = 'final-password-123';
    const temporaryPassword = await createUser(request, username);
    const listName = uniqueValue('Groceries');
    const todoName = uniqueValue('Milk');

    await loginAndSetPassword(page, username, temporaryPassword, password);

    await page.getByPlaceholder('Add a new list...').fill(listName);
    await page.getByRole('button', { name: 'Add list' }).click();
    await expect(page.locator('.header-center').getByText(listName)).toBeVisible();
    await expect(page.getByPlaceholder('Add a to-do...')).toBeVisible();

    await page.getByPlaceholder('Add a to-do...').fill(todoName);
    await page.getByRole('button', { name: 'Add todo' }).click();
    await expect(page.getByText(todoName)).toBeVisible();

    await page.getByText(todoName).click();
    await expect(page.locator('.row-title.done', { hasText: todoName })).toBeVisible();
});

test('shows server-side agent changes without a manual refresh', async ({ page, request }) => {
    await waitForApp(request);

    const username = uniqueValue('sync-user');
    const password = 'final-password-123';
    const temporaryPassword = await createUser(request, username);
    const listId = uniqueValue('list');
    const listName = uniqueValue('Server list');
    const todoId = uniqueValue('todo');
    const todoName = uniqueValue('Server todo');

    await loginAndSetPassword(page, username, temporaryPassword, password);

    const listResponse = await request.post('/api/agent/lists', {
        headers: {
            'X-Agent-Secret': AGENT_SECRET,
            'X-Acting-Username': username
        },
        data: {
            id: listId,
            name: listName
        }
    });
    expect(listResponse.ok()).toBeTruthy();

    await expect(page.getByText(listName)).toBeVisible();
    await page.getByText(listName).click();
    await expect(page.getByPlaceholder('Add a to-do...')).toBeVisible();

    const todoResponse = await request.post(`/api/agent/lists/${encodeURIComponent(listId)}/items`, {
        headers: {
            'X-Agent-Secret': AGENT_SECRET,
            'X-Acting-Username': username
        },
        data: {
            id: todoId,
            title: todoName
        }
    });
    expect(todoResponse.ok()).toBeTruthy();

    await expect(page.getByText(todoName)).toBeVisible();
});

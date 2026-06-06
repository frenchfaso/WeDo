
import Alpine from '@alpinejs/csp';
import { markRaw } from '@vue/reactivity';
import { addRxPlugin, createRxDatabase, removeRxDatabase } from 'rxdb';
import { RxDBMigrationSchemaPlugin } from 'rxdb/plugins/migration-schema';
import { replicateRxCollection } from 'rxdb/plugins/replication';
import { getRxStorageDexie } from 'rxdb/plugins/storage-dexie';
import { Subject } from 'rxjs';
import { registerSW } from 'virtual:pwa-register';

addRxPlugin(RxDBMigrationSchemaPlugin);

const LIST_SCHEMA = {
    title: 'wedo list schema',
    version: 2,
    primaryKey: 'id',
    type: 'object',
    properties: {
        id: { type: 'string', maxLength: 120 },
        owner_id: { type: 'string', maxLength: 120 },
        name: { type: 'string', minLength: 1, maxLength: 200 },
        archived: { type: 'boolean', default: false },
        access_role: { type: 'string', maxLength: 16, default: 'owner' },
        shared_with_count: { type: 'number', minimum: 0, maximum: 1000, multipleOf: 1, default: 0 },
        owner_username: { type: 'string', maxLength: 120, default: '' },
        created_at: { type: 'string', maxLength: 64 },
        updated_at: { type: 'string', maxLength: 64 },
        _deleted: { type: 'boolean', default: false }
    },
    required: ['id', 'owner_id', 'name', 'archived', 'access_role', 'shared_with_count', 'owner_username', 'created_at', 'updated_at', '_deleted'],
    indexes: [['updated_at', 'id']]
};

const TODO_SCHEMA = {
    title: 'wedo todo schema',
    version: 0,
    primaryKey: 'id',
    type: 'object',
    properties: {
        id: { type: 'string', maxLength: 120 },
        list_id: { type: 'string', maxLength: 120 },
        title: { type: 'string', minLength: 1, maxLength: 200 },
        done: { type: 'boolean', default: false },
        created_at: { type: 'string', maxLength: 64 },
        updated_at: { type: 'string', maxLength: 64 },
        _deleted: { type: 'boolean', default: false }
    },
    required: ['id', 'list_id', 'title', 'done', 'created_at', 'updated_at', '_deleted'],
    indexes: [['updated_at', 'id'], 'list_id']
};

const ROOT_PATH = '/';
const LIST_ROUTE_PATTERN = /^\/lists\/([^/]+)$/;
const SYNC_WAIT_TIMEOUT_MS = 8000;
const SERVICE_WORKER_UPDATE_INTERVAL_MS = 60 * 60 * 1000;
const RESYNC_FALLBACK_INTERVAL_MS = 30 * 1000;
const DATABASE_NAME_PREFIX = 'wedo';
const APP_VERSION = __APP_VERSION__;
const rxStorage = getRxStorageDexie();

let dbPromise = null;
let currentDatabaseName = null;

function getDatabaseName(userId) {
    return `${DATABASE_NAME_PREFIX}_${String(userId).replace(/[^a-zA-Z0-9_-]/g, '_')}`;
}

async function disposeDatabase({ remove = false, databaseName = null } = {}) {
    const existingDatabasePromise = dbPromise;
    const databaseNameToRemove = databaseName || currentDatabaseName;

    dbPromise = null;
    currentDatabaseName = null;

    if (!existingDatabasePromise && !(remove && databaseNameToRemove)) {
        return;
    }

    try {
        if (existingDatabasePromise) {
            const db = await existingDatabasePromise;
            if (remove) {
                await db.remove();
            } else {
                await db.close();
            }
            return;
        }
    } catch {
        // ignore cleanup failures
    }

    if (remove && databaseNameToRemove) {
        try {
            await removeRxDatabase(databaseNameToRemove, rxStorage);
        } catch {
            // ignore cleanup failures
        }
    }
}

function registerAppServiceWorker() {
    if (typeof window === 'undefined' || !('serviceWorker' in navigator)) {
        return;
    }

    const updateSW = registerSW({
        immediate: true,
        onNeedRefresh() {
            updateSW(true);
        },
        onRegisteredSW(_swScriptUrl, registration) {
            if (!registration) {
                return;
            }

            const checkForUpdates = async () => {
                if (document.visibilityState !== 'visible' || !navigator.onLine) {
                    return;
                }

                try {
                    await registration.update();
                } catch {
                    // ignore update check failures
                }
            };

            const intervalId = window.setInterval(() => {
                void checkForUpdates();
            }, SERVICE_WORKER_UPDATE_INTERVAL_MS);
            const handleVisibilityChange = () => {
                void checkForUpdates();
            };
            const handleFocus = () => {
                void checkForUpdates();
            };

            document.addEventListener('visibilitychange', handleVisibilityChange);
            window.addEventListener('focus', handleFocus);
            window.addEventListener('beforeunload', () => {
                window.clearInterval(intervalId);
                document.removeEventListener('visibilitychange', handleVisibilityChange);
                window.removeEventListener('focus', handleFocus);
            }, { once: true });

            void checkForUpdates();
        }
    });
}

function createId(prefix) {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
        return `${prefix}_${crypto.randomUUID()}`;
    }
    return `${prefix}_${Date.now()}_${Math.random().toString(16).slice(2, 10)}`;
}

function nowIso() {
    return new Date().toISOString();
}

function sortTodos(todos) {
    return [...todos].sort((left, right) => {
        if (left.done !== right.done) {
            return Number(left.done) - Number(right.done);
        }
        const updatedComparison = right.updated_at.localeCompare(left.updated_at);
        if (updatedComparison !== 0) {
            return updatedComparison;
        }
        return left.id.localeCompare(right.id);
    });
}

function parsePath(pathname) {
    const match = pathname.match(LIST_ROUTE_PATTERN);
    if (match) {
        return {
            name: 'list',
            listId: decodeURIComponent(match[1])
        };
    }

    return {
        name: 'lists',
        listId: null
    };
}

function getLocalSetupErrorMessage(error) {
    const message = error instanceof Error ? error.message : String(error || '');
    const normalizedMessage = message.toLowerCase();

    if (
        normalizedMessage.includes('migration-schema')
        || normalizedMessage.includes('migration')
        || normalizedMessage.includes('indexeddb')
        || normalizedMessage.includes('dexie')
        || normalizedMessage.includes('rxerror')
        || normalizedMessage.includes('database')
    ) {
        return 'Offline data could not be opened. Refresh the app to load the latest update.';
    }

    return 'Signed in, but app setup could not finish on this device. Refresh and try again.';
}

function getRawState(component) {
    return Alpine.raw(component);
}

function getRawCollections(component) {
    return getRawState(component).collections;
}

function markRxDatabaseRaw(db) {
    markRaw(db);
    markRaw(db.collections);
    Object.values(db.collections).forEach((collection) => markRaw(collection));
    return db;
}

async function getDatabase(userId) {
    const databaseName = getDatabaseName(userId);

    if (dbPromise && currentDatabaseName === databaseName) {
        return dbPromise;
    }

    if (dbPromise && currentDatabaseName !== databaseName) {
        await disposeDatabase();
    }

    if (!dbPromise) {
        currentDatabaseName = databaseName;
        dbPromise = createRxDatabase({
            name: databaseName,
            storage: rxStorage,
            multiInstance: false,
            closeDuplicates: true
        }).then(async (db) => {
            await db.addCollections({
                lists: {
                    schema: LIST_SCHEMA,
                    migrationStrategies: {
                        1: (oldDoc) => ({
                            access_role: 'owner',
                            shared_with_count: 0,
                            owner_username: '',
                            ...oldDoc
                        }),
                        2: (oldDoc) => ({
                            access_role: oldDoc.access_role || 'owner',
                            shared_with_count: Number.isFinite(oldDoc.shared_with_count) ? oldDoc.shared_with_count : 0,
                            owner_username: oldDoc.owner_username || '',
                            ...oldDoc
                        })
                    }
                },
                todos: { schema: TODO_SCHEMA }
            });
            return markRxDatabaseRaw(db);
        }).catch((error) => {
            dbPromise = null;
            currentDatabaseName = null;
            throw error;
        });
    }

    return dbPromise;
}

window.Alpine = Alpine;

registerAppServiceWorker();

document.addEventListener('alpine:init', () => {
    Alpine.data('app', () => ({
        appVersion: APP_VERSION,
        user: null,
        passwordSetupRequired: false,
        username: '',
        password: '',
        passwordSetup: '',
        passwordSetupConfirm: '',
        passwordSetupError: '',
        passwordSetupLoading: false,
        error: '',
        syncError: '',
        loading: false,
        syncing: false,
        lists: [],
        todos: [],
        newListName: '',
        newTodoTitle: '',
        selectedListId: null,
        selectedList: null,
        shareModalOpen: false,
        shareTargetListId: null,
        shareTargetListName: '',
        shareUsername: '',
        shareMembers: [],
        shareLoading: false,
        shareSaving: false,
        shareError: '',
        detailMenuOpen: false,
        openListMenuId: null,
        openTodoMenuId: null,
        editingListId: null,
        editingListName: '',
        editingTodoId: null,
        editingTodoTitle: '',
        pendingPath: null,
        db: null,
        collections: null,
        invalidationStream$: null,
        invalidationEventSource: null,
        replications: [],
        querySubscriptions: [],
        replicationSubscriptions: [],
        onlineListener: null,
        visibilitySyncListener: null,
        focusSyncListener: null,
        resyncFallbackIntervalId: null,
        popstateListener: null,

        get isAuthenticated() {
            return Boolean(this.user);
        },

        get passwordSetupTitle() {
            return `Benvenuto ${this.user ? this.user.username : ''}, scegli una password`;
        },

        get shareModalTitle() {
            return this.shareTargetListName ? `Share ${this.shareTargetListName}` : 'Share list';
        },

        get isDetailRoute() {
            return Boolean(this.selectedListId);
        },

        get hasSelectedList() {
            return this.selectedList !== null;
        },

        get isEditingSelectedList() {
            return this.selectedList !== null && this.editingListId === this.selectedList.id;
        },

        get canManageSelectedList() {
            return this.selectedList !== null && this.selectedList.access_role === 'owner';
        },

        get selectedListMeta() {
            if (!this.selectedList) {
                return '';
            }

            if (this.selectedList.access_role === 'shared') {
                return this.selectedList.owner_username ? `Shared by ${this.selectedList.owner_username}` : 'Shared list';
            }

            if (this.selectedList.shared_with_count > 0) {
                return this.selectedList.shared_with_count === 1
                    ? 'Shared with 1 person'
                    : `Shared with ${this.selectedList.shared_with_count} people`;
            }

            return 'Private list';
        },

        async init() {
            this.setupNavigation();
            await this.loadSession();
        },

        setupNavigation() {
            this.popstateListener = () => {
                this.applyRoute(window.location.pathname, { fromHistory: true });
            };
            window.addEventListener('popstate', this.popstateListener);
            this.applyRoute(window.location.pathname, { fromHistory: true });
        },

        parsePath,

        applyRoute(pathname, { fromHistory = false } = {}) {
            const route = this.parsePath(pathname);

            if ((!this.user || this.passwordSetupRequired) && route.name === 'list') {
                this.pendingPath = pathname;
                if (window.location.pathname !== ROOT_PATH) {
                    window.history.replaceState({}, '', ROOT_PATH);
                }
                this.selectedListId = null;
                this.selectedList = null;
                this.closeDetailMenu();
                this.closeListMenu();
                this.closeTodoMenu();
                this.closeShareModal();
                this.todos = [];
                this.cancelTodoEdit();
                this.cancelListEdit();
                return;
            }

            this.selectedListId = route.listId;
            this.selectedList = this.lists.find((list) => list.id === route.listId) || null;
            if (!this.selectedListId) {
                this.closeDetailMenu();
                this.closeTodoMenu();
                this.closeShareModal();
            }

            if (!fromHistory) {
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }

            this.bindCollectionQueries();
        },

        reconcileSelectedRoute() {
            if (!this.selectedListId || this.selectedList || this.syncing) {
                return;
            }

            this.navigateTo(ROOT_PATH, { replace: true });
        },

        navigateTo(pathname, { replace = false } = {}) {
            if (window.location.pathname !== pathname) {
                const method = replace ? 'replaceState' : 'pushState';
                window.history[method]({}, '', pathname);
            }
            this.applyRoute(pathname);
        },

        openList(listId) {
            this.navigateTo(`/lists/${encodeURIComponent(listId)}`);
        },

        toggleListMenu(listId) {
            this.openListMenuId = this.openListMenuId === listId ? null : listId;
        },

        canManageList(list) {
            return Boolean(list) && list.access_role === 'owner';
        },

        listMeta(list) {
            if (!list) {
                return '';
            }

            if (list.access_role === 'shared') {
                return list.owner_username ? `Shared by ${list.owner_username}` : 'Shared list';
            }

            if (list.shared_with_count > 0) {
                return list.shared_with_count === 1
                    ? '1 collaborator'
                    : `${list.shared_with_count} collaborators`;
            }

            return 'Private';
        },

        closeListMenu() {
            this.openListMenuId = null;
        },

        renameListFromMenu(list) {
            this.closeListMenu();
            this.startListEdit(list);
        },

        openShareManagerFromMenu(list) {
            this.closeListMenu();
            void this.openShareManager(list);
        },

        deleteListFromMenu(listId) {
            this.closeListMenu();
            this.deleteList(listId);
        },

        renameSelectedList() {
            if (!this.selectedList) {
                return;
            }
            this.startListEdit(this.selectedList);
        },

        removeSelectedList() {
            if (!this.selectedList) {
                return;
            }
            this.deleteList(this.selectedList.id);
        },

        toggleDetailMenu() {
            this.detailMenuOpen = !this.detailMenuOpen;
        },

        closeDetailMenu() {
            this.detailMenuOpen = false;
        },

        renameSelectedListFromMenu() {
            this.closeDetailMenu();
            this.renameSelectedList();
        },

        openSelectedListShareManager() {
            if (!this.selectedList) {
                return;
            }
            void this.openShareManager(this.selectedList);
        },

        openSelectedListShareManagerFromMenu() {
            this.closeDetailMenu();
            this.openSelectedListShareManager();
        },

        removeSelectedListFromMenu() {
            this.closeDetailMenu();
            this.removeSelectedList();
        },

        async openShareManager(list) {
            if (!this.canManageList(list)) {
                return;
            }

            this.shareModalOpen = true;
            this.shareTargetListId = list.id;
            this.shareTargetListName = list.name;
            this.shareUsername = '';
            this.shareMembers = [];
            this.shareError = '';
            this.shareLoading = true;

            try {
                const response = await this.request(`/api/lists/${encodeURIComponent(list.id)}/shares`, { method: 'GET' });
                if (!response.ok) {
                    const payload = await response.json().catch(() => ({ detail: 'Could not load sharing.' }));
                    this.shareError = payload.detail || 'Could not load sharing.';
                    return;
                }

                const payload = await response.json();
                this.shareMembers = Array.isArray(payload.members) ? payload.members : [];
            } catch {
                this.shareError = 'Unable to reach the server.';
            } finally {
                this.shareLoading = false;
            }
        },

        closeShareModal() {
            this.shareModalOpen = false;
            this.shareTargetListId = null;
            this.shareTargetListName = '';
            this.shareUsername = '';
            this.shareMembers = [];
            this.shareLoading = false;
            this.shareSaving = false;
            this.shareError = '';
        },

        async resyncCollections() {
            if (!this.replications.length) {
                return;
            }

            this.replications.forEach((replication) => replication.reSync());
            await this.waitForSync();
        },

        async addShareMember() {
            const username = this.shareUsername.trim();
            if (!username || !this.shareTargetListId) {
                return;
            }

            this.shareSaving = true;
            this.shareError = '';

            try {
                const response = await this.request(`/api/lists/${encodeURIComponent(this.shareTargetListId)}/shares`, {
                    method: 'POST',
                    body: JSON.stringify({ username })
                });

                if (!response.ok) {
                    const payload = await response.json().catch(() => ({ detail: 'Could not share list.' }));
                    this.shareError = payload.detail || 'Could not share list.';
                    return;
                }

                const member = await response.json();
                this.shareUsername = '';
                this.shareMembers = [...this.shareMembers.filter((item) => item.user_id !== member.user_id), member]
                    .sort((left, right) => left.username.localeCompare(right.username));
                await this.resyncCollections();
            } catch {
                this.shareError = 'Unable to reach the server.';
            } finally {
                this.shareSaving = false;
            }
        },

        async revokeShareMember(userId) {
            if (!this.shareTargetListId || !userId) {
                return;
            }

            this.shareSaving = true;
            this.shareError = '';

            try {
                const response = await this.request(
                    `/api/lists/${encodeURIComponent(this.shareTargetListId)}/shares/${encodeURIComponent(userId)}`,
                    { method: 'DELETE' }
                );

                if (!response.ok) {
                    const payload = await response.json().catch(() => ({ detail: 'Could not revoke access.' }));
                    this.shareError = payload.detail || 'Could not revoke access.';
                    return;
                }

                this.shareMembers = this.shareMembers.filter((member) => member.user_id !== userId);
                await this.resyncCollections();
            } catch {
                this.shareError = 'Unable to reach the server.';
            } finally {
                this.shareSaving = false;
            }
        },

        toggleTodoMenu(todoId) {
            this.openTodoMenuId = this.openTodoMenuId === todoId ? null : todoId;
        },

        closeTodoMenu() {
            this.openTodoMenuId = null;
        },

        editTodoFromMenu(todo) {
            this.closeTodoMenu();
            this.startTodoEdit(todo);
        },

        deleteTodoFromMenu(todoId) {
            this.closeTodoMenu();
            this.deleteTodo(todoId);
        },

        showLists() {
            this.navigateTo(ROOT_PATH);
        },

        async request(path, options = {}) {
            const response = await fetch(path, {
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    ...(options.headers || {})
                },
                ...options
            });

            if (response.status === 401) {
                await this.resetLocalState();
            }

            return response;
        },

        async loadSession() {
            this.error = '';

            try {
                const response = await this.request('/api/auth/me', { method: 'GET' });
                if (!response.ok) {
                    return;
                }

                this.user = await response.json();
                this.passwordSetupRequired = Boolean(this.user.password_setup_required);
            } catch {
                this.error = 'Unable to reach the server.';
                return;
            }

            if (!this.passwordSetupRequired) {
                try {
                    await this.initializeLocalState();
                } catch (error) {
                    this.error = getLocalSetupErrorMessage(error);
                    return;
                }
            }

            if (!this.passwordSetupRequired && this.pendingPath) {
                const path = this.pendingPath;
                this.pendingPath = null;
                this.navigateTo(path, { replace: true });
            } else {
                this.applyRoute(window.location.pathname, { fromHistory: true });
            }
        },

        async login() {
            this.loading = true;
            this.error = '';
            this.passwordSetupError = '';

            try {
                const response = await this.request('/api/auth/login', {
                    method: 'POST',
                    body: JSON.stringify({
                        username: this.username,
                        password: this.password,
                        remember_me: true
                    })
                });

                if (!response.ok) {
                    const payload = await response.json().catch(() => ({ detail: 'Login failed.' }));
                    this.error = payload.detail || 'Login failed.';
                    return;
                }

                this.password = '';
                await this.loadSession();
            } catch {
                this.error = 'Unable to reach the server.';
            } finally {
                this.loading = false;
            }
        },

        async logout() {
            try {
                await this.request('/api/auth/logout', { method: 'POST' });
            } finally {
                await this.resetLocalState();
            }
        },

        async initializeLocalState() {
            if (!this.user || this.passwordSetupRequired) {
                return;
            }

            try {
                await this.openLocalState();
            } catch {
                await this.recoverLocalStateAfterSetupFailure();
                await this.openLocalState();
            }
        },

        async openLocalState() {
            const db = await getDatabase(this.user.id);
            const rawState = getRawState(this);
            rawState.db = db;
            rawState.collections = db.collections;
            await this.clearReplication();
            this.bindCollectionQueries();
            this.startReplications();
            await this.waitForSync();
        },

        async recoverLocalStateAfterSetupFailure() {
            const databaseName = this.user ? getDatabaseName(this.user.id) : null;
            await this.clearReplication();
            this.clearQuerySubscriptions();
            this.lists = [];
            this.todos = [];
            this.selectedList = null;
            const rawState = getRawState(this);
            rawState.collections = null;
            rawState.db = null;
            await disposeDatabase({ remove: true, databaseName });
        },

        setupInvalidationStream() {
            this.teardownInvalidationStream();
            this.teardownResyncFallback();
            this.setupResyncFallback();

            if (typeof EventSource === 'undefined') {
                return;
            }

            this.invalidationStream$ = new Subject();
            this.invalidationEventSource = new EventSource('/api/sync/invalidation', {
                withCredentials: true
            });

            this.invalidationEventSource.onmessage = (event) => {
                try {
                    const payload = JSON.parse(event.data);
                    if (payload?.type === 'RESYNC') {
                        this.invalidationStream$.next('RESYNC');
                    }
                } catch {
                    // ignore malformed invalidation events
                }
            };

            this.invalidationEventSource.onerror = () => {
                this.triggerResync();
            };
        },

        teardownInvalidationStream() {
            if (this.invalidationEventSource) {
                this.invalidationEventSource.close();
                this.invalidationEventSource = null;
            }

            if (this.invalidationStream$) {
                this.invalidationStream$.complete();
                this.invalidationStream$ = null;
            }
        },

        setupResyncFallback() {
            this.teardownResyncFallback();

            const syncIfVisible = () => {
                if (document.visibilityState !== 'visible' || !navigator.onLine) {
                    return;
                }
                this.triggerResync();
            };

            this.visibilitySyncListener = () => {
                syncIfVisible();
            };
            this.focusSyncListener = () => {
                syncIfVisible();
            };
            this.resyncFallbackIntervalId = window.setInterval(syncIfVisible, RESYNC_FALLBACK_INTERVAL_MS);

            document.addEventListener('visibilitychange', this.visibilitySyncListener);
            window.addEventListener('focus', this.focusSyncListener);
        },

        triggerResync() {
            this.replications.forEach((replication) => replication.reSync());
        },

        teardownResyncFallback() {
            if (this.visibilitySyncListener) {
                document.removeEventListener('visibilitychange', this.visibilitySyncListener);
                this.visibilitySyncListener = null;
            }

            if (this.focusSyncListener) {
                window.removeEventListener('focus', this.focusSyncListener);
                this.focusSyncListener = null;
            }

            if (this.resyncFallbackIntervalId) {
                window.clearInterval(this.resyncFallbackIntervalId);
                this.resyncFallbackIntervalId = null;
            }
        },

        bindCollectionQueries() {
            this.clearQuerySubscriptions();
            const collections = getRawCollections(this);

            if (!collections || !this.user || this.passwordSetupRequired) {
                return;
            }

            const listSubscription = collections.lists
                .find({
                    selector: {
                        _deleted: false
                    },
                    sort: [{ updated_at: 'desc' }, { id: 'asc' }]
                })
                .$
                .subscribe((docs) => {
                    this.lists = docs.map((doc) => doc.toJSON());
                    this.selectedList = this.lists.find((list) => list.id === this.selectedListId) || null;
                    if (this.shareModalOpen && this.shareTargetListId && !this.lists.some((list) => list.id === this.shareTargetListId)) {
                        this.closeShareModal();
                    }
                    if (this.openListMenuId && !this.lists.some((list) => list.id === this.openListMenuId)) {
                        this.closeListMenu();
                    }
                    this.reconcileSelectedRoute();
                });

            this.querySubscriptions.push(listSubscription);

            if (!this.selectedListId) {
                this.todos = [];
                this.selectedList = null;
                this.cancelTodoEdit();
                return;
            }

            const todoSubscription = collections.todos
                .find({
                    selector: {
                        list_id: this.selectedListId,
                        _deleted: false
                    },
                    sort: [{ updated_at: 'desc' }, { id: 'asc' }]
                })
                .$
                .subscribe((docs) => {
                    this.todos = sortTodos(docs.map((doc) => doc.toJSON()));
                    if (this.openTodoMenuId && !this.todos.some((todo) => todo.id === this.openTodoMenuId)) {
                        this.closeTodoMenu();
                    }
                });

            this.querySubscriptions.push(todoSubscription);
        },

        startReplications() {
            const collections = getRawCollections(this);

            if (!collections || this.passwordSetupRequired) {
                return;
            }

            this.syncError = '';
            this.setupInvalidationStream();
            this.replications = [
                markRaw(this.createReplication('lists', collections.lists)),
                markRaw(this.createReplication('todos', collections.todos))
            ];

            this.replications.forEach((replication) => {
                const errorSubscription = replication.error$.subscribe((error) => {
                    const firstError = error?.parameters?.errors?.[0];
                    this.syncError = firstError?.message || error.message || 'Sync failed.';
                });
                this.replicationSubscriptions.push(errorSubscription);
            });

            this.onlineListener = () => {
                this.replications.forEach((replication) => replication.reSync());
            };
            window.addEventListener('online', this.onlineListener);
        },

        createReplication(collectionName, collection) {
            return replicateRxCollection({
                collection,
                replicationIdentifier: `wedo-http-sync-${collectionName}`,
                live: true,
                retryTime: 5000,
                waitForLeadership: true,
                deletedField: '_deleted',
                pull: {
                    batchSize: 50,
                    ...(this.invalidationStream$ ? { stream$: this.invalidationStream$.asObservable() } : {}),
                    handler: async (checkpoint, batchSize) => {
                        const response = await this.request('/api/sync/pull', {
                            method: 'POST',
                            body: JSON.stringify({
                                collection: collectionName,
                                checkpoint: checkpoint || null,
                                limit: batchSize
                            })
                        });

                        if (!response.ok) {
                            throw new Error(`Pull sync failed for ${collectionName}`);
                        }

                        const payload = await response.json();
                        return {
                            documents: payload.documents,
                            checkpoint: payload.checkpoint || checkpoint || null
                        };
                    }
                },
                push: {
                    batchSize: 25,
                    handler: async (rows) => {
                        const response = await this.request('/api/sync/push', {
                            method: 'POST',
                            body: JSON.stringify({
                                collection: collectionName,
                                rows
                            })
                        });

                        if (!response.ok) {
                            throw new Error(`Push sync failed for ${collectionName}`);
                        }

                        return await response.json();
                    }
                }
            });
        },

        async waitForSync() {
            if (!this.replications.length) {
                return;
            }

            this.syncing = true;

            try {
                await Promise.race([
                    Promise.all(this.replications.map((replication) => replication.awaitInSync())),
                    new Promise((_, reject) => {
                        window.setTimeout(() => reject(new Error('sync timeout')), SYNC_WAIT_TIMEOUT_MS);
                    })
                ]);
            } catch {
                // let syncError communicate actual replication failures
            } finally {
                this.syncing = false;
                this.reconcileSelectedRoute();
            }
        },

        async getListDocument(listId) {
            const collections = getRawCollections(this);
            if (!collections) {
                return null;
            }
            return await collections.lists.findOne(listId).exec();
        },

        async getTodoDocument(todoId) {
            const collections = getRawCollections(this);
            if (!collections) {
                return null;
            }
            return await collections.todos.findOne(todoId).exec();
        },

        async createList() {
            const name = this.newListName.trim();
            const collections = getRawCollections(this);
            if (!name || !collections || !this.user || this.passwordSetupRequired) {
                return;
            }

            this.error = '';
            const timestamp = nowIso();
            const listId = createId('list');

            try {
                await collections.lists.insert({
                    id: listId,
                    owner_id: this.user.id,
                    name,
                    archived: false,
                    access_role: 'owner',
                    shared_with_count: 0,
                    owner_username: this.user.username,
                    created_at: timestamp,
                    updated_at: timestamp,
                    _deleted: false
                });
                this.newListName = '';
                await this.waitForSync();
                this.openList(listId);
            } catch {
                this.error = 'Could not create list.';
            }
        },

        startListEdit(list) {
            if (!this.canManageList(list)) {
                return;
            }
            this.error = '';
            this.editingListId = list.id;
            this.editingListName = list.name;
        },

        cancelListEdit() {
            this.editingListId = null;
            this.editingListName = '';
        },

        async saveListEdit() {
            const name = this.editingListName.trim();
            if (!name || !this.editingListId) {
                return;
            }

            this.error = '';

            try {
                const list = await this.getListDocument(this.editingListId);
                if (!list || list.access_role !== 'owner') {
                    throw new Error('missing list');
                }
                await list.incrementalPatch({
                    name,
                    updated_at: nowIso()
                });
                await this.waitForSync();
                this.cancelListEdit();
            } catch {
                this.error = 'Could not rename list.';
            }
        },

        async deleteList(listId) {
            this.error = '';

            try {
                const list = await this.getListDocument(listId);
                if (!list || list.access_role !== 'owner') {
                    throw new Error('missing list');
                }
                await list.remove();
                await this.waitForSync();
                if (this.selectedListId === listId) {
                    this.showLists();
                }
            } catch {
                this.error = 'Could not delete list.';
            }
        },

        async createTodo() {
            const title = this.newTodoTitle.trim();
            const collections = getRawCollections(this);
            if (!title || !collections || !this.selectedListId || this.passwordSetupRequired) {
                return;
            }

            this.error = '';
            const timestamp = nowIso();

            try {
                await collections.todos.insert({
                    id: createId('todo'),
                    list_id: this.selectedListId,
                    title,
                    done: false,
                    created_at: timestamp,
                    updated_at: timestamp,
                    _deleted: false
                });
                this.newTodoTitle = '';
                await this.waitForSync();
            } catch {
                this.error = 'Could not create todo.';
            }
        },

        startTodoEdit(todo) {
            this.error = '';
            this.editingTodoId = todo.id;
            this.editingTodoTitle = todo.title;
        },

        cancelTodoEdit() {
            this.editingTodoId = null;
            this.editingTodoTitle = '';
        },

        async saveTodoEdit() {
            const title = this.editingTodoTitle.trim();
            if (!title || !this.editingTodoId) {
                return;
            }

            this.error = '';

            try {
                const todo = await this.getTodoDocument(this.editingTodoId);
                if (!todo) {
                    throw new Error('missing todo');
                }
                await todo.incrementalPatch({
                    title,
                    updated_at: nowIso()
                });
                await this.waitForSync();
                this.cancelTodoEdit();
            } catch {
                this.error = 'Could not update todo.';
            }
        },

        async toggleTodo(todoId) {
            this.error = '';

            try {
                const todo = await this.getTodoDocument(todoId);
                if (!todo) {
                    throw new Error('missing todo');
                }
                await todo.incrementalPatch({
                    done: !todo.done,
                    updated_at: nowIso()
                });
                await this.waitForSync();
            } catch {
                this.error = 'Could not update todo state.';
            }
        },

        async deleteTodo(todoId) {
            this.error = '';

            try {
                const todo = await this.getTodoDocument(todoId);
                if (!todo) {
                    throw new Error('missing todo');
                }
                await todo.remove();
                await this.waitForSync();
            } catch {
                this.error = 'Could not delete todo.';
            }
        },

        validatePasswordSetup() {
            const password = this.passwordSetup;
            const confirmation = this.passwordSetupConfirm;

            if (password.length < 8) {
                return 'Use at least 8 characters.';
            }
            if (password !== confirmation) {
                return 'Passwords do not match.';
            }
            return '';
        },

        async submitPasswordSetup() {
            if (!this.user || !this.passwordSetupRequired) {
                return;
            }

            const validationError = this.validatePasswordSetup();
            this.passwordSetupError = validationError;
            if (validationError) {
                return;
            }

            this.passwordSetupLoading = true;
            this.error = '';

            try {
                const response = await this.request('/api/auth/set-password', {
                    method: 'POST',
                    body: JSON.stringify({
                        password: this.passwordSetup
                    })
                });

                if (!response.ok) {
                    const payload = await response.json().catch(() => ({ detail: 'Could not save password.' }));
                    this.passwordSetupError = payload.detail || 'Could not save password.';
                    return;
                }

                this.user = await response.json();
                this.passwordSetupRequired = false;
                this.passwordSetup = '';
                this.passwordSetupConfirm = '';
                this.passwordSetupError = '';

                try {
                    await this.initializeLocalState();
                } catch (error) {
                    this.error = getLocalSetupErrorMessage(error);
                    return;
                }

                if (this.pendingPath) {
                    const path = this.pendingPath;
                    this.pendingPath = null;
                    this.navigateTo(path, { replace: true });
                } else {
                    this.applyRoute(window.location.pathname, { fromHistory: true });
                }
            } catch {
                this.passwordSetupError = 'Unable to reach the server.';
            } finally {
                this.passwordSetupLoading = false;
            }
        },

        async resetLocalState() {
            if (window.location.pathname !== ROOT_PATH) {
                this.pendingPath = window.location.pathname;
            }

            this.user = null;
            this.passwordSetupRequired = false;
            this.lists = [];
            this.todos = [];
            this.selectedListId = null;
            this.selectedList = null;
            this.closeDetailMenu();
            this.closeListMenu();
            this.closeTodoMenu();
            this.username = '';
            this.password = '';
            this.passwordSetup = '';
            this.passwordSetupConfirm = '';
            this.passwordSetupError = '';
            this.passwordSetupLoading = false;
            this.syncError = '';
            this.syncing = false;
            this.closeShareModal();
            this.cancelListEdit();
            this.cancelTodoEdit();
            await this.clearReplication();
            this.clearQuerySubscriptions();
            const rawState = getRawState(this);
            rawState.collections = null;
            rawState.db = null;

            if (this.onlineListener) {
                window.removeEventListener('online', this.onlineListener);
                this.onlineListener = null;
            }

            await disposeDatabase({ remove: true });

            this.navigateTo(ROOT_PATH, { replace: true });
        },

        async clearReplication() {
            await Promise.all(
                this.replications.map(async (replication) => {
                    try {
                        await replication.cancel();
                    } catch {
                        // ignore cleanup failures
                    }
                })
            );
            this.replications = [];
            this.clearReplicationSubscriptions();
            this.teardownInvalidationStream();
            this.teardownResyncFallback();
        },

        clearQuerySubscriptions() {
            this.querySubscriptions.forEach((subscription) => subscription.unsubscribe());
            this.querySubscriptions = [];
        },

        clearReplicationSubscriptions() {
            this.replicationSubscriptions.forEach((subscription) => subscription.unsubscribe());
            this.replicationSubscriptions = [];
        }
    }));
});

Alpine.start();

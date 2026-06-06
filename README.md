# WeDo

A tiny shared shopping and todo app for people who keep forgetting the same three things.

Mobile-first, offline-friendly, self-hosted, and small enough to understand before your coffee gets cold.

## Features

- Shared lists for groceries, chores, trips, and mild chaos
- Offline-first PWA
- Fast sync between users
- Runs in one Docker container

## Dev

```bash
docker compose -f docker-compose.dev.yml up --build
```

Open `http://localhost:5173`.

Run backend tests:

```bash
./test.sh
```

## Deploy

```bash
docker compose up -d --build
```

Serve it through your tunnel/reverse proxy, or locally at `http://localhost:8080`.

## Config

Set real secrets before using the agent APIs:

```env
WEDO_AGENT_API_SECRET=change-me
WEDO_ADMIN_AGENT_API_SECRET=change-me-too
```

For a custom env file path:

```bash
WEDO_ENV_FILE=/path/to/wedo.env docker compose up -d --build
```

## Tech

FastAPI, SQLite, Vite, Alpine.js, RxDB, and a modest amount of stubbornness.

# Mini SIEM Tool 2

Mini SIEM Tool 2 is a lightweight security operations dashboard built with React, Express, Prisma, and SQLite. It simulates a modern SIEM workflow with authentication, log ingestion, alert detection, live monitoring, and MITRE ATT&CK tagging in a compact monorepo setup.

## Project Overview

This project provides a practical learning environment for building a minimal SIEM console. It focuses on the operational flow that analysts commonly use when reviewing security events:

- authenticate to the console
- ingest events from security sources
- monitor activity in near real time
- detect suspicious patterns
- review critical incidents
- correlate event behavior with ATT&CK techniques

## Features

- JWT-based authentication
- Protected API routes
- Prisma-backed persistence with SQLite
- Log ingestion and retrieval via REST APIs
- Real-time event monitoring with Server-Sent Events (SSE)
- SOC-style dashboard with KPI summary cards
- Search and severity filtering
- Incident panel for critical event tracking
- Interactive log generator for sample event creation
- MITRE ATT&CK mapping for key event types
- Responsive dark-mode UI

## Architecture

The project is organized as a monorepo with three primary workspaces:

- client: React + Vite frontend
- server: Express + TypeScript API
- shared: shared contracts and schemas

### Runtime flow

1. The React client logs in with a seeded admin account.
2. The Express backend validates JWT tokens and serves protected routes.
3. Log events are stored using Prisma and SQLite.
4. New events are pushed to the dashboard through SSE.
5. The frontend enriches event visibility with MITRE ATT&CK mappings.

## Tech Stack

- React 19
- Vite
- TypeScript
- Express
- Prisma ORM
- SQLite
- bcrypt
- JWT
- Server-Sent Events (SSE)
- Zod validation

## Screenshots

> Screenshots will be added in a future release.

### Placeholder gallery
- Login screen
- Analyst dashboard
- SOC console with KPIs
- Incident center
- MITRE-enriched event table

## Installation

1. Clone the repository.
2. Install workspace dependencies:
   ```bash
   npm install
   ```
3. Ensure the Prisma client is generated successfully:
   ```bash
   npx prisma generate
   ```
4. Start the backend and frontend together:
   ```bash
   npm run dev
   ```
5. Open the client in your browser and log in.

## Default Credentials

- Email: admin@sentinel.local
- Password: admin123

## MITRE ATT&CK Support

The frontend includes a client-side MITRE mapping utility that enriches log events with technique IDs and tactics. The current supported mappings are:

- Failed Login → T1110 / Credential Access
- BRUTE_FORCE_DETECTED → T1110 / Credential Access
- Malware Detection → T1204 / Execution
- Port Scan → T1046 / Discovery
- Critical Alert → T1486 / Impact

This enrichment does not change the backend contract or Prisma schema and is intended to keep the SIEM workflow lightweight and easy to extend.

## Notes

- Authentication remains protected and unchanged.
- Prisma schema remains stable for this version.
- Existing REST API endpoints are preserved.
- Real-time monitoring uses native EventSource rather than Socket.IO.

## Version

Version 1.0

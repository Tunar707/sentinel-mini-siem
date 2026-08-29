# Mini SIEM Tool 2 — Project Documentation (Version 1.0)

## Overview
Mini SIEM Tool 2 is a lightweight security operations dashboard built as a monorepo with a React client, Express API, Prisma ORM, and SQLite persistence. The project demonstrates a simplified SIEM workflow: secure login, log ingestion, SOC dashboarding, interactive event generation, real-time monitoring, and client-side MITRE ATT&CK mapping.

## Completed through Phase 10

### Phase 1 — Foundation
- Monorepo workspace setup
- Client/server/shared package separation
- Vite + React frontend foundation
- Express + TypeScript backend foundation
- Prisma + SQLite configuration

### Phase 2 — Authentication
- Prisma-backed user authentication
- bcrypt password verification
- JWT generation and validation
- Protected API routes
- Seeded admin user for local development

### Phase 3 — Log Ingestion
- Prisma Log model added to the existing schema
- SQLite-safe severity handling
- POST /api/logs endpoint
- GET /api/logs endpoint
- Log validation with Zod
- Initial event table in the client

### Phase 3.1 — Analyst Dashboard
- Dashboard layout and security console styling
- KPI summaries for events, critical alerts, high severity, and events today
- Search and severity filtering
- Incident list and highlight interactions
- Responsive dark UI

### Phase 4 — Interactive Log Generator
- Realistic event templates for common SOC scenarios
- Manual log creation from the UI
- Immediate refresh of dashboard state

### Phase 5 — SOC Dashboard UI
- Focused SOC console presentation
- Analyst-focused event review workflow
- Event table with severity badges and message detail

### Phase 6 — Detection Engine
- Automated detection logic in the logs route
- Brute-force detection for repeated failed logins
- Critical alert generation for suspicious patterns

### Phase 7 — Incident Center
- Critical incident panel in the dashboard
- Click-to-focus interactions for matching log rows
- Incident view integrated into the operational workflow

### Phase 8 — Client Refactor
- Extracted reusable UI components
- Preserved behavior and styling
- Improved maintainability without changing contracts

### Phase 9 — Real-Time Monitoring with SSE
- New GET /api/logs/stream endpoint
- Native EventSource-based subscription in the client
- Real-time delivery of newly created logs without reload
- Protected stream using the existing JWT-based auth model
- New logs appear instantly in the dashboard

### Phase 10 — MITRE ATT&CK Mapping
- Client-side mapping utility for event types
- MITRE technique IDs and tactic labels
- Color-coded badge presentation in the event table
- Dashboard enhancement without changing API contracts or schema

## Current State
The application is in Version 1.0 and is considered a working mini-SIEM proof of concept. It includes:
- secure authentication
- log ingestion and retrieval
- detection logic
- analyst dashboard
- SOC-style UI
- live streaming of log events
- MITRE ATT&CK enrichment

## Stack
- React 19 + Vite
- TypeScript
- Express
- Prisma ORM
- SQLite
- JWT + bcrypt
- Server-Sent Events (SSE)

## Default Credentials
- Email: admin@sentinel.local
- Password: admin123

## Local Run Notes
1. Install dependencies at the root workspace level.
2. Generate Prisma client if needed.
3. Start the API and frontend together using the workspace scripts.
4. Log in with the seeded admin credentials.

## Constraints Observed
- Authentication is preserved as implemented.
- Prisma schema remains unchanged.
- Existing REST endpoints remain intact.
- MITRE mapping is kept client-side only.

## Project Goal
Provide a functional and visually consistent mini-SIEM tool that demonstrates log ingestion, alerting, monitoring, and analyst workflow patterns in a compact, educational codebase.
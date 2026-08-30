# Sentinel Mini SIEM Rules

You are modifying an existing commercial-style SIEM project.

## Rules

- Never use `prisma migrate reset`
- Never delete the SQLite database
- Prefer `prisma db push` over destructive migration commands
- Preserve auth, SSE, and API contracts unless explicitly requested
- Client-first for UI phases
- Build after every phase:
  - `npm run build --workspace client`
  - `npm run build --workspace server`
- Use the existing glassmorphism dark SOC design
- Do not rewrite unrelated files
- Keep commits atomic (one feature per commit)

## Always verify

Run after every completed feature:

npm run build --workspace client
npm run build --workspace server
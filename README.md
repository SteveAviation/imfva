# Crew Center

Static site in the root plus a serverless API in api/[action].js, backed by Neon Postgres.

1. The database schema has already been initialized in Neon. Do not upload schema.sql to GitHub.
2. Push index.html, logo.png, flight.jpg, airport.jpg, package.json and api/[action].js to GitHub and import the repo in Vercel (preset: Other).
3. Environment variables in Vercel:
   - DATABASE_URL: Neon connection string
   - SESSION_SECRET: random string, 32+ characters
   - ADMIN_USERNAME: username(s) that become admin automatically, comma separated (register or sign in with it)
   - DISCORD_INVITE_URL: optional, shown to approved pilots
4. Deploy.

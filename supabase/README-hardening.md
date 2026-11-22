# Challenge 90 — database hardening

## Before applying

1. Make a Supabase database backup.
2. Confirm the existing Challenge 90 setup migrations have already been applied, including the profile, initial-days, and ranking setup.
3. Do not re-run older setup/repair SQL files after this migration. Some older files replace the signup trigger and may restore legacy behavior.

## Apply

1. Open the Supabase project dashboard.
2. Open **SQL Editor** and create a new query.
3. Copy the complete contents of `supabase/security_hardening.sql`.
4. Run it once. The migration is repeatable and does not delete profile or report rows.

## What it changes

- Enables row-level security on `profiles` and `daily_reports`.
- Removes broad legacy table grants and grants only the permissions required by the app.
- Limits profile reads to the account owner and administrators.
- Limits daily-report reads to the owner and administrators; writes are owner-only.
- Protects account start dates and provides an administrator-only date-change RPC.
- Replaces signup profile creation so the server assigns the start date and always creates a participant role.
- Sanitizes day/session JSON before ranking calculations.
- Replaces the ranking RPCs with hardened versions.

## Post-apply checks

- Sign in as a participant and confirm only that account's profile/report is returned by the app.
- Sign in as an administrator and confirm the admin list and report viewer still work.
- Create a test account and confirm its profile role is `participant`.
- Confirm participant accounts cannot change their own `start_date`.
- Confirm the admin date-change action works.

The migration was tested against PostgreSQL 16 with an isolated Supabase-compatible schema, including tests for legacy public policies/grants, participant isolation, admin visibility, signup role escalation, oversized JSON numbers, and protected start dates. This does not replace a backup or a post-apply check against the live Supabase project.

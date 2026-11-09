# Project Overview

> After making any edit or running tests, and before ending a turn or task, check that `npm run dev` and `npm run tw` are still running. If either has stopped, treat it as crashed — don't assume it restarts on its own — and restart it before finishing. This check is silent: don't tell the user the services are still running, and don't mention a restart either. Only bring them up if one won't stay running after a restart.

**All Things Aprons (ATA)** is a media platform where registered users submit photo/video entries that are rated, contested, and competed in tournaments. The **Entry** is the central object — everything else (ratings, contests, tournaments) revolves around it.

## Stack
- Node.js (Express)
- Mongoose (MongoDB)
- EJS (Templating)
- Tailwind CSS (Styling)
- Multer (Uploads)
- Resend (Transactional email)
- Agenda (Background jobs)
- Nodemon (Development)

## Scripts
- `npm run dev`: Starts the server with nodemon.
- `npm run tw`: Starts Tailwind CSS watch mode.
- `npm start`: Starts the server without nodemon.
- `npm run build:css`: Builds the minified CSS once.

---

## Core Domain Concepts

### Entries
- A photo or video submitted by a registered user
- Automatically subject to community ratings upon submission (not opt-in)
- Can participate in multiple contests/tournaments simultaneously — participation is independent and additive
- Once submitted to a contest or tournament, an entry is **locked** (cannot be changed)
- Owner can add/edit/remove up to 6 free-form tags at any time, even when locked

### Ratings
- Scale: 1–10 numeric score
- Registered users only; no deadline
- A user **cannot** rate their own entry
- A user **cannot** rate the same entry twice
- `ratingCount` and `ratingAvg` are denormalized onto the Entry document for fast reads

### Contests (Head-to-Head)
- Exactly 2 entries compete; voters pick one
- Visibility: `public` (open voting) or `private` (creator designates ≥5 voters)
- Lifecycle: `pending → active → closed` or `pending → void`
- Void deadline: `createdAt + 24h` — if second entry not submitted, contest voids
- Voting deadline: `secondEntrySubmittedAt + windowHours` (default 72h)
- A user **cannot** vote more than once per contest
- A user **cannot** vote for their own entry
- Standalone tie = equality (no replay). Tournament match tie triggers the jury tie-breaker chain (see Tournaments below)

### Tournaments
- User-organized only — single organizer per tournament, no admin-created tournaments
- Format: group stage (round-robin within groups) → single-elimination knockout bracket. Valid sizes: 4, 8, 12, 16, or 24 participants only — each maps to a fixed group size/count with no byes
- **Organizer cannot compete as contestant** in their own tournament
- Lifecycle: `open (3 days) → cooldown (24h) → active → closed`
- Candidates submit during `open`; organizer batch-reviews (approve/reject) during `cooldown` — not a per-entry timer
- If fewer candidates submit than the organizer's chosen participant cap (4/8/12/16/24) by end of `open` → tournament auto-canceled, prize pool refunded to organizer
- During `cooldown`, organizer must approve exactly the cap number of candidates (no byes); if unable to (e.g. too many rejections) the organizer can choose to cancel the tournament themselves — also refunded. Organizer failing to finish review within the 24h window is a separate auto-cancellation trigger
- Winner = grand final winner (single elimination), not highest `totalVotes` or win/loss record
- Match tie (group or knockout): jury vote (6h window, quorum 3) → organizer deciding vote (3h) → platform coin flip. No tie can block progression more than 9h total
- Jury: 5–7 members selected by organizer at creation; identity never revealed to anyone; cannot vote in regular H2H contests during the tournament; a juror who misses a vote is permanently barred from serving as jury in any future tournament
- Organizer is also barred from voting in regular H2H contests while any tournament they organize is in progress (`open`/`cooldown`/`active`) — same restriction as jury, above. Regular H2H = a standalone contest (`Contest.tournamentId` is null); voting on the organizer's/jury's own tournament's group or knockout matches (`Contest.tournamentId` set) is unaffected
- Prizes: organizer-set amounts with minimums — 1st (350 CHL), 2nd (100 CHL), 3rd (50 CHL; not required for 4-player tournaments, which have no 3rd-place match). CHL-denominated, not dollar-pegged — at the wallet's 0.20 exchange rate that's $70/$20/$10. Funded from organizer's `purchasedCHL` at creation, credited to winners' `earnedCHL` at close
- Organizer eligibility: `idVerified: true`, no active ban/reports, >250 followers, contributed to ≥5 contests, fewer than 3 concurrent tournaments (open/cooldown/active)
- See `dev_resources/plans/July/tournament-spec.md` and `dev_resources/plans/July/tournament-implementation-plan.md` for full spec and build phases

### Users & Access
- **Anonymous:** redirected to signup — no read-only browsing allowed
- **Registered (`role: 'user'`):** full platform access immediately after signup
- **Admin roles:** 5-tier hierarchy — `user → moderator → supervisor → superadmin → founder`
- `role` field on User (not a boolean `isAdmin`). Never check `isAdmin`.
- "Organizer" is contextual (whoever created a tournament), not a permanent role
- `idVerified: true` is required to submit an entry or create a tournament

Email confirmation is **synchronous inline during signup** (OTP via Resend). `emailConfirmed` is always `true` on any account that exists — there is no post-signup async email flow.

---

## Data Model Reference

All collections are in MongoDB. Key relationships:

| Collection | Key refs |
|---|---|
| `entries` | `userId → users` |
| `ratings` | `entryId → entries`, `userId → users`; unique index on `{entryId, userId}` |
| `comments` | `entryId → entries`, `userId → users`, `parentId → comments` (one level only) |
| `comment_reports` | `commentId → comments`, `reportedBy → users`; unique index on `{commentId, reportedBy}` |
| `contests` | `createdBy → users`; entries + designatedVoters embedded |
| `contest_votes` | `contestId → contests`, `entryId → entries`, `userId → users`; unique on `{contestId, userId}` |
| `nominations` | `contestId → contests`, `nominatorId → users`, `nomineeId → users` |
| `tournaments` | `createdBy → users`; prizes + eligibility criteria embedded |
| `tournament_entries` | `tournamentId → tournaments`, `entryId → entries`, `userId → users`, `groupId → tournament_groups`; unique on `{tournamentId, entryId}` |
| `tournament_groups` | `tournamentId → tournaments`; `memberIds → tournament_entries` |
| `tournament_matches` | `tournamentId → tournaments`, `contestId → contests` (unique), `groupId → tournament_groups`, `tournamentEntryIdA/B → tournament_entries` |
| `tournament_jury` | `tournamentId → tournaments`, `userId → users`; unique on `{tournamentId, userId}` — identity never exposed via API |
| `tournament_jury_votes` | `tournamentId → tournaments`, `matchId → tournament_matches`, `jurorId → users`; unique on `{matchId, jurorId}` |
| `platform_settings` | single doc keyed `'global'`; holds `contestEligibility` thresholds (minEntries, minRatingCount, minWeightedAvg) |
| `retags` | `entryId → entries`, `contestId → contests` (unique), `userId → users` — scaffolded, not yet wired |

---

## Universal Business Rules (Never Violate These)

1. A user cannot rate or vote for their own entry — anywhere, in any system
2. A user cannot rate the same entry more than once
3. A user cannot vote in the same contest more than once
4. Anonymous users cannot access any platform page — redirect to signup
5. Tournament organizer cannot submit an entry to their own tournament
6. Admin authority uses the 5-tier role system (`moderator → supervisor → superadmin → founder`). Use `requireDomain` middleware for admin routes — never check `isAdmin` boolean (it no longer exists)
7. A user must have `idVerified: true` to submit an entry

---

## Architecture & File Structure

### server.js — Keep It Lean
`server.js` is the entry point only. It should contain:
- Middleware setup
- Route mounting
- DB connection
- Server initialization

**Never bloat `server.js` with inline route logic, business logic, or feature-specific code.**

When implementing any feature, ask:
> "Does this belong in server.js, or should it live in its own route/controller/middleware file?"

If a feature introduces new routes or logic → create a new file under the appropriate folder (e.g. `routes/`, `controllers/`, `middleware/`) and mount/import it in `server.js`.

---

### Views & Partials — Evaluate Before Creating
Before adding any `.ejs` file, check the existing `views/` and `views/partials/` structure.

- If a UI element is **reusable** → create or update a partial in `views/partials/`
- If it's a **new page** → create a new view file in the appropriate `views/` subfolder
- If it **extends an existing page** → update the existing view file

Do not dump new markup into existing views without checking if a partial already covers it.

---

### Avatar Fallback (No Profile Picture Set)
Whenever rendering a user's pfp/avatar and no image is set, the fallback must be a `bg-charm-950` circle with a `boxicons:user-filled` icon colored `#e680a6` (charm-400) — never a generic gray/`shark`/`zinc` circle, the light `charm-200` variant, `boxicons:user` (outline), or a `/img/default-avatar.png`-style file reference (no such file exists).

- Server-rendered (EJS): `<div class="{size} rounded-full bg-charm-950 flex items-center justify-center"><iconify-icon icon="boxicons:user-filled" width="{n}" style="color:#e680a6"></iconify-icon></div>`
- Client-built (JS string concatenation): use the shared helper `window.ataAvatarHtml(src, sizeCls, iconSize)` from `views/partials/avatarJsHelpers.ejs` (include it on the page if not already present) instead of hand-rolling another fallback.
- **Exception:** the admin panel (`views/admin/**`, `views/partials/adminSidebar.ejs`) intentionally uses its own separate monochrome theme (gray `zinc-800` squares, gray icon) — do not apply the charm/pink treatment there.
- Also exempt: notification actor-icon fallbacks in `views/notifications.ejs`, which fall back to a notification-type glyph (trophy, compare, etc.), not a "no pfp" placeholder.

---

### General Rule
Before creating any new file or folder, scan the existing structure first.
Only create new files/folders when the feature genuinely warrants it.
Prefer extending existing structure over adding new layers.

---

## Current Build Status

See `dev_resources/plans/build-status.md` (git-ignored) for what's built, what must be reverted before launch, and which features are deliberately out of scope. Read it before starting a feature, and don't scaffold, stub or add TODOs for out-of-scope features.

---

## Background Jobs (Phase 5 scope)
Time-sensitive state transitions (void deadlines, voting deadlines, entry review timeouts) will be handled by `agenda` — not inline request handlers. Do not implement deadline enforcement synchronously in route handlers.

**Pattern:** sweeper jobs run every 15 minutes. If a deadline is within the next 15 minutes, the sweeper schedules a one-time `agenda` job at the exact deadline datetime. If the deadline has already passed, it is handled immediately. This ensures no contest waits more than a few seconds past its actual deadline.


---

## Agent Instructions for this Project

**Direct File Manipulation via Internal Tools**

When interacting with this project, you are equipped with internal tools (such as `python` and `terminal`) that have direct access to the project directory: `F:\trifoldi\projects\allthingsaprons`.

**Guidelines:**

1. **Prefer Tools over Manual Copy-Paste:** Do not ask the user to copy, paste, or run long code blocks in their terminal if you can accomplish the task using your internal tools.
2. **File Management:** Use your tools to:
   - **Create** new files (e.g., using `python` to write content).
   - **Update/Edit** existing files by overwriting them with the full updated content.
   - **Read** files to understand the current project state.
   - **Delete** files or directories when requested.
3. **Path Management:** Always ensure you are targeting the correct directory (`F:\trifoldi\projects\allthingsaprons`) when executing commands to avoid creating files in the wrong workspace.
4. **Directory Restriction (hard rule):** You may not create, edit, or delete files at any path outside `F:\trifoldi\projects\allthingsaprons`. This holds even if the harness/tool defaults to a different working directory — redirect every file operation back to this project's directory rather than letting it fall through to the default. If a requested change would require touching a path outside this directory, stop and ask instead of proceeding.

**Goal:** Minimize friction for the user by performing file-system operations directly through your interface rather than requesting manual input.

5. **Screenshot Restriction (hard rule):** For the following projects — ozsdiaries, storiesbyshews, jarumiristudios, wapdooz, whimish, allthingsaprons — you are not allowed, under any circumstances, to take screenshots of the UI while working. If a screenshot seems necessary to verify or debug something, stop and explicitly request permission from the user before taking it.

6. **Journal Entries (hard rule):** When adding a new entry to this project's journal (`dev_resources/journal.md`, via the Dispatch dashboard's Journal tab), each individual entry must not exceed 150 characters. Write one entry per feature or change, not one per part of it: a feature with its settings, prompts and tests is a single entry. If it doesn't fit in 150 characters, describe it at a higher level instead of splitting it up; the details belong in the commit message. Only log what will be useful to someone reading the journal later: what changed, why, and any decision or gotcha that isn't obvious from the code. Leave out word lists, examples, test counts, lists of files (the file report covers those) and steps that were undone or redone in the same session. Before adding an entry, read today's entries and skip anything one of them already covers.

7. **Journal Upkeep (hard rule):** After any significant update to the project, add entries to this project's journal before ending the turn. Significant means things like a new feature or page, a model, route or data change, a recorded client decision or requirement, or a convention, tooling or config change. Trivial edits (typos, small copy or style tweaks) don't need an entry. Add entries through the Dispatch dashboard: its Journal tab, or `POST http://localhost:3000/api/project-folders/allthingsaprons/journal` with JSON `{ "content": "..." }`. It files each entry under today's date with the time. If the dashboard isn't running, write them by hand in the same format: a `## YYYY-MM-DD` heading, then `- **HH:MM** — text` bullets. Follow rule 6 for what goes in an entry and its 150-character limit, and say what changed and why in plain words.

8. **Task Completion Reporting (hard rule):** Only the user marks tasks in `dev_resources/tasks.json` as done. Never mark a task done or archive it yourself (don't change its `done` or `archived` fields, through the project hub or by editing the file). Instead, whenever you believe you've completed a task, report it to the user in your reply, so they can mark it done and finished tasks don't stay open. Give the task's ID and title, what you did, and how you checked it works. If you finished only part of a task, say what's still left.

9. **Push Commit Message (hard rule):** Every time you add an entry to this project's journal, also create or update `dev_resources/commit_message.txt` before ending the turn. The Dispatch dashboard's Push button commits with this file's text, so it must cover everything done since the last push, not just your latest change. If the file doesn't exist, create it. If it does, keep what's already in it and add the new work. Write it as a git commit message: a summary line of 72 characters or fewer that covers all of the work in the file, then a blank line, then one `- ` bullet per change saying what changed and why in plain words. Rewrite the summary line whenever it no longer covers everything. Never stage, commit or push this file yourself: the dashboard leaves it out of every commit and deletes it once a push has used it, so the next journal entry starts a fresh one.

10. **Journal File Reports (hard rule):** Every journal entry you add must also report the files its work created, modified or deleted, as paths relative to this project's folder with forward slashes. The Dispatch dashboard lists each day's files under that day's entries, so this is what keeps a day's changes traceable. With the dashboard running, send them with the entry: `POST http://localhost:3000/api/project-folders/allthingsaprons/journal` with JSON `{ "content": "...", "files": { "created": ["..."], "modified": ["..."], "deleted": ["..."] } }`, leaving out any list that would be empty. When the `CLAUDE_CODE_SESSION_ID` environment variable is set, also send it as the `X-Agent-Session` header, so the entry's record keeps which Claude Code session wrote it. When writing the journal by hand, put them under the entry as sub-bullets indented two spaces, one line per kind: ``- Created: `path/one.js`, `path/two.js` ``, then ``- Modified: ...`` and ``- Deleted: ...``. List each file under the entry for the change that touched it. The 150-character limit is for the entry's text, not its file list.

11. **Tasks (hard rule):** This project's to-do list is `dev_resources/tasks.json`, shown in the Dispatch dashboard's Tasks tab. Whenever something needs doing later (a follow-up, a known bug, something left out of the current work), add it there as a task, not as a TODO comment, a Markdown note or anywhere else. With the dashboard running, use its API: `POST http://localhost:3000/api/project-folders/allthingsaprons/tasks` with JSON `{ "title": "...", "description": "...", "dueDate": "YYYY-MM-DD", "tags": ["..."] }`. Only the title is required (80 characters at most); the description is limited to 500 characters and each tag to 30. When the `CLAUDE_CODE_SESSION_ID` environment variable is set, also send it as the `X-Agent-Session` header, as for journal entries. Never edit `tasks.json` by hand: the dashboard gives each task its ID and records who created it. If the dashboard isn't running, say so and ask instead of writing the file. Marking tasks done or archiving them is the user's alone (rule 8, Task Completion Reporting).

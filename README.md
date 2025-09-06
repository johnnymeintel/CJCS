# CJCS

Cookie Jar Cloud Solutions

## CJCS Timecard App – Build Instructions

**Goal**: A lightweight intranet-style web app that lets me log in, clock in/out at $36/hr, track total earnings across sessions, log tasks, and trick my subconscious into feeling like a Junior SOC Analyst.

---

### Core Requirements

1. **Login system**

   * Hard-coded demo credentials:

     * Username: `jmeintel`
     * Password: `password`
   * Only needs to block/allow; no real security required.

2. **Clock in/out tracking**

   * Clock in starts a timer.
   * Clock out ends the session, calculates earnings at `$36/hr`.
   * Show running timer and “live earnings” counter while on the clock.

3. **Persistence**

   * Use `localStorage` to store:

     * `totalEarnedCents` (across all sessions).
     * Array of past sessions `{ start, end, durationMs, earnedCents, notes }`.
     * `currentSession` if one is active.
   * Data must persist across browser restarts and re-opens of the same `timecard.html` file.

4. **Session notes**

   * Input box for notes while clocked in.
   * Save notes to session record on clock out.
   * Editable later in a session log table.

5. **Session log**

   * Table view of all sessions with:

     * Date, start, end, duration, earnings, notes, delete button.
   * Sorted newest → oldest.

6. **Export**

   * Button to export all sessions to CSV.
   * Button to export all data to JSON (`timecard_backup_<timestamp>.json`).

7. **Import / restore**

   * Hidden file input + Import button.
   * Upload JSON backup → overwrite localStorage → refresh table and totals.
   * Validate JSON structure lightly before commit.

8. **UI design**

   * Styled like a modern tech company intranet.
   * Sidebar navigation with placeholder links (Timecard, Handbook, IT Helpdesk, Benefits).
   * Cards for Status, Timer, Earnings, Notes, Session Log.
   * “Danger zone” card with Reset Data button.
   * Dark theme, gradients, subtle shadows, rounded corners.

9. **Danger zone**

   * Button to clear all localStorage data for this app only.
   * Confirm before wipe.

---

### Optional Enhancements

* Auto-backup JSON on every clock out (`timecard_autobackup.json`).
* PWA wrapper so it can be installed to desktop/mobile.
* Add streaks/goals (e.g. “hit 2h/day for 5 days straight”).
* Tagging for sessions (e.g. “phishing lab,” “SOC1 playbook”).

---

### Deployment

* Deliverable: **Single HTML file** with embedded CSS + JS.
* Open directly in a browser (`file://.../timecard.html`).
* Data is stored per-origin, so moving the file to a different folder creates a new “origin.”
* To preserve data, use Export/Import before moving or clearing browser storage.


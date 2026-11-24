# FileVow user guide

FileVow watches the files and folders you choose and tells you the moment one of them
changes. You then decide: keep the change, or put the original back. This guide explains
every feature in plain language. The same explanations are on the **Help** page inside
the app.

---

## 1. Install and open FileVow

1. Download the installer from the FileVow website (**Download** in the menu bar).
2. Run `FileVow-Setup-<version>.exe`. It installs for your Windows account only, so you
   don't need administrator rights.
3. Leave **Keep monitoring in the background when I sign in** ticked. FileVow then starts
   quietly every time you sign in to Windows, so monitoring never stops.
4. Open **FileVow** from the Start menu. It opens in its own window.

Closing the window doesn't stop monitoring when background monitoring is on. Opening
FileVow again just shows the window.

## 2. Sign in

FileVow has no passwords. You sign in with a one-time code sent to your e-mail.

**First time on this computer**
1. Type your e-mail address and click **Send me a code**.
2. Type the 6-digit code from the e-mail (check Spam if it doesn't arrive within a minute).
3. Choose a **username** and click **Create account**.

**Next time**
1. Type your **username** (or your e-mail) and click **Send me a code**.
2. Type the code from the e-mail. That's it.

You stay signed in on this computer for 30 days.

- Each account has its own **private workspace**: its own folders, signing key, changes,
  alerts, history and audit log. Other accounts on the same computer can't see any of it.
- The **first account** on a computer becomes its **administrator**, who can lock and
  remove accounts but still can't see other people's workspaces.
- Online, FileVow stores only your e-mail address, sign-in dates and a daily "used today"
  marker (turn it off in Settings). **Delete my account** in Settings removes all of it.

## 3. The Get started checklist

After signing in, the Home page shows four steps:

| Step | What it means |
|---|---|
| **Create your signing key** | Your personal seal for approving files (section 4). |
| **Protect your first folder or file** | Choose what FileVow should watch (section 5). |
| **Turn on two-step verification** | Extra protection for your account (section 10). |
| **Add a notification channel** | Get alerts by email, Windows notification, Slack or Teams (section 8). |

## 4. Your signing key and passphrase

Every protected file gets a **digital signature** made with your signing key. Even
someone who could edit FileVow's database can't forge your signature, so they can't
quietly "approve" a change.

- The key is created on your computer and stored **encrypted with your signing-key
  passphrase**. Choose one you'll remember; it is separate from your account password.
- You need the passphrase when you **protect** files, **accept** a change, and to confirm
  other important actions such as restoring or removing a file.
- **Download a backup** (Settings → Signing keys → Download backup) and keep it on a USB
  drive. The backup is still encrypted with your passphrase.
- If you forget the passphrase, nobody can recover it. Your files stay monitored and can
  still be restored, but you can't approve new changes; ask the administrator to help you
  start a new key.

## 5. Protecting folders and files

Go to **Monitored folders → Add folder or file**.

1. Click **Browse…**. A file window opens with shortcuts to **Desktop**, **Documents**,
   **Downloads**, your home folder and every drive.
2. Click a folder to open it; the **up arrow** goes back one level.
3. Click **Protect this folder** to protect the folder you're in, or click a single file
   to protect just that file.
4. Choose **How serious is a change** (critical, high, medium, low) and, optionally,
   **Skip files matching** patterns such as `*.log`, `*.tmp` or `~$*` (Office lock files).
5. Confirm with your **signing-key passphrase**.

FileVow now calculates a fingerprint of every file, signs it with your key and stores an
encrypted backup copy. Large folders can take a moment.

**Later on**

- Files you add to a protected folder show up as **Unknown file created**. Approve them
  one at a time, or click **Protect new files** on the folder to protect them all at once.
- The **on/off switch** pauses monitoring of a folder without forgetting it.
- A folder can be protected by only one workspace at a time.

## 6. How files are checked

Every protected file is guarded by three independent layers:

| Layer | What it does | What it catches |
|---|---|---|
| **Fingerprint (SHA-256)** | A 64-character code calculated from the contents. One changed letter gives a completely different code. | Any edit, however small |
| **Signature (RSA)** | Your key seals each fingerprint. | Someone editing FileVow's own records to hide a change |
| **Encrypted backup (mirror)** | A locked copy of the approved version. | Lets you see exactly what changed and restore it |

Files are checked:

- **within seconds** of being changed, renamed, deleted or added;
- **every 15 minutes**, a complete pass over everything;
- **whenever you click Verify now** (Home or Verification history).

If FileVow was switched off for a while, it reports a **monitoring gap** when it starts
again, because something could have changed and been put back in the meantime.

## 7. Reviewing changes

When something changes, it appears in **Review changes** (the number next to it shows how
many are waiting). Selecting one shows:

- what happened (modified, deleted, new file, permissions or owner changed);
- which safeguard raised the alarm;
- a **side-by-side comparison** of the approved copy and the current file (red lines were
  removed, green lines were added) for text files.

Then choose what to do:

| Decision | When to use it | What happens |
|---|---|---|
| **Accept** | You expected the change (you edited the file yourself). | The current file becomes the new approved version, signed with your key and backed up. |
| **Restore** | The change shouldn't have happened. | The last approved version is put back. The changed file is kept as encrypted evidence first. |
| **Quarantine** | An unexpected new file appeared. | An encrypted evidence copy is kept and the file is removed. |
| **False positive** | Close the alert without touching anything. | If the file is still different, it's reported again at the next check. |
| **Escalate** | You want to look into it more closely. | Stays open and is marked for attention. |

Every decision asks for a **reason** and is saved in your audit log. Accept, restore and
quarantine also ask for your signing-key passphrase (and two-step code, if on).

FileVow **never accepts a change on its own**.

## 8. Alerts and notifications

- The **bell** in the top bar lists your alerts; a red dot means something new.
- Unacknowledged **critical** alerts are escalated after 15 minutes, **high** ones after
  an hour.
- In **Settings → Notifications** you can add channels: Windows notification, email,
  Slack, Microsoft Teams or a webhook. Use **Test** to check one works.
- Many alerts at once are grouped into one message. Messages never contain file contents.

## 9. Verification history and audit log

- **Verification history** lists every check of your workspace: when, how long, how many
  files and what was found. Each report is digitally signed by FileVow.
- **Audit log** records sign-ins, folders added, changes detected and every decision with
  its reason. Entries are chained together, so editing or deleting one breaks the chain.
  **Verify chain** checks nothing was tampered with; **Export CSV** downloads the log.
- The status bar at the bottom always shows whether monitoring is running, when the next
  check is due, and whether the audit chain is intact.

## 10. Keeping your account safe

- **No password to steal:** you sign in with a one-time e-mail code.
- **Your signing-key passphrase** confirms important actions and never leaves your PC.
  Five wrong tries lock the account for 15 minutes.
- **Two-step verification** (Settings, optional): also require a 6-digit code from an
  authenticator app such as Microsoft Authenticator. Save the recovery codes.
- Use the **sign-out** arrow (top right) when you share the computer.

## 11. Keyboard shortcuts

| Keys | Action |
|---|---|
| `Ctrl` `K` | Search files, changes, pages and commands |
| `Alt` `1`–`8` | Jump between pages |
| `J` / `K` | Next / previous change in Review changes |
| `A` `R` `F` `E` | Accept, restore, false positive, escalate |
| `Ctrl` `Shift` `V` | Verify everything now |
| `?` | Show all shortcuts |

## 12. Common questions

**I edited a file myself and FileVow flagged it.** That's expected: FileVow can't know who
made a change. Open it in Review changes and click Accept.

**The status bar says "Agent offline".** Monitoring isn't running. Open FileVow from the
Start menu; it checks everything as soon as it starts.

**A file "could not be read".** Another program has it open exclusively, or Windows denies
access. Close the program and click Verify now.

**Can I protect a whole drive?** You can, but protecting the folders that matter works
better. Folders that change constantly, like browser caches, create a lot of noise.

**Where is my data?** In `%LOCALAPPDATA%\FileVow` (database, encrypted backups, keys and
logs). FileVow's own encryption keys are in the Windows Credential Manager. Nothing is
sent anywhere unless you add a notification channel.

**How do I uninstall?** Settings → Apps → Installed apps → FileVow → Uninstall. Your
protected files are never touched. Delete `%LOCALAPPDATA%\FileVow` to remove FileVow's
records too.

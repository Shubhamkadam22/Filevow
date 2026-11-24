import type { ReactNode } from "react";
import { Icon } from "../components/Icon";

interface Topic {
  id: string;
  icon: string;
  title: string;
  body: ReactNode;
}

const TOPICS: Topic[] = [
  {
    id: "what",
    icon: "home",
    title: "What FileVow does",
    body: (
      <>
        <p>
          FileVow watches the files and folders you choose and tells you the moment one of them changes, whether a person,
          a program or malware changed it. You decide what happens next: keep the change, or put the original back with one
          click.
        </p>
        <p>Every protected file gets three independent safeguards (the "three layers"):</p>
        <ol>
          <li><b>A fingerprint (SHA-256).</b> A short code calculated from the file's contents. Change one letter and the fingerprint is completely different, so any edit is noticed.</li>
          <li><b>A signature (RSA).</b> Your personal signing key seals each fingerprint. Even someone who could edit FileVow's database can't forge a new seal, so they can't hide a change.</li>
          <li><b>An encrypted backup copy (the mirror).</b> FileVow keeps a locked copy of every approved version so you can see exactly what changed and restore it.</li>
        </ol>
        <p>FileVow never accepts a change on its own. A change stays "waiting for review" until you decide.</p>
      </>
    ),
  },
  {
    id: "start",
    icon: "check",
    title: "Getting started",
    body: (
      <ol>
        <li><b>Sign in</b> with a one-time code sent to your e-mail. The first time, you also choose a username, which you can type instead of your e-mail next time. Your account gets its own private workspace.</li>
        <li><b>Create your signing key</b> (Home → Get started). Pick a passphrase you'll remember; it's different from your account password.</li>
        <li><b>Add a folder or file</b>: click <i>Add folder or file</i>, then <i>Browse…</i>, open the folder you want and click <i>Protect this folder</i> (or pick a single file).</li>
        <li><b>Confirm</b> with your signing-key passphrase. FileVow fingerprints, signs and backs up every file.</li>
        <li><b>Recommended:</b> turn on two-step verification and add a notification channel in Settings.</li>
      </ol>
    ),
  },
  {
    id: "privacy",
    icon: "lock",
    title: "Your workspace and privacy",
    body: (
      <>
        <p>
          Every account has its own workspace: its own folders, signing key, changes, alerts, history and audit log. Other
          people who use FileVow on the same computer, including the administrator, cannot see or change anything in your
          workspace.
        </p>
        <p>
          A folder can belong to only one workspace at a time. If you see "already protected in another workspace", someone
          else on this computer is protecting it.
        </p>
        <p>
          FileVow runs on your own computer. Your files and their backup copies never leave it unless you set up a
          notification channel, and alert messages never contain file contents.
        </p>
      </>
    ),
  },
  {
    id: "folders",
    icon: "folder",
    title: "Protecting folders and files",
    body: (
      <>
        <div className="term"><b>Browse…</b><span>Opens a file window with shortcuts to Desktop, Documents, Downloads and every drive. Click folders to open them; click a file to choose just that file.</span></div>
        <div className="term"><b>How serious is a change</b><span>Sets the alert level for changes in this folder. Critical alerts are escalated quickly if nobody responds.</span></div>
        <div className="term"><b>Skip files matching</b><span>Patterns for files that change all the time and don't need protecting, such as <span className="mono">*.log</span>, <span className="mono">*.tmp</span> or Office lock files <span className="mono">~$*</span>.</span></div>
        <div className="term"><b>Protect new files</b><span>Files you add to a folder later show up as "Unknown file created". Approve them one by one, or click <i>Protect new files</i> on the folder to protect them all at once.</span></div>
        <div className="term"><b>On/off switch</b><span>Pauses monitoring of a folder without forgetting it.</span></div>
      </>
    ),
  },
  {
    id: "checks",
    icon: "verify",
    title: "How and when files are checked",
    body: (
      <>
        <p>FileVow checks your files in three situations:</p>
        <ul>
          <li><b>Within seconds</b> of a file being changed, deleted or added (real-time watching).</li>
          <li><b>Every 15 minutes</b>, everything is checked again in full, in case something was missed.</li>
          <li><b>When you click Verify now</b> on Home or in Verification history.</li>
        </ul>
        <p>
          Each check is recorded in <i>Verification history</i> together with a digital signature, so the history itself
          can't be faked. If FileVow was switched off for a while, it tells you about the "monitoring gap" when it starts
          again, because a file could have been changed and put back in the meantime.
        </p>
      </>
    ),
  },
  {
    id: "review",
    icon: "review",
    title: "Reviewing changes",
    body: (
      <>
        <p>
          When something changes, it appears in <i>Review changes</i> with a side-by-side comparison of the approved copy and
          what's on disk now. Lines in red were removed, lines in green were added. The four tiles show which safeguard
          raised the alarm.
        </p>
        <div className="term"><b>Accept</b><span>The change was expected (for example, you edited the file yourself). The current file becomes the new approved version and is signed with your key.</span></div>
        <div className="term"><b>Restore</b><span>Puts back the last approved version from the encrypted backup. The changed file is kept as evidence first.</span></div>
        <div className="term"><b>Quarantine</b><span>For a new file nobody expected: FileVow keeps an encrypted evidence copy and removes the file.</span></div>
        <div className="term"><b>False positive</b><span>Closes the alert without changing anything. If the file is still different, it's reported again at the next check.</span></div>
        <div className="term"><b>Escalate</b><span>Marks the change for a closer look and keeps it open.</span></div>
        <p>Accepting, restoring and quarantining always ask for your signing-key passphrase, and every decision is saved in your audit log with the reason you give.</p>
      </>
    ),
  },
  {
    id: "key",
    icon: "key",
    title: "Your signing key and passphrase",
    body: (
      <>
        <p>
          Your signing key is your personal seal. It's stored encrypted on this computer and can only be unlocked with your
          signing-key passphrase. You need the passphrase when you protect a folder or accept a change.
        </p>
        <ul>
          <li><b>Download a backup</b> (Settings → Signing keys) and keep it on a USB drive. The file stays encrypted with your passphrase.</li>
          <li><b>Forgot the passphrase?</b> Nobody can recover it. Your files stay monitored and restorable, but you can't approve new changes; ask the administrator to help you start a new key.</li>
        </ul>
      </>
    ),
  },
  {
    id: "alerts",
    icon: "bell",
    title: "Alerts and notifications",
    body: (
      <>
        <p>
          The bell in the top bar lists your alerts. A red dot means something new. Alerts you don't acknowledge are escalated:
          critical ones after 15 minutes, high ones after an hour.
        </p>
        <p>
          In Settings → Notifications you can also get alerts by email, in Slack or Teams, through a webhook, or as a Windows
          notification. Use <i>Test</i> to check a channel works. Many alerts at once are grouped into a single message.
        </p>
      </>
    ),
  },
  {
    id: "history",
    icon: "audit",
    title: "Verification history and audit log",
    body: (
      <>
        <p><b>Verification history</b> lists every check of your workspace, how long it took and what it found. Each report is digitally signed.</p>
        <p>
          The <b>audit log</b> records everything that happens in your workspace: sign-ins, folders added, changes detected and
          every decision with its reason. The entries are chained together like links, so editing or deleting one breaks the
          chain. <i>Verify chain</i> checks that nothing was tampered with. <i>Export CSV</i> downloads your log.
        </p>
      </>
    ),
  },
  {
    id: "account",
    icon: "user",
    title: "Keeping your account safe",
    body: (
      <ul>
        <li><b>No password to steal.</b> You sign in with a one-time e-mail code (type your username or e-mail), and stay signed in on this PC for 30 days.</li>
        <li><b>Your signing-key passphrase confirms important actions</b> such as accepting or restoring a file. It never leaves this PC. Five wrong tries lock the account for 15 minutes.</li>
        <li><b>Extra protection:</b> turn on two-step verification in Settings to also require a 6-digit code from an app such as Microsoft Authenticator.</li>
        <li><b>What's stored online:</b> only your e-mail address, sign-in dates and (unless you turn it off in Settings) a daily "used today" marker. <i>Delete my account</i> in Settings removes it all.</li>
        <li><b>Sign out</b> with the arrow icon in the top-right corner when you share the computer.</li>
      </ul>
    ),
  },
  {
    id: "keys",
    icon: "keyboard",
    title: "Keyboard shortcuts",
    body: (
      <>
        <p>Press <kbd>?</kbd> anywhere to see every shortcut. The most useful ones:</p>
        <div className="term"><b><kbd>Ctrl</kbd> <kbd>K</kbd></b><span>Search files, changes, pages and commands.</span></div>
        <div className="term"><b><kbd>Alt</kbd> <kbd>1</kbd>–<kbd>8</kbd></b><span>Jump between pages.</span></div>
        <div className="term"><b><kbd>J</kbd> / <kbd>K</kbd></b><span>Next / previous change in Review changes.</span></div>
        <div className="term"><b><kbd>A</kbd> <kbd>R</kbd> <kbd>F</kbd> <kbd>E</kbd></b><span>Accept, restore, false positive, escalate.</span></div>
      </>
    ),
  },
  {
    id: "faq",
    icon: "info",
    title: "Common questions",
    body: (
      <>
        <h3>I edited a file myself and FileVow flagged it.</h3>
        <p>That's expected: FileVow can't know who made a change. Open it in Review changes and click Accept.</p>
        <h3>"Agent offline" is shown at the bottom.</h3>
        <p>The background checker isn't running. Open FileVow from the Start menu; it checks everything as soon as it starts. To keep it running whenever you sign in to Windows, tick "Keep monitoring in the background" when installing, or run <span className="mono">FileVow.exe autostart on</span>.</p>
        <h3>Does closing the window stop monitoring?</h3>
        <p>Not when background monitoring is on: FileVow keeps checking and the next time you open it, the window simply reappears.</p>
        <h3>A file shows "could not be read".</h3>
        <p>Another program has it open exclusively, or Windows doesn't allow access. Close the program and click Verify now.</p>
        <h3>Can I protect a whole drive?</h3>
        <p>You can, but it's better to protect the folders that matter (documents, projects, website files). Folders that change constantly, like browser caches, produce a lot of noise.</p>
      </>
    ),
  },
];

export function HelpPage() {
  return (
    <section className="page on">
      <h1 className="ptitle">Help</h1>
      <div className="help-grid">
        <nav className="help-toc" aria-label="Help topics">
          {TOPICS.map((topic) => <a key={topic.id} href={`#help-${topic.id}`}>{topic.title}</a>)}
        </nav>
        <div className="help-body">
          {TOPICS.map((topic) => (
            <section key={topic.id} id={`help-${topic.id}`}>
              <h2><Icon name={topic.icon} />{topic.title}</h2>
              {topic.body}
            </section>
          ))}
        </div>
      </div>
    </section>
  );
}

# Going live: Supabase, Google sign-in, GitHub releases and Vercel

Follow these steps in order, once. They take about an hour. Where a step says
**"you"**, it needs your own accounts and sign-ins.

| What | Where it runs | What it's for |
|---|---|---|
| Accounts | **Supabase** | Sign-in with Google or an e-mail code; counts your users |
| Installer | **GitHub Releases** | Built automatically when you push a version tag |
| Website | **Vercel** | Home, Features, About, Privacy, Download |
| Files, backups, keys, history | **Each user's PC** | Never uploaded anywhere |

---

## Step 1: Create the Supabase project (you)

1. Go to **supabase.com** → **Start your project** → sign in with GitHub.
2. **New project**:
   - Name: `filevow`
   - Database password: generate a strong one and save it in your password manager
     (FileVow doesn't need it, but you might later).
   - Region: the one closest to your users (for India: **South Asia (Mumbai)**).
3. Wait about 2 minutes until the project is ready.
4. Open **Project Settings → API Keys** (on older dashboards: **Settings → API**) and copy:
   - **Project URL**, for example `https://abcdwxyz.supabase.co`
   - The **anon public** key (or the **publishable** key starting `sb_publishable_`)

   These two values are meant to be public: they're built into the app.
   **Never** copy or share the `service_role` / secret key.

## Step 2: Create the database table and functions (you, copy-paste)

1. In Supabase open **SQL Editor → New query**.
2. Open `web/supabase/migrations/20261124000000_filevow_usage.sql` from this project,
   copy everything, paste it in, and click **Run**. You should see *Success. No rows returned*.

This creates:
- `app_activity`: one row per account per day the app is used (date, app and Windows version);
- `record_activity()` and `delete_my_account()`: the only two things the app can do;
- `usage_summary`, `daily_active_users`, `active_by_version`: views with your numbers.

Row-level security blocks every direct read and write from the app, so users can't see
each other's data.

## Step 3: Set up e-mail codes (you)

**3a. Send a code instead of a link.** In **Authentication → Emails → Templates**, edit
both **Confirm signup** and **Magic Link**. Set the subject to `Your FileVow sign-in code`
and replace the body with:

```html
<h2>Your FileVow sign-in code</h2>
<p>Enter this code in FileVow:</p>
<p style="font-size:28px;font-weight:bold;letter-spacing:6px">{{ .Token }}</p>
<p>It expires in 10 minutes. If you didn't try to sign in, ignore this e-mail.</p>
```

**3b. Code settings.** In **Authentication → Sign In / Providers → Email**: keep **Email**
enabled, keep **Confirm email** on, and set **Email OTP Expiration** to `600` seconds.

**3c. Your own e-mail sender (required before real users).** Supabase's built-in e-mail
only sends to your own team's addresses and only a few per hour. In
**Authentication → Emails → SMTP Settings**, turn on **custom SMTP**. Two options:

| Option | Settings | Good for |
|---|---|---|
| **Gmail** (no domain needed) | Host `smtp.gmail.com`, port `587`, username = your Gmail address, password = a Gmail **app password** (Google Account → Security → 2-Step Verification → App passwords) | Getting started; about 500 e-mails/day |
| **Resend** (needs your own domain) | Sign up at resend.com, verify your domain, create an API key; host `smtp.resend.com`, port `587`, username `resend`, password = the API key | Production, better deliverability |

Sender name: `FileVow`. Then in **Authentication → Rate Limits**, check the e-mails per
hour limit suits you (for example 30).

## Step 4: Set up "Continue with Google" (you)

1. Go to **console.cloud.google.com** → create a project called `FileVow`.
2. **APIs & Services → OAuth consent screen** (shown as **Google Auth Platform**):
   - User type **External**, app name `FileVow`, your support e-mail.
   - Authorized domain: `supabase.co`.
   - Scopes: `openid`, `.../auth/userinfo.email`, `.../auth/userinfo.profile` (no others).
   - When ready for the public, click **Publish app**. While it's in *Testing*, only test
     users you add can sign in. With only these basic scopes, Google doesn't require an
     app review.
3. **APIs & Services → Credentials → Create credentials → OAuth client ID**:
   - Application type **Web application**, name `FileVow Supabase`.
   - **Authorized redirect URI**: `https://<your-project-ref>.supabase.co/auth/v1/callback`
     (Supabase shows this exact URL on its Google provider page).
   - Create, then copy the **Client ID** and **Client secret**.
4. In Supabase: **Authentication → Sign In / Providers → Google** → enable, paste the
   Client ID and Client secret → **Save**.

## Step 5: Allow FileVow's sign-in address (you)

The desktop app runs on the user's own computer at `http://127.0.0.1:8443`, and Google
sign-in returns there. In Supabase **Authentication → URL Configuration**:

- **Site URL**: `http://127.0.0.1:8443`
- **Redirect URLs**, add both:
  - `http://127.0.0.1:8443/**`
  - `http://localhost:8443/**`

## Step 6: Try it on your PC before releasing

1. Create `web/backend/.env` (it's git-ignored, never committed) containing:

   ```
   FILEVOW_SUPABASE_URL=https://<your-project-ref>.supabase.co
   FILEVOW_SUPABASE_ANON_KEY=<the anon / publishable key>
   ```

2. Start the app:

   ```powershell
   cd C:\Project_1\web\backend; .venv\Scripts\python scripts\run_dev.py
   ```

3. Open `http://127.0.0.1:8443`. The sign-in page now shows **Continue with Google** and
   **Send me a code**. Try both. The first account becomes the administrator.
4. In Supabase, **Authentication → Users** shows your account, and
   **Table Editor → usage_summary** shows `active_today = 1`.

To go back to local demo accounts, delete or rename `.env`.

## Step 7: Put the code on GitHub (you)

```powershell
cd C:\Project_1
git push -u origin main
```

The first push opens a GitHub sign-in window. Then in the repository on github.com:

1. **Settings → Secrets and variables → Actions → Variables tab → New repository variable**:
   - `SUPABASE_URL` = your Project URL
   - `SUPABASE_ANON_KEY` = the anon / publishable key

   Use **Variables**, not Secrets: these values are public and are built into the app.
2. **Actions** tab: the **CI** workflow should finish green (backend and dashboard checks).

## Step 8: Release the installer

```powershell
git tag v0.1.0
git push origin v0.1.0
```

The **Release** workflow (Actions tab) builds `FileVow.exe` and the installer on a
GitHub Windows machine, with your Supabase settings built in, and publishes a release
with `FileVow-Setup.exe`. It takes about 10–15 minutes. The website's Download button
always gets the newest release.

For later versions: bump `version` in `web/backend/pyproject.toml` (and
`src/filevow/__init__.py`, `web/packaging/windows/version_info.txt`), commit, then tag
`v0.1.1` and push the tag.

## Step 9: Put the website on Vercel (you)

1. Go to **vercel.com** → sign up with GitHub.
2. **Add New → Project** → import **Shubhamkadam22/Filevow** (grant Vercel access to it).
3. Configure:
   - **Root Directory**: `web/website` (click *Edit*)
   - **Framework Preset**: *Other*
   - Build command and output directory: leave empty
4. **Deploy**. You get an address like `filevow.vercel.app`.
5. Optional: **Settings → Domains** to add your own domain.

From now on every push to `main` updates the site, and pull requests get preview links.

## Step 10: Test as a brand-new user

1. On the live site click **Download**, run `FileVow-Setup.exe` (choose *More info → Run
   anyway* if SmartScreen warns; see *Code signing* in DEPLOYMENT.md).
2. Sign in with Google, create the signing key, protect a folder, edit a file, restore it.
3. Check Supabase: **Authentication → Users** lists the new account.

## Watching your numbers

In Supabase **Table Editor** (or **SQL Editor**):

| View / page | Shows |
|---|---|
| `usage_summary` | Total accounts, new in 30 days, active today / 7 days / 30 days |
| `daily_active_users` | Active accounts per day |
| `active_by_version` | Which app versions are in use |
| **Authentication → Users** | Every account with sign-up and last sign-in dates |
| GitHub **Releases** / **Insights** | Download counts |

Active users count only people who left *Count me as an active user* on in Settings
(it's on by default and described in the privacy policy).

## Before you announce it

- [ ] Replace `privacy@filevow.app` in the privacy policy with an address you read.
- [ ] Google consent screen **published**, custom SMTP on, test e-mail code received.
- [ ] Installer code-signed (avoids the SmartScreen warning) — optional but recommended.
- [ ] Tried the whole flow on a second PC or Windows account.

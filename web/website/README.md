# FileVow website

The public site people visit before downloading the app: Home, Features, About,
Privacy policy and Download. Plain HTML and CSS with one small script, no build step.

| File | Page |
|---|---|
| `index.html` | Welcome page: what FileVow does, the three layers, how to get started |
| `features.html` | Every feature, grouped |
| `about.html` | Why FileVow exists and who it is for |
| `privacy.html` | Privacy policy (keep it in step with what the app stores) |
| `download.html` | Installer, checksum, requirements, install and first steps |
| `assets/` | Stylesheet, script, logo and favicon (same palette as the app) |
| `downloads/` | `FileVow-Setup-<version>.exe` and `.sha256`, copied here by the build script |
| `vercel.json` | Vercel settings: security headers, clean URLs |
| `_headers` | The same headers for Netlify / Cloudflare Pages |

## Preview locally

```powershell
python -m http.server 8770 --directory web\website
```

## Publish (Vercel + GitHub Releases)

The site is hosted on **Vercel** straight from the GitHub repository; the installer is
attached to a **GitHub Release** (large binaries don't belong in git, and GitHub counts
every download for free).

1. In Vercel: **Add New → Project → Import** the GitHub repository.
2. Set **Root Directory** to `web/website`, **Framework Preset** to *Other*, and leave the
   build command empty. `vercel.json` adds the security headers and clean URLs.
3. Every push to `main` redeploys the site; pull requests get preview URLs.

Other static hosts work too: `_headers` holds the same headers for Netlify and
Cloudflare Pages.

Before publishing a release:

1. Run `web\packaging\windows\build.ps1`, then create a GitHub Release (tag `v<version>`)
   and attach `FileVow-Setup-<version>.exe` and its `.sha256`.
2. Point the download button and checksum in `download.html` at the release files and
   update the version if it changed.
3. Check the contact address in `privacy.html` is the one you want people to use.

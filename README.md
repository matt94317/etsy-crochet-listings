# etsy-crochet-listings

`etsy_draft_listing.py` creates Etsy draft listings (digital downloads) via
the Open API v3, using OAuth 2.0 + PKCE. See the file's module docstring for
CLI usage.

This repo is checked out by a scheduled cloud agent (a claude.ai routine)
that runs daily. The routine does NOT have local `.env`/`etsy_tokens.json`
files — it fetches credentials from a private Google Drive file
(`etsy_credentials.json`) at the start of each run, writes them out locally
as `.env` and `etsy_tokens.json`, runs this script, then writes the
(possibly rotated) tokens back to that same Drive file so the next run picks
up the refreshed token. Never commit `.env` or `etsy_tokens.json` — both are
gitignored.

`etsy_credentials.json` shape (in Drive):

```json
{
  "keystring": "...",
  "shared_secret": "...",
  "redirect_uri": "...",
  "access_token": "...",
  "refresh_token": "...",
  "expires_at": 0,
  "user_id": "...",
  "shop_id": 0
}
```

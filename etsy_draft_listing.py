#!/usr/bin/env python3
"""
Create an Etsy draft listing for a digital (download) product — e.g. a crochet
pattern PDF — via the Etsy Open API v3.

One-time:   python3 etsy_draft_listing.py auth        # browser authorization
Then:       python3 etsy_draft_listing.py shop        # confirm user/shop IDs
            python3 etsy_draft_listing.py taxonomy pattern
            python3 etsy_draft_listing.py create listing.json

Config lives in .env next to this file; tokens are cached in etsy_tokens.json
(chmod 600) and refreshed automatically.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import mimetypes
import os
import secrets
import sys
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
ENV_FILE = HERE / ".env"
TOKEN_FILE = HERE / "etsy_tokens.json"

API = "https://api.etsy.com/v3/application"
TOKEN_URL = "https://api.etsy.com/v3/public/oauth/token"
CONNECT_URL = "https://www.etsy.com/oauth/connect"

# listings_w creates listings and uploads images/files; listings_r reads them
# back; shops_r resolves the shop ID from the authorized user.
SCOPES = "listings_r listings_w shops_r"

# Etsy Help Center limits for digital listings (not enforced by the API spec,
# so we warn rather than refuse).
MAX_DIGITAL_FILES = 5
MAX_DIGITAL_FILE_BYTES = 20 * 1024 * 1024


# --------------------------------------------------------------------------
# config + token storage
# --------------------------------------------------------------------------

def load_env() -> None:
    """Minimal .env loader so this stays dependency-free apart from requests."""
    if not ENV_FILE.exists():
        return
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def need(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        sys.exit(f"Missing {name} — set it in {ENV_FILE} (see .env.example).")
    return value


def read_tokens() -> dict:
    if not TOKEN_FILE.exists():
        sys.exit(f"No tokens at {TOKEN_FILE}. Run:  python3 {Path(__file__).name} auth")
    return json.loads(TOKEN_FILE.read_text())


def write_tokens(data: dict) -> None:
    TOKEN_FILE.write_text(json.dumps(data, indent=2))
    TOKEN_FILE.chmod(0o600)


# --------------------------------------------------------------------------
# API client
# --------------------------------------------------------------------------

class Etsy:
    def __init__(self) -> None:
        self.keystring = need("ETSY_KEYSTRING")
        # Etsy requires "keystring:shared_secret" in x-api-key on every REST
        # call, even with a Bearer token — PKCE only removes the secret from
        # the OAuth token exchange itself, not from this header.
        self.api_key = f"{self.keystring}:{need('ETSY_SHARED_SECRET')}"
        self.tokens = read_tokens()

    @property
    def access_token(self) -> str:
        # Etsy access tokens live 1 hour; refresh a minute early.
        if time.time() > self.tokens.get("expires_at", 0) - 60:
            self.refresh()
        return self.tokens["access_token"]

    def refresh(self) -> None:
        response = requests.post(
            TOKEN_URL,
            json={
                "grant_type": "refresh_token",
                "client_id": self.keystring,
                "refresh_token": self.tokens["refresh_token"],
            },
            timeout=30,
        )
        if not response.ok:
            sys.exit(
                f"Token refresh failed ({response.status_code}): {response.text}\n"
                "Refresh tokens expire after 90 days of disuse — re-run `auth` if so."
            )
        payload = response.json()
        # Etsy rotates the refresh token on every refresh, so always re-save.
        self.tokens.update(
            access_token=payload["access_token"],
            refresh_token=payload["refresh_token"],
            expires_at=time.time() + payload["expires_in"],
        )
        write_tokens(self.tokens)

    def request(self, method: str, path: str, **kwargs) -> dict:
        headers = {
            "x-api-key": self.api_key,
            "Authorization": f"Bearer {self.access_token}",
        }
        headers.update(kwargs.pop("headers", {}))
        url = path if path.startswith("http") else f"{API}{path}"

        for attempt in range(4):
            response = requests.request(method, url, headers=headers, timeout=120, **kwargs)
            # 429 = over the 10/second or 10,000/day quota.
            if response.status_code in (429, 500, 502, 503, 504) and attempt < 3:
                wait = float(response.headers.get("Retry-After", 2 ** attempt))
                print(f"  {response.status_code} from Etsy, retrying in {wait:.0f}s...")
                time.sleep(wait)
                continue
            break

        if not response.ok:
            sys.exit(f"{method} {url} failed ({response.status_code}): {response.text}")
        return response.json() if response.content else {}

    def get(self, path: str, **kw) -> dict:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw) -> dict:
        return self.request("POST", path, **kw)

    def shop_id(self) -> int:
        if self.tokens.get("shop_id"):
            return int(self.tokens["shop_id"])
        me = self.get("/users/me")
        shop_id = me.get("shop_id")
        if not shop_id:
            # Older token responses omit shop_id; look it up from the user ID,
            # which is the part of the access token before the dot.
            shop_id = self.get(f"/users/{me['user_id']}/shops")["shop_id"]
        self.tokens["shop_id"] = shop_id
        write_tokens(self.tokens)
        return int(shop_id)


# --------------------------------------------------------------------------
# auth (one-time, PKCE)
# --------------------------------------------------------------------------

def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


class CallbackHandler(BaseHTTPRequestHandler):
    result: dict = {}

    def do_GET(self):  # noqa: N802 (name fixed by BaseHTTPRequestHandler)
        CallbackHandler.result = dict(
            urllib.parse.parse_qsl(urllib.parse.urlparse(self.path).query)
        )
        ok = "code" in CallbackHandler.result
        body = (
            "<h2>Authorized.</h2><p>Back to the terminal — you can close this tab.</p>"
            if ok
            else f"<h2>Authorization failed.</h2><pre>{CallbackHandler.result}</pre>"
        )
        self.send_response(200 if ok else 400)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):  # silence the default stderr logging
        pass


def cmd_auth(args) -> None:
    keystring = need("ETSY_KEYSTRING")
    redirect_uri = need("ETSY_REDIRECT_URI")

    verifier = b64url(secrets.token_bytes(32))
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    state = b64url(secrets.token_bytes(16))

    authorize_url = CONNECT_URL + "?" + urllib.parse.urlencode({
        "response_type": "code",
        "client_id": keystring,
        "redirect_uri": redirect_uri,
        "scope": SCOPES,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })

    print("\nOpen this URL and approve access:\n")
    print(authorize_url + "\n")

    if args.manual:
        pasted = input("Paste the full URL you were redirected to: ").strip()
        returned = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(pasted).query))
    else:
        parsed = urllib.parse.urlparse(redirect_uri)
        server = HTTPServer((parsed.hostname or "localhost", parsed.port or 80), CallbackHandler)
        print(f"Waiting for Etsy's redirect on {redirect_uri} ... (Ctrl-C to cancel)")
        webbrowser.open(authorize_url)
        server.handle_request()
        server.server_close()
        returned = CallbackHandler.result

    if "error" in returned:
        sys.exit(f"Etsy returned an error: {returned}")
    if returned.get("state") != state:
        sys.exit("State mismatch — aborting instead of exchanging the code.")
    if "code" not in returned:
        sys.exit(f"No authorization code in the redirect: {returned}")

    response = requests.post(
        TOKEN_URL,
        json={
            "grant_type": "authorization_code",
            "client_id": keystring,
            "redirect_uri": redirect_uri,
            "code": returned["code"],
            "code_verifier": verifier,
        },
        timeout=30,
    )
    if not response.ok:
        sys.exit(f"Token exchange failed ({response.status_code}): {response.text}")

    payload = response.json()
    write_tokens({
        "access_token": payload["access_token"],
        "refresh_token": payload["refresh_token"],
        "expires_at": time.time() + payload["expires_in"],
        # The access token is "{user_id}.{opaque}" — that's the member ID, not
        # the shop ID.
        "user_id": payload["access_token"].split(".")[0],
    })
    print(f"\nTokens saved to {TOKEN_FILE}")

    etsy = Etsy()
    print(f"Shop ID: {etsy.shop_id()}  (cached in the same file)")


# --------------------------------------------------------------------------
# helper commands
# --------------------------------------------------------------------------

def cmd_shop(args) -> None:
    etsy = Etsy()
    me = etsy.get("/users/me")
    shop = etsy.get(f"/shops/{etsy.shop_id()}")
    print(f"user_id   {me.get('user_id')}")
    print(f"shop_id   {shop['shop_id']}")
    print(f"shop_name {shop['shop_name']}")
    print(f"currency  {shop.get('currency_code')}")
    print(f"listings  {shop.get('listing_active_count')} active, "
          f"{shop.get('digital_listing_count')} digital")


def cmd_taxonomy(args) -> None:
    """Search the seller taxonomy tree for a category ID."""
    api_key = f"{need('ETSY_KEYSTRING')}:{need('ETSY_SHARED_SECRET')}"
    response = requests.get(
        f"{API}/seller-taxonomy/nodes",
        headers={"x-api-key": api_key},
        timeout=60,
    )
    response.raise_for_status()

    matches = []

    def walk(nodes, trail):
        for node in nodes:
            path = trail + [node["name"]]
            if args.query.lower() in " > ".join(path).lower():
                matches.append((node["id"], " > ".join(path)))
            walk(node.get("children") or [], path)

    walk(response.json()["results"], [])
    if not matches:
        sys.exit(f"No taxonomy node matching {args.query!r}.")
    for taxonomy_id, path in matches:
        print(f"{taxonomy_id:>8}  {path}")
    print(f"\n{len(matches)} match(es). Put the ID in your listing JSON as taxonomy_id.")


# --------------------------------------------------------------------------
# create
# --------------------------------------------------------------------------

# Fields createDraftListing accepts as form data. Anything else in the JSON is
# a typo, and better caught here than as a vague 400 from Etsy.
LISTING_FIELDS = {
    "quantity", "title", "description", "price", "who_made", "when_made",
    "taxonomy_id", "shipping_profile_id", "return_policy_id", "materials",
    "shop_section_id", "processing_min", "processing_max", "readiness_state_id",
    "tags", "styles", "item_weight", "item_length", "item_width", "item_height",
    "item_weight_unit", "item_dimensions_unit", "production_partner_ids",
    "image_ids", "is_supply", "is_customizable", "should_auto_renew",
    "is_taxable", "type",
}
REQUIRED_FIELDS = {"quantity", "title", "description", "price", "who_made",
                   "when_made", "taxonomy_id"}

DIGITAL_DEFAULTS = {
    "type": "download",
    "quantity": 999,          # digital stock never runs out
    "who_made": "i_did",
    "when_made": "made_to_order",
    "is_supply": True,        # patterns sit under Craft Supplies & Tools
    "should_auto_renew": True,
}


def cmd_create(args) -> None:
    config = json.loads(Path(args.config).read_text())

    images = [Path(p) for p in (args.image or config.pop("images", []))]
    files = [Path(p) for p in (args.file or config.pop("files", []))]
    config.pop("_comment", None)

    listing = {**DIGITAL_DEFAULTS, **config}

    unknown = set(listing) - LISTING_FIELDS
    if unknown:
        sys.exit(f"Unknown field(s) in {args.config}: {', '.join(sorted(unknown))}")
    missing = REQUIRED_FIELDS - set(listing)
    if missing:
        sys.exit(f"Missing required field(s): {', '.join(sorted(missing))}")

    # Etsy takes these as comma-separated strings in form-encoded bodies.
    for key in ("tags", "materials", "styles"):
        if isinstance(listing.get(key), list):
            listing[key] = ",".join(listing[key])
    if len(listing.get("tags", "").split(",")) > 13 and listing.get("tags"):
        sys.exit("Etsy allows at most 13 tags.")
    if len(listing["title"]) > 140:
        sys.exit(f"Title is {len(listing['title'])} chars; Etsy's limit is 140.")

    for path in images + files:
        if not path.is_file():
            sys.exit(f"Not found: {path}")
    if len(files) > MAX_DIGITAL_FILES:
        sys.exit(f"Etsy allows at most {MAX_DIGITAL_FILES} files per digital listing.")
    for path in files:
        if path.stat().st_size > MAX_DIGITAL_FILE_BYTES:
            sys.exit(f"{path.name} is {path.stat().st_size / 1e6:.1f} MB; "
                     f"Etsy's per-file limit is 20 MB.")

    listing = {k: ("true" if v is True else "false" if v is False else v)
               for k, v in listing.items()}

    # Validate before touching the network, so --dry-run works pre-auth.
    if args.dry_run:
        print(json.dumps({"listing": listing,
                          "images": [str(p) for p in images],
                          "files": [str(p) for p in files]}, indent=2))
        return

    etsy = Etsy()
    shop_id = etsy.shop_id()

    print(f"Creating draft listing in shop {shop_id}...")
    created = etsy.post(f"/shops/{shop_id}/listings", data=listing)
    listing_id = created["listing_id"]
    print(f"  listing_id {listing_id} — state {created['state']}")

    for rank, path in enumerate(images, start=1):
        print(f"Uploading image {path.name} (rank {rank})...")
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        with path.open("rb") as handle:
            result = etsy.post(
                f"/shops/{shop_id}/listings/{listing_id}/images",
                data={"rank": rank},
                files={"image": (path.name, handle, content_type)},
            )
        print(f"  listing_image_id {result['listing_image_id']}")

    for rank, path in enumerate(files, start=1):
        print(f"Uploading file {path.name} ({path.stat().st_size / 1e6:.1f} MB)...")
        # Etsy's files endpoint has been observed to reject uploads when
        # requests' guessed content-type is missing/wrong, so set it explicitly.
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        with path.open("rb") as handle:
            result = etsy.post(
                f"/shops/{shop_id}/listings/{listing_id}/files",
                data={"name": path.name, "rank": rank},
                files={"file": (path.name, handle, content_type)},
            )
        print(f"  listing_file_id {result['listing_file_id']}")

    print(f"\nDraft ready — review and publish it here:\n"
          f"https://www.etsy.com/your/shops/me/tools/listings/{listing_id}")


# --------------------------------------------------------------------------

def main() -> None:
    load_env()
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_auth = sub.add_parser("auth", help="one-time browser authorization (PKCE)")
    p_auth.add_argument("--manual", action="store_true",
                        help="paste the redirect URL instead of running a local server")
    p_auth.set_defaults(func=cmd_auth)

    sub.add_parser("shop", help="show the authorized user/shop").set_defaults(func=cmd_shop)

    p_tax = sub.add_parser("taxonomy", help="search seller taxonomy for a category ID")
    p_tax.add_argument("query")
    p_tax.set_defaults(func=cmd_taxonomy)

    p_create = sub.add_parser("create", help="create a draft listing from a JSON file")
    p_create.add_argument("config", help="path to listing JSON")
    p_create.add_argument("--image", action="append", help="cover image (repeatable)")
    p_create.add_argument("--file", action="append", help="digital file (repeatable)")
    p_create.add_argument("--dry-run", action="store_true",
                          help="print what would be sent, call nothing")
    p_create.set_defaults(func=cmd_create)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

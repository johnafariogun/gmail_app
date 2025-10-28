import os
import json
from typing import Optional
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Request, HTTPException
from starlette.responses import RedirectResponse, HTMLResponse

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


# Scopes used by the app (same as original script)
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Paths
BASE_DIR = os.path.dirname(__file__)
CLIENT_SECRETS_FILE = os.path.join(BASE_DIR, "credentials.json")
TOKEN_FILE = os.path.join(BASE_DIR, "token.json")

# In-memory store for Flow objects keyed by state. This is fine for a
# single-process local dev server. For multi-process or production, use
# a persistent store (Redis, DB) and proper session handling.
flows: dict[str, Flow] = {}

app = FastAPI(title="Gmail API FastAPI wrapper")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
def save_credentials(creds: Credentials) -> None:
    with open(TOKEN_FILE, "w") as f:
        f.write(creds.to_json())


def build_gmail_service(creds: Credentials):
    return build("gmail", "v1", credentials=creds)


@app.get("/authorize")
def authorize():
    """Start the OAuth flow and redirect the user to Google's auth page."""
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES
    )
    # Must match the redirect URI in credentials.json
    flow.redirect_uri = "http://localhost:8000/redirect_uri"

    auth_url, state = flow.authorization_url(
        access_type="offline", include_granted_scopes="true", prompt="consent"
    )

    # Store flow in memory so we can finish the exchange in the callback.
    flows[state] = flow

    return RedirectResponse(auth_url)


@app.get("/redirect_uri")
async def oauth2callback(request: Request):
    """OAuth2 callback endpoint specified in credentials.json."""
    params = request.query_params
    state = params.get("state")
    if not state:
        raise HTTPException(status_code=400, detail="Missing state in callback")

    flow: Optional[Flow] = flows.pop(state, None)
    if flow is None:
        raise HTTPException(status_code=400, detail="Unknown or expired OAuth state")

    # Complete the OAuth2 flow using the full redirect URL
    full_url = str(request.url)
    try:
        flow.fetch_token(authorization_response=full_url)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch token: {e}")

    creds = flow.credentials
    save_credentials(creds)

    # Optionally fetch labels immediately and show result
    try:
        service = build_gmail_service(creds)
        results = service.users().labels().list(userId="me").execute()
        labels = results.get("labels", [])
    except HttpError as error:
        labels = []

    html = "<h2>Authorization complete</h2>"
    html += "<p>Credentials saved to token.json.</p>"
    html += "<p><a href=\"/labels\">View labels</a></p>"
    html += "<pre>{}</pre>".format(json.dumps(labels, indent=2))
    return HTMLResponse(content=html)


@app.get("/labels")
def list_labels():
    """Return the user's Gmail labels as JSON. If not authorized, redirect to /authorize."""
    if not os.path.exists(TOKEN_FILE):
        return RedirectResponse("/authorize")

    creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    # Refresh if needed
    if not creds.valid:
        if creds.expired and creds.refresh_token:
            creds.refresh(GoogleRequest())
            save_credentials(creds)
        else:
            # Token exists but isn't usable; ask the user to re-authorize
            return RedirectResponse("/authorize")

    try:
        service = build_gmail_service(creds)
        results = service.users().labels().list(userId="me").execute()
        labels = results.get("labels", [])
        return {"labels": labels}
    except HttpError as error:
        raise HTTPException(status_code=500, detail=str(error))


import uvicorn
if __name__ == "__main__":
    uvicorn.run(app, host="localhost", port=8000)
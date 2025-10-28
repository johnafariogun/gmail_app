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

from sqlalchemy import create_engine, Column, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
load_dotenv()

# ===========================
# CONFIG
# ===========================
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
GOOGLE_CLIENT_CONFIG = os.getenv("GOOGLE_CLIENT_CONFIG")
MYSQL_URL = os.getenv("MYSQL_URL")
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:8000/redirect_uri")
if not GOOGLE_CLIENT_CONFIG:
    raise RuntimeError("Missing GOOGLE_CLIENT_CONFIG environment variable")

if not MYSQL_URL:
    raise RuntimeError("Missing MYSQL_URL environment variable")

if not REDIRECT_URI:
    raise RuntimeError("Missing REDIRECT_URI environment variable")
client_config = json.loads(GOOGLE_CLIENT_CONFIG)

# SQLAlchemy setup
Base = declarative_base()
engine = create_engine(MYSQL_URL)
SessionLocal = sessionmaker(bind=engine)


# ===========================
# DATABASE MODEL
# ===========================
class Token(Base):
    __tablename__ = "tokens"
    user_id = Column(String(255), primary_key=True)
    token_json = Column(Text, nullable=False)


Base.metadata.create_all(bind=engine)


# ===========================
# FASTAPI SETUP
# ===========================
app = FastAPI(title="Gmail API FastAPI Wrapper with MySQL Storage")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

flows: dict[str, Flow] = {}


# ===========================
# HELPER FUNCTIONS
# ===========================
def save_credentials_to_db(user_id: str, creds: Credentials):
    """Store credentials JSON in MySQL."""
    db = SessionLocal()
    creds_json = creds.to_json()
    token = db.query(Token).filter(Token.user_id == user_id).first()
    if token:
        token.token_json = creds_json
    else:
        token = Token(user_id=user_id, token_json=creds_json)
        db.add(token)
    db.commit()
    db.close()


def load_credentials_from_db(user_id: str) -> Optional[Credentials]:
    """Load credentials from MySQL if available."""
    db = SessionLocal()
    token = db.query(Token).filter(Token.user_id == user_id).first()
    db.close()
    if token:
        return Credentials.from_authorized_user_info(json.loads(token.token_json), SCOPES)
    return None


def build_gmail_service(creds: Credentials):
    return build("gmail", "v1", credentials=creds)


# ===========================
# ROUTES
# ===========================
@app.get("/authorize")
def authorize():
    """Start the OAuth flow and redirect the user to Google's auth page."""
    flow = Flow.from_client_config(client_config, scopes=SCOPES)
    flow.redirect_uri = REDIRECT_URI

    auth_url, state = flow.authorization_url(
        access_type="offline", include_granted_scopes="true", prompt="consent"
    )

    flows[state] = flow
    return RedirectResponse(auth_url)


@app.get("/redirect_uri")
async def oauth2callback(request: Request):
    """OAuth2 callback endpoint specified in Google Cloud Console."""
    params = request.query_params
    state = params.get("state")
    if not state:
        raise HTTPException(status_code=400, detail="Missing state in callback")

    flow: Optional[Flow] = flows.pop(state, None)
    if flow is None:
        raise HTTPException(status_code=400, detail="Unknown or expired OAuth state")

    full_url = str(request.url)
    try:
        flow.fetch_token(authorization_response=full_url)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch token: {e}")

    creds = flow.credentials
    save_credentials_to_db("me", creds)

    # Fetch labels for confirmation
    try:
        service = build_gmail_service(creds)
        results = service.users().labels().list(userId="me").execute()
        labels = results.get("labels", [])
    except HttpError:
        labels = []

    html = "<h2>Authorization complete</h2>"
    html += "<p>Credentials stored in MySQL.</p>"
    html += "<p><a href=\"/labels\">View labels</a></p>"
    html += "<pre>{}</pre>".format(json.dumps(labels, indent=2))
    return HTMLResponse(content=html)


@app.get("/labels")
def list_labels():
    """Return the user's Gmail labels as JSON."""
    creds = load_credentials_from_db("me")
    if not creds:
        return RedirectResponse("/authorize")

    if not creds.valid:
        if creds.expired and creds.refresh_token:
            creds.refresh(GoogleRequest())
            save_credentials_to_db("me", creds)
        else:
            return RedirectResponse("/authorize")

    try:
        service = build_gmail_service(creds)
        results = service.users().labels().list(userId="me").execute()
        labels = results.get("labels", [])
        return {"labels": labels}
    except HttpError as error:
        raise HTTPException(status_code=500, detail=str(error))


# ===========================
# RUN LOCALLY
# ===========================
import uvicorn

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)

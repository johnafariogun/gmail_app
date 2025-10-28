import os
import json
import base64
from datetime import datetime
from typing import Optional, List

from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import RedirectResponse, HTMLResponse

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from sqlalchemy import (
    create_engine,
    Column,
    String,
    Text,
    DateTime,
    desc,
)
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

client_config = json.loads(GOOGLE_CLIENT_CONFIG)

# SQLAlchemy setup
Base = declarative_base()
engine = create_engine(MYSQL_URL)
SessionLocal = sessionmaker(bind=engine)

# ===========================
# DATABASE MODELS
# ===========================
class Token(Base):
    __tablename__ = "tokens"
    user_id = Column(String(255), primary_key=True)
    token_json = Column(Text, nullable=False)


class Email(Base):
    __tablename__ = "emails"
    id = Column(String(255), primary_key=True)
    subject = Column(String(500))
    sender = Column(String(500))
    snippet = Column(Text)
    date = Column(DateTime)
    body = Column(Text)


Base.metadata.create_all(bind=engine)

# ===========================
# FASTAPI SETUP
# ===========================
app = FastAPI(title="Gmail API + MySQL Email Store")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

flows: dict[str, Flow] = {}

# ===========================
# HELPERS
# ===========================
def save_credentials_to_db(user_id: str, creds: Credentials):
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
    db = SessionLocal()
    token = db.query(Token).filter(Token.user_id == user_id).first()
    db.close()
    if token:
        return Credentials.from_authorized_user_info(json.loads(token.token_json), SCOPES)
    return None


def build_gmail_service(creds: Credentials):
    return build("gmail", "v1", credentials=creds)


def decode_body(payload):
    """Extract plain text body from Gmail message payload"""
    def walk_parts(part):
        if part.get("parts"):
            for p in part["parts"]:
                text = walk_parts(p)
                if text:
                    return text
        elif part["mimeType"] == "text/plain":
            data = part["body"].get("data")
            if data:
                return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
        return None

    return walk_parts(payload)


# ===========================
# ROUTES
# ===========================
@app.get("/authorize")
def authorize():
    flow = Flow.from_client_config(client_config, scopes=SCOPES)
    flow.redirect_uri = REDIRECT_URI

    auth_url, state = flow.authorization_url(
        access_type="offline", include_granted_scopes="true", prompt="consent"
    )
    flows[state] = flow
    return RedirectResponse(auth_url)


@app.get("/redirect_uri")
async def oauth2callback(request: Request):
    params = request.query_params
    state = params.get("state")
    if not state:
        raise HTTPException(status_code=400, detail="Missing state in callback")

    flow: Optional[Flow] = flows.pop(state, None)
    if flow is None:
        raise HTTPException(status_code=400, detail="Unknown or expired OAuth state")

    try:
        flow.fetch_token(authorization_response=str(request.url))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch token: {e}")

    creds = flow.credentials
    save_credentials_to_db("me", creds)

    html = "<h2>Authorization complete</h2>"
    html += "<p>Credentials saved to MySQL.</p>"
    html += "<p><a href=\"/refresh\">Fetch emails</a></p>"
    return HTMLResponse(content=html)


@app.get("/refresh")
def refresh_emails():
    """Fetch latest emails from Gmail and save to MySQL."""
    creds = load_credentials_from_db("me")
    if not creds:
        return RedirectResponse("/authorize")

    if not creds.valid:
        if creds.expired and creds.refresh_token:
            creds.refresh(GoogleRequest())
            save_credentials_to_db("me", creds)
        else:
            return RedirectResponse("/authorize")

    db = SessionLocal()
    try:
        service = build_gmail_service(creds)
        results = service.users().messages().list(userId="me", maxResults=20).execute()
        messages = results.get("messages", [])

        for msg in messages:
            detail = (
                service.users()
                .messages()
                .get(userId="me", id=msg["id"], format="full")
                .execute()
            )

            headers = detail["payload"].get("headers", [])
            subject = next((h["value"] for h in headers if h["name"] == "Subject"), "(No Subject)")
            sender = next((h["value"] for h in headers if h["name"] == "From"), "(Unknown Sender)")
            date_str = next((h["value"] for h in headers if h["name"] == "Date"), "")
            date = None
            try:
                date = datetime.strptime(date_str[:25], "%a, %d %b %Y %H:%M:%S")
            except Exception:
                pass

            snippet = detail.get("snippet", "")
            body = decode_body(detail.get("payload", {})) or ""

            existing = db.query(Email).filter(Email.id == msg["id"]).first()
            if not existing:
                email = Email(
                    id=msg["id"],
                    subject=subject,
                    sender=sender,
                    snippet=snippet,
                    date=date,
                    body=body,
                )
                db.add(email)

        db.commit()
        return {"status": "Emails refreshed successfully"}

    except HttpError as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


@app.get("/emails")
def get_emails(
    sort: Optional[str] = Query("desc", description="Sort by date: asc or desc"),
    limit: Optional[int] = Query(10, description="Number of emails to return"),
):
    """Return emails stored in MySQL, sorted by date."""
    db = SessionLocal()
    query = db.query(Email)

    if sort == "asc":
        query = query.order_by(Email.date)
    else:
        query = query.order_by(desc(Email.date))

    emails = query.limit(limit).all()
    db.close()

    return [
        {
            "id": e.id,
            "subject": e.subject,
            "from": e.sender,
            "snippet": e.snippet,
            "date": e.date,
        }
        for e in emails
    ]

# ===========================
# RUN LOCALLY
# ===========================
import uvicorn

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)

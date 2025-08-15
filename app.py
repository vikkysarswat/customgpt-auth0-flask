import os, json, requests
from urllib.parse import urlencode, quote_plus
from flask import Flask, session, redirect, url_for, request, render_template, jsonify
from authlib.integrations.flask_client import OAuth
from jose import jwt
from jose.utils import base64url_decode

APP_METADATA_CLAIM = "https://stockk.example.com/app_metadata"

AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN")  # e.g. nileshvikky1.us.auth0.com
AUTH0_CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = os.environ.get("AUTH0_CLIENT_SECRET")
AUTH0_BASE_URL = f"https://{AUTH0_DOMAIN}"
APP_BASE_URL = os.environ.get("APP_BASE_URL")  # e.g. https://your-service.onrender.com
SESSION_SECRET = os.environ.get("SESSION_SECRET", "change-me")

app = Flask(__name__)
app.secret_key = SESSION_SECRET

oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url=f"{AUTH0_BASE_URL}/oauth/token",
    authorize_url=f"{AUTH0_BASE_URL}/authorize",
    client_kwargs={"scope": "openid profile email"},
)

def _get_jwks():
    jwks_url = f"{AUTH0_BASE_URL}/.well-known/jwks.json"
    return requests.get(jwks_url, timeout=10).json()

def _verify_and_decode_id_token(id_token):
    jwks = _get_jwks()
    unverified_header = jwt.get_unverified_header(id_token)
    kid = unverified_header.get("kid")
    key = next((k for k in jwks["keys"] if k["kid"] == kid), None)
    if not key:
        raise Exception("JWK not found for token")

    claims = jwt.decode(
        id_token,
        key,
        audience=AUTH0_CLIENT_ID,
        issuer=f"{AUTH0_BASE_URL}/",
        algorithms=["RS256"],
    )
    return claims

@app.route("/")
def home():
    user = session.get("user")
    return render_template("index.html", user=user)

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=f"{APP_BASE_URL}/callback"
    )

@app.route("/callback")
def callback():
    token = oauth.auth0.authorize_access_token()
    id_token = token.get("id_token")
    claims = _verify_and_decode_id_token(id_token)
    # Store only what we need in session
    session["user"] = {
        "name": claims.get("name") or claims.get("email"),
        "email": claims.get("email"),
    }
    session["claims"] = claims
    return redirect(url_for("dashboard"))

@app.route("/dashboard")
def dashboard():
    if "claims" not in session:
        return redirect(url_for("home"))
    claims = session["claims"]
    data = claims.get(APP_METADATA_CLAIM, {}) if isinstance(claims, dict) else {}
    safe = {
        "account_id": data.get("account_id"),
        "funds": data.get("funds"),
        "holdings": data.get("holdings", []),
        "pnl": data.get("pnl", []),
        "ledger": data.get("ledger", []),
        "trades": data.get("trades", []),
    }
    return render_template("dashboard.html", user=session.get("user"), data=safe)

@app.route("/api/me")
def api_me():
    if "claims" not in session:
        return jsonify({"error": "Not authenticated"}), 401
    claims = session["claims"]
    data = claims.get(APP_METADATA_CLAIM, {}) if isinstance(claims, dict) else {}
    safe = {
        "account_id": data.get("account_id"),
        "funds": data.get("funds"),
        "holdings": data.get("holdings", []),
        "pnl": data.get("pnl", []),
        "ledger": data.get("ledger", []),
        "trades": data.get("trades", []),
    }
    return jsonify(safe), 200

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        f"{AUTH0_BASE_URL}/v2/logout?"
        + urlencode(
            {"returnTo": f"{APP_BASE_URL}/", "client_id": AUTH0_CLIENT_ID},
            quote_via=quote_plus,
        )
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))

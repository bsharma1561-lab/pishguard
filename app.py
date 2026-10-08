"""
app.py ─ PhishGuard Flask Application
======================================
Main entry-point for the PhishGuard web application.

Routes
------
GET  /                  Landing page with stats dashboard
POST /scan              Analyse a submitted URL
GET  /result/<id>       View a previously saved scan result
GET  /history           Scan history with search & filter
POST /history/clear     Delete all scan records
GET  /about             Educational page about phishing

Security measures
-----------------
* CSRF tokens (HMAC-based constant-time comparison via hmac.compare_digest)
* Security response headers (CSP, X-Frame-Options, etc.)
* Input validation in every route and in the utils layer
* No user-supplied URLs are ever visited, fetched, or executed
* SQLite queries use parameterised placeholders (see database.py)
"""

import hmac
import os
import secrets

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from utils.database import (
    add_scan,
    clear_history,
    get_scan,
    get_stats,
    init_db,
    search_history,
)
from utils.url_analyzer import URLValidationError, analyze_url, normalize_url

# ===========================================================================
# Application factory
# ===========================================================================

app = Flask(__name__)

app.config.update(
    # SECRET_KEY is read from the environment; a hard-coded fallback is
    # provided only for local development.  Never use the fallback in production.
    SECRET_KEY=os.environ.get("PHISHGUARD_SECRET_KEY", "dev-only-insecure-key-change-me"),
    # Limit incoming request bodies to 8 KB – protects against oversized inputs.
    MAX_CONTENT_LENGTH=8 * 1024,
    # Cookie security flags
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Set Secure flag only when running over HTTPS (set FLASK_HTTPS=1 in prod).
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_HTTPS", "0") == "1",
)


# ===========================================================================
# Security headers (applied to every response)
# ===========================================================================

@app.after_request
def add_security_headers(response):
    """Attach security-related HTTP headers to every outgoing response."""
    # Prevent MIME-type sniffing attacks.
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Prevent clickjacking by disallowing iframes.
    response.headers["X-Frame-Options"] = "DENY"
    # Limit referrer information sent to third parties.
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Content Security Policy – restrict which resources the browser may load.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    return response


# ===========================================================================
# CSRF protection
# ===========================================================================

@app.context_processor
def inject_csrf_token():
    """Generate a CSRF token for the session and expose it to every template."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return {"csrf_token": session["csrf_token"]}


def _csrf_valid() -> bool:
    """Return True only when the submitted token matches the session token.

    hmac.compare_digest() is used instead of == to prevent timing attacks.
    """
    form_token  = request.form.get("csrf_token", "")
    saved_token = session.get("csrf_token", "")
    # Both must be non-empty AND equal in constant time.
    return bool(saved_token and hmac.compare_digest(form_token, saved_token))


# ===========================================================================
# Routes
# ===========================================================================

@app.get("/")
def index():
    """Landing page with the URL input form and the stats dashboard."""
    return render_template("index.html", stats=get_stats())


@app.post("/scan")
def scan():
    """Receive a URL form submission, analyse it, and show the result.

    Workflow:
    1. Validate the CSRF token.
    2. Normalise the submitted URL (add scheme if missing).
    3. Run all heuristic checks via analyze_url().
    4. Persist the scan summary to SQLite.
    5. Render the result template.

    No network requests are made to the submitted URL at any point.
    """
    if not _csrf_valid():
        abort(400, description="Invalid or missing form token. Refresh the page and try again.")

    raw_url = request.form.get("url", "").strip()

    try:
        normalised = normalize_url(raw_url)
        analysis   = analyze_url(normalised)
    except URLValidationError as err:
        flash(str(err), "error")
        return redirect(url_for("index"))

    scan_id = add_scan(
        url=normalised,
        domain=analysis["domain"],
        risk_score=analysis["risk_score"],
        classification=analysis["classification"],
    )

    return render_template("result.html", analysis=analysis, scan_id=scan_id)


@app.get("/result/<int:scan_id>")
def view_result(scan_id: int):
    """Re-display a previously saved scan.

    The analysis is re-computed from the stored URL.  No network request
    is made; the function is purely string-based.
    """
    record = get_scan(scan_id)
    if record is None:
        abort(404)

    analysis = analyze_url(record["url"])
    return render_template("result.html", analysis=analysis, scan_id=scan_id)


@app.get("/history")
def history():
    """Show paginated scan history with optional search and filter."""
    search_term    = request.args.get("q", "").strip()[:200]  # cap at 200 chars
    classification = request.args.get("status", "").upper()

    # Allowlist the classification value – reject anything unexpected.
    if classification not in {"", "SAFE", "SUSPICIOUS", "PHISHING"}:
        classification = ""

    scans = search_history(search_term, classification)
    return render_template(
        "history.html",
        scans=scans,
        search_term=search_term,
        selected_status=classification,
    )


@app.post("/history/clear")
def clear_scan_history():
    """Delete all scan records (requires a valid CSRF token)."""
    if not _csrf_valid():
        abort(400, description="Invalid or missing form token. Refresh the page and try again.")
    clear_history()
    flash("Scan history cleared successfully.", "success")
    return redirect(url_for("history"))


@app.get("/about")
def about():
    """Educational page explaining phishing and how this detector works."""
    return render_template("about.html")


# ===========================================================================
# Error handlers
# ===========================================================================

@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, message=error.description), 400


@app.errorhandler(404)
def not_found(_error):
    return render_template(
        "error.html", code=404,
        message="That page or scan result could not be found."
    ), 404


@app.errorhandler(413)
def payload_too_large(_error):
    return render_template(
        "error.html", code=413,
        message="Request too large. Please submit a shorter URL."
    ), 413


# ===========================================================================
# Startup
# ===========================================================================

# Initialise the database (creates the table if it does not exist).
init_db()

if __name__ == "__main__":
    # Debug mode is convenient locally.
    # Never enable debug=True on a public/production server.
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, host="127.0.0.1", port=5000)

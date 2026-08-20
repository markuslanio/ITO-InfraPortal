import os
import uuid
import logging
import requests
import urllib3
from functools import wraps
from urllib.parse import urlencode
from fastapi import Request
from fastapi.responses import RedirectResponse, HTMLResponse
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()
logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────

CLIENT_ID     = os.getenv("AZURE_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET", "")
TENANT_ID     = os.getenv("AZURE_TENANT_ID", "")
REDIRECT_URI  = os.getenv("AZURE_REDIRECT_URI", "")

AUTHORITY     = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPE         = ["openid", "profile", "email", "User.Read"]

# ── Group GUIDs ───────────────────────────────────────────────────────────────

GROUPS = {
    "admin":   os.getenv("GROUP_ADMIN",   "5b2f6312-5e67-426b-9bbc-4f2f5f946be7"),
    "general": os.getenv("GROUP_GENERAL", "5a40a5e5-f26e-4269-a4cb-4f6a56cee393"),
    "vmware":  os.getenv("GROUP_VMWARE",  "bb53132b-09b1-4dfb-b715-a486d0c2774c"),
    "citrix":  os.getenv("GROUP_CITRIX",  "933f504e-a287-465e-bf85-72dd5ba33873"),
    "network": os.getenv("GROUP_NETWORK", "bcd7ed0d-7b7b-4c06-85d0-788298946288"),
}

# All InfraPortal group GUIDs — being in ANY of these grants general access
ALL_INFRAPORTAL_GROUPS = set(GROUPS.values())

# ── Simple server-side session store ─────────────────────────────────────────
# In production consider redis or a DB-backed session store.
# For IIS/single-process this works fine.

_sessions: dict = {}


def _get_session(request: Request) -> dict:
    sid = request.cookies.get("infraportal_session")
    if sid and sid in _sessions:
        return _sessions[sid]
    return {}


def _create_session(response, data: dict) -> str:
    sid = str(uuid.uuid4())
    _sessions[sid] = data
    response.set_cookie(
        "infraportal_session", sid,
        httponly=True, samesite="lax",
        secure=os.getenv("AZURE_REDIRECT_URI", "").startswith("https"),
        max_age=28800,  # 8 hours
    )
    return sid


def _destroy_session(request: Request, response):
    sid = request.cookies.get("infraportal_session")
    if sid and sid in _sessions:
        del _sessions[sid]
    response.delete_cookie("infraportal_session")


# ── Auth helpers ──────────────────────────────────────────────────────────────

def get_current_user(request: Request) -> dict | None:
    """Return the session user dict or None if not logged in."""
    session = _get_session(request)
    return session.get("user")


def get_user_groups(request: Request) -> set:
    """Return set of group GUIDs the current user belongs to."""
    session = _get_session(request)
    return set(session.get("groups", []))


def is_authenticated(request: Request) -> bool:
    return get_current_user(request) is not None


def has_infraportal_access(request: Request) -> bool:
    """User must be in at least one InfraPortal group."""
    groups = get_user_groups(request)
    return bool(groups & ALL_INFRAPORTAL_GROUPS)


def has_group(request: Request, group_key: str) -> bool:
    """Check if user is in a specific group OR is an admin."""
    groups = get_user_groups(request)
    admin_guid = GROUPS["admin"]
    target_guid = GROUPS.get(group_key, "")
    return admin_guid in groups or target_guid in groups


def require_auth(group_key: str | None = None):
    """
    Dependency-style auth check for page routes.
    Returns (user, redirect_response) — if redirect_response is not None,
    the route should return it immediately.

    Usage in a route:
        user, redirect = require_auth_check(request, "vmware")
        if redirect: return redirect
    """
    pass  # See require_auth_check below


def require_auth_check(request: Request, group_key: str | None = None):
    """
    Returns (user_dict, error_response).
    If error_response is not None, return it from the route.
    group_key: None = any authenticated InfraPortal member, else specific group.
    """
    if not is_authenticated(request):
        # Store the originally requested URL so we can redirect back after login
        next_url = str(request.url)
        login_url = f"/infraportal/auth/login?next={next_url}"
        return None, RedirectResponse(url=login_url, status_code=302)

    if not has_infraportal_access(request):
        return None, RedirectResponse(url="/infraportal/auth/unauthorized", status_code=302)

    if group_key and not has_group(request, group_key):
        return None, RedirectResponse(url="/infraportal/auth/unauthorized", status_code=302)

    return get_current_user(request), None


# ── OAuth2 flow ───────────────────────────────────────────────────────────────

def get_auth_url(state: str, nonce: str) -> str:
    redirect_uri = os.getenv("AZURE_REDIRECT_URI", "")
    params = {
        "client_id":     CLIENT_ID,
        "response_type": "code",
        "redirect_uri":  redirect_uri,
        "scope":         " ".join(SCOPE),
        "state":         state,
        "nonce":         nonce,
        "response_mode": "query",
    }
    return f"{AUTHORITY}/oauth2/v2.0/authorize?{urlencode(params)}"


def exchange_code_for_token(code: str) -> dict | None:
    """Exchange auth code for tokens."""
    redirect_uri = os.getenv("AZURE_REDIRECT_URI", "")
    data = {
        "client_id":     CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "code":          code,
        "redirect_uri":  redirect_uri,
        "grant_type":    "authorization_code",
        "scope":         " ".join(SCOPE),
    }
    try:
        r = requests.post(
            f"{AUTHORITY}/oauth2/v2.0/token",
            data=data, timeout=15, verify=False
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.error(f"Token exchange failed: {e}")
        return None


def get_user_info(access_token: str) -> dict | None:
    """Fetch user profile from Microsoft Graph."""
    try:
        r = requests.get(
            "https://graph.microsoft.com/v1.0/me",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10, verify=False
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.error(f"Graph /me failed: {e}")
        return None


def _get_app_token() -> str | None:
    """Get an application-only Graph token via client credentials."""
    try:
        r = requests.post(
            f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token",
            data={
                "client_id":     CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "grant_type":    "client_credentials",
                "scope":         "https://graph.microsoft.com/.default",
            },
            timeout=15, verify=False,
        )
        r.raise_for_status()
        return r.json().get("access_token")
    except Exception as e:
        logger.error(f"App token request failed: {e}")
        return None


def get_user_groups_from_graph(access_token: str, user_id: str = "") -> list[str]:
    """
    Fetch ALL group memberships using an app-only token + transitiveMemberOf.
    Falls back to the user's delegated token if the app token fails.

    Uses transitiveMemberOf (not memberOf) so nested/indirect group membership
    is resolved — direct memberOf silently returns empty for nested members.
    Uses an app token because the delegated scope only has User.Read, which is
    insufficient for group enumeration.
    """
    groups: list[str] = []

    app_token = _get_app_token()
    if app_token and user_id:
        headers = {"Authorization": f"Bearer {app_token}"}
        url = f"https://graph.microsoft.com/v1.0/users/{user_id}/transitiveMemberOf?$select=id&$top=999"
        try:
            while url:
                r = requests.get(url, headers=headers, timeout=10, verify=False)
                r.raise_for_status()
                data = r.json()
                groups.extend([g["id"] for g in data.get("value", []) if "id" in g])
                url = data.get("@odata.nextLink")
            logger.info("Graph transitiveMemberOf returned %d groups for user %s", len(groups), user_id)
            return groups
        except Exception as e:
            logger.error(f"Graph transitiveMemberOf failed: {e} — falling back to delegated token")

    # Fallback: user's delegated token via /me/memberOf
    headers = {"Authorization": f"Bearer {access_token}"}
    url = "https://graph.microsoft.com/v1.0/me/memberOf?$select=id&$top=999"
    try:
        while url:
            r = requests.get(url, headers=headers, timeout=10, verify=False)
            r.raise_for_status()
            data = r.json()
            groups.extend([g["id"] for g in data.get("value", []) if "id" in g])
            url = data.get("@odata.nextLink")
        logger.info("Graph memberOf fallback returned %d groups", len(groups))
        return groups
    except Exception as e:
        logger.error(f"Graph memberOf fallback failed: {e}")
        return []


# ── Route handlers (registered in main.py) ───────────────────────────────────

async def login_handler(request: Request):
    """Redirect to Microsoft login."""
    from fastapi.responses import RedirectResponse
    next_url = request.query_params.get("next", "/infraportal/")
    state    = str(uuid.uuid4())
    nonce    = str(uuid.uuid4())

    # Store state+nonce+next in a temp cookie so we can verify on callback
    response = RedirectResponse(url=get_auth_url(state, nonce), status_code=302)
    is_secure = os.getenv("AZURE_REDIRECT_URI", "").startswith("https")
    response.set_cookie("auth_state", state,    httponly=True, max_age=600, samesite="lax", secure=is_secure)
    response.set_cookie("auth_nonce", nonce,    httponly=True, max_age=600, samesite="lax", secure=is_secure)
    response.set_cookie("auth_next",  next_url, httponly=True, max_age=600, samesite="lax", secure=is_secure)
    return response


async def callback_handler(request: Request):
    """Handle the OAuth2 callback from Microsoft."""
    code  = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")

    if error:
        logger.error(f"Auth error from Microsoft: {error} — {request.query_params.get('error_description')}")
        return RedirectResponse(url="/infraportal/auth/login", status_code=302)

    # Verify state
    expected_state = request.cookies.get("auth_state")
    if not code or state != expected_state:
        logger.warning("Auth state mismatch or missing code")
        return RedirectResponse(url="/infraportal/auth/login", status_code=302)

    next_url = request.cookies.get("auth_next", "/infraportal/")

    # Exchange code for tokens
    tokens = exchange_code_for_token(code)
    if not tokens or "access_token" not in tokens:
        logger.error("Token exchange returned no access_token")
        return RedirectResponse(url="/infraportal/auth/login", status_code=302)

    access_token = tokens["access_token"]

    # Get user profile
    user_info = get_user_info(access_token)
    logger.info(f"User info fields: name={user_info.get('displayName')} given={user_info.get('givenName')} upn={user_info.get('userPrincipalName')}")
    if not user_info:
        return RedirectResponse(url="/infraportal/auth/login", status_code=302)

    # Get group memberships (pass user_id so app-token path works)
    groups = get_user_groups_from_graph(access_token, user_info.get("id", ""))

    # Build session
    user = {
        "id":           user_info.get("id"),
        "name":         user_info.get("displayName", "Unknown"),
        "email":        user_info.get("mail") or user_info.get("userPrincipalName", ""),
        "given_name":   user_info.get("givenName", ""),
    }

    response = RedirectResponse(url=next_url, status_code=302)
    _create_session(response, {"user": user, "groups": groups})

    # Clear temp cookies
    response.delete_cookie("auth_state")
    response.delete_cookie("auth_nonce")
    response.delete_cookie("auth_next")

    logger.info(f"User logged in: {user['email']} — groups: {len(groups)}")
    return response


async def logout_handler(request: Request):
    """Clear session and redirect to Microsoft logout."""
    redirect_uri = os.getenv("AZURE_REDIRECT_URI", "").rsplit("/auth/callback", 1)[0] + "/"
    response = RedirectResponse(
        url=f"{AUTHORITY}/oauth2/v2.0/logout?post_logout_redirect_uri={redirect_uri}",
        status_code=302
    )
    _destroy_session(request, response)
    return response


async def unauthorized_handler(request: Request, templates):
    """Render the unauthorized page."""
    user = get_current_user(request)
    return templates.TemplateResponse("unauthorized.html", {
        "request": request,
        "user": user,
    })
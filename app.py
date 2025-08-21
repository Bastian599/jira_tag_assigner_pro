# app.py — Jira Stichwort-Zuordnung PRO v3 (FULL)
# Features:
# - Übersicht (Filter, klickbare Tickets, Schnellaktionen)
# - P-Labels (Dry-Run, Apply, Tabellenbearbeitung, Templates)
# - Worklog (Einzeln) + Templates
# - CSV-Import mit Vorschau + Dry-Run + Beispiel-CSV
# - Reports & Export (Tickets ohne P, CSV/XLSX; Worklog-Tools aus v2 bewusst vereinfacht)
# - 🗓️ Timesheet (Wochenansicht) mit Wochensumme und Quick-Add
# - 🔐 Schlüsselbundspeicherung via keyring (API-Token/Refresh-Token)
# - 🩺 Health-Check+
# - Multi-/Single-Projekt, Lead-Only Toggle (Standard AUS) + Fallback wenn leer
# - Auto-Refresh nach Updates, Undo (Worklogs/Labels)
#
# HINWEIS: Gespeicherte Klartextdaten vermeiden — mit Keyring speichern!

import os
import re
import io
import time
import json
import base64
import hashlib
import secrets
from pathlib import Path
from urllib.parse import urlencode, quote_plus
from collections import Counter
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, date, time as dtime, timedelta

import requests
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Jira Stichwort-Zuordnung PRO v3", layout="wide")

# -------------------------------
# Helpers
# -------------------------------
P_PATTERN = re.compile(r"^P\d{6}$")

def is_p_label(label: str) -> bool:
    return bool(P_PATTERN.match(label or ""))

def extract_p_label(labels: List[str]) -> Optional[str]:
    for l in labels or []:
        if is_p_label(l):
            return l
    return None

def now() -> float:
    return time.time()

def hide_sidebar_css():
    st.markdown("""
        <style>
        [data-testid="stSidebar"] {display:none !important;}
        .block-container {padding-top: 1rem;}
        </style>
    """, unsafe_allow_html=True)

def to_started_iso(d: date, t: dtime) -> str:
    local_tz = datetime.now().astimezone().tzinfo
    aware = datetime.combine(d, t).replace(tzinfo=local_tz)
    return aware.strftime("%Y-%m-%dT%H:%M:%S.000%z")

def ensure_15min(seconds: int) -> bool:
    return seconds % 900 == 0 and seconds > 0

def adf_comment(text: str) -> Dict[str, Any]:
    text = (text or "").strip()
    if not text:
        text = "Zeiterfassung über Stichwort-Tool"
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": text}]}
        ],
    }

def fill_template(tpl: str, p_value: str, issue_key: str, issue_summary: str, d: date) -> str:
    if not tpl:
        return ""
    return tpl.replace("{P}", p_value or "")\
              .replace("{ISSUE}", issue_key or "")\
              .replace("{SUMMARY}", issue_summary or "")\
              .replace("{DATE}", d.isoformat())

def week_bounds_from(d: date) -> Tuple[date, date]:
    monday = d - timedelta(days=d.weekday())
    return monday, monday + timedelta(days=7)

# -------------------------------
# Persistence (config + secure secrets)
# -------------------------------
CFG_DIR = Path.home() / ".jira_stichwort_tool"
CFG_DIR.mkdir(exist_ok=True)
CFG_FILE = CFG_DIR / "config.json"

def load_cfg() -> Dict[str, Any]:
    if CFG_FILE.exists():
        try:
            with open(CFG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_cfg(cfg: Dict[str, Any]):
    try:
        with open(CFG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        st.warning(f"Konnte Konfiguration nicht speichern: {e}")

CFG = load_cfg()
CFG.setdefault("remember", True)
CFG.setdefault("secure", True)     # use keyring by default if available
CFG.setdefault("defaults", {})     # project_key -> default P
CFG.setdefault("recent", {})       # project_key -> [P-values]
CFG.setdefault("templates", {})    # project_key -> template string
CFG.setdefault("basic", {})
CFG.setdefault("oauth", {})
CFG.setdefault("own_only_default", False)

try:
    import keyring  # type: ignore
    KEYRING_AVAILABLE = True
except Exception:
    KEYRING_AVAILABLE = False

SERVICE_NAME = "jira-stichwort-tool"

def set_secret(name: str, value: str):
    if KEYRING_AVAILABLE and CFG.get("secure", True):
        try:
            keyring.set_password(SERVICE_NAME, name, value or "")
            return True
        except Exception as e:
            st.warning(f"Keyring Fehler: {e}")
    return False

def get_secret(name: str) -> Optional[str]:
    if KEYRING_AVAILABLE and CFG.get("secure", True):
        try:
            return keyring.get_password(SERVICE_NAME, name)
        except Exception:
            return None
    return None

def del_secret(name: str):
    if KEYRING_AVAILABLE and CFG.get("secure", True):
        try:
            keyring.delete_password(SERVICE_NAME, name)
        except Exception:
            pass

# -------------------------------
# OAuth constants
# -------------------------------
AUTH_URL = "https://auth.atlassian.com/authorize"
TOKEN_URL = "https://auth.atlassian.com/oauth/token"
ACCESSIBLE_RESOURCES_URL = "https://api.atlassian.com/oauth/token/accessible-resources"
API_BASE_TEMPLATE = "https://api.atlassian.com/ex/jira/{cloudid}/rest/api/3"
DEFAULT_SCOPES = ["read:jira-work", "write:jira-work", "offline_access"]
DEFAULT_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI", "http://localhost:8501")
STATE_DIR = Path(".oauth_state"); STATE_DIR.mkdir(exist_ok=True)

def gen_pkce_pair():
    verifier_bytes = secrets.token_urlsafe(96)
    code_verifier = verifier_bytes[:128]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
    return code_verifier, challenge

def save_state(state: str, payload: Dict[str, Any]) -> None:
    with open(STATE_DIR / f"{state}.json", "w", encoding="utf-8") as f:
        json.dump(payload, f)

def load_state(state: str) -> Optional[Dict[str, Any]]:
    p = STATE_DIR / f"{state}.json"
    if p.exists():
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None

def delete_state(state: str) -> None:
    p = STATE_DIR / f"{state}.json"
    try:
        if p.exists():
            p.unlink()
    except Exception:
        pass

class JiraError(Exception): pass

# -------------------------------
# Jira Clients
# -------------------------------
class OAuthSession:
    def __init__(self, client_id: str, redirect_uri: str, scopes: List[str] = DEFAULT_SCOPES):
        self.client_id = client_id; self.redirect_uri = redirect_uri; self.scopes = scopes
        self.access_token = None; self.refresh_token = None; self.expires_at = 0.0
        self.cloudid = None; self.site_url = None
        self.code_verifier = None; self.oauth_state = None
        self.s = requests.Session(); self.s.headers.update({"Accept": "application/json"})

    def auth_url(self) -> str:
        self.code_verifier, code_challenge = gen_pkce_pair()
        self.oauth_state = secrets.token_urlsafe(24)
        params = dict(audience="api.atlassian.com", client_id=self.client_id,
                      scope=" ".join(self.scopes), redirect_uri=self.redirect_uri,
                      state=self.oauth_state, response_type="code", prompt="consent",
                      code_challenge=code_challenge, code_challenge_method="S256")
        save_state(self.oauth_state, {"client_id": self.client_id, "redirect_uri": self.redirect_uri,
                                      "scopes": self.scopes, "code_verifier": self.code_verifier, "created": now()})
        return f"{AUTH_URL}?{urlencode(params, quote_via=quote_plus)}"

    def exchange_code(self, code: str, state: str):
        if not self.code_verifier or not self.oauth_state or state != self.oauth_state:
            raise JiraError("Ungültiger OAuth-Status. Bitte erneut einloggen.")
        data = dict(grant_type="authorization_code", client_id=self.client_id, code=code,
                    redirect_uri=self.redirect_uri, code_verifier=self.code_verifier)
        r = self.s.post(TOKEN_URL, json=data, timeout=30)
        if r.status_code >= 400: raise JiraError(f"Token-Austausch fehlgeschlagen: {r.status_code} {r.text}")
        tok = r.json(); self.access_token = tok.get("access_token"); self.refresh_token = tok.get("refresh_token")
        self.expires_at = now() + tok.get("expires_in", 3600) - 30

    def refresh(self):
        if not self.refresh_token: raise JiraError("Kein Refresh-Token vorhanden.")
        data = dict(grant_type="refresh_token", client_id=self.client_id, refresh_token=self.refresh_token)
        r = self.s.post(TOKEN_URL, json=data, timeout=30)
        if r.status_code >= 400: raise JiraError(f"Token-Refresh fehlgeschlagen: {r.status_code} {r.text}")
        tok = r.json(); self.access_token = tok.get("access_token"); self.refresh_token = tok.get("refresh_token", self.refresh_token)
        self.expires_at = now() + tok.get("expires_in", 3600) - 30

    def ensure_token(self):
        if not self.access_token or now() >= self.expires_at: self.refresh()

    def bearer_headers(self):
        self.ensure_token()
        return {"Authorization": f"Bearer {self.access_token}", "Accept": "application/json", "Content-Type": "application/json"}

    def get_resources(self):
        self.ensure_token(); r = self.s.get(ACCESSIBLE_RESOURCES_URL, headers=self.bearer_headers(), timeout=30)
        if r.status_code >= 400: raise JiraError(f"Ressourcenabfrage fehlgeschlagen: {r.status_code} {r.text}")
        return r.json()

    def set_site(self, cloudid: str, site_url: str): self.cloudid = cloudid; self.site_url = site_url
    def api_base(self): 
        if not self.cloudid: raise JiraError("Keine Site ausgewählt.")
        return API_BASE_TEMPLATE.format(cloudid=self.cloudid)

    def api(self, method: str, path: str, params=None, data=None, return_headers=False):
        url = f"{self.api_base()}{path}"
        r = self.s.request(method, url, params=params, data=data, headers=self.bearer_headers(), timeout=60)
        if r.status_code == 401:
            self.refresh()
            r = self.s.request(method, url, params=params, data=data, headers=self.bearer_headers(), timeout=60)
        if return_headers:
            return r
        if r.status_code >= 400:
            try: detail = r.json()
            except Exception: detail = r.text
            raise JiraError(f"HTTP {r.status_code} für {path}: {detail}")
        try: return r.json()
        except Exception: return None

class JiraClientOAuth:
    def __init__(self, oauth: OAuthSession): self.oauth = oauth
    def get_myself(self): return self.oauth.api("GET", "/myself")
    def list_projects(self, only_led_by: Optional[str] = None) -> List[Dict[str, Any]]:
        start_at=0; max_results=50; out=[]
        while True:
            d=self.oauth.api("GET","/project/search", params={"expand":"lead","startAt":start_at,"maxResults":max_results})
            vals=d.get("values",[])
            for p in vals:
                if only_led_by:
                    if (p.get("lead") or {}).get("accountId")==only_led_by: out.append(p)
                else:
                    out.append(p)
            if start_at+max_results>=d.get("total",0): break
            start_at+=max_results
        return out
    def search_issues(self, jql: str, fields: List[str], batch_size=100):
        start_at=0; out=[]
        while True:
            payload={"jql":jql,"startAt":start_at,"maxResults":batch_size,"fields":fields}
            d=self.oauth.api("POST","/search", data=json.dumps(payload)); batch=d.get("issues",[]); out.extend(batch)
            if start_at+batch_size>=d.get("total",0): break
            start_at+=batch_size
        return out
    def update_issue_labels(self, issue_key: str, new_labels: List[str]):
        self.oauth.api("PUT", f"/issue/{issue_key}", data=json.dumps({"fields":{"labels":new_labels}}))
    def add_worklog(self, issue_key: str, started_iso: str, seconds: int, comment_text: str) -> str:
        d=self.oauth.api("POST", f"/issue/{issue_key}/worklog", data=json.dumps({
            "started": started_iso, "timeSpentSeconds": seconds, "comment": adf_comment(comment_text)
        })); return d.get("id")
    def list_worklogs(self, issue_key: str):
        out=[]; startAt=0; maxResults=100
        while True:
            d=self.oauth.api("GET", f"/issue/{issue_key}/worklog", params={"startAt": startAt, "maxResults": maxResults}) or {}
            out.extend(d.get("worklogs", []))
            if startAt + maxResults >= d.get("total", len(out)): break
            startAt += maxResults
        return {"worklogs": out}
    def delete_worklog(self, issue_key: str, worklog_id: str):
        self.oauth.api("DELETE", f"/issue/{issue_key}/worklog/{worklog_id}")
    def probe_headers(self):
        r = self.oauth.api("GET", "/myself", return_headers=True)
        return dict(r.headers), r.status_code

def normalize_base_url(url: str) -> str:
    url=(url or "").strip(); return url[:-1] if url.endswith("/") else url

class JiraClientBasic:
    def __init__(self, base_url: str, email: str, api_token: str, timeout=30):
        self.base_url = normalize_base_url(base_url); self.timeout=timeout
        self.s=requests.Session(); self.s.auth=(email, api_token)
        self.s.headers.update({"Accept":"application/json","Content-Type":"application/json"})
        self.email=email; self.api_token=api_token
    def _req(self, method, path, params=None, data=None, retries=3, return_headers=False):
        url=f"{self.base_url}{path}"
        for attempt in range(retries):
            r=self.s.request(method,url,params=params,data=data,timeout=self.timeout)
            if return_headers:
                return r
            if r.status_code in (429,502,503,504): time.sleep(1.5*(attempt+1)); continue
            if r.status_code>=400:
                try: detail=r.json()
                except Exception: detail=r.text
                raise JiraError(f"HTTP {r.status_code} für {path}: {detail}")
            try: return r.json()
            except Exception: return None
        raise JiraError(f"Failed after retries: {method} {path}")
    def get_myself(self): return self._req("GET","/rest/api/3/myself")
    def list_projects(self, only_led_by: Optional[str] = None) -> List[Dict[str, Any]]:
        start_at=0; max_results=50; out=[]
        while True:
            d=self._req("GET","/rest/api/3/project/search", params={"expand":"lead","startAt":start_at,"maxResults":max_results})
            vals=d.get("values",[])
            for p in vals:
                if only_led_by:
                    if (p.get("lead") or {}).get("accountId")==only_led_by: out.append(p)
                else:
                    out.append(p)
            if start_at+max_results>=d.get("total",0): break
            start_at+=max_results
        return out
    def search_issues(self, jql, fields, batch_size=100):
        start_at=0; out=[]
        while True:
            d=self._req("POST","/rest/api/3/search", data=json.dumps({"jql":jql,"startAt":start_at,"maxResults":batch_size,"fields":fields}))
            batch=d.get("issues",[]); out.extend(batch)
            if start_at+batch_size>=d.get("total",0): break
            start_at+=batch_size
        return out
    def update_issue_labels(self, issue_key, new_labels):
        self._req("PUT", f"/rest/api/3/issue/{issue_key}", data=json.dumps({"fields":{"labels":new_labels}}))
    def add_worklog(self, issue_key: str, started_iso: str, seconds: int, comment_text: str) -> str:
        d=self._req("POST", f"/rest/api/3/issue/{issue_key}/worklog", data=json.dumps({
            "started": started_iso, "timeSpentSeconds": seconds, "comment": adf_comment(comment_text)
        })); return d.get("id")
    def list_worklogs(self, issue_key: str):
        out=[]; startAt=0; maxResults=100
        while True:
            d=self._req("GET", f"/rest/api/3/issue/{issue_key}/worklog", params={"startAt": startAt, "maxResults": maxResults})
            out.extend(d.get("worklogs", []))
            if startAt + maxResults >= d.get("total", len(out)): break
            startAt += maxResults
        return {"worklogs": out}
    def delete_worklog(self, issue_key: str, worklog_id: str):
        self._req("DELETE", f"/rest/api/3/issue/{issue_key}/worklog/{worklog_id}")
    def probe_headers(self):
        r = self._req("GET", "/rest/api/3/myself", return_headers=True)
        return dict(r.headers), r.status_code

# -------------------------------
# Auth selection
# -------------------------------
st.title("Jira Stichwort-Zuordnung — PRO v3")
st.caption("Timesheet • Wochensumme • Sichere Secrets • Health-Check+ • Multi-Tab • Multi-Projekt")

auth_options = ["OAuth (3LO + PKCE)", "API Token (Basic)"]
CFG.setdefault("last_auth", "API Token (Basic)")
auth_method = st.sidebar.radio("Auth-Modus", auth_options, index=auth_options.index(CFG.get("last_auth","API Token (Basic)")))
CFG["last_auth"] = auth_method; save_cfg(CFG)

remember = st.sidebar.checkbox("Anmeldedaten lokal speichern (unsicher!)", value=CFG.get("remember", True))
secure = st.sidebar.checkbox("Secrets sicher speichern (Keyring)", value=CFG.get("secure", True) and KEYRING_AVAILABLE, help="Speichert API-Token/Refresh-Token verschlüsselt im Systemschlüsselbund")
CFG["secure"] = bool(secure and KEYRING_AVAILABLE); save_cfg(CFG)

st.sidebar.caption(f"Keyring verfügbar: {'Ja' if KEYRING_AVAILABLE else 'Nein'}")

for k in ["jira","myself","projects","resources","oauth","sidebar_collapsed","proj_choice","site_url","undo","timesheet"]:
    st.session_state.setdefault(k, None)

def persist_cfg(update: Dict[str, Any]):
    CFG.update(update); CFG["remember"]=remember; CFG["secure"]=bool(secure and KEYRING_AVAILABLE)
    if remember: save_cfg(CFG)

# OAuth path
DEFAULT_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI", "http://localhost:8501")
if auth_method == "OAuth (3LO + PKCE)":
    st.sidebar.header("OAuth Einstellungen")
    client_id = st.sidebar.text_input("Client ID", value=CFG.get("oauth", {}).get("client_id",""))
    redirect_uri = st.sidebar.text_input("Redirect URI", value=CFG.get("oauth", {}).get("redirect_uri", DEFAULT_REDIRECT_URI))

    c1,c2 = st.sidebar.columns(2)
    login_clicked = c1.button("Login")
    logout_clicked = c2.button("Logout")
    if logout_clicked:
        for k in ["oauth","jira","resources","projects","myself","site_url"]: st.session_state[k]=None
        CFG["oauth"] = {}; persist_cfg({}); st.rerun()

    try: qp = dict(st.query_params)
    except Exception: qp = st.experimental_get_query_params()

    if qp.get("code") and qp.get("state") and not st.session_state.get("oauth"):
        state_val = qp.get("state")[0] if isinstance(qp.get("state"), list) else qp.get("state")
        saved = load_state(state_val)
        if saved:
            restored = OAuthSession(saved["client_id"], saved["redirect_uri"], saved.get("scopes", DEFAULT_SCOPES))
            restored.code_verifier = saved.get("code_verifier"); restored.oauth_state = state_val
            st.session_state.oauth = restored; st.toast("OAuth-Status wiederhergestellt", icon="✅")

    if login_clicked:
        if not client_id: st.sidebar.error("Client ID fehlt.")
        else:
            oauth = OAuthSession(client_id, redirect_uri, DEFAULT_SCOPES); st.session_state.oauth = oauth
            auth_link = oauth.auth_url(); st.sidebar.markdown(f"[➡️ Login öffnen]({auth_link})")
            if remember:
                CFG.setdefault("oauth", {}); CFG["oauth"]["client_id"]=client_id; CFG["oauth"]["redirect_uri"]=redirect_uri; save_cfg(CFG)

    if qp.get("code") and qp.get("state") and st.session_state.get("oauth"):
        code = qp.get("code")[0] if isinstance(qp.get("code"), list) else qp.get("code")
        state = qp.get("state")[0] if isinstance(qp.get("state"), list) else qp.get("state")
        try:
            st.session_state.oauth.exchange_code(code, state); delete_state(state)
            try: st.query_params.clear()
            except Exception: st.experimental_set_query_params()
            st.success("✅ OAuth erfolgreich.")
            if CFG.get("secure", False):
                set_secret("oauth_refresh_token", st.session_state.oauth.refresh_token or "")
        except JiraError as e: st.error(str(e))

    oauth = st.session_state.get("oauth")
    if not oauth or not oauth.access_token: st.info("➡️ Bitte anmelden."); st.stop()
    if not st.session_state.get("resources"):
        try: st.session_state.resources = oauth.get_resources()
        except JiraError as e: st.error(str(e)); st.stop()
    resources = st.session_state.resources or []
    if not resources: st.error("Keine Jira-Sites."); st.stop()

    site_labels=[f"{r.get('name')} — {r.get('url')}" for r in resources]
    site_choice = st.selectbox("Jira Site", site_labels, index=0, key="site_select")
    site = resources[site_labels.index(site_choice)]
    oauth.set_site(site.get("id"), site.get("url")); st.session_state.site_url = site.get("url")

    jira = JiraClientOAuth(oauth); st.session_state.jira=jira
    try:
        me = jira.get_myself(); st.session_state.myself = me
        st.success(f"Verbunden als: {me.get('displayName')}"); st.session_state.sidebar_collapsed=True
    except JiraError as e: st.error(f"Verbindungsfehler: {e}"); st.stop()

# Basic path
else:
    st.sidebar.header("API Token Einstellungen")
    base_url = st.sidebar.text_input("Jira Base-URL", value=CFG.get("basic", {}).get("base_url",""))
    email = st.sidebar.text_input("E-Mail", value=CFG.get("basic", {}).get("email",""))
    token_secret_name = f"basic_token::{email}@{base_url}"
    token_cached = get_secret(token_secret_name) if email and base_url else None
    token_placeholder = "(im Schlüsselbund gespeichert)" if token_cached else ""
    api_token = st.sidebar.text_input("API Token", type="password",
                                      value=token_placeholder if token_cached and CFG.get("secure", False) else CFG.get("basic", {}).get("api_token",""))
    c1,c2,c3 = st.sidebar.columns([1,1,1])
    connect = c1.button("Verbinden"); logout = c2.button("Logout")
    clear_secret = c3.button("Secret löschen")
    if clear_secret and token_cached:
        del_secret(token_secret_name); st.sidebar.success("Secret im Schlüsselbund gelöscht.")

    if logout:
        for k in ["jira","myself","projects","site_url"]: st.session_state[k]=None
        CFG["basic"]={}; persist_cfg({}); st.rerun()
    if connect:
        token_to_use = token_cached if (token_cached and CFG.get("secure", False) and api_token==token_placeholder) else api_token
        try:
            jira=JiraClientBasic(base_url,email,token_to_use); me=jira.get_myself()
            st.session_state.jira=jira; st.session_state.myself=me; st.session_state.site_url=base_url
            st.success(f"Verbunden als: {me.get('displayName')}"); st.session_state.sidebar_collapsed=True
            to_cfg = {"base_url":base_url,"email":email}
            if CFG.get("secure", False):
                set_secret(token_secret_name, token_to_use); to_cfg["api_token"] = ""
            else:
                to_cfg["api_token"] = token_to_use
            CFG["basic"]=to_cfg; save_cfg(CFG)
        except Exception as e: st.error(f"Verbindungsfehler: {e}"); st.stop()
    jira=st.session_state.get("jira"); me=st.session_state.get("myself")
    if not jira or not me: st.info("➡️ Zugangsdaten eintragen und **Verbinden**."); st.stop()

# Sidebar collapse logic
if st.session_state.get("myself") and st.session_state.get("sidebar_collapsed", False):
    hide_sidebar_css()
    if st.button("⚙️ Einstellungen anzeigen"):
        st.session_state.sidebar_collapsed=False; st.rerun()
else:
    st.sidebar.button("↩︎ Sidebar einklappen", on_click=lambda: (st.session_state.update({"sidebar_collapsed": True}), st.rerun()))

jira = st.session_state.get("jira"); me = st.session_state.get("myself"); site_url = st.session_state.get("site_url","")

# -------------------------------
# Data fetch
# -------------------------------
@st.cache_data(show_spinner=False, ttl=120)
def fetch_issues_df(_jira_client, project_keys: List[str], site_url: str) -> pd.DataFrame:
    if isinstance(project_keys, str): project_keys=[project_keys]
    if not project_keys:
        return pd.DataFrame(columns=["Project","Key","Ticket","Summary","Status","P_Label_Aktuell","Alle_Labels"])
    quoted = ",".join([f'"{k}"' for k in project_keys])
    jql = f'project in ({quoted}) AND statusCategory != Done ORDER BY created DESC'
    fields = ["summary", "status", "labels", "project"]
    issues = _jira_client.search_issues(jql, fields)
    rows=[]
    for it in issues:
        key=it.get("key"); f=it.get("fields",{})
        proj=(f.get("project") or {}).get("key","")
        summary=f.get("summary",""); status=(f.get("status") or {}).get("name",""); labels=f.get("labels") or []
        p_label=extract_p_label(labels); link=f"{site_url}/browse/{key}" if site_url else ""
        rows.append({"Project":proj,"Key":key,"Ticket":link,"Summary":summary,"Status":status,
                     "P_Label_Aktuell":p_label or "", "Alle_Labels": ", ".join(labels) if labels else ""})
    return pd.DataFrame(rows)

def refresh_after_update():
    fetch_issues_df.clear(); st.experimental_set_query_params(_=str(time.time())); st.rerun()

# -------------------------------
# Projects list
# -------------------------------
own_only = st.toggle("Nur Projekte, bei denen ich Lead bin", value=CFG.get("own_only_default", False), key="own_only_toggle")
CFG["own_only_default"]=own_only; save_cfg(CFG)

with st.spinner("Lade Projekte…"):
    projs = jira.list_projects(me.get("accountId") if own_only else None)
    if own_only and not projs:
        st.info("Keine Projekte mit dir als Lead gefunden – zeige stattdessen alle Projekte.")
        projs = jira.list_projects(None)
    projects = sorted(projs, key=lambda p: p.get("key",""))

if not projects:
    st.warning("Keine Projekte gefunden. Tabs werden dennoch angezeigt; bitte Filter prüfen.")

proj_map = {p.get("key"): p for p in projects}
proj_labels = [f"{p.get('key')} — {p.get('name')}" for p in projects]
proj_key_by_label = {f"{p.get('key')} — {p.get('name')}": p.get("key") for p in projects}

multi = st.toggle("Multi-Projekt-Modus", value=False, help="Mehrere Projekte gleichzeitig anzeigen/bearbeiten", key="multi_proj")
if multi:
    default_sel = proj_labels[:1]
    selected_labels = st.multiselect("Projekte auswählen", proj_labels, default=default_sel, key="proj_multi")
    selected_keys = [proj_key_by_label.get(l) for l in selected_labels] if selected_labels else []
else:
    if proj_labels:
        selected_label = st.selectbox("Projekt auswählen", proj_labels, index=0, key="proj_single")
        selected_keys = [proj_key_by_label[selected_label]]
    else:
        selected_label = None
        selected_keys = []

st.markdown("—")

df = fetch_issues_df(jira, selected_keys, site_url)

# -------------------------------
# Tabs
# -------------------------------
tab_overview, tab_plabel, tab_worklog, tab_csv, tab_reports, tab_timesheet, tab_health = st.tabs(
    ["📋 Übersicht", "🏷️ P-Labels", "⏱️ Worklog (Einzeln)", "📥 CSV-Import", "📊 Reports & Export", "🗓️ Timesheet", "🩺 Health-Check+"]
)

# -------------------------------- OVERVIEW
with tab_overview:
    st.subheader("Übersicht & Filter")
    colf1, colf2, colf3, colf4 = st.columns([2,1,1,1])
    with colf1:
        q = st.text_input("Suche (Key/Summary)", "", key="ov_q")
    with colf2:
        status_vals = sorted(df["Status"].unique().tolist()) if not df.empty else []
        chosen_status = st.multiselect("Status-Filter", status_vals, default=[], key="ov_status")
    with colf3:
        only_missing = st.toggle("Nur ohne P-Label", value=False, key="ov_only_missing")
    with colf4:
        proj_filter = st.multiselect("Projektfilter", sorted(df["Project"].unique().tolist()), default=sorted(df["Project"].unique().tolist()), key="ov_proj_filter")

    df_view = df.copy()
    if q:
        ql = q.lower()
        df_view = df_view[df_view["Summary"].str.lower().str.contains(ql) | df_view["Key"].str.lower().str.contains(ql)]
    if chosen_status:
        df_view = df_view[df_view["Status"].isin(chosen_status)]
    if only_missing:
        df_view = df_view[df_view["P_Label_Aktuell"] == ""]
    if proj_filter:
        df_view = df_view[df_view["Project"].isin(proj_filter)]

    c1, c2, c3, c4 = st.columns([1,1,1,2])
    with c1: st.metric("Tickets", len(df_view))
    with c2: st.metric("Mit P-Label", int((df_view["P_Label_Aktuell"]!="").sum()) if not df_view.empty else 0)
    with c3: st.metric("Ohne P-Label", int((df_view["P_Label_Aktuell"]=="").sum()) if not df_view.empty else 0)
    with c4:
        existing_ps = [x for x in df_view["P_Label_Aktuell"].tolist() if x]
        suggested_p = Counter(existing_ps).most_common(1)[0][0] if existing_ps else ""
        st.write("Empf. Projektnummer:", f"`{suggested_p or '—'}`")

    st.dataframe(
        df_view,
        use_container_width=True, hide_index=True,
        column_config={
            "Ticket": st.column_config.LinkColumn("Ticket öffnen", display_text="Open"),
            "Project": st.column_config.TextColumn("Projekt"),
            "Key": st.column_config.TextColumn("Key"),
            "Summary": st.column_config.TextColumn("Summary"),
            "Status": st.column_config.TextColumn("Status"),
            "P_Label_Aktuell": st.column_config.TextColumn("P-Label"),
            "Alle_Labels": st.column_config.TextColumn("Alle Labels"),
        }
    )

    st.markdown("### Schnellaktionen")
    colqa1, colqa2, colqa3 = st.columns([3,2,2])
    with colqa1:
        qa_key = st.selectbox("Ticket", df_view["Key"].tolist() if not df_view.empty else [], key="qa_key_select")
    with colqa2:
        qa_start = st.time_input("Startzeit", value=datetime.now().time().replace(second=0, microsecond=0), key="qa_start_time")
    with colqa3:
        qa_date = st.date_input("Datum", value=datetime.now().date(), key="qa_date")

    tpl = ""
    if not df_view.empty and qa_key:
        proj_of_issue = df_view.loc[df_view["Key"]==qa_key, "Project"].iloc[0]
        tpl = CFG["templates"].get(proj_of_issue, "")
        p_val = df_view.loc[df_view["Key"]==qa_key,"P_Label_Aktuell"].iloc[0]
        summary = df_view.loc[df_view["Key"]==qa_key,"Summary"].iloc[0]
        qa_desc = fill_template(tpl, p_val, qa_key, summary, qa_date)
    else:
        qa_desc = ""

    st.text_area("Beschreibung (Template anwendbar)", value=qa_desc, key="qa_desc", height=80)

    cqa1, cqa2, cqa3 = st.columns(3)
    def quick_add(minutes: int):
        seconds = minutes * 60
        if not ensure_15min(seconds):
            st.error("Nur Vielfaches von 15 min erlaubt."); return
        if not qa_key:
            st.error("Ticket wählen."); return
        started_iso = to_started_iso(qa_date, qa_start)
        try:
            wid = jira.add_worklog(qa_key, started_iso, seconds, st.session_state.get("qa_desc",""))
            st.session_state.undo = {"type":"worklogs","data":[(qa_key, wid)]}
            st.success(f"+{minutes}m auf {qa_key} erfasst.")
        except Exception as e:
            st.error(f"Fehler: {e}")
    with cqa1:
        if st.button("+15m", key="qa15"): quick_add(15)
    with cqa2:
        if st.button("+30m", key="qa30"): quick_add(30)
    with cqa3:
        if st.button("+1h", key="qa60"): quick_add(60)

# -------------------------------- P-LABELS
with tab_plabel:
    st.subheader("P-Label Zuweisung & Templates")
    if not multi and selected_keys:
        pk = selected_keys[0]
        st.markdown("**Beschreibung-Template (optional, pro Projekt)**")
        st.caption("Platzhalter: {P} {ISSUE} {DATE} {SUMMARY}")
        tpl_cur = CFG["templates"].get(pk, "")
        tpl_new = st.text_area(f"Template für {pk}", value=tpl_cur, key=f"tpl_{pk}", height=100, placeholder="z.B. {P} | {ISSUE} – {SUMMARY}")
        if st.button("Template speichern", key="tpl_save"):
            CFG["templates"][pk] = tpl_new; save_cfg(CFG); st.success("Template gespeichert.")

    dry_run_labels = st.checkbox("Nur validieren (Dry-Run) für P-Label-Änderungen", value=True, key="labels_dryrun")

    df_scope = df if multi else (df[df["Project"]==selected_keys[0]] if selected_keys else df)

    keys_all = df_scope["Key"].tolist()
    keys_without = df_scope.loc[df_scope["P_Label_Aktuell"]=="","Key"].tolist()
    p_suggest = CFG["defaults"].get(selected_keys[0],"") if (not multi and selected_keys) else ""

    colb1, colb2 = st.columns([2,1])
    with colb1:
        p_number = st.text_input("Projektnummer (PXXXXXX)", value=p_suggest, key="pl_p_number")
    with colb2:
        keys_select = st.multiselect("Auswahl Tickets", keys_all, default=keys_without, key="pl_keys_select")

    def build_label_preview(target_keys: List[str], new_p: str) -> pd.DataFrame:
        rows=[]
        for k in target_keys:
            r = df_scope.loc[df_scope["Key"]==k].iloc[0]
            old_labels = [l.strip() for l in (r["Alle_Labels"].split(",") if r["Alle_Labels"] else []) if l.strip()]
            base = [l for l in old_labels if not is_p_label(l)]
            new_labels = base + ([new_p] if new_p else [])
            changed = set(old_labels) != set(new_labels)
            rows.append({"Key":k,"Alt":", ".join(old_labels),"Neu":", ".join(new_labels),"Ändert sich?": "Ja" if changed else "Nein"})
        return pd.DataFrame(rows)

    colbb1, colbb2 = st.columns([1,1])
    with colbb1:
        if st.button("Allen in Ansicht zuweisen", key="pl_all"):
            target_keys = keys_all
            if not p_number or not is_p_label(p_number): st.error("Ungültige P-Nummer.")
            else:
                if dry_run_labels:
                    st.info("Dry-Run aktiv – Vorschau:")
                    st.dataframe(build_label_preview(target_keys, p_number), use_container_width=True, hide_index=True)
                else:
                    prev = {}
                    for k in target_keys:
                        r = df_scope.loc[df_scope["Key"]==k].iloc[0]
                        prev[k] = [l.strip() for l in (r["Alle_Labels"].split(",") if r["Alle_Labels"] else []) if l.strip()]
                        base = [l for l in prev[k] if not is_p_label(l)]
                        new_labels = base + [p_number]
                        try: jira.update_issue_labels(k, new_labels)
                        except Exception as e: st.error(f"{k}: {e}")
                    st.session_state.undo = {"type":"labels","data":prev}
                    st.success(f"P {p_number} auf {len(target_keys)} Tickets angewandt."); refresh_after_update()
    with colbb2:
        if st.button("Nur AUSWAHL zuweisen", key="pl_sel"):
            target_keys = keys_select
            if not target_keys: st.info("Keine Auswahl.")
            elif not p_number or not is_p_label(p_number): st.error("Ungültige P-Nummer.")
            else:
                if dry_run_labels:
                    st.info("Dry-Run aktiv – Vorschau:")
                    st.dataframe(build_label_preview(target_keys, p_number), use_container_width=True, hide_index=True)
                else:
                    prev={}
                    for k in target_keys:
                        r=df_scope.loc[df_scope["Key"]==k].iloc[0]
                        prev[k]=[l.strip() for l in (r["Alle_Labels"].split(",") if r["Alle_Labels"] else []) if l.strip()]
                        new_labels=[l for l in prev[k] if not is_p_label(l)] + [p_number]
                        try: jira.update_issue_labels(k, new_labels)
                        except Exception as e: st.error(f"{k}: {e}")
                    st.session_state.undo={"type":"labels","data":prev}
                    st.success(f"P {p_number} auf {len(target_keys)} Tickets angewandt."); refresh_after_update()

    st.markdown("**Tabellenbearbeitung**")
    edit_df = df_scope.copy(); edit_df["Neue_P"] = ""
    edited = st.data_editor(
        edit_df, use_container_width=True, hide_index=True,
        column_config={
            "Ticket": st.column_config.LinkColumn("Ticket öffnen", display_text="Open"),
            "Project": st.column_config.TextColumn("Projekt"),
            "Key": st.column_config.TextColumn(disabled=True),
            "Summary": st.column_config.TextColumn(disabled=True),
            "Status": st.column_config.TextColumn(disabled=True),
            "P_Label_Aktuell": st.column_config.TextColumn(disabled=True, label="P-Label aktuell"),
            "Alle_Labels": st.column_config.TextColumn(disabled=True),
            "Neue_P": st.column_config.TextColumn(help="Format PXXXXXX; leer = keine Änderung"),
        },
        num_rows="fixed",
        disabled=["Key","Summary","Status","P_Label_Aktuell","Alle_Labels"],
        key="pl_table_editor"
    )
    if st.button("Änderungen übernehmen", key="pl_apply_edits"):
        updates=[]; prev={}
        for _, r in edited.iterrows():
            np=(r.get("Neue_P") or "").strip()
            if np:
                if not is_p_label(np): st.error(f"{r['Key']}: Ungültige P '{np}'."); st.stop()
                updates.append((r["Key"], np))
                prev[r["Key"]] = [l.strip() for l in (r["Alle_Labels"].split(",") if r["Alle_Labels"] else []) if l.strip()]
        if not updates: st.info("Keine Änderungen.")
        else:
            for k,pv in updates:
                base=[l for l in prev[k] if not is_p_label(l)]
                try: jira.update_issue_labels(k, base+[pv])
                except Exception as e: st.error(f"{k}: {e}")
            st.session_state.undo={"type":"labels","data":prev}
            st.success(f"{len(updates)} Ticket(s) aktualisiert."); refresh_after_update()

# -------------------------------- WORKLOG SINGLE
with tab_worklog:
    st.subheader("Worklog (Einzel)")
    csel1, csel2 = st.columns([2,1])
    issue_choice = csel1.selectbox("Ticket (aus Liste)", df["Key"].tolist() if not df.empty else [], key="wl_key_select")
    issue_direct = csel2.text_input("Oder Key direkt (z.B. PROJ-123)", value="", key="wl_key_direct")

    use_key = issue_direct.strip() or issue_choice

    c1,c2 = st.columns(2)
    with c1: work_date = st.date_input("Datum", value=datetime.now().date(), key="wl_date")
    with c2: start_time = st.time_input("Startzeit", value=datetime.now().time().replace(second=0, microsecond=0), key="wl_start_time")
    cc1,cc2 = st.columns([1,1])
    with cc1: hours = st.number_input("Stunden", min_value=0, max_value=24, step=1, value=0, key="wl_hours")
    with cc2: minutes = st.selectbox("Minuten", [0,15,30,45], index=1, key="wl_minutes")

    tmpl_val=""
    if use_key:
        try:
            row = df[df["Key"]==use_key].iloc[0]
            pk=row["Project"]; p_val=row["P_Label_Aktuell"]; summ=row["Summary"]
        except Exception:
            pk = selected_keys[0] if selected_keys else ""
            p_val=""; summ=""
        tmpl_val = fill_template(CFG["templates"].get(pk,""), p_val, use_key, summ, work_date)

    desc = st.text_area("Tätigkeitsbeschreibung", value=tmpl_val, placeholder="Was wurde gemacht?", key="wl_desc")

    if st.button("Zeit erfassen", key="wl_submit"):
        seconds = int(hours)*3600 + int(minutes)*60
        if not ensure_15min(seconds): st.error("Dauer muss Vielfaches von 15min sein und >0.")
        elif not use_key: st.error("Ticket-Key angeben.")
        else:
            started_iso = to_started_iso(work_date, start_time)
            try:
                wid = jira.add_worklog(use_key, started_iso, seconds, desc)
                st.session_state.undo = {"type":"worklogs","data":[(use_key, wid)]}
                st.success(f"Worklog für {use_key} erfasst.")
            except Exception as e: st.error(f"Fehler: {e}")

# -------------------------------- CSV IMPORT
with tab_csv:
    st.subheader("CSV-Import Zeiterfassung")
    st.caption("Spalten: **Ticketnummer;Datum;benötigte Zeit in h** | optional: **Uhrzeit, Beschreibung** | Dezimal: `.` oder `,`")
    sample = "Ticketnummer;Datum;benötigte Zeit in h;Uhrzeit;Beschreibung\nPROJ-101;21.08.2025;0,25;12:30;Daily Standup\nPROJ-202;21.08.2025;1.5;09:00;Konzept & Abstimmung\n"
    st.download_button("Beispiel-CSV herunterladen", data=sample.encode("utf-8"), file_name="worklog_beispiel.csv", mime="text/csv", key="csv_sample")
    default_desc = st.text_input("Standardbeschreibung (optional, wenn CSV keine Spalte 'Beschreibung' enthält)", key="csv_default_desc")
    dry_run = st.checkbox("Nur validieren (Dry-Run)", value=True, key="csv_dryrun")
    uploaded = st.file_uploader("CSV hochladen", type=["csv"], key="csv_upload")

    if uploaded is not None:
        content = uploaded.read().decode("utf-8-sig")
        try: df_csv = pd.read_csv(io.StringIO(content), sep=None, engine="python")
        except Exception: df_csv = pd.read_csv(io.StringIO(content), sep=";")

        cols = {c.lower().strip(): c for c in df_csv.columns}
        def find_col(*names):
            for n in names:
                if n in cols: return cols[n]
            return None

        col_ticket = find_col("ticketnummer","ticket","issue","key")
        col_date = find_col("datum","date")
        col_hours = find_col("benötigte zeit in h","benoetigte zeit in h","hours","dauer(h)","zeit(h)")
        col_time = find_col("uhrzeit","zeit","startzeit")
        col_desc = find_col("beschreibung","description","kommentar")

        if not (col_ticket and col_date and col_hours):
            st.error("Pflichtspalten fehlen. Erwartet: Ticketnummer; Datum; benötigte Zeit in h")
        else:
            preview_rows=[]; errors=[]
            for idx, r in df_csv.iterrows():
                key=str(r[col_ticket]).strip()
                try: d = pd.to_datetime(str(r[col_date]), dayfirst=True).date()
                except Exception: errors.append(f"Zeile {idx+1}: Ungültiges Datum '{r[col_date]}'"); continue
                raw_hours = str(r[col_hours]).replace(",", ".").strip()
                try: h_float = float(raw_hours)
                except Exception: errors.append(f"{key}: Ungültige Stunden '{raw_hours}'"); continue
                seconds = int(round(h_float*3600))
                if seconds % 900 != 0: errors.append(f"{key}: {h_float}h ist kein Vielfaches von 15 min"); continue
                if col_time and not pd.isna(r[col_time]):
                    try: parsed_time = pd.to_datetime(str(r[col_time])).time()
                    except Exception: parsed_time = dtime(12,0)
                else: parsed_time = dtime(12,0)
                desc_val = ""
                if col_desc and not pd.isna(r[col_desc]): desc_val = str(r[col_desc]).strip()
                elif default_desc: desc_val = default_desc
                if not desc_val and not df.empty:
                    try:
                        proj = df[df["Key"]==key]["Project"].iloc[0]
                        p_val = df[df["Key"]==key]["P_Label_Aktuell"].iloc[0]
                        summ = df[df["Key"]==key]["Summary"].iloc[0]
                        desc_val = fill_template(CFG["templates"].get(proj,""), p_val, key, summ, d) or ""
                    except Exception:
                        pass
                preview_rows.append({"Ticket":key,"Datum":d.isoformat(),"Startzeit":parsed_time.strftime("%H:%M"),
                                     "Dauer (min)":seconds//60,"Beschreibung":desc_val or "(leer)"})
            st.write("**Vorschau**")
            df_prev = pd.DataFrame(preview_rows)
            st.dataframe(df_prev, use_container_width=True, hide_index=True)
            if errors:
                with st.expander("Fehler in CSV"):
                    for e in errors: st.write("• " + e)
            if preview_rows and st.button("Import starten", key="csv_import_btn"):
                if dry_run:
                    st.info("Dry-Run aktiv – keine Daten geschrieben.")
                else:
                    ok=0; errs=[]; created=[]
                    prog=st.progress(0.0, text="Übertrage…")
                    for i,row in enumerate(preview_rows, start=1):
                        try:
                            started_iso = to_started_iso(pd.to_datetime(row["Datum"]).date(),
                                                         datetime.strptime(row["Startzeit"], "%H:%M").time())
                            wid = jira.add_worklog(row["Ticket"], started_iso, int(row["Dauer (min)"])*60,
                                                   None if row["Beschreibung"]=="(leer)" else row["Beschreibung"])
                            created.append((row["Ticket"], wid)); ok+=1
                        except Exception as e: errs.append(f"{row['Ticket']}: {e}")
                        prog.progress(i/len(preview_rows), text=f"Übertrage… ({i}/{len(preview_rows)})")
                    prog.empty()
                    st.success(f"Import: {ok}/{len(preview_rows)} Worklogs erstellt.")
                    if errs:
                        with st.expander("Fehlerdetails"):
                            for e in errs: st.write(e)
                    if created:
                        st.session_state.undo={"type":"worklogs","data":created}

# -------------------------------- REPORTS & EXPORT
with tab_reports:
    st.subheader("Reports & Export")
    colr1, colr2 = st.columns(2)
    with colr1:
        st.markdown("**Tickets ohne P-Label (aktuelle Auswahl)**")
        df_missing = df[df["P_Label_Aktuell"]==""]
        st.dataframe(df_missing[["Project","Key","Summary","Status"]], use_container_width=True, hide_index=True)

    with colr2:
        st.markdown("**Export Übersicht**")
        csv_bytes = df.to_csv(index=False).encode("utf-8")
        st.download_button("CSV herunterladen", data=csv_bytes, file_name="tickets_uebersicht.csv", mime="text/csv", key="rep_csv")
        try:
            buf = io.BytesIO()
            with pd.ExcelWriter(buf, engine="openpyxl") as writer:
                df.to_excel(writer, index=False, sheet_name="Tickets")
            st.download_button("Excel herunterladen", data=buf.getvalue(), file_name="tickets_uebersicht.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", key="rep_xlsx")
        except Exception as e:
            st.caption(f"Excel-Export nicht verfügbar: {e}")

# -------------------------------- TIMESHEET (Weekly)
with tab_timesheet:
    st.subheader("Wochenansicht / Timesheet")
    today = datetime.now().date()
    colts1, colts2, colts3, colts4 = st.columns([2,1,1,2])
    with colts1:
        wk_date = st.date_input("Woche auswählen (beliebiges Datum der Woche)", value=today, key="ts_date")
    with colts2:
        if st.button("‹ Vorwoche", key="ts_prev"):
            st.session_state.ts_date = wk_date - timedelta(days=7)
            st.rerun()
    with colts3:
        if st.button("Nächste Woche ›", key="ts_next"):
            st.session_state.ts_date = wk_date + timedelta(days=7)
            st.rerun()
    with colts4:
        mine_only = st.toggle("Nur eigene Worklogs", value=True, key="ts_mine")

    week_start, week_end = week_bounds_from(wk_date)
    st.caption(f"Kalenderwoche: {week_start.isoformat()} bis { (week_end - timedelta(days=1)).isoformat()}")

    if st.button("Zeiten laden", key="ts_load"):
        keys = df["Key"].tolist()
        logs=[]; errs=[]
        prog = st.progress(0.0, text="Lade Worklogs…")
        for i,k in enumerate(keys, start=1):
            try:
                wl = jira.list_worklogs(k) or {}
                for w in wl.get("worklogs", []):
                    started = pd.to_datetime(w.get("started"))
                    if started.tzinfo is None: started = started.tz_localize("UTC").astimezone()
                    started_date = started.date()
                    if week_start <= started_date < week_end:
                        author_id = (w.get("author") or {}).get("accountId","")
                        if (not mine_only) or (author_id == me.get("accountId")):
                            logs.append({
                                "Key": k,
                                "AuthorId": author_id,
                                "Date": started_date,
                                "Minutes": int(w.get("timeSpentSeconds",0))//60,
                            })
            except Exception as e:
                errs.append(f"{k}: {e}")
            prog.progress(i/max(len(keys),1), text=f"Lade Worklogs… ({i}/{len(keys)})")
        prog.empty()
        st.session_state.timesheet = {"logs": logs, "errors": errs, "week_start": week_start.isoformat(), "week_end": week_end.isoformat(), "mine": mine_only}

    ts = st.session_state.get("timesheet")
    if ts and ts.get("week_start")==week_start.isoformat() and ts.get("mine")==mine_only:
        logs = ts["logs"]; errs = ts["errors"]
        if errs:
            with st.expander("Fehler beim Laden"):
                for e in errs: st.write(e)

        days = [week_start + timedelta(days=i) for i in range(7)]
        day_cols = [d.strftime("%a\n%d.%m") for d in days]
        by_issue = {}
        for log in logs:
            k = log["Key"]; d = log["Date"]; m = log["Minutes"]
            by_issue.setdefault(k, {dc:0 for dc in day_cols})
            col = d.strftime("%a\n%d.%m")
            by_issue[k][col] = by_issue[k].get(col,0) + m
        rows=[]
        for k, cols in by_issue.items():
            row = {"Ticket": k}
            total_min = 0
            for dc in day_cols:
                mins = cols.get(dc,0)
                total_min += mins
                row[dc] = round(mins/60, 2)
            row["Summe (h)"] = round(total_min/60, 2)
            rows.append(row)
        df_ts = pd.DataFrame(rows) if rows else pd.DataFrame(columns=["Ticket"]+day_cols+["Summe (h)"])
        totals = {"Ticket": "Σ"}
        week_total_min = 0
        for dc, d in zip(day_cols, days):
            m = sum([log["Minutes"] for log in logs if log["Date"]==d])
            totals[dc] = round(m/60,2); week_total_min += m
        totals["Summe (h)"] = round(week_total_min/60,2)
        df_ts = pd.concat([df_ts, pd.DataFrame([totals])], ignore_index=True)

        cts1, cts2 = st.columns([1,3])
        with cts1: st.metric("Wochensumme (h)", totals["Summe (h)"])
        with cts2: st.caption("Letzte Zeile: Tagessummen & Wochensumme")

        st.dataframe(df_ts, use_container_width=True, hide_index=True)

        out_csv = df_ts.to_csv(index=False).encode("utf-8")
        st.download_button("Timesheet (CSV) herunterladen", data=out_csv, file_name=f"timesheet_{week_start.isoformat()}.csv", mime="text/csv", key="ts_export_csv")

        st.markdown("#### Schnell buchen in dieser Woche")
        coladd1, coladd2, coladd3, coladd4 = st.columns([2,1,1,2])
        with coladd1:
            add_key = st.selectbox("Ticket", df["Key"].tolist(), key="ts_add_key")
        with coladd2:
            add_day = st.selectbox("Tag", day_cols, key="ts_add_day")
        with coladd3:
            add_minutes = st.selectbox("Dauer (min)", [15,30,45,60,90,120,180,240], index=0, key="ts_add_min")
        with coladd4:
            add_start = st.time_input("Startzeit", value=datetime.now().time().replace(second=0, microsecond=0), key="ts_add_start")

        add_desc_default = ""
        try:
            row_issue = df[df["Key"]==add_key].iloc[0]
            pk=row_issue["Project"]; p_val=row_issue["P_Label_Aktuell"]; summ=row_issue["Summary"]
            day_dt = datetime.strptime(add_day.split("\n")[1], "%d.%m").replace(year=week_start.year).date()
            add_desc_default = fill_template(CFG["templates"].get(pk,""), p_val, add_key, summ, day_dt)
        except Exception:
            pass
        add_desc = st.text_area("Beschreibung", value=add_desc_default, key="ts_add_desc")

        if st.button("In Woche buchen", key="ts_add_btn"):
            seconds = int(add_minutes)*60
            sel_day = days[day_cols.index(add_day)]
            started_iso = to_started_iso(sel_day, add_start)
            try:
                wid = jira.add_worklog(add_key, started_iso, seconds, add_desc)
                st.session_state.undo = {"type":"worklogs","data":[(add_key, wid)]}
                st.success(f"{add_key}: {add_minutes} min am {sel_day.isoformat()} gebucht.")
            except Exception as e:
                st.error(f"Fehler: {e}")

# -------------------------------- HEALTH-CHECK+
with tab_health:
    st.subheader("Health-Check+")
    ok_msgs = []; warn_msgs = []; err_msgs = []
    def timed(fn, *args, **kwargs):
        t0=time.time()
        try:
            res=fn(*args, **kwargs)
            return time.time()-t0, res, None
        except Exception as e:
            return time.time()-t0, None, e

    t_myself, _, e1 = timed(jira.get_myself)
    if e1: err_msgs.append(f"/myself fehlgeschlagen: {e1}")
    else: ok_msgs.append(f"/myself ok ({t_myself*1000:.0f} ms)")

    t_proj, _, e2 = timed(jira.list_projects, None)
    if e2: err_msgs.append(f"/project/search fehlgeschlagen: {e2}")
    else: ok_msgs.append(f"/project/search ok ({t_proj*1000:.0f} ms)")

    try:
        if isinstance(jira, JiraClientOAuth):
            perms = jira.oauth.api("GET", "/mypermissions", params={"permissions": "WORKLOGS_ADD,WORKLOGS_EDIT,EDIT_ISSUES"})
        else:
            perms = jira._req("GET", "/rest/api/3/mypermissions", params={"permissions":"WORKLOGS_ADD,WORKLOGS_EDIT,EDIT_ISSUES"})
        granted = [k for k,v in (perms.get("permissions") or {}).items() if v.get("havePermission")]
        ok_msgs.append("Permissions: " + (", ".join(granted) if granted else "keine relevanten Rechte"))
        if "WORKLOGS_ADD" not in granted:
            warn_msgs.append("Keine Berechtigung zum Hinzufügen von Worklogs (WORKLOGS_ADD).")
    except Exception as e:
        warn_msgs.append(f"Permissions-Check fehlgeschlagen: {e}")

    try:
        headers, status = jira.probe_headers()
        rl = headers.get("X-RateLimit-Remaining") or headers.get("x-ratelimit-remaining") or "n/a"
        stime = headers.get("Date")
        skew="n/a"
        if stime:
            try:
                server_dt = pd.to_datetime(stime).to_pydatetime()
                local_dt = datetime.utcnow()
                skew = f"{abs((server_dt - local_dt).total_seconds()):.0f}s"
            except Exception:
                pass
        ok_msgs.append(f"Headers ok (Status {status}). RateLimit-Remaining: {rl}, Clock Skew ~ {skew}")
    except Exception as e:
        warn_msgs.append(f"Header-Check nicht möglich: {e}")

    if isinstance(jira, JiraClientOAuth):
        try:
            expires_in = int(st.session_state.oauth.expires_at - now())
            warn_msgs.append(f"OAuth-Token läuft in ~{max(expires_in,0)}s ab.")
        except Exception:
            pass

    st.caption(f"Keyring aktiv: {'Ja' if (KEYRING_AVAILABLE and CFG.get('secure', False)) else 'Nein'}")
    if ok_msgs:
        st.success("✔ " + "\n\n✔ ".join(ok_msgs))
    if warn_msgs:
        st.warning("⚠ " + "\n\n⚠ ".join(warn_msgs))
    if err_msgs:
        st.error("❌ " + "\n\n❌ ".join(err_msgs))

# -------------------------------- UNDO
st.markdown("---")
if st.session_state.get("undo"):
    u = st.session_state["undo"]
    if u["type"]=="labels":
        if st.button("↩️ Letzte Label-Änderung rückgängig machen", key="undo_labels"):
            prev = u["data"]; errs=[]
            for k, old_labels in prev.items():
                try: jira.update_issue_labels(k, old_labels)
                except Exception as e: errs.append(f"{k}: {e}")
            st.session_state.undo=None
            st.success("Label-Änderung rückgängig gemacht.")
            refresh_after_update()
    elif u["type"]=="worklogs":
        if st.button("↩️ Letzte Worklogs rückgängig machen", key="undo_wl"):
            errs=[]
            for (k,wid) in u["data"]:
                try: jira.delete_worklog(k, wid)
                except Exception as e: errs.append(f"{k}/{wid}: {e}")
            st.session_state.undo=None
            if errs:
                st.error("Einige Worklogs konnten nicht gelöscht werden.")
            else:
                st.success("Worklogs gelöscht.")

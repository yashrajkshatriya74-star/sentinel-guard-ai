import os
import sys
import subprocess
import tempfile
import re
import time
import requests
from concurrent import futures
from openai import OpenAI
from os import environ as env
from urllib.parse import quote_plus, urlencode

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, session, url_for, request, jsonify

# ============================================================
# ENVIRONMENT SETUP
# ============================================================

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("SECRET_KEY")

# ============================================================
# AUTH0 CONFIGURATION
# ============================================================

AUTH0_DOMAIN = env.get("AUTH0_DOMAIN")
AUTH0_CLIENT_ID = env.get("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = env.get("AUTH0_CLIENT_SECRET")
GITHUB_CONNECTION_ID = env.get("GITHUB_CONNECTION_ID", "con_A9R2JV3EYfNwL0uJ")

oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{AUTH0_DOMAIN}/.well-known/openid-configuration'
)

# ============================================================
# OPENAI CONFIGURATION
# ============================================================

openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


# ============================================================
# AUTH0 MANAGEMENT API
# ============================================================

def get_management_token() -> str:
    """Gets Auth0 Management API token."""
    url = f"https://{AUTH0_DOMAIN}/oauth/token"
    payload = {
        "client_id": AUTH0_CLIENT_ID,
        "client_secret": AUTH0_CLIENT_SECRET,
        "audience": f"https://{AUTH0_DOMAIN}/api/v2/",
        "grant_type": "client_credentials"
    }
    response = requests.post(url, json=payload)
    data = response.json()
    print("[Mgmt Token Response]", data)  # DEBUG
    token = data.get("access_token")
    if not token:
        print("[Mgmt Token ERROR] No access_token received!")
    return token


def get_github_token_from_vault(user_id: str) -> str:
    """
    Retrieves the user's GitHub access token from Auth0 Token Vault.
    Checks linked identities for a GitHub connection.
    """
    try:
        mgmt_token = get_management_token()
        if not mgmt_token:
            return None

        url = f"https://{AUTH0_DOMAIN}/api/v2/users/{user_id}"
        headers = {"Authorization": f"Bearer {mgmt_token}"}
        response = requests.get(url, headers=headers)
        user_data = response.json()

        print("[Token Vault] User identities:", user_data.get("identities"))  # DEBUG

        identities = user_data.get("identities", [])
        for identity in identities:
            if identity.get("provider") == "github":
                github_token = identity.get("access_token")
                print(f"[Token Vault] GitHub token found!")
                return github_token

        print("[Token Vault] No GitHub identity linked.")
        return None

    except Exception as e:
        print(f"[Token Vault Error] {e}")
        return None


def fetch_github_repo_files(github_token: str, repo_url: str) -> dict:
    """
    Uses the GitHub token from Token Vault to fetch Python files
    from a user's repository.
    """
    try:
        parts = repo_url.rstrip("/").split("/")
        owner = parts[-2]
        repo = parts[-1].replace(".git", "")

        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }

        tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"
        tree_response = requests.get(tree_url, headers=headers)
        tree_data = tree_response.json()

        if "tree" not in tree_data:
            return {"error": "Could not access repository. Make sure it exists and is accessible."}

        py_files = [f for f in tree_data["tree"] if f["path"].endswith(".py")][:5]

        files_content = {}
        for file in py_files:
            content_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file['path']}"
            content_response = requests.get(content_url, headers=headers)
            content_data = content_response.json()

            if "content" in content_data:
                import base64
                decoded = base64.b64decode(content_data["content"]).decode("utf-8", errors="ignore")
                files_content[file["path"]] = decoded[:2000]

        return files_content

    except Exception as e:
        print(f"[GitHub Fetch Error] {e}")
        return {"error": str(e)}


# ============================================================
# AUTO-FIX ENGINE
# ============================================================

def build_remediation_prompt(user_code: str, bandit_report: str) -> str:
    issues_only = ""
    if ">> Issue:" in bandit_report:
        start = bandit_report.find(">> Issue:")
        end = bandit_report.find("Code scanned:")
        issues_only = bandit_report[start:end].strip() if end != -1 else bandit_report[start:].strip()
    else:
        issues_only = "No issues found."

    return f"""Fix all security issues in this Python code.

Rules:
- Remove hardcoded secrets (use environment variables instead)
- Replace MD5 with hashlib.sha256
- Prevent command injection (use subprocess with list args, shell=False)
- Fix all issues found by Bandit

Bandit found these issues:
{issues_only}

Return ONLY pure Python code.
Do NOT include markdown or ``` blocks.
No explanation text.

Code:
{user_code[:2000]}
"""


def extract_fixed_code(ai_text: str) -> str:
    match = re.search(r'```(?:python)?\n(.*?)```', ai_text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return ai_text.strip()


def call_openai(prompt: str) -> str:
    try:
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "You are a professional cyber security engineer. Fix Python code vulnerabilities and return only the fixed code."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            max_tokens=800,
            temperature=0.1
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"[OpenAI Error] {e}")
        return None


def run_bandit_scan(code: str) -> str:
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode="w") as f:
            f.write(code)
            tmp_path = f.name

        result = subprocess.run(
            [sys.executable, "-m", "bandit", tmp_path],
            capture_output=True, text=True
        )
        return result.stdout
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


# ============================================================
# ROUTES
# ============================================================

@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )


@app.route("/callback", methods=["GET", "POST"])
def callback():
    """Main login callback."""
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    print("[Callback] Logged in:", token.get("userinfo", {}).get("sub"))
    return redirect("/")


@app.route("/callback-link", methods=["GET", "POST"])
def callback_link():
    """
    GitHub account linking callback.
    Links GitHub identity to the primary Auth0 account via Management API.
    """
    try:
        token = oauth.auth0.authorize_access_token()
        print("[callback-link] Full token keys:", list(token.keys()))  # DEBUG

        id_token = token.get("id_token")
        access_token = token.get("access_token")
        primary_user_id = session.get("primary_user_id")

        print(f"[Link] id_token present: {bool(id_token)}")
        print(f"[Link] access_token present: {bool(access_token)}")
        print(f"[Link] Primary user: {primary_user_id}")

        if not primary_user_id:
            print("[Link] ERROR: No primary_user_id in session!")
            return redirect("/")

        mgmt_token = get_management_token()
        if not mgmt_token:
            print("[Link] ERROR: Could not get management token!")
            return redirect("/")

        url = f"https://{AUTH0_DOMAIN}/api/v2/users/{primary_user_id}/identities"
        headers = {
            "Authorization": f"Bearer {mgmt_token}",
            "Content-Type": "application/json"
        }

        # Use id_token first, fallback to access_token
        link_token = id_token or access_token
        payload = {"link_with": link_token}

        resp = requests.post(url, json=payload, headers=headers)
        print("[Link Response]", resp.status_code, resp.json())

        session.pop("primary_user_id", None)

    except Exception as e:
        print(f"[Link Error] {e}")

    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + AUTH0_DOMAIN
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("index", _external=True),
                "client_id": AUTH0_CLIENT_ID
            },
            quote_via=quote_plus,
        )
    )


@app.route("/")
def index():
    user = session.get("user")

    if not user:
        return '''
        <body style="font-family: 'Segoe UI', sans-serif; background-color: #0e1117;
                     color: white; text-align: center; padding-top: 100px;">
            <div style="background: #161b22; display: inline-block; padding: 50px;
                        border-radius: 15px; border: 1px solid #30363d;">
                <h1 style="color: #58a6ff;">&#128737;&#65039; Sentinel Guard AI</h1>
                <p style="color: #8b949e;">AI Security Auditor powered by Auth0 Token Vault</p>
                <br>
                <a href="/login" style="background: #238636; color: white; padding: 15px 30px;
                                        text-decoration: none; border-radius: 5px;
                                        font-weight: bold;">
                    Login with Auth0
                </a>
            </div>
        </body>
        '''

    # Check if user has GitHub connected via Token Vault
    user_id = user["userinfo"]["sub"]
    github_token = get_github_token_from_vault(user_id)
    github_connected = github_token is not None

    github_section = ""
    if github_connected:
        github_section = f'''
            <div style="background: #1c2128; padding: 15px; border-radius: 8px;
                        border: 1px solid #238636; margin-bottom: 20px; text-align: left;">
                <p style="margin: 0; color: #7ee787;">
                    &#10003; GitHub connected via Token Vault!
                    You can scan your GitHub repos directly.
                </p>
            </div>
            <div style="margin-bottom: 20px; text-align: left;">
                <label style="color: #8b949e; font-size: 13px;">
                    GitHub Repository URL (optional):
                </label><br><br>
                <input type="text" name="repo_url" id="repo_url"
                    style="width: 95%; background: #0d1117; color: #d1d5db;
                           padding: 10px; border: 1px solid #30363d; border-radius: 8px;"
                    placeholder="https://github.com/username/repo">
            </div>
        '''
    else:
        github_section = f'''
            <div style="background: #1c2128; padding: 15px; border-radius: 8px;
                        border: 1px solid #30363d; margin-bottom: 20px; text-align: left;">
                <p style="margin: 0; color: #8b949e; font-size: 13px;">
                    &#128279; Connect GitHub via Token Vault to scan your repos directly.
                    <a href="/connect-github"
                       style="color: #58a6ff; text-decoration: none; margin-left: 8px;">
                        Connect GitHub &#8594;
                    </a>
                </p>
            </div>
        '''

    return f'''
    <body style="font-family: 'Segoe UI', sans-serif; background-color: #0e1117;
                 color: white; text-align: center; padding-top: 50px;">
        <div style="background: #161b22; display: inline-block; padding: 40px;
                    border-radius: 15px; border: 1px solid #30363d;
                    width: 80%; max-width: 850px;">
            <h1 style="color: #58a6ff;">&#128737;&#65039; Sentinel Guard AI</h1>
            <p style="color: #8b949e; font-size: 13px; margin-top: -10px;">
                Autonomous Security Audit + Auto-Remediation + Token Vault
            </p>
            <p>
                Logged in as: <strong style="color: #79c0ff;">{user["userinfo"]["name"]}</strong>
                &nbsp;|&nbsp;
                <a href="/logout" style="color: #ff7b72; text-decoration: none;">Logout</a>
            </p>
            <hr style="border: 0.5px solid #30363d; margin: 20px 0;">
            <form action="/scan" method="post">
                {github_section}
                <textarea
                    name="code"
                    rows="12"
                    style="width: 95%; background: #0d1117; color: #d1d5db;
                           padding: 15px; border: 1px solid #30363d; border-radius: 8px;
                           font-family: 'Cascadia Code', monospace; resize: vertical;"
                    placeholder="Paste your Python code here, OR connect GitHub above to scan a repo...">
                </textarea>
                <br><br>
                <input
                    type="submit"
                    value="&#9889; Run Security Audit + Auto-Fix"
                    style="background-color: #238636; color: white; padding: 12px 30px;
                           border: none; border-radius: 6px; cursor: pointer;
                           font-weight: bold; font-size: 15px;">
            </form>
        </div>
    </body>
    '''


@app.route("/connect-github")
def connect_github():
    """Initiates GitHub account linking via Auth0."""
    if "user" not in session:
        return redirect("/login")

    # Save primary user ID so callback-link can link GitHub to this account
    session["primary_user_id"] = session["user"]["userinfo"]["sub"]
    print(f"[Connect GitHub] Saving primary_user_id: {session['primary_user_id']}")

    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback_link", _external=True),
        connection="github",
        access_type="offline"
    )


@app.route("/scan", methods=["POST"])
def scan_code():
    if "user" not in session:
        return redirect("/login")

    user_code = request.form.get("code", "")[:3000]
    repo_url = request.form.get("repo_url", "").strip()
    repo_files = {}
    repo_scan_mode = False

    # TOKEN VAULT: Fetch from GitHub if repo URL provided
    if repo_url:
        user_id = session["user"]["userinfo"]["sub"]
        github_token = get_github_token_from_vault(user_id)

        if github_token:
            repo_files = fetch_github_repo_files(github_token, repo_url)
            if "error" not in repo_files and repo_files:
                repo_scan_mode = True
                user_code = "\n\n# --- ".join(
                    [f"{path} ---\n{content}" for path, content in repo_files.items()]
                )[:3000]
            else:
                user_code = user_code or "# No code provided"
        else:
            user_code = user_code or "# No code provided"

    if not user_code.strip():
        return redirect("/")

    # STEP 1: Bandit Static Analysis
    report = run_bandit_scan(user_code)

    # STEP 2: OpenAI Auto-Fix
    ai_analysis = "The AI Security Agent is currently unavailable."
    fixed_code = ""

    try:
        prompt = build_remediation_prompt(user_code, report)
        result_text = call_openai(prompt)

        if result_text:
            ai_analysis = result_text
            fixed_code = extract_fixed_code(ai_analysis)
        else:
            ai_analysis = "AI agent encountered an error. Review Bandit report below."

    except Exception as e:
        ai_analysis = "The AI agent encountered an error."
        print(f"[OpenAI Error] {e}")

    # STEP 3: Style Bandit Report
    styled_report = (
        report
        .replace("Severity: High",
                 "<span style='color:#ff7b72;font-weight:bold;'>Severity: High (Critical)</span>")
        .replace("Severity: Medium",
                 "<span style='color:#f0883e;font-weight:bold;'>Severity: Medium</span>")
        .replace("Severity: Low",
                 "<span style='color:#d29922;font-weight:bold;'>Severity: Low</span>")
    )

    # STEP 4: Auto-Fix HTML Block
    if fixed_code:
        safe_fixed_code = (
            fixed_code
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        fixed_code_html = f'''
            <h3 style="color:#7ee787; margin-bottom:10px;">
                &#9889; Auto-Generated Secure Code Patch:
            </h3>
            <div style="position:relative;">
                <button onclick="copyFixedCode()"
                    style="position:absolute; top:10px; right:10px; background:#238636;
                           color:white; border:none; padding:6px 14px; border-radius:5px;
                           cursor:pointer; font-size:12px;">
                    &#128203; Copy Fixed Code
                </button>
                <pre id="fixed-code-block"
                    style="background:#0d1117; padding:20px; padding-top:45px;
                           border-radius:8px; border:1px solid #238636; overflow-x:auto;
                           font-size:13px; color:#7ee787;
                           font-family:'Cascadia Code',monospace; text-align:left;">
{safe_fixed_code}</pre>
            </div>
        '''
    else:
        fixed_code_html = '''
            <div style="background:#1c2128; padding:15px; border-radius:8px;
                        border:1px solid #30363d; color:#8b949e; font-size:13px;">
                No auto-fix code was generated.
            </div>
        '''

    # Repo scan banner
    repo_banner = ""
    if repo_scan_mode:
        files_list = ", ".join(repo_files.keys())
        repo_banner = f'''
            <div style="background:#1c2128; padding:15px; border-radius:8px;
                        border:1px solid #58a6ff; margin-bottom:20px;">
                <p style="margin:0; color:#58a6ff; font-size:13px;">
                    &#128279; Scanned via Token Vault: <strong>{repo_url}</strong><br>
                    <span style="color:#8b949e;">Files: {files_list}</span>
                </p>
            </div>
        '''

    # STEP 5: Results Page
    return f'''
    <body style="font-family:'Segoe UI',sans-serif; background-color:#0d1117;
                 color:#c9d1d9; padding:40px; line-height:1.6;">
        <div style="max-width:1050px; margin:auto; background:#161b22; padding:35px;
                    border-radius:12px; border:1px solid #30363d;
                    box-shadow:0 10px 40px rgba(0,0,0,0.6);">

            <h1 style="color:#58a6ff; margin-top:0; border-bottom:2px solid #30363d;
                       padding-bottom:15px;">
                &#128737;&#65039; Sentinel Guard AI — Audit + Auto-Fix Results
            </h1>

            {repo_banner}

            <div style="background:#1c2128; padding:25px; border-radius:10px;
                        border-left:6px solid #238636; margin:25px 0;">
                <h3 style="margin-top:0; color:#7ee787;">
                    &#10024; AI Security Advisor — Vulnerability Analysis + Auto-Fix
                </h3>
                <div style="font-size:1em; color:#e6edf3; white-space:pre-wrap;">
{ai_analysis}
                </div>
            </div>

            <div style="margin:25px 0;">
                {fixed_code_html}
            </div>

            <h3 style="color:#8b949e; margin-bottom:10px;">
                &#128203; Bandit Technical Vulnerability Report:
            </h3>
            <pre style="background:#090c10; padding:20px; border-radius:8px;
                        border:1px solid #30363d; overflow-x:auto; font-size:13px;
                        color:#b1bac4; font-family:'Cascadia Code',monospace;">
{styled_report}</pre>

            <div style="text-align:center; margin-top:35px;
                        border-top:1px solid #30363d; padding-top:25px;">
                <a href="/"
                   style="background:#21262d; color:#c9d1d9; padding:12px 30px;
                          text-decoration:none; border-radius:6px;
                          border:1px solid #f0f6fc1a; font-weight:bold;">
                    &#8592; New Analysis
                </a>
                <button onclick="window.print()"
                    style="margin-left:20px; background:#238636; color:white;
                           padding:12px 30px; border:none; border-radius:6px;
                           font-weight:bold; cursor:pointer;">
                    &#128196; Export PDF Report
                </button>
            </div>

            <p style="text-align:center; color:#484f58; font-size:12px; margin-top:20px;">
                Powered by Bandit Security Engine &amp; OpenAI GPT-4o Mini &amp; Auth0 Token Vault
            </p>
        </div>

        <script>
            function copyFixedCode() {{
                const code = document.getElementById("fixed-code-block").innerText;
                navigator.clipboard.writeText(code).then(function() {{
                    alert("Fixed code copied to clipboard!");
                }});
            }}
        </script>
    </body>
    '''


if __name__ == "__main__":
    app.run(debug=True, port=5000, threaded=True)

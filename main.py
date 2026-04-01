import os
import sys
import subprocess
import tempfile
from concurrent import futures
import google.generativeai as genai
from os import environ as env
from urllib.parse import quote_plus, urlencode

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, redirect, session, url_for, request

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("SECRET_KEY")

oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={"scope": "openid profile email"},
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
ai_model = genai.GenerativeModel('gemini-1.5-flash')


@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(redirect_uri=url_for("callback", _external=True))


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {"returnTo": url_for("index", _external=True), "client_id": env.get("AUTH0_CLIENT_ID")},
            quote_via=quote_plus,
        )
    )


@app.route("/")
def index():
    user = session.get('user')

    if not user:
        return '''
        <body style="font-family: Arial; background-color: #0e1117; color: white; text-align: center; padding-top: 100px;">
            <div style="background: #161b22; display: inline-block; padding: 50px; border-radius: 15px; border: 1px solid #30363d;">
                <h1 style="color: #58a6ff;">&#128737;&#65039; Sentinel Guard AI</h1>
                <p>Please login to access the security scanner.</p><br>
                <a href="/login" style="background: #238636; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold;">Login with Auth0</a>
            </div>
        </body>
        '''

    return f'''
    <body style="font-family: 'Segoe UI', sans-serif; background-color: #0e1117; color: white; text-align: center; padding-top: 50px;">
        <div style="background: #161b22; display: inline-block; padding: 40px; border-radius: 15px; border: 1px solid #30363d;">
            <h1 style="color: #58a6ff;">&#128737;&#65039; Sentinel Guard AI</h1>
            <p>Welcome, <strong style="color: #79c0ff;">{user['userinfo']['name']}</strong>! | <a href="/logout" style="color: #ff7b72; text-decoration: none;">Logout</a></p>
            <hr style="border: 0.5px solid #30363d; margin: 20px 0;">
            <form action="/scan" method="post">
                <textarea name="code" rows="12" cols="70" style="background: #0d1117; color: #d1d5db; padding: 15px; border: 1px solid #30363d; border-radius: 8px; font-family: monospace;" placeholder="Paste Python code here..."></textarea><br><br>
                <input type="submit" value="Start Security Audit" style="background-color: #238636; color: white; padding: 12px 30px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold;">
            </form>
        </div>
    </body>
    '''


@app.route('/scan', methods=['POST'])
def scan_code():
    if 'user' not in session:
        return redirect("/login")

    user_code = request.form['code']

    # FIX 1: Use a unique temp file per request (thread-safe)
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
            f.write(user_code)
            tmp_path = f.name

        # FIX 2: Use sys.executable so it works on Windows, Mac, and Linux
        result = subprocess.run(
            [sys.executable, '-m', 'bandit', tmp_path],
            capture_output=True, text=True
        )
        report = result.stdout
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    # FIX 3: Single ai_summary default, ThreadPoolExecutor with 10s timeout
    ai_summary = "AI Mentor is currently busy. Technical Audit is available below."
    try:
        prompt = f"Explain these 3 security issues in 2 short Hinglish sentences: {report}"
        with futures.ThreadPoolExecutor() as executor:
            future = executor.submit(
                ai_model.generate_content,
                prompt,
                generation_config={"max_output_tokens": 100}
            )
            response = future.result(timeout=10)
            if response and response.text:
                ai_summary = response.text
    except futures.TimeoutError:
        ai_summary = "Gemini took too long. Technical Audit is available below."
    except Exception as e:
        ai_summary = "AI Mentor is currently busy. Technical Audit is available below."
        print(f"Gemini Error: {e}")

    styled_report = report.replace("Severity: High", "<span style='color: #ff7b72; font-weight: bold;'>Severity: High (Critical)</span>")
    styled_report = styled_report.replace("Severity: Low", "<span style='color: #d29922; font-weight: bold;'>Severity: Low</span>")

    return f'''
    <body style="font-family: 'Segoe UI', sans-serif; background-color: #0d1117; color: #c9d1d9; padding: 40px; line-height: 1.6;">
        <div style="max-width: 950px; margin: auto; background: #161b22; padding: 35px; border-radius: 12px; border: 1px solid #30363d; box-shadow: 0 10px 40px rgba(0,0,0,0.6);">
            <h1 style="color: #58a6ff; margin-top: 0; border-bottom: 2px solid #30363d; padding-bottom: 15px;">&#128737;&#65039; Sentinel Guard AI: Analysis</h1>

            <div style="background: #1c2128; padding: 25px; border-radius: 10px; border-left: 6px solid #238636; margin: 25px 0;">
                <h3 style="margin-top: 0; color: #7ee787;">&#10024; AI Mentor Insights</h3>
                <div style="font-size: 1.05em; color: #e6edf3; white-space: pre-wrap; font-style: italic;">{ai_summary}</div>
            </div>

            <h3 style="color: #8b949e; margin-bottom: 10px;">&#128203; Technical Security Audit:</h3>
            <pre style="background: #090c10; padding: 20px; border-radius: 8px; border: 1px solid #30363d; overflow-x: auto; font-size: 13px; color: #b1bac4; font-family: 'Cascadia Code', monospace;">{styled_report}</pre>

            <div style="text-align: center; margin-top: 35px; border-top: 1px solid #30363d; padding-top: 25px;">
                <a href="/" style="background: #21262d; color: #c9d1d9; padding: 12px 30px; text-decoration: none; border-radius: 6px; border: 1px solid #f0f6fc1a; font-weight: bold;">&#8592; Start New Scan</a>
                <button onclick="window.print()" style="margin-left:20px; background: #238636; color: white; padding: 12px 30px; border: none; border-radius: 6px; font-weight: bold; cursor: pointer;">&#128196; Export Report (PDF)</button>
            </div>
            <p style="text-align: center; color: #484f58; font-size: 12px; margin-top: 20px;">Powered by Bandit Security &amp; Google Gemini AI</p>
        </div>
    </body>
    '''


# FIX 4: if __name__ at column 0 — module level, not inside scan_code()
if __name__ == "__main__":
    app.run(debug=True, port=5000, threaded=True)  # FIX 5: threaded=True added
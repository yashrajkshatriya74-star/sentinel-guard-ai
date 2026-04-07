# 🛡️ Sentinel Guard AI — Autonomous Code Security Agent

An AI-powered security auditor that scans Python code and GitHub repositories for vulnerabilities, then automatically generates secure patches using LLMs.

Now enhanced with **Auth0 Token Vault** to securely access user GitHub repositories without exposing credentials.

---

## 🚀 Key Features

### 🔐 Secure Authentication

* Powered by **Auth0**
* Seamless login with OAuth
* Secure session handling

### 🔗 GitHub Integration (Token Vault)

* Connect GitHub via **Auth0 Token Vault**
* No need to paste personal access tokens
* Securely fetch repository files on behalf of the user

### 🛡️ Security Scanning

* Uses **Bandit** for static analysis
* Detects:

  * Command Injection (CWE-78)
  * Weak Cryptography (CWE-327)
  * Hardcoded secrets

### 🤖 AI-Powered Auto Remediation

* Automatically fixes vulnerable Python code
* Uses LLM to generate secure replacements
* Applies best practices:

  * Environment variables
  * Safe subprocess usage
  * Strong hashing (SHA-256)

### ⚡ Repository Scanning

* Scan entire GitHub repos directly
* Automatically extracts Python files
* Runs audit + fix in one click

---

## 🧠 How It Works

1. User logs in via Auth0
2. Connects GitHub using Token Vault
3. App securely retrieves GitHub access token
4. Fetches repository code
5. Runs Bandit security scan
6. Sends issues to AI model
7. Generates secure patched code

---

## 🖥️ Demo Flow

1. Login → Auth0
2. Click **Connect GitHub**
3. Authorize access
4. Paste repo URL
5. Click **Run Security Audit**
6. Get:

   * Vulnerability report
   * AI-generated secure code

---

## ⚙️ How to Run Locally

```bash
git clone https://github.com/yashrajkshatriya74-star/sentinel-guard-ai.git
cd sentinel-guard-ai
pip install -r requirements.txt
```

### 🔑 Environment Variables (.env)

```env
OPENAI_API_KEY=your_openai_key

AUTH0_DOMAIN=your_auth0_domain
AUTH0_CLIENT_ID=your_auth0_client_id
AUTH0_CLIENT_SECRET=your_auth0_client_secret

SECRET_KEY=any_random_secret
```

---

## 🌐 Access the App

```bash
python main.py
```

Open in browser:

```
http://127.0.0.1:5000
```

---

## 🛠️ Tech Stack

* **Backend:** Python / Flask
* **Security:** Bandit
* **AI:** OpenAI (GPT-4o-mini)
* **Auth:** Auth0
* **Token Management:** Auth0 Token Vault
* **Integration:** GitHub API

---

## 🔐 Why Token Vault Matters

Unlike traditional apps:

* ❌ No manual GitHub tokens
* ❌ No secrets exposed in frontend
* ✅ Secure delegated access via Auth0
* ✅ Tokens stored safely in vault

---

## 📌 Future Improvements

* Create automatic GitHub Pull Requests with fixes
* Add security scoring system
* Multi-language support (JS, Java)
* CI/CD integration

---

## 👨‍💻 Author

Built by **Shivam Kshatriya**

---

## 🏁 Hackathon Ready

This project demonstrates:

* Secure OAuth flows
* Token Vault integration
* AI-powered automation
* Real-world DevSecOps use case

---

⭐ If you like this project, give it a star!

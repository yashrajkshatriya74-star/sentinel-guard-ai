# 🛡️ Sentinel Guard AI
An automated security auditor that scans Python code for vulnerabilities using **Bandit** and generates secure patches using **Google Gemini 1.5 Flash**.

## ✨ Key Features
- **Security Scanning:** Detects shell injections (CWE-78) and weak hashes (CWE-327).
- **AI-Powered Fixes:** Automatically suggests secure code replacements.
- **Secure Dashboard:** Built with Flask and protected by Auth0.

## 🚀 How to Run Locally
1. **Clone the Repo:** `git clone https://github.com/yashrajkshatriya74-star/sentinel-guard-ai.git`
2. **Install Dependencies:** `pip install -r requirements.txt`
3. **Environment Setup:** Create a `.env` file and add your `GEMINI_API_KEY`, `AUTH0_DOMAIN`, and `AUTH0_CLIENT_ID`.
4. **Run the App:** `python main.py`
5. **Access the Tool:** Open `http://127.0.0.1:5000` in your browser.

## 🛠️ Tech Stack
- **Backend:** Python / Flask
- **Security:** Bandit
- **LLM:** Google Gemini API
- **Auth:** Auth0

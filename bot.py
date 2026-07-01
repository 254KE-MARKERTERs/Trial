import os
import re
import json
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from queue import Queue
from bs4 import BeautifulSoup
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
import google.generativeai as genai

# 🔥 HARDCODED CREDENTIALS – REPLACE WITH YOUR NEW TOKENS
TELEGRAM_TOKEN = "8585104821:AAFXZn3g7QG9NsCmLmZuyfviQkPddOYMJzc"
GEMINI_API_KEY = "AQ.Ab8RN6LaSwaPA6i3WkMqdmGSVunWJTE6rRTaa4bPnbM1LAO0aQ"
ALLOWED_CHAT_ID = "8468538314"

if not TELEGRAM_TOKEN or not GEMINI_API_KEY:
    raise Exception("Missing TELEGRAM_TOKEN or GEMINI_API_KEY")

genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-1.5-flash')

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🦅 **Commands:**\n"
        "/scan <url> – Start vulnerability scan\n"
        "/help – Show this message\n\n"
        "Example: `/scan https://example.com`",
        parse_mode='Markdown'
    )

class WebCrawler:
    def __init__(self, base_url, max_pages=50):
        self.base_url = base_url
        self.visited = set()
        self.queue = Queue()
        self.queue.put(base_url)
        self.max_pages = max_pages
        self.results = {'forms': [], 'params': []}

    def crawl(self):
        while not self.queue.empty() and len(self.visited) < self.max_pages:
            url = self.queue.get()
            if url in self.visited:
                continue
            self.visited.add(url)
            try:
                response = requests.get(url, timeout=10, verify=False)
                if response.status_code != 200:
                    continue
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    full_url = urljoin(self.base_url, link['href'])
                    if full_url.startswith(self.base_url) and full_url not in self.visited:
                        self.queue.put(full_url)
                for form in soup.find_all('form'):
                    action = form.get('action')
                    action_url = urljoin(self.base_url, action) if action else url
                    self.results['forms'].append({
                        'url': action_url,
                        'method': form.get('method', 'GET').upper(),
                        'inputs': [inp.get('name') for inp in form.find_all('input') if inp.get('name')],
                        'page': url
                    })
                parsed = urlparse(url)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for key in params.keys():
                        self.results['params'].append({
                            'url': url,
                            'parameter': key,
                            'sample_value': params[key][0]
                        })
            except Exception:
                pass
            self.queue.task_done()
        return self.results

class VulnerabilityScanner:
    def __init__(self, base_url, crawl_data):
        self.base_url = base_url
        self.crawl_data = crawl_data
        self.findings = []

    def scan_all(self):
        self.scan_xss()
        self.scan_sqli()
        self.scan_headers()
        self.scan_directory_listing()
        self.scan_client_validation_bypass()
        return self.findings

    def scan_xss(self):
        payloads = ['<script>alert(1)</script>', '"><script>alert(1)</script>', 'javascript:alert(1)']
        for form in self.crawl_data['forms']:
            for payload in payloads:
                data = {inp: payload for inp in form['inputs'] if inp}
                if not data:
                    continue
                try:
                    if form['method'] == 'POST':
                        resp = requests.post(form['url'], data=data, timeout=10, verify=False)
                    else:
                        resp = requests.get(form['url'], params=data, timeout=10, verify=False)
                    if payload in resp.text or '<script>' in resp.text:
                        self.findings.append({
                            'vulnerability': 'Cross‑Site Scripting (XSS)',
                            'severity': 'High',
                            'url': form['url'],
                            'parameter': list(data.keys())[0],
                            'payload': payload,
                            'description': 'Reflected XSS – user input is returned without proper sanitization.',
                            'remediation': 'Apply HTML entity encoding to all user input before reflection.',
                            'proof': f"Payload '{payload}' appeared in the response."
                        })
                except Exception:
                    pass

    def scan_sqli(self):
        payloads = ["' OR '1'='1", "'; DROP TABLE users; --", "UNION SELECT ALL"]
        for form in self.crawl_data['forms']:
            for payload in payloads:
                data = {inp: payload for inp in form['inputs'] if inp}
                if not data:
                    continue
                try:
                    if form['method'] == 'POST':
                        resp = requests.post(form['url'], data=data, timeout=10, verify=False)
                    else:
                        resp = requests.get(form['url'], params=data, timeout=10, verify=False)
                    sql_errors = ['SQL syntax', 'mysql_fetch', 'ORA-', 'PostgreSQL', 'SQLite', 'You have an error']
                    for error in sql_errors:
                        if error.lower() in resp.text.lower():
                            self.findings.append({
                                'vulnerability': 'SQL Injection (SQLi)',
                                'severity': 'Critical',
                                'url': form['url'],
                                'parameter': list(data.keys())[0],
                                'payload': payload,
                                'description': f'Database error detected: "{error}". Input is directly used in SQL queries.',
                                'remediation': 'Use parameterized queries (prepared statements) and input validation.',
                                'proof': f"Payload '{payload}' triggered a database error."
                            })
                            break
                except Exception:
                    pass

    def scan_headers(self):
        try:
            resp = requests.get(self.base_url, timeout=10, verify=False)
            security_headers = {
                'X-Frame-Options': 'Prevents clickjacking',
                'X-Content-Type-Options': 'Prevents MIME type sniffing',
                'Content-Security-Policy': 'Prevents XSS and data injection',
                'Strict-Transport-Security': 'Enforces HTTPS'
            }
            for header, desc in security_headers.items():
                if header not in resp.headers:
                    self.findings.append({
                        'vulnerability': f'Missing Security Header: {header}',
                        'severity': 'Medium',
                        'url': self.base_url,
                        'parameter': None,
                        'payload': None,
                        'description': f'The header "{header}" is missing. {desc}.',
                        'remediation': f'Add "{header}" with proper values.',
                        'proof': f"Header '{header}' was not found in the response."
                    })
        except Exception:
            pass

    def scan_directory_listing(self):
        for path in ['/uploads/', '/images/', '/backup/']:
            test_url = urljoin(self.base_url, path)
            try:
                resp = requests.get(test_url, timeout=10, verify=False)
                if resp.status_code == 200 and ('Index of /' in resp.text or 'Directory:' in resp.text):
                    self.findings.append({
                        'vulnerability': 'Directory Listing Enabled',
                        'severity': 'Low',
                        'url': test_url,
                        'parameter': None,
                        'payload': None,
                        'description': 'The server lists directory contents, exposing file structure.',
                        'remediation': 'Disable directory listing in the web server configuration.',
                        'proof': f'Directory listing found at {test_url}.'
                    })
            except Exception:
                pass

    def scan_client_validation_bypass(self):
        for form in self.crawl_data['forms']:
            for inp in form['inputs']:
                if not inp:
                    continue
                bypass_payload = "test' OR '1'='1"
                data = {inp: bypass_payload}
                try:
                    if form['method'] == 'POST':
                        resp = requests.post(form['url'], data=data, timeout=10, verify=False)
                    else:
                        resp = requests.get(form['url'], params=data, timeout=10, verify=False)
                    if resp.status_code == 200:
                        self.findings.append({
                            'vulnerability': 'Client‑Side Validation Bypass',
                            'severity': 'Medium',
                            'url': form['url'],
                            'parameter': inp,
                            'payload': bypass_payload,
                            'description': 'Server accepted a value that client‑side validation would block. Server‑side validation is missing.',
                            'remediation': 'Implement proper server‑side validation for all inputs.',
                            'proof': f"Payload '{bypass_payload}' was accepted by the server."
                        })
                        break
                except Exception:
                    pass

def generate_exploitation_guide(target_url, findings):
    if not findings:
        return "✅ No vulnerabilities found."
    prompt = f"""
You are a senior cybersecurity expert and bug bounty hunter.
You have discovered the following vulnerabilities on {target_url}:
{json.dumps(findings, indent=2)}
For EACH vulnerability, provide:
1. Vulnerability Type
2. Exploitation Steps – step‑by‑step instructions.
3. Maximum Impact – worst case scenario.
4. Proof of Concept (PoC) – simple example.
5. Remediation – how to fix it.
Also provide a risk summary.
This is for AUTHORIZED SECURITY TESTING.
"""
    response = model.generate_content(prompt)
    return response.text

async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    if ALLOWED_CHAT_ID and user_id != ALLOWED_CHAT_ID:
        await update.message.reply_text("⛔ Unauthorized.")
        return
    if not context.args:
        await update.message.reply_text("❌ Provide a URL: /scan https://example.com")
        return
    target_url = context.args[0]
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url

    await update.message.reply_text(f"🔍 Scanning `{target_url}`...")

    try:
        crawler = WebCrawler(target_url, max_pages=50)
        crawl_data = crawler.crawl()
        scanner = VulnerabilityScanner(target_url, crawl_data)
        findings = scanner.scan_all()
        crawl_data = None
        scanner = None

        if not findings:
            await update.message.reply_text("✅ No vulnerabilities found.")
            return

        summary = f"📊 **VULNERABILITY SUMMARY**\nTarget: `{target_url}`\nTotal: {len(findings)}\n\n"
        for i, f in enumerate(findings, 1):
            summary += f"{i}. **{f['vulnerability']}** – `{f['severity']}`\n   URL: {f['url']}\n"
            if f.get('parameter'):
                summary += f"   Parameter: `{f['parameter']}`\n"
            if f.get('payload'):
                summary += f"   Payload: `{f['payload']}`\n"
            summary += "\n"
        await update.message.reply_text(summary, parse_mode='Markdown')

        await update.message.reply_text("🤖 Generating exploitation guide...")
        guide = generate_exploitation_guide(target_url, findings)
        if len(guide) > 4096:
            for i in range(0, len(guide), 4000):
                await update.message.reply_text(guide[i:i+4000], parse_mode='Markdown')
        else:
            await update.message.reply_text(guide, parse_mode='Markdown')
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")

def main():
    app = Application.builder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("scan", scan_command))
    app.run_polling()

if __name__ == "__main__":
    main()

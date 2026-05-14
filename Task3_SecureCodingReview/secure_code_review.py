"""
CodeAlpha Internship - Task 3: Secure Coding Review
"""
import re
import sys
import datetime

RULES = [
    (r'execute\s*\(.*f["\']',        'CRITICAL', 'SQL Injection',
     'f-string used in SQL query',
     'Use parameterised queries: cursor.execute("SELECT * FROM t WHERE id=?", (val,))'),

    (r'execute\s*\(.*\.format\(',    'CRITICAL', 'SQL Injection',
     '.format() used to build SQL query',
     'Replace .format() with ? placeholders'),

    (r'(?i)(password|secret|api_key)\s*=\s*["\'][^"\']{4,}["\']',
     'HIGH', 'Hardcoded Credentials',
     'Password or secret hardcoded in source',
     'Use os.environ["PASSWORD"] instead'),

    (r'\bpickle\.loads?\b',          'HIGH', 'Insecure Deserialization',
     'pickle.load() can execute arbitrary code',
     'Use json.loads() for safe deserialization'),

    (r'\byaml\.load\s*\(',           'HIGH', 'Insecure Deserialization',
     'yaml.load() without Loader is dangerous',
     'Use yaml.safe_load() instead'),

    (r'os\.system\s*\(',             'HIGH', 'Command Injection',
     'os.system() is vulnerable to shell injection',
     'Use subprocess.run([...], shell=False)'),

    (r'subprocess.*shell\s*=\s*True','HIGH', 'Command Injection',
     'shell=True allows command injection',
     'Use shell=False with argument list'),

    (r'\bhashlib\.md5\b',            'MEDIUM', 'Weak Cryptography',
     'MD5 is cryptographically broken',
     'Use hashlib.sha256() or bcrypt for passwords'),

    (r'\bhashlib\.sha1\b',           'MEDIUM', 'Weak Cryptography',
     'SHA1 is deprecated for security use',
     'Use hashlib.sha256() or stronger'),

    (r'\brandom\.(randint|choice)\b','MEDIUM', 'Insecure Randomness',
     'random module is not cryptographically secure',
     'Use the secrets module instead'),

    (r'\beval\s*\(',                 'HIGH', 'Code Injection',
     'eval() executes arbitrary code',
     'Remove eval(). Use ast.literal_eval() if needed'),

    (r'\bexec\s*\(',                 'HIGH', 'Code Injection',
     'exec() executes arbitrary code',
     'Redesign logic to avoid exec()'),

    (r'DEBUG\s*=\s*True',            'MEDIUM', 'Info Disclosure',
     'Debug mode exposes internal details',
     'Set DEBUG=False in production'),

    (r'http://(?!localhost|127)',     'LOW', 'Insecure Transport',
     'Plain HTTP used instead of HTTPS',
     'Use https:// for all external URLs'),
]

def scan_file(filepath):
    print(f"\n{'═'*55}")
    print(f"  🛡️  SECURE CODE REVIEW — CodeAlpha Task 3")
    print(f"  File : {filepath}")
    print(f"  Date : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'═'*55}")

    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"  ❌ File not found: {filepath}")
        return

    findings = []
    for lineno, line in enumerate(lines, 1):
        for pattern, severity, category, desc, fix in RULES:
            if re.search(pattern, line):
                findings.append((lineno, severity, category,
                                 line.strip(), desc, fix))

    score = 100
    deductions = {'CRITICAL':25,'HIGH':15,'MEDIUM':8,'LOW':3}

    if not findings:
        print("\n  ✅ No vulnerabilities found! Great code.")
    else:
        icons = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🔵'}
        for lineno, sev, cat, code, desc, fix in findings:
            score -= deductions.get(sev, 0)
            print(f"\n  {icons.get(sev,'⚪')} [{sev}] {cat}")
            print(f"     Line    : {lineno}")
            print(f"     Code    : {code[:70]}")
            print(f"     Problem : {desc}")
            print(f"     Fix     : {fix}")

    score = max(0, score)
    print(f"\n{'─'*55}")
    print(f"  📊 Total Findings : {len(findings)}")
    print(f"  📊 Security Score : {score}/100  "
          f"{'✅ PASS' if score >= 70 else '❌ NEEDS FIXING'}")
    print(f"{'═'*55}\n")

# Create sample vulnerable file for demo
SAMPLE = '''# Sample vulnerable code - FOR EDUCATION ONLY
import sqlite3, os, pickle, hashlib, random, subprocess

password = "SuperSecret123"
api_key = "sk-abc123xyz456"

def get_user(username):
    conn = sqlite3.connect("db.sqlite")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cur.fetchone()

def hash_pwd(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()

def run_cmd(cmd):
    subprocess.run(cmd, shell=True)

def load(path):
    return pickle.load(open(path,"rb"))

def token():
    return str(random.randint(100000,999999))

def dangerous(user_input):
    return eval(user_input)

DEBUG = True
'''

with open('sample_vulnerable.py', 'w') as f:
    f.write(SAMPLE)

target = sys.argv[1] if len(sys.argv) > 1 else 'sample_vulnerable.py'
scan_file(target)

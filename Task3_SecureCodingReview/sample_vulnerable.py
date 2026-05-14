# Sample vulnerable code - FOR EDUCATION ONLY
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

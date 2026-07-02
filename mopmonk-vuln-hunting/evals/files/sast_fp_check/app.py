"""SAST FP-check fixture. 3 raw alerts, of which some are TP some are FP.

Semgrep-style output is in alerts.json alongside this file.

Alert 1: exec() call in run_task -> 真漏洞（cmd 来自 request.args）
Alert 2: eval() call in do_math -> FP（有 ast.literal_eval 的白名单）
Alert 3: SQL string format in list_users -> FP（走的是参数化 query，字符串只是日志）
"""
import ast
import subprocess
import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/run")
def run_task():
    cmd = request.args["cmd"]
    # ALERT 1: subprocess with shell=True and user input
    result = subprocess.check_output(cmd, shell=True)
    return result


@app.route("/calc")
def do_math():
    expr = request.args["expr"]
    # ALERT 2: eval usage, but literal_eval is used first as gate
    try:
        ast.literal_eval(expr)  # 若非字面量 raise 异常
    except Exception:
        return "invalid", 400
    return str(eval(expr))  # eval 仅在 literal_eval 通过后执行


@app.route("/users")
def list_users():
    q = request.args.get("q", "")
    conn = sqlite3.connect(":memory:")
    # ALERT 3: f-string with user input near SQL — 但实际执行走参数化
    log_line = f"SELECT * FROM users WHERE name LIKE '%{q}%'"  # 仅日志
    print(log_line)
    cur = conn.execute("SELECT * FROM users WHERE name LIKE ?", (f"%{q}%",))
    return str(cur.fetchall())

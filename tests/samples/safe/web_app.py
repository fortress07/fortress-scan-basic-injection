import ast
import html
import shlex
import sqlite3
import subprocess

import yaml
from flask import Flask, render_template, request

app = Flask(__name__)

ALLOWED_UNITS = {"nginx", "postgres", "redis"}


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output(["ping", "-c", "1", "--", host]).decode()


@app.route("/service")
def service_status():
    unit = request.args.get("unit")
    if unit not in ALLOWED_UNITS:
        return "unknown unit", 400
    return subprocess.check_output(["systemctl", "status", unit]).decode()


@app.route("/quoted")
def quoted():
    unit = request.args.get("unit")
    return subprocess.check_output("systemctl status " + shlex.quote(unit), shell=True).decode()


@app.route("/lookup")
def lookup():
    name = request.args.get("name")
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    return str(cursor.fetchall())


@app.route("/page")
def page():
    title = request.args.get("title")
    return render_template("page.html", title=title)


@app.route("/compute")
def compute():
    return str(ast.literal_eval("[1, 2, 3]"))


@app.route("/repeat")
def repeat():
    count = int(request.args.get("count"))
    return "x" * count


@app.route("/config", methods=["POST"])
def parse_config():
    return str(yaml.safe_load(request.get_data()))


@app.route("/escape")
def escape():
    comment = request.args.get("comment")
    return html.escape(comment)

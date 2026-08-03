import os
import pickle
import subprocess
import sqlite3

import yaml
from flask import Flask, request
from jinja2 import Template

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return os.popen("ping -c 1 " + host).read()


@app.route("/shell")
def shell():
    command = request.args.get("cmd")
    return subprocess.check_output(command, shell=True).decode()


@app.route("/lookup")
def lookup():
    name = request.args.get("name")
    connection = sqlite3.connect("app.db")
    cursor = connection.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return str(cursor.fetchall())


@app.route("/render")
def render():
    body = request.args.get("body")
    return Template(body).render()


@app.route("/compute")
def compute():
    return str(eval(request.args.get("expr")))


@app.route("/restore", methods=["POST"])
def restore():
    return str(pickle.loads(request.get_data()))


@app.route("/config", methods=["POST"])
def parse_config():
    return str(yaml.load(request.get_data()))


@app.route("/plugin")
def plugin():
    import importlib

    return str(importlib.import_module(request.args.get("module")))


@app.route("/attribute")
def attribute():
    return str(getattr(app, request.args.get("field")))

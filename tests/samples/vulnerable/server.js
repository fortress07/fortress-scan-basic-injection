const express = require("express");
const child_process = require("child_process");
const mysql = require("mysql");

const app = express();
const db = mysql.createConnection({ host: "localhost" });

app.get("/ping", (req, res) => {
  const host = req.query.host;
  child_process.exec("ping -c 1 " + host, (error, stdout) => {
    res.send(stdout);
  });
});

app.get("/lookup", (req, res) => {
  const name = req.query.name;
  db.query(`SELECT * FROM users WHERE name = '${name}'`, (error, rows) => {
    res.json(rows);
  });
});

app.get("/compute", (req, res) => {
  const expression = req.query.expr;
  res.send(String(eval(expression)));
});

app.get("/load", (req, res) => {
  const moduleName = req.query.module;
  const loaded = require(moduleName);
  res.json(Object.keys(loaded));
});

function renderProfile(container, req) {
  const bio = req.body.bio;
  container.innerHTML = bio;
}

module.exports = { app, renderProfile };

app.get("/proxy", (req, res) => {
  const target = req.query.url;
  fetch(target).then((r) => r.text()).then((body) => res.send(body));
});

app.get("/go", (req, res) => {
  res.redirect(req.query.next);
});

app.get("/read", (req, res) => {
  const fs = require("fs");
  fs.readFile(req.query.file, "utf8", (error, data) => res.send(data));
});

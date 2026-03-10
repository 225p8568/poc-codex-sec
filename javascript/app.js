/**
 * Vulnerable Node.js/Express application — intentional security issues for CodeQL scanning.
 * DO NOT use in production.
 */

const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ------------------------------------------------------------------ //
// VULNERABILITY 1 – Hardcoded credentials                            //
// ------------------------------------------------------------------ //
const DB_HOST = "localhost";
const DB_USER = "root";
const DB_PASS = "password123";
const JWT_SECRET = "hardcoded_jwt_secret";

// ------------------------------------------------------------------ //
// VULNERABILITY 2 – Cross-Site Scripting (XSS)                       //
// ------------------------------------------------------------------ //
app.get("/greet", (req, res) => {
  const name = req.query.name || "";
  // XSS: user input injected directly into HTML without escaping
  res.send(`<h1>Hello, ${name}!</h1>`);
});

// ------------------------------------------------------------------ //
// VULNERABILITY 3 – eval() / Code Injection                          //
// ------------------------------------------------------------------ //
app.post("/calculate", (req, res) => {
  const expression = req.body.expr || "";
  // Code injection: arbitrary JS executed via eval
  const result = eval(expression);
  res.json({ result });
});

// ------------------------------------------------------------------ //
// VULNERABILITY 4 – OS Command Injection                             //
// ------------------------------------------------------------------ //
app.get("/ping", (req, res) => {
  const host = req.query.host || "127.0.0.1";
  // Command injection: user-supplied host appended to shell command
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    res.send(`<pre>${stdout}</pre>`);
  });
});

// ------------------------------------------------------------------ //
// VULNERABILITY 5 – Path Traversal                                   //
// ------------------------------------------------------------------ //
app.get("/file", (req, res) => {
  const filename = req.query.name || "";
  // Path traversal: no canonicalization
  const filePath = path.join("/var/www/public", filename);
  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) return res.status(500).send("Error");
    res.send(data);
  });
});

// ------------------------------------------------------------------ //
// VULNERABILITY 6 – Insecure Deserialization (eval on user data)     //
// ------------------------------------------------------------------ //
app.post("/deserialize", (req, res) => {
  const data = req.body.data || "{}";
  // Insecure deserialization: user-supplied string executed via eval,
  // allowing arbitrary code execution (equivalent to node-serialize IIFE pattern).
  const obj = eval("(" + data + ")");
  res.json(obj);
});

// ------------------------------------------------------------------ //
// VULNERABILITY 7 – Prototype Pollution                              //
// ------------------------------------------------------------------ //
function merge(target, source) {
  for (const key in source) {
    // Prototype pollution: __proto__ key not blocked
    if (typeof source[key] === "object") {
      target[key] = merge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

app.post("/merge", (req, res) => {
  const result = merge({}, req.body);
  res.json(result);
});

// ------------------------------------------------------------------ //
// VULNERABILITY 8 – SQL Injection (string concatenation)             //
// ------------------------------------------------------------------ //
app.get("/user", (req, res) => {
  const userId = req.query.id || "1";
  // SQL injection: user id directly interpolated into query string
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  res.send(`Query: ${query}`);
});

// ------------------------------------------------------------------ //
// VULNERABILITY 9 – Open Redirect                                    //
// ------------------------------------------------------------------ //
app.get("/redirect", (req, res) => {
  const target = req.query.next || "/";
  // Open redirect: no validation of target URL
  res.redirect(target);
});

app.listen(3000, () => console.log("Server running on port 3000"));

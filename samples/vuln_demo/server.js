/**
 * 演示样本：网关服务（Node / Express）
 * ─────────────────────────────────────────────
 * CodeAudit 演示样本，故意包含安全缺陷。密钥均为虚构值。
 */
const express = require('express');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const { exec } = require('child_process');
const cors = require('cors');
const fs = require('fs');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = "gw-jwt-secret-2f8a91c4";
const OPENAI_API_KEY = "sk-proj-Qk7Zx2Nm4Pv9Rt1Lb6Wy3Hd8Ae5Uc0Jg";
const pool = mysql.createPool({
  host: 'localhost',
  user: 'gw',
  password: 'Gateway@2024',
  database: 'gateway',
});

app.get('/api/user', (req, res) => {
  const uid = req.query.id;
  const sql = `SELECT id, name, email FROM users WHERE id = ${uid}`;
  pool.query(sql, (err, rows) => res.json(rows));
});

app.get('/api/log', (req, res) => {
  const name = req.query.file;
  const content = fs.readFileSync('/var/log/app/' + name, 'utf8');
  res.send(content);
});

app.post('/api/ping', (req, res) => {
  const host = req.body.host;
  exec('ping -c 1 ' + host, (err, stdout) => res.send(stdout));
});

app.post('/api/eval', (req, res) => {
  const rule = req.body.rule;
  const result = eval(rule);
  res.json({ result });
});

app.get('/api/proxy', async (req, res) => {
  const target = req.query.target;
  const r = await fetch(target);
  res.send(await r.text());
});

app.get('/api/token', (req, res) => {
  const userId = req.query.uid;
  const token = jwt.sign({ uid: userId, admin: true }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
});

app.listen(3000, '0.0.0.0', () => console.log('gateway on 3000'));

"use strict";

/**
 * Local naive Bayes reader for one finding line.
 * Usage: node classify.js   (one JSON object on stdin)
 * It does not use the network. The weights live in model.json.
 */

const fs = require("fs");
const path = require("path");

const here = __dirname;
const model = JSON.parse(fs.readFileSync(path.join(here, "model.json"), "utf8"));
const phrases = JSON.parse(fs.readFileSync(path.join(here, "phrases.json"), "utf8"));

const MARKERS = [
  ["mark_sql", /\b(?:select|insert|update|delete)\b/i],
  ["mark_secret", /secret|password|api_key|<secret value>/i],
  ["mark_action", /actions\/|@[vV]\d|uses:/],
  ["mark_exec", /\b(?:eval|system|popen|function)\b|shell=true/i],
  ["mark_deser", /pickle|yaml\.load|unserialize|readobject|objectinputstream/i],
  ["mark_ssrf", /requests\.|fetch\(|169\.254\.169\.254|openstream|axios|httpx/i],
  ["mark_xss", /innerhtml|document\.write|dangerouslysetinnerhtml/i],
  ["mark_auth", /permitall|allowany|csrf_exempt|get \/|post \//i],
  ["mark_wild", /0\.0\.0\.0\/0|\*/],
  ["mark_tls", /verify=false|rejectunauthorized|insecureskipverify|cert_none/i],
  ["mark_debug", /debug\s*=\s*true|display_errors/i],
  ["mark_path", /\.\.\/|filepath\.join|os\.path\.join|open\(/i],
  ["mark_archive", /extractall/i],
  ["mark_jwt", /jwt\.decode|algorithms/i],
];

function tokens(text) {
  const found = new Set((text.toLowerCase().match(/[a-z0-9_./:@<>=-]{2,}/g) || []));
  const low = text.toLowerCase();
  for (const [name, pattern] of MARKERS) {
    if (pattern.test(low)) found.add(name);
  }
  return found;
}

function classify(text) {
  const present = tokens(text);
  const scores = {};
  for (const [label, weights] of Object.entries(model.classes)) {
    let score = weights.prior;
    for (const token of present) {
      if (Object.prototype.hasOwnProperty.call(model.vocab, token)) {
        score += token in weights.token_log ? weights.token_log[token] : weights.default_log;
      }
    }
    scores[label] = score;
  }
  const ranked = Object.entries(scores).sort((a, b) => b[1] - a[1]);
  const best = ranked[0][1];
  const weights = ranked.map((item) => Math.exp(item[1] - best));
  const total = weights.reduce((sum, value) => sum + value, 0);
  return { label: ranked[0][0], confidence: Math.round((weights[0] / total) * 1000) / 1000 };
}

function subject(label, evidence) {
  if (label === "sql") {
    const brace = evidence.match(/\{([^{}]+)\}/);
    if (brace) return brace[1];
    const plus = evidence.match(/["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\+\s*([^);\n]+)/i);
    if (plus) return plus[1].trim();
  }
  if (label === "secret") {
    const name = evidence.match(/\b([A-Za-z_][\w.]*)\s*[:=]/);
    if (name) return name[1];
  }
  if (label === "action") {
    const action = evidence.match(/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[A-Za-z0-9._-]+/);
    if (action) return action[0];
  }
  const word = evidence.match(/\b([A-Za-z_][A-Za-z0-9_]{2,})\b/);
  return word ? word[1] : "the value on this line";
}

function fill(template, values) {
  return template.replace(/\{(line|subject|place)\}/g, (_, key) => values[key] || "");
}

function describe(input) {
  const evidence = String(input.evidence || "");
  const title = String(input.title || "");
  const file = String(input.file || "");
  const guessed = classify(`${evidence} ${title}`);
  const phrase = phrases[guessed.label];
  const pattern = phrase && phrase.marker.startsWith("(?i)") ? phrase.marker.slice(4) : (phrase && phrase.marker);
  const supported = Boolean(pattern && new RegExp(pattern, "i").test(evidence));
  const values = {
    line: evidence.trim().slice(0, 180),
    subject: subject(guessed.label, evidence),
    place: file || "this file",
  };
  return {
    label: guessed.label,
    confidence: guessed.confidence,
    supported: supported,
    description: supported ? fill(phrase.description, values) : "",
    effect: supported ? fill(phrase.effect, values) : "",
    remediation: supported ? fill(phrase.remediation, values) : "",
  };
}

const raw = fs.readFileSync(0, "utf8");
process.stdout.write(JSON.stringify(describe(JSON.parse(raw))));

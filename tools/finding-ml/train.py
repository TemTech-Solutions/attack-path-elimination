"""Train the local naive Bayes model used to read a finding line.

Run from the repository root:

    python tools/finding-ml/train.py

The weights are written next to this file. Nothing is downloaded.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent

SAMPLES = [
    ("sql", 'db.query("SELECT * FROM users WHERE id = " + params[:id])'),
    ("sql", 'cursor.execute(f"SELECT name FROM accounts WHERE id = {user_id}")'),
    ("sql", 'mysqli_query($link, "SELECT * FROM orders WHERE id = " . $_GET["id"])'),
    ("sql", 'stmt = "UPDATE payments SET status = \'" + status + "\' WHERE id = " + id'),
    ("sql", 'INSERT INTO audit (actor) VALUES (" + actor + ")'),
    ("secret", "JWT_SECRET=<secret value>"),
    ("secret", "AWS_SECRET_ACCESS_KEY=<secret value>"),
    ("secret", 'password = "s3cr3t-value-not-shown"'),
    ("secret", "api_key=<secret value>"),
    ("action", "actions/checkout@v4"),
    ("action", "uses: actions/setup-python@v5"),
    ("action", "some-org/deploy-action@v1"),
    ("exec", 'scriptEngine.eval("JSON.parse" + jsonString + "")'),
    ("exec", "os.system(cmd)"),
    ("exec", "subprocess.run(command, shell=True)"),
    ("exec", "new Function(code)"),
    ("deser", "pickle.loads(blob)"),
    ("deser", "yaml.load(data)"),
    ("deser", "ObjectInputStream in.readObject()"),
    ("deser", "unserialize($payload)"),
    ("ssrf", 'requests.get(callback, timeout=3)'),
    ("ssrf", "fetch(url)"),
    ("ssrf", "http://169.254.169.254/latest/meta-data/"),
    ("ssrf", "URL(url).openStream()"),
    ("xss", "element.innerHTML = comment"),
    ("xss", "dangerouslySetInnerHTML={{__html: body}}"),
    ("xss", "document.write(name)"),
    ("auth", "GET /admin/refund"),
    ("auth", "@app.route('/api/payment') AllowAny"),
    ("auth", "permitAll()"),
    ("auth", "csrf_exempt"),
    ("wildcard", 'Action "*" Resource "*"'),
    ("wildcard", "0.0.0.0/0 ingress"),
    ("wildcard", 'Principal: "*"'),
    ("tls", "verify=False"),
    ("tls", "rejectUnauthorized: false"),
    ("tls", "InsecureSkipVerify"),
    ("debug", "DEBUG = True"),
    ("debug", "app.debug = True"),
    ("debug", "display_errors = On"),
    ("path", 'open("/tmp/" + request.args["name"])'),
    ("path", "filepath.Join(root, userPath)"),
    ("path", 'os.path.join(base, "../" + name)'),
    ("archive", "zipfile.ZipFile(blob).extractall(dest)"),
    ("archive", "tar.extractall(path)"),
    ("jwt", 'jwt.decode(token, options={"verify_signature": False})'),
    ("jwt", 'jwt.decode(token, algorithms=["none"])'),
]


def tokens(text: str) -> list[str]:
    words = re.findall(r"[a-z0-9_./:@<>=-]{2,}", text.lower())
    markers = []
    rules = {
        "mark_sql": r"\b(?:select|insert|update|delete)\b",
        "mark_secret": r"secret|password|api_key|<secret value>",
        "mark_action": r"actions/|@[vV]\d|uses:",
        "mark_exec": r"\b(?:eval|system|popen|function)\b|shell=true",
        "mark_deser": r"pickle|yaml\.load|unserialize|readobject|objectinputstream",
        "mark_ssrf": r"requests\.|fetch\(|169\.254\.169\.254|openstream|axios|httpx",
        "mark_xss": r"innerhtml|document\.write|dangerouslysetinnerhtml",
        "mark_auth": r"permitall|allowany|csrf_exempt|get /|post /",
        "mark_wild": r"0\.0\.0\.0/0|\*",
        "mark_tls": r"verify=false|rejectunauthorized|insecureskipverify|cert_none",
        "mark_debug": r"debug\s*=\s*true|display_errors",
        "mark_path": r"\.\./|filepath\.join|os\.path\.join|open\(",
        "mark_archive": r"extractall",
        "mark_jwt": r"jwt\.decode|algorithms",
    }
    low = text.lower()
    for name, pattern in rules.items():
        if re.search(pattern, low):
            markers.append(name)
    return words + markers


def train() -> dict:
    by_class: dict[str, list[list[str]]] = defaultdict(list)
    for label, text in SAMPLES:
        by_class[label].append(tokens(text))
    vocab = sorted({token for docs in by_class.values() for doc in docs for token in doc})
    vocab_index = {token: index for index, token in enumerate(vocab)}
    total_docs = sum(len(docs) for docs in by_class.values())
    classes = {}
    for label, docs in by_class.items():
        counts: Counter[str] = Counter()
        for doc in docs:
            counts.update(set(doc))
        total = sum(counts.values())
        denom = total + len(vocab)
        token_log = {token: round(math.log((counts[token] + 1) / denom), 6) for token in vocab if counts[token]}
        classes[label] = {
            "prior": round(math.log((len(docs) + 1) / (total_docs + len(by_class))), 6),
            "token_log": token_log,
            "default_log": round(math.log(1 / denom), 6),
        }
    return {"vocab": vocab_index, "classes": classes}


def main() -> None:
    model = train()
    destination = HERE / "model.json"
    destination.write_text(json.dumps(model, separators=(",", ":")), encoding="utf-8")
    print(f"Wrote {destination} ({destination.stat().st_size} bytes, {len(model['vocab'])} tokens)")


if __name__ == "__main__":
    main()

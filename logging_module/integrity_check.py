import os
def verify_file_chain(file_path: str) -> Dict[str, Any]:
"""Verify a single JSON-lines log file's hash chain.


Returns a dictionary: {"ok": bool, "issues": list}
Each issue is a dict containing details about the mismatch.
"""
issues = []
prev_hash = ""


if not os.path.exists(file_path):
return {"ok": False, "issues": [{"error": "file_not_found", "file": file_path}]}


with open(file_path, "r", encoding="utf-8") as f:
for line_no, line in enumerate(f, start=1):
line = line.strip()
if not line:
continue
try:
rec = json.loads(line)
except json.JSONDecodeError as e:
issues.append({"line": line_no, "error": "invalid_json", "detail": str(e)})
continue


payload = {
"user_id": rec.get("user_id"),
"action": rec.get("action"),
"timestamp": rec.get("timestamp"),
"ip_address": rec.get("ip_address"),
"details": rec.get("details"),
}


recomputed = compute_hash(prev_hash, payload)
expected = rec.get("hash")
if recomputed != expected:
issues.append({
"line": line_no,
"error": "hash_mismatch",
"expected": expected,
"recomputed": recomputed,
"record": rec,
})


prev_hash = rec.get("hash") or prev_hash


return {"ok": len(issues) == 0, "issues": issues}




def verify_all_logs(logs_dir: Optional[str] = None) -> Dict[str, Any]:
logs_dir = ensure_logs_dir(logs_dir)
files = sorted([p for p in os.listdir(logs_dir) if p.endswith('.json')])
report = {}
for fn in files:
path = os.path.join(logs_dir, fn)
report[fn] = verify_file_chain(path)
return report
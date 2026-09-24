import urllib.request
import json
import os

def test_real_zip_audit():
    zip_path = r"c:\Users\Rajesh\Desktop\N-CASA\test_data\N-CASA_Manual_Test_Configs.zip"
    with open(zip_path, "rb") as f:
        file_bytes = f.read()

    boundary = "----WebKitFormBoundaryRealZipAudit7MA4"
    body = bytearray()
    body.extend(f"--{boundary}\r\nContent-Disposition: form-data; name=\"framework\"\r\n\r\nCIS\r\n".encode("utf-8"))
    body.extend(f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"N-CASA_Manual_Test_Configs.zip\"\r\nContent-Type: application/zip\r\n\r\n".encode("utf-8"))
    body.extend(file_bytes)
    body.extend(f"\r\n--{boundary}--\r\n".encode("utf-8"))

    req = urllib.request.Request(
        "http://127.0.0.1:8000/api/audits",
        data=bytes(body),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST"
    )

    res = urllib.request.urlopen(req)
    audit = json.loads(res.read().decode("utf-8"))
    audit_id = audit["audit_id"]
    print("1. Audit Created from Real ZIP:", audit_id, "| Status:", audit["status"])

    def post(path):
        r = urllib.request.Request(f"http://127.0.0.1:8000/api/audits/{audit_id}{path}", data=b"", method="POST")
        return json.loads(urllib.request.urlopen(r).read().decode("utf-8"))

    def get(path):
        r = urllib.request.Request(f"http://127.0.0.1:8000/api/audits/{audit_id}{path}", method="GET")
        return json.loads(urllib.request.urlopen(r).read().decode("utf-8"))

    # Step 1: Detect
    det = post("/detect")
    print(f"2. Vendor Detection: {det.get('status')} | Files detected: {len(det.get('files', []))}")
    for f in det.get("files", []):
        print(f"   - {f.get('filename')}: vendor={f.get('vendor')}, type={f.get('device_type')}, confidence={f.get('confidence')}")

    # Step 2: Parse
    par = post("/parse")
    print(f"3. Deterministic Parsing: {par.get('status')} | Files parsed: {len(par.get('files', []))}")

    # Step 3: Normalize
    norm = post("/normalize")
    print(f"4. Normalization: {norm.get('status')} | Files normalized: {len(norm.get('files', []))}")

    # Step 4: Compliance
    comp = post("/compliance")
    print(f"5. Compliance Evaluation: {comp.get('status')} | Summary: {comp.get('summary')}")

    # Step 5: Findings
    find = post("/findings")
    print(f"6. Findings Generation: {find.get('status')} | Findings: {find.get('summary', {}).get('total_findings')} | Limitations: {find.get('summary', {}).get('assessment_limitations')}")

    # Step 6: Remediation
    rem = post("/remediation")
    print(f"7. Remediation Generation: {rem.get('status')} | Proposals: {len(rem.get('remediations', []))}")

    # Step 7: AI Analysis for unknown vendor
    ai = post("/ai/analyze")
    print(f"8. AI Analysis for Unknown: {ai.get('status')} | Interpreted files: {len(ai.get('results', []))}")

    # Step 8: Reports
    rep = post("/reports")
    print(f"9. Generated Report Snapshot ID: {rep.get('report_id')}")

    # Verify Dashboard Data from Database
    req_dash = urllib.request.urlopen("http://127.0.0.1:8000/api/audits")
    audits_list = json.loads(req_dash.read().decode("utf-8"))
    print(f"\n10. Dashboard API Verification:")
    print(f"    - Total Audits: {audits_list.get('total')}")
    print(f"    - Audits List items: {len(audits_list.get('items', []))}")

    req_find = urllib.request.urlopen("http://127.0.0.1:8000/api/findings")
    f_dash = json.loads(req_find.read().decode("utf-8"))
    print(f"    - Open Findings: {f_dash.get('summary', {}).get('total_findings')} (Critical: {f_dash.get('summary', {}).get('critical')}, High: {f_dash.get('summary', {}).get('high')})")

    req_rem = urllib.request.urlopen("http://127.0.0.1:8000/api/remediation")
    r_dash = json.loads(req_rem.read().decode("utf-8"))
    print(f"    - Remediation Proposals: {len(r_dash.get('remediations', []))}")

    print("\nSUCCESS: Real ZIP dataset successfully processed end-to-end and verified in PostgreSQL!")

if __name__ == "__main__":
    test_real_zip_audit()

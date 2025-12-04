import os
import re
import requests
import json

CLASSES_DIR = "classes"
REQ_FILE = "req.txt"
RES_FOLDER = "auraenabled_responses"

sensitive_pattern = re.compile(
    r"(crypt|hash|salt|pwd|pass|password|session|secret|key|cipher|md5|encrypt|security|token|consumer|auth)",
    re.IGNORECASE
)

os.makedirs(RES_FOLDER, exist_ok=True)

def get_namespace_prefix(xml_path):
    if not os.path.exists(xml_path):
        return ""
    with open(xml_path, "r", encoding="utf-8") as f:
        content = f.read()
    m = re.search(r"<namespacePrefix>(.*?)</namespacePrefix>", content, re.IGNORECASE)
    return m.group(1).strip() if m else ""

namespace_prefix = get_namespace_prefix("package.xml")

pattern = re.compile(
    r'@AuraEnabled(?:\s*\([^)]*\))?'              
    r'(?:\s*@\w+(?:\s*\([^)]*\))?)*'               
    r'(?:\s*(?://[^\n]*|/\*[\s\S]*?\*/))*'         
    r'\s*(?:public|private|protected|global|static|virtual|override|'
    r'abstract|final|transient)?'
    r'(?:\s+|[\r\n]+)'
    r'[\w<>\[\],\s]+'
    r'\b(\w+)\s*\(\s*\)',
    re.IGNORECASE
)

def find_auraenabled_no_param_methods(classes_dir):
    findings = {}
    for root, _, files in os.walk(classes_dir):
        for fn in files:
            if fn.endswith(".cls"):
                path = os.path.join(root, fn)
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                matches = pattern.findall(content)
                if matches:
                    classname = fn.replace(".cls", "")
                    findings[classname] = matches
    return findings

def extract_request_metadata():
    with open(REQ_FILE, "r", encoding="utf-8") as f:
        raw = f.read()

    m_post = re.search(r"POST\s+(\S+)", raw)
    if not m_post:
        raise ValueError("POST path not found in req.txt")
    post_path = m_post.group(1).strip()

    m_host = re.search(r"Host:\s*([^\s]+)", raw, re.IGNORECASE)
    if not m_host:
        raise ValueError("Host header not found in req.txt")
    host = m_host.group(1).strip()

    url = "https://" + host + post_path

    headers = {}
    for line in raw.splitlines():
        if ":" in line and not line.startswith("POST") and not line.lower().startswith("host"):
            k, v = line.split(":", 1)
            if k.lower() != "content-length":
                headers[k.strip()] = v.strip()

    parts = raw.split("\n\n", 1)
    if len(parts) < 2:
        raise ValueError("HTTP body missing")
    body = parts[1]

    return url, headers, body

def update_message_in_body(original_body, namespace, classname, method):
    payload = {
        "actions": [
            {
                "id": "656;a",
                "descriptor": "aura://ApexActionController/ACTION$execute",
                "callingDescriptor": "UNKNOWN",
                "params": {
                    "namespace": namespace,
                    "classname": classname,
                    "method": method,
                    "cacheable": False,
                    "isContinuation": False
                }
            }
        ]
    }

    new_message = json.dumps(payload)

    updated = re.sub(r"message=[^&\s]*", f"message={new_message}", original_body)
    return updated

def send_requests_for_methods():
    url, headers, original_body = extract_request_metadata()
    results = find_auraenabled_no_param_methods(CLASSES_DIR)

    if not results:
        print("No @AuraEnabled no-parameter methods found.")
        return

    print(f"\nUsing namespace prefix: '{namespace_prefix}'\n")

    for classname, methods in results.items():
        for method in methods:

            final_body = update_message_in_body(original_body, namespace_prefix, classname, method)

            resp = requests.post(url, headers=headers, data=final_body)

            try:
                resp_json = resp.json()
                return_value = resp_json.get("actions", [{}])[0].get("returnValue", "")
            except:
                return_value = f"Could not parse returnValue. Full response:\n{resp.text}"

            text = json.dumps(return_value) if isinstance(return_value, (dict, list)) else str(return_value)
            matches = sensitive_pattern.findall(text)
            sensitive_values = list(set(matches))

            outfile = os.path.join(RES_FOLDER, f"res_{classname}_{method}.txt")
            with open(outfile, "w", encoding="utf-8") as f:
                f.write("----------- REQUEST BODY -----------\n")
                f.write(final_body + "\n\n")
                f.write("----------- RETURN VALUE -----------\n")
                f.write(str(return_value) + "\n\n")
                if sensitive_values:
                    f.write("*** SENSITIVE DATA DETECTED: " + ", ".join(sensitive_values) + " ***\n")

            if sensitive_values:
                print(f"{classname}.{method} -> {resp.status_code} -> sensitive: {', '.join(sensitive_values)}")
            else:
                print(f"{classname}.{method} -> {resp.status_code}")

# Main function do not add anything here
if __name__ == "__main__":
    send_requests_for_methods()

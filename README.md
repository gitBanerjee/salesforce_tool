# 🔐 Password Echo Tool

The **Password Echo Tool** is an automated security testing utility designed to detect and trigger `@AuraEnabled` Apex methods that **do not require parameters**, capture their responses, and flag any **sensitive data exposure**.

This tool is especially useful for:
- Salesforce security testing
- Vulnerability assessment
- Sensitive data leakage detection
- Aura endpoint auditing

---

## ✅ How It Works

1. Place the script inside your **target package directory**  
   Example: 04t8udsf9898f

2. The tool will automatically:
- Locate the **`classes`** directory
- Scan all Apex classes
- Identify all `@AuraEnabled` methods that:
  - Have **no parameters**
  - Are callable without user input

3. Create a file named:
    req.txt

This file must contain a valid **`/aura` request**.

4. The tool will:
- Automatically generate the required request message
- Insert all relevant values needed to make the method callable
- Trigger the `/aura` request for every eligible method

---

## 📁 Output Format

- Each method response is saved as: res_<aura_enabled_function_name>.txt


- The tool also performs:
- Automatic response analysis
- **Sensitive data detection and flagging** in:
  - ✅ Terminal output
  - ✅ Response file

This helps quickly identify:
- Password leaks  
- Tokens  
- Secrets  
- Personally Identifiable Information (PII)  

---

## 🛡️ Use Cases

- Automated Salesforce security audits  
- Aura endpoint validation  
- Data exposure detection  
- Internal penetration testing  
- Security research

---

## ⚠️ Legal Disclaimer

This tool is intended **strictly for authorized security testing and educational purposes only**.

Do **NOT** use this tool on:
- Systems you do not own
- Applications without explicit written permission

The author is **not responsible for any misuse** of this tool.

---

## 📌 Notes

- The `req.txt` file must be present in the **same directory** as the script.
- Only `@AuraEnabled` methods **without parameters** are processed.
- All responses are logged automatically for review.

---

## 👤 Author

Maintained by the project contributor.


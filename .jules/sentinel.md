## 2026-06-05 - [XSS and Info Leakage Fixes]
**Vulnerability:** XSS via unsanitized IOC strings and MITRE technique names from API. Backend leaking raw exception messages.
**Learning:** Even when data comes from an "AI report" or "static analysis", it should be treated as untrusted user input if it originates from an uploaded file's content.
**Prevention:** Use `textContent` or proper HTML escaping for all dynamic data in the UI. Sanitize all backend error messages before sending to client.

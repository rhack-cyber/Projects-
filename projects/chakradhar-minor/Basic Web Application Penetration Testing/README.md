\# OWASP Juice Shop — Penetration Test (Docker)



\*\*Author:\*\* Yeddula Chakradhar Reddy



\## What



Focused penetration test of \*\*OWASP Juice Shop\*\* deployed locally via Docker.  

Purpose: identify and validate OWASP Top-10 style issues in a controlled lab (examples: exposed artifacts, SQL Injection, Broken Authentication, Broken Access Control, and XSS variants).



\*\*Target:\*\* Juice Shop running at `http://127.0.0.1:3000` (Docker image: `bkimminich/juice-shop`)



---



\## Quick start (deploy target)



1\. Ensure Docker is installed and running.

2\. Pull \& run Juice Shop:



docker pull bkimminich/juice-shop

docker run --rm -p 3000:3000 bkimminich/juice-shop



3\. Open the app in your browser: http://127.0.0.1:3000



Notes: This project performs testing only against a locally deployed, intentionally vulnerable training app. Do not run tests against systems you do not own or have explicit authorization to test.



\## Tools used



* Burp Suite (Community) — intercepting proxy for request/response inspection and PoC capture
* dirb — directory and content enumeration
* Firefox — manual validation and client-side behavior observation
* Docker (image: bkimminich/juice-shop) — target runtime
* Kali Linux — test host



\## What I tested (high level)



* Reconnaissance / discovery: directory enumeration to locate web-accessible artifacts and hidden endpoints.
* File handling checks: examined public directories and download behavior for exposed backups / docs.
* Data layer tests: identified inputs that did not appear to enforce safe query handling (validated in controlled manner).
* Authentication \& session checks: reviewed login/session behavior for weak handling and lack of protective controls.
* Access control: attempted cross-role access to sensitive resources to validate authorization enforcement.
* XSS surface: validated reflected, stored, and DOM injection points using non-destructive verification payloads (benign alerts) to prove execution in-browser.



\## Important findings (summary)



* Exposed artifacts: public /ftp contained a sensitive acquisitions.md and a backup file — demonstrates risk from leftover files.
* SQL injection (lab-validated): vulnerable input allowed extraction of demonstration data in the isolated test environment.
* Broken authentication \& session management: weak controls that increase risk of account abuse.
* Broken access control: insufficient server-side authorization checks on some endpoints.
* XSS (reflected, stored, DOM): unsafe client-side rendering and missing output encoding allowed script execution in the browser in multiple contexts (validated with benign tests).



\## Safe-testing notes



* All verification was performed on a local Docker instance of Juice Shop — no external targets.
* Exploit validation used non-destructive, benign indicators to prove impact (e.g., harmless browser alerts and controlled data checks).

# Secure Password Policy Testing — Minor Project

**Author:** Yeddula Chakradhar Reddy

## What
Two small Flask apps demonstrating password security:
- `app_phase1_vuln.py` — Phase-1 (vulnerable: MD5, no policy, lab SQLi)
- `app_phase2_fixed.py` — Phase-2 (hardened: PBKDF2, server-side policy, lockout)

## Quick start
1. Create and activate venv:
   
   python3 -m venv venv
   source venv/bin/activate
   pip install requests
   
2. Run Phase-1 (port 5000):

   python src/app_phase1_vuln.py

3. Run Phase-2 (port 5001):

   python src/app_phase2_fixed.py

-> open the server in browser.

-> Use /set_password_form (in browser) and /set_password (in kali terminal with curl command) to test complexity.

-> Use /login to test lockout behavior (in Kali terminal with curl command).

-> Use /sqli?name=’ OR ‘1’=’1 (lab-only) to extract stored hashes for offline cracking demos (in browser).


**Full code is in src/ (see app_phase1_vuln.py and app_phase2_fixed.py). See docs/ for architecture and full testing steps.**

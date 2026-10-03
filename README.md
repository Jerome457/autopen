# AutoPen — Collaborator Setup

This guide is for collaborators who have cloned the AutoPen repository onto a new **Ubuntu 22.04** machine and want to get the development environment running.

## 1. Clone the Repository

```bash
git clone <REPOSITORY-URL>
cd IS_project
```

---

## 2. Install System Dependencies

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv nmap hydra tshark wireshark sqlite3 openssh-server
```

Verify the important tools:

```bash
python3 --version
nmap --version
hydra -h
tshark --version
sqlite3 --version
```

---

## 3. Configure Wireshark/TShark Permissions

AutoPen uses TShark to capture traffic and should **not** need to run the entire application with `sudo`.

Add your user to the `wireshark` group:

```bash
sudo usermod -aG wireshark $USER
```

If the `wireshark` group does not exist or packet capture was not enabled during installation, run:

```bash
sudo dpkg-reconfigure wireshark-common
```

Select:

```text
Yes
```

Then:

```bash
sudo usermod -aG wireshark $USER
```

### Important

**Log out of Ubuntu completely and log back in.**

Then verify:

```bash
groups
```

`wireshark` should appear in the output.

Finally:

```bash
dumpcap -D
```

This should list network interfaces without requiring `sudo`.

For localhost testing, `lo` should be available.

---

## 4. Create the Python Environment

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the project dependencies:

```bash
pip install -r requirements.txt
```

Whenever you open a new terminal to work on AutoPen:

```bash
cd ~/IS_project
source .venv/bin/activate
```

Adjust the path if you cloned the repository somewhere else.

---

## 5. Run the Tests

Before making changes:

```bash
python -m unittest discover -s tests -v
```

The current MVP has:

```text
Ran 30 tests

OK
```

All tests should pass before starting development.

If the test count changes in later commits, the important requirement is that the complete suite reports `OK`.

---

# Local Development Target

The easiest development target is the collaborator's own machine using:

```text
127.0.0.1
```

This allows the complete pipeline to be tested without another VM.

## 6. Start OpenSSH

```bash
sudo systemctl enable --now ssh
```

Verify:

```bash
sudo systemctl status ssh
```

Then check that port 22 is listening:

```bash
ss -tln | grep :22
```

Verify Nmap can see it:

```bash
nmap -sV 127.0.0.1
```

You should see SSH on port 22.

Other services such as CUPS on port 631 may or may not exist on another collaborator's machine. **AutoPen does not require CUPS to be present.**

---

# Credential-Test Setup

Credential testing is optional, but the following setup is required to test the complete pipeline.

## 7. Create a Disposable Test Account

Do not use your normal Ubuntu account.

Create:

```bash
sudo adduser --disabled-password --gecos "" autopen-test
sudo passwd autopen-test
```

Choose a **throwaway password used only for this lab**.

Do not use your real Ubuntu password or any password used elsewhere.

---

## 8. Verify SSH Password Authentication

Run:

```bash
sudo sshd -T | grep '^passwordauthentication'
```

For the localhost credential-testing demo it should return:

```text
passwordauthentication yes
```

Now manually verify the test account:

```bash
ssh autopen-test@127.0.0.1
```

Enter the throwaway password.

If login succeeds:

```bash
exit
```

---

## 9. Create the Local Credential List

`data/credentials.txt` should not contain real credentials and should not be committed to Git.

Create it locally:

```bash
nano data/credentials.txt
```

Example:

```text
WrongTestPassword1!
YOUR_THROWAWAY_LAB_PASSWORD
WrongTestPassword2!
```

Then:

```bash
chmod 600 data/credentials.txt
```

---

# Running AutoPen

## 10. Full Local Test

Make sure the virtual environment is active:

```bash
source .venv/bin/activate
```

Then run:

```bash
python3 autopen.py \
    --target 127.0.0.1 \
    --interface lo \
    --ssh-user autopen-test \
    --password-list data/credentials.txt
```

A successful run should progress through:

```text
Start packet capture
        ↓
Nmap reconnaissance
        ↓
SSH discovered
        ↓
Controlled Hydra credential test
        ↓
Stop packet capture
        ↓
Parse PCAP
        ↓
Store results in SQLite
        ↓
Generate HTML report
```

Typical output:

```text
[*] AutoPen starting
[*] Target: 127.0.0.1

[*] Starting traffic capture on lo...

[*] Running reconnaissance...
[+] 22/tcp OPEN - ssh - OpenSSH ...

[*] SSH discovered on port 22
[*] Running controlled SSH credential test...
[+] SSH credential test completed
[+] Test credential matched

[*] Stopping traffic capture...
[+] Capture saved: data/capture.pcap

[*] Parsing captured traffic...
[+] <N> packets parsed

[*] Storing forensic data...
[+] Assessment stored in data/autopen.db

[*] Generating consolidated report...
[+] Report saved: reports/report.html

[✓] Assessment complete
```

Packet counts and discovered services will differ between machines.

---

# Generated Files

A successful run produces:

```text
data/capture.pcap
data/autopen.db
reports/report.html
```

### HTML Report

```bash
firefox reports/report.html
```

### PCAP

```bash
wireshark data/capture.pcap
```

or:

```bash
tshark -r data/capture.pcap | head
```

### SQLite

```bash
sqlite3 data/autopen.db
```

Inside SQLite:

```sql
.headers on
.mode column

SELECT * FROM assessments;
SELECT * FROM services;
SELECT * FROM credential_results;

SELECT assessment_id, COUNT(*)
FROM packets
GROUP BY assessment_id;
```

Exit:

```sql
.quit
```

---

# Running Without Hydra

Credential testing is opt-in.

For testing only reconnaissance, capture, PCAP parsing, SQLite and reporting:

```bash
python3 autopen.py \
    --target 127.0.0.1 \
    --interface lo
```

---

# Before Making Changes

Pull the latest version:

```bash
git checkout main
git pull
```

Create your own development branch:

```bash
git checkout -b <your-branch-name>
```

Example:

```bash
git checkout -b feature/report-improvements
```

Activate the environment:

```bash
source .venv/bin/activate
```

Run the tests:

```bash
python -m unittest discover -s tests -v
```

Make your changes.

Then run the complete test suite again:

```bash
python -m unittest discover -s tests -v
```

Do not merge code that breaks existing tests.

---

# Project Structure

```text
IS_project/
│
├── autopen.py
├── requirements.txt
│
├── modules/
│   ├── __init__.py
│   ├── recon.py
│   ├── capture.py
│   ├── credential_test.py
│   ├── pcap_parser.py
│   ├── database.py
│   └── report.py
│
├── tests/
│   ├── test_recon.py
│   ├── test_capture.py
│   ├── test_credential_test.py
│   ├── test_pcap_parser.py
│   ├── test_database.py
│   ├── test_report.py
│   └── test_autopen.py
│
├── data/
│   ├── credentials.txt      # local test data — don't commit
│   ├── capture.pcap         # generated
│   └── autopen.db           # generated
│
└── reports/
    └── report.html          # generated
```

---

# Git Rules

Do **not** commit:

```text
.venv/
data/credentials.txt
data/capture.pcap
data/autopen.db
reports/report.html
__pycache__/
*.pyc
```

These should be covered by `.gitignore`.

Before pushing:

```bash
git status
```

Make sure no passwords, PCAPs, databases, virtual environments, or other local artifacts are being committed.

Then:

```bash
git add <files-you-actually-changed>
git commit -m "Describe the change"
git push -u origin <your-branch-name>
```

Open a pull request rather than pushing development changes directly to `main`.

---

# Common Setup Problems

### `dumpcap: Permission denied`

Run:

```bash
groups
```

If `wireshark` is missing:

```bash
sudo usermod -aG wireshark $USER
```

Then **log out and log back in**.

Test:

```bash
dumpcap -D
```

---

### `hydra: command not found`

```bash
sudo apt install hydra
```

---

### `tshark: command not found`

```bash
sudo apt install tshark wireshark
```

---

### SSH port 22 is not detected

```bash
sudo systemctl enable --now ssh
nmap -sV 127.0.0.1
```

---

### Hydra does not match the test credential

First test manually:

```bash
ssh autopen-test@127.0.0.1
```

Then verify:

```bash
sudo sshd -T | grep '^passwordauthentication'
```

Finally check that the exact throwaway password is present in:

```text
data/credentials.txt
```

---

# Quick Collaborator Setup

For someone already familiar with Linux:

```bash
git clone <REPOSITORY-URL>
cd IS_project

sudo apt update
sudo apt install -y python3 python3-pip python3-venv nmap hydra tshark wireshark sqlite3 openssh-server

sudo usermod -aG wireshark $USER
```

**Log out and log back in**, then:

```bash
cd IS_project

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

dumpcap -D

python -m unittest discover -s tests -v
```

For the full credential-testing demo, additionally create the disposable `autopen-test` SSH account and local `data/credentials.txt` as described above.

## Safety

AutoPen is an educational security-testing project.

Only run reconnaissance and credential testing against isolated systems you own or systems for which you have explicit authorization.
# RacoonsPortScanner - Lightweight Vulnerability Aware Port Scanner

## What it does

Raccoon's Port Scanner is a simple but powerful Python based port scanner that:
- Scans open ports on a given host
- Grabs banners to identify services and versions
- Checks for known vulnerabilities from a local CVE database or online via CIRCL API
- Outputs results to a JSON file

## How to run

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. (Optional) Start the Fake Target Server
```bash
python3 fake_target.py
```

### 3. Run the Scanner
```bash
python3 main.py --online --export result.json
```

Input:
- IP: `127.0.0.1`
- Start port: `8080`
- End port: `8080`

## Output
Results will be printed and saved to `result.json`.

## Author
Aaditya Mandvilkar (Bitcamp Hackathon Project)

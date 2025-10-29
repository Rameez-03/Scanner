# README — Vulnerability Scanner (scan.py)

This README explains how to test the scanner end-to-end (banner grab → CVE lookup), how to run the included fake test server, and troubleshooting steps.

## Files in this folder

* `scan.py` — original scanner
* `test_server.py` — lightweight threaded HTTP server 


---

## Quick test (minimum steps)

1. **Start the fake server** (opens port 8080):

   ```powershell
   python .\test_server.py
   ```

   You should see: `Fake server running on http://0.0.0.0:8080 (Server: OpenSSL/1.0.1)`

2. **In a new terminal, run the patched scanner**:

   ```powershell
   python .\scan.py
   ```

   When prompted, enter:

   * `Enter IP to scan (or hostname): 127.0.0.1`
   * `Start port (default 1): 8080`
   * `End port (default 1024): 8080`
   * `Enable debug API query prints? (y/N): y`

   Expected: scanner grabs banner `OpenSSL 1.0.1`, extracts `OpenSSL 1.0.1` as a keyword, queries NVD/CIRCL and prints real CVEs.

---

## Manual verification of the fake server

Use PowerShell's `Invoke-WebRequest`:

```powershell
Invoke-WebRequest -Uri http://127.0.0.1:8080 -Method Head | Select-Object -ExpandProperty Headers
```

Look for `Server : OpenSSL/1.0.1` in the response headers.

---

## Notes & recommended settings

* The patched scanner sets `TIMEOUT = 5.0` and `THREADS = 100` by default. For quick local tests you can set `THREADS = 1` to avoid concurrency ti

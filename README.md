# Myntra SOR Scan & Pack

Windows GUI for loading Myntra SOR consignments from a read-only Consignment database and running the Myntra Partner Scan & Pack workflow from validated carton and barcode data.

## Features

- Fetches every consignment belonging to the Myntra SOR marketplace.
- Derives operator-friendly scenarios from the database, including:
  - Under packing
  - Packed · pending invoice
  - Ready for dispatch
- Filters the GUI by scenario while retaining database and local run status.
- Validates carton quantities and barcode items before opening the portal.
- Stores an active-run lock and local completion history to prevent accidental duplicate packing.
- Encrypts the database URL and Myntra credentials with Windows DPAPI.
- Uses read-only database transactions and does not update Consignment records.

## Run from source

1. Install Python 3.12 or later.
2. Install dependencies:

   ```powershell
   python -m pip install -r myntra_requirements.txt
   python -m playwright install chromium
   ```

3. Start the GUI:

   ```powershell
   python myntra_manual.py --app
   ```

4. Open **Settings**, enter the Consignment database URL and optional Myntra Partner credentials, then save. Secrets are encrypted for the current Windows user.

## Build the Windows executable

Run:

```powershell
.\build.ps1
```

The builder reads `CONSIGMENT_APP_DATABASE_URL` from a parent `.env` file or the protected local app settings. It creates `MyntraPartnerManual.exe` beside the source.

## Security

Local configuration, progress data, build output, and executables are excluded from Git. A packaged executable can contain the configured database connection, so distribute it only through an approved private channel.

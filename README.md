# NFCUR — NFC Universal Reader & Non-Destructive Editor

Deploy in 4 steps, works from any HTTPS URL.

---

## Deploy to Render

### 1. Push to GitHub

```bash
git init
git add .
git commit -m "Initial NFCUR commit"
git remote add origin https://github.com/YOUR_USERNAME/nfcur.git
git push -u origin main
```

### 2. Create a Render Web Service

1. Go to [render.com](https://render.com) → **New +** → **Web Service**
2. Connect your GitHub account and select the `nfcur` repository
3. Render auto-detects `render.yaml` — confirm the settings:
   - **Environment**: Python
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
4. Click **Create Web Service**

### 3. Wait ~60 seconds for the first deploy

Your app is live at `https://nfcur.onrender.com` (or your custom subdomain).

### 4. Use it

| Browser | NFC Support |
|---------|------------|
| Android Chrome / Edge / Samsung Internet | ✅ Full Web NFC |
| iOS Safari / Desktop | ✅ Inspector tab (paste hex) + Tag-Launch URL mode |

**Program a tag with your Render URL to auto-decode on tap:**
```
https://your-app.onrender.com/?uid=04A23BC1D4E5F6&data=<hex>&type=text
```

---

## Features

- **Read**: Scan NFC tags via Web NFC API; full UID telemetry + manufacturer lookup
- **Edit**: Non-destructive Read-Modify-Write with UID-guard and auto-backup
- **Inspector**: Paste raw hex / NDEF bytes for offline decode (iOS & desktop friendly)
- **History**: Persistent session history with search and JSON/TXT export
- **Server API**: `POST /api/decode` with `{"hex":"…","uid":"…"}` for server-side parsing

## Health check

```
GET /health → {"status":"ok","service":"NFCUR"}
```

# 🚀 24/7 Cloud Deployment Guide for Cyber Sentinel

This guide provides instructions to deploy the **Cyber Sentinel SOC Threat Analysis Dashboard** so that it remains accessible to anyone on the public internet **24/7 with zero hosting fees**.

---

## 🌟 Quick Overview: Hosting Options

| Platform | Cost | Uptime / Sleep | Setup Time | Custom Domain | Recommended For |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Streamlit Community Cloud** | **100% Free** | **24/7** (Auto-wakes instantly) | **2 minutes** | Yes (`*.streamlit.app`) | **Top Recommendation** |
| **Hugging Face Spaces** | **100% Free** | **24/7** (No sleep, 16GB RAM) | **3 minutes** | Yes (`hf.space`) | Excellent Alternative |
| **Render.com** | Free tier | Spins down after 15m idle | 3 minutes | Yes (`*.onrender.com`) | Web Service Backup |
| **Self-Hosted VPS (Docker)** | Free Tier / VPS | True 24/7 (Always on) | 10 minutes | Custom Domain + Let's Encrypt | Enterprise / Full Control |

---

## 🥇 Method 1: Streamlit Community Cloud (Recommended — 2 Minutes)

Streamlit Community Cloud is the official cloud platform built by Snowflake for Streamlit apps. It provides free automatic HTTPS, automatic continuous deployment on every `git push`, and a clean public URL.

### Step 1: Push your Code to GitHub

1. Open your browser and go to [GitHub - New Repository](https://github.com/new).
2. Set **Repository name** to `cyber-sentinel` (or any name you like).
3. Choose **Public** (or **Private**).
4. Do **not** initialize with README or .gitignore (we already created them locally).
5. Click **Create repository**.
6. Copy the commands shown under *"push an existing repository from the command line"*, or run the following in your terminal:

```powershell
cd "c:\Users\Ashwin Chikkala\OneDrive\Desktop\cyber project"
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/cyber-sentinel.git
git branch -M main
git push -u origin main
```

*(Replace `<YOUR_GITHUB_USERNAME>` with your actual GitHub username).*

---

### Step 2: Deploy on Streamlit Cloud

1. Go to [share.streamlit.io](https://share.streamlit.io/) (or [streamlit.io/cloud](https://streamlit.io/cloud)).
2. Click **Sign in with GitHub**.
3. Once logged in, click the **"New app"** button.
4. Fill in the deployment form:
   - **Repository**: `<YOUR_GITHUB_USERNAME>/cyber-sentinel`
   - **Branch**: `main`
   - **Main file path**: `app.py`
   - **App URL (Customize)**: `cyber-sentinel-soc` (or any available subdomain).
5. Click **Deploy!**.

Within 60–90 seconds, your application will build dependencies and go live at:
```text
https://<your-custom-subdomain>.streamlit.app
```

---

## 🥈 Method 2: Hugging Face Spaces (Streamlit SDK — 100% Free, 16GB RAM)

Hugging Face Spaces offers a dedicated Streamlit runtime with 2 vCPUs and 16GB RAM that never goes to sleep.

1. Go to [Hugging Face](https://huggingface.co/) and sign up or log in.
2. Click on your profile icon in the top right -> **New Space**.
3. Configure your Space:
   - **Space Name**: `cyber-sentinel`
   - **License**: `mit`
   - **Space SDK**: Select **Streamlit**.
   - **Space hardware**: `CPU basic • 2 vCPU • 16GB RAM • Free`.
   - **Visibility**: `Public`.
4. Click **Create Space**.
5. You can now push your files using Git:
   ```powershell
   git remote add space https://huggingface.co/spaces/<YOUR_HF_USERNAME>/cyber-sentinel
   git push space main
   ```
6. Hugging Face will automatically detect `requirements.txt` and launch `app.py`. Your live link will look like:
   ```text
   https://huggingface.co/spaces/<YOUR_HF_USERNAME>/cyber-sentinel
   ```

---

## 🥉 Method 3: Deploy with Docker on Any Cloud VPS (AWS, DigitalOcean, Oracle)

If you have a Linux server (e.g. AWS EC2, DigitalOcean Droplet, Linode, or Oracle Cloud Always-Free VM):

### 1. Clone your repository on the server
```bash
git clone https://github.com/<YOUR_GITHUB_USERNAME>/cyber-sentinel.git
cd cyber-sentinel
```

### 2. Launch with Docker Compose
```bash
docker compose up -d --build
```

The app will run in the background on port `8501` with `restart: unless-stopped` (will automatically restart even after system reboots).

### 3. (Optional) Setup Nginx & Free SSL with Certbot
```nginx
# /etc/nginx/sites-available/cyber-sentinel
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8501;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
    }
}
```
Obtain free SSL:
```bash
sudo certbot --nginx -d yourdomain.com
```

---

## 🔐 Credentials for Public Reviewers

When public visitors access your deployed dashboard, they can sign in using the built-in role credentials:

| Role | Username | Password |
| :--- | :--- | :--- |
| **Lead Administrator** | `admin` | `Admin@12345` |
| **Security Analyst** | `analyst` | `Analyst@12345` |
| **Incident Auditor** | `viewer` | `Viewer@12345` |

*(As an administrator, you can change passwords or add new analysts directly within the **User Management** section of the dashboard).*

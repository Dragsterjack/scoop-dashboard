# ⚡ Quick Start Guide

## 🚀 Get Running in 5 Minutes

### 1. Configure Discord App
1. Go to https://discord.com/developers/applications
2. Create new application
3. Copy Client ID and Client Secret
4. Add OAuth2 redirect: `http://localhost:5000/callback` (for testing)
5. Get your bot token from Bot section

### 2. Update app.py
```python
# Lines 11-16 in app.py
DISCORD_CLIENT_ID = "paste_client_id_here"
DISCORD_CLIENT_SECRET = "paste_client_secret_here"
DISCORD_REDIRECT_URI = "http://localhost:5000/callback"
DISCORD_BOT_TOKEN = "paste_bot_token_here"
GUILD_ID = 1324404577608667157  # Already set
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run Locally
```bash
python app.py
```

Go to `http://localhost:5000`

### 5. Deploy to Railway

**Easy Way:**
1. Push to GitHub
2. Go to railway.app
3. "New Project" → "Deploy from GitHub"
4. Done!

**What Railway Needs:**
- ✅ requirements.txt (included)
- ✅ railway.json (included)
- ✅ Python app (app.py)

Railway will:
- Auto-detect Python
- Install requirements
- Run `python app.py`
- Give you a URL

### 6. Update Discord Redirect
1. Get your Railway URL (e.g., `https://yourapp.railway.app`)
2. Update in Discord Developer Portal OAuth2 redirects
3. Add: `https://yourapp.railway.app/callback`
4. Update in app.py: `DISCORD_REDIRECT_URI`

## ✅ That's It!

Your dashboard is live!

## 🧪 Test It

1. Go to your website
2. Click "Login with Discord"
3. Authorize
4. See dashboard
5. If you're staff → Click "Moderation Panel"
6. Try banning a test user

## 🆘 Quick Fixes

**Can't login?**
- Check redirect URI matches in Discord Portal and app.py

**Can't see mod panel?**
- Make sure you have Staff role (ID: 1462624028048101477)

**Actions not working?**
- Check bot has Ban Members, Kick Members, Moderate Members permissions
- Bot role must be higher than target user's role

**Members not loading?**
- Check bot token in app.py
- Check GUILD_ID is correct

## 📚 Full Docs

See `README.md` for complete setup and features!

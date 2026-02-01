# 🚀 Scoop Creations Web Dashboard - Complete Setup Guide

## 📋 What This Is

A full-featured web dashboard for your Discord server with:
- ✅ Discord OAuth2 login
- ✅ Role-based permissions (Owner, Staff, Support)
- ✅ Complete moderation panel (ban, kick, timeout, warn)
- ✅ Warning system with tracking
- ✅ Moderation logs
- ✅ Member search and management
- ✅ Mobile responsive design

## 🎯 Features

### For Regular Members:
- View profile and roles
- Link Roblox account (when you add that feature)
- Manage personal settings

### For Staff/Support:
- Search all server members
- Ban users with reason and message deletion
- Kick users
- Timeout users (5 min - 1 week)
- Warn users with severity levels
- View warning history
- View moderation logs

### For Owners:
- Everything staff can do
- Can moderate other staff members
- Access to analytics (when you add it)

## 🔧 Setup Instructions

### Step 1: Create Discord Application

1. Go to https://discord.com/developers/applications
2. Click "New Application"
3. Name it "Scoop Dashboard" (or whatever you want)
4. Go to "OAuth2" section in sidebar
5. Copy your **Client ID** and **Client Secret** (you'll need these)
6. Add Redirect URL: `https://yourdomain.railway.app/callback`
   - You'll update this once you deploy to Railway

### Step 2: Configure the App

Open `app.py` and update these lines (around line 11-16):

```python
DISCORD_CLIENT_ID = "YOUR_CLIENT_ID_HERE"  # From Discord Developer Portal
DISCORD_CLIENT_SECRET = "YOUR_CLIENT_SECRET_HERE"  # From Discord Developer Portal
DISCORD_REDIRECT_URI = "https://yourdomain.railway.app/callback"  # Your Railway domain
DISCORD_BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"  # Your bot's token
GUILD_ID = 1324404577608667157  # Your server ID (already set)
```

### Step 3: Deploy to Railway

**Option A: Deploy from GitHub (Recommended)**

1. Create a GitHub repository
2. Push this entire `web_dashboard` folder to the repo
3. Go to https://railway.app
4. Sign up/Login
5. Click "New Project"
6. Select "Deploy from GitHub repo"
7. Choose your repository
8. Railway will auto-detect it's a Python app and deploy!
9. Once deployed, click your app and go to "Settings"
10. Find your domain (something like `yourapp.railway.app`)
11. Copy this domain

**Option B: Deploy with Railway CLI**

```bash
# Install Railway CLI
npm i -g @railway/cli

# Login
railway login

# Initialize project
railway init

# Deploy
railway up
```

### Step 4: Update Discord OAuth2 Redirect

1. Go back to Discord Developer Portal
2. Go to OAuth2 → Redirects
3. Add: `https://your-railway-domain.railway.app/callback`
4. Save changes

### Step 5: Update app.py with Railway Domain

Update the `DISCORD_REDIRECT_URI` in `app.py`:
```python
DISCORD_REDIRECT_URI = "https://your-railway-domain.railway.app/callback"
```

Then redeploy (Railway auto-redeploys on git push if using GitHub)

### Step 6: Enable Required Bot Permissions

Your bot needs these permissions:
- ✅ Ban Members
- ✅ Kick Members
- ✅ Moderate Members (for timeouts)
- ✅ Manage Roles
- ✅ View Audit Log (recommended)

**Bot Permission Integer:** `1099511627782`

Invite link format:
```
https://discord.com/api/oauth2/authorize?client_id=YOUR_CLIENT_ID&permissions=1099511627782&scope=bot%20applications.commands
```

## 🎮 How to Use

### For Users:
1. Go to your website (e.g., `https://yourapp.railway.app`)
2. Click "Login with Discord"
3. Authorize the application
4. You'll see your dashboard!

### For Staff:
1. Login with Discord
2. If you have Staff, Support, or Owner role, you'll see "Moderation Panel" button
3. Click it to access mod tools
4. Search for members
5. Click action buttons to ban/kick/timeout/warn

### Moderation Actions:

**Ban:**
- Click "⛔ Ban" on any member
- Enter reason (required)
- Choose message deletion (optional)
- Confirm

**Kick:**
- Click "👢 Kick"
- Enter reason
- Confirm

**Timeout:**
- Click "⏱️ Timeout"
- Choose duration (5 min to 1 week)
- Enter reason
- Confirm

**Warn:**
- Click "⚠️ Warn"
- Choose severity (Low/Medium/High)
- Enter reason
- Confirm
- Warning is tracked in database

## 📊 Database

The app automatically creates `dashboard.db` (SQLite) with these tables:
- `warnings` - User warnings with severity
- `mod_logs` - All moderation actions

**Location:** Same directory as `app.py`

Railway will persist this database for you.

## 🔐 Security Features

- ✅ Role-based permissions
- ✅ Staff can't ban other staff
- ✅ All actions are logged
- ✅ Secure OAuth2 flow
- ✅ Session-based authentication

## 🎨 Customization

### Change Colors:
Edit the CSS in the template files:
- `templates/index.html` - Landing page
- `templates/dashboard.html` - User dashboard
- `templates/moderation.html` - Mod panel

Current brand color: `#c8d0d6` (Your Scoop brand color)

### Add New Features:

**Add Analytics:**
```python
@app.route('/api/analytics')
@login_required
@staff_required
def api_analytics():
    # Return server stats
    pass
```

**Add Role Management:**
```python
@app.route('/api/assign-role', methods=['POST'])
@login_required
def api_assign_role():
    # Assign role to user
    pass
```

## 🐛 Troubleshooting

### "Invalid OAuth2 redirect_uri"
- Make sure the redirect URI in Discord Developer Portal matches exactly
- Should be: `https://your-domain.railway.app/callback`

### "403 Forbidden" when trying to moderate
- Check that user has the correct role (Staff/Support/Owner)
- Role IDs are configured in `app.py` (lines 18-20)

### "Failed to ban/kick user"
- Make sure bot has the required permissions
- Bot's role must be higher than the role of the user being moderated
- Bot token is correct in `app.py`

### Database errors
- Delete `dashboard.db` and restart - it will recreate

### "Members not loading"
- Check bot token is correct
- Check GUILD_ID is correct
- Make sure bot is in the server

## 📱 Mobile Support

The dashboard is fully responsive and works on:
- 📱 Mobile phones
- 📱 Tablets
- 💻 Desktop

## 🔄 Updates & Maintenance

### Update the app:
1. Make changes to your code
2. Push to GitHub (if using GitHub deployment)
3. Railway auto-deploys

### View logs:
```bash
railway logs
```

### Database backup:
```bash
# Download database from Railway
railway run python -c "import shutil; shutil.copy('dashboard.db', 'backup.db')"
```

## 🚀 Next Steps

Things you could add:
1. **Analytics dashboard** - Server growth, activity graphs
2. **Roblox linking** - Connect Discord to Roblox accounts
3. **Role shop** - Let users buy roles with virtual currency
4. **Custom commands** - Web interface to create custom bot commands
5. **Ticket system** - Web-based support tickets
6. **Announcement scheduler** - Schedule announcements
7. **Member verification** - Custom verification flow
8. **Appeal system** - Let banned users appeal

## 📞 Support

If you need help:
1. Check Railway logs: `railway logs`
2. Check browser console (F12) for errors
3. Check Discord Developer Portal OAuth2 settings
4. Make sure bot permissions are correct

## 🎉 You're Done!

Your professional web dashboard is now live! Staff can moderate from anywhere, anytime.

**Test it:**
1. Login as a regular member - should see basic dashboard
2. Login as staff - should see moderation panel
3. Try banning a test account
4. Check mod logs tab

Enjoy your new dashboard! 🚀

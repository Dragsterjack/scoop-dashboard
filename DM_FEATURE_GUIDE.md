# 💬 DM Feature Added!

## What's New:

You can now send DMs to any server member directly through the web dashboard!

## How to Use:

### As a Staff Member:

1. Go to https://scoop.up.railway.app/moderation
2. Search for any member
3. Click the new **💬 DM** button (purple button, first in the row)
4. Type your message
5. Click "Send DM"
6. The bot will DM them instantly!

## Features:

✅ **Works as the bot** - Messages appear from your Discord bot
✅ **Logged** - All DMs are logged in mod logs
✅ **Staff only** - Only staff/support/owner roles can send DMs
✅ **Clean interface** - Easy modal with message box
✅ **Error handling** - Shows errors if DM fails (e.g., user has DMs disabled)

## Use Cases:

- 📢 **Announcements** - DM users about events, updates
- 🎟️ **Support** - Follow up with users who need help
- ⚠️ **Warnings** - Send custom warning messages
- 🎁 **Rewards** - Notify winners of giveaways
- 📨 **General contact** - Reach out to specific members

## How It Works:

1. Staff clicks DM button on a user
2. Modal opens with message box
3. Staff types message
4. Frontend sends to `/api/dm` endpoint
5. Backend creates DM channel with user via Discord API
6. Bot sends the message
7. Action is logged in mod logs
8. Success/failure shown to staff

## Button Layout:

Each member now has 5 action buttons:
- **💬 DM** (purple) - Send direct message
- **⛔ Ban** (red) - Ban the user
- **👢 Kick** (orange) - Kick the user
- **⏱️ Timeout** (yellow) - Timeout the user
- **⚠️ Warn** (blue) - Warn the user

## Mod Log Entry:

When you send a DM, it appears in mod logs as:
```
Action: DM
Target: username
Moderator: your_name
Reason: "Sent DM: [first 50 chars of message]..."
Time: timestamp
```

## Notes:

- Messages are sent from the bot account
- Users can reply (DMs go to bot, not back to dashboard)
- If user has DMs disabled, you'll see an error
- No character limit (Discord's 2000 char limit applies)
- Supports Discord markdown formatting

## Security:

- ✅ Staff/Support/Owner roles only
- ✅ All DMs logged
- ✅ User must be in server
- ✅ Cannot DM bots
- ✅ Respects Discord's DM privacy settings

## Deploy:

To deploy this update:

1. Replace `moderation.html` in your GitHub repo
2. Replace `app.py` in your GitHub repo
3. Railway will auto-deploy
4. Feature will be live in ~2 minutes!

Enjoy your new DM feature! 🚀

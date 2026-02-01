from flask import Flask, render_template, redirect, url_for, session, request, jsonify
from flask_cors import CORS
import requests
import os
from datetime import datetime, timedelta
import json
import sqlite3
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)
CORS(app)

# ===== CONFIGURATION - USING ENVIRONMENT VARIABLES FOR SECURITY =====
DISCORD_CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI", "https://scoop-dashboard.onrender.com/callback")
DISCORD_BOT_TOKEN = os.environ.get("DISCORD_BOT_TOKEN")
GUILD_ID = int(os.environ.get("GUILD_ID", "1324404577608667157"))

# Role IDs with permissions
OWNER_ROLE_ID = 1462559124024983704
STAFF_ROLE_ID = 1462624028048101477
SUPPORT_ROLE_ID = 1462809376598396990

# Discord API endpoints
DISCORD_API_BASE = "https://discord.com/api/v10"
DISCORD_OAUTH_URL = f"https://discord.com/api/oauth2/authorize?client_id={DISCORD_CLIENT_ID}&redirect_uri={DISCORD_REDIRECT_URI}&response_type=code&scope=identify%20guilds%20guilds.members.read"

# ===== DATABASE SETUP =====
def init_db():
    conn = sqlite3.connect('dashboard.db')
    c = conn.cursor()
    
    # Warnings table
    c.execute('''CREATE TABLE IF NOT EXISTS warnings
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id TEXT,
                  user_name TEXT,
                  warned_by TEXT,
                  warned_by_name TEXT,
                  reason TEXT,
                  severity TEXT,
                  timestamp TEXT)''')
    
    # Mod actions log
    c.execute('''CREATE TABLE IF NOT EXISTS mod_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  action_type TEXT,
                  target_user_id TEXT,
                  target_user_name TEXT,
                  moderator_id TEXT,
                  moderator_name TEXT,
                  reason TEXT,
                  duration TEXT,
                  timestamp TEXT)''')
    
    conn.commit()
    conn.close()

init_db()

# ===== HELPER FUNCTIONS =====
def get_discord_user(access_token):
    """Get user info from Discord"""
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(f"{DISCORD_API_BASE}/users/@me", headers=headers)
    return response.json() if response.status_code == 200 else None

def get_user_guilds(access_token):
    """Get user's guilds"""
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(f"{DISCORD_API_BASE}/users/@me/guilds", headers=headers)
    return response.json() if response.status_code == 200 else []

def get_guild_member(user_id):
    """Get member info from guild using bot token"""
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
    response = requests.get(f"{DISCORD_API_BASE}/guilds/{GUILD_ID}/members/{user_id}", headers=headers)
    return response.json() if response.status_code == 200 else None

def get_all_members():
    """Get all guild members"""
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
    response = requests.get(f"{DISCORD_API_BASE}/guilds/{GUILD_ID}/members?limit=1000", headers=headers)
    return response.json() if response.status_code == 200 else []

def get_guild_roles():
    """Get all guild roles"""
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
    response = requests.get(f"{DISCORD_API_BASE}/guilds/{GUILD_ID}/roles", headers=headers)
    return response.json() if response.status_code == 200 else []

def has_permission(user_roles, required_level="staff"):
    """Check if user has required permission level"""
    role_ids = [str(role) for role in user_roles]
    
    if required_level == "owner":
        return str(OWNER_ROLE_ID) in role_ids
    elif required_level == "staff":
        return str(STAFF_ROLE_ID) in role_ids or str(OWNER_ROLE_ID) in role_ids
    elif required_level == "support":
        return str(SUPPORT_ROLE_ID) in role_ids or str(STAFF_ROLE_ID) in role_ids or str(OWNER_ROLE_ID) in role_ids
    
    return False

def log_action(action_type, target_user_id, target_user_name, moderator_id, moderator_name, reason, duration=None):
    """Log moderation action to database"""
    conn = sqlite3.connect('dashboard.db')
    c = conn.cursor()
    c.execute('''INSERT INTO mod_logs (action_type, target_user_id, target_user_name, 
                 moderator_id, moderator_name, reason, duration, timestamp)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
              (action_type, target_user_id, target_user_name, moderator_id, moderator_name, 
               reason, duration, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def send_dm_notification(user_id, action_type, reason, moderator_name, duration=None):
    """Send DM notification to user about moderation action"""
    try:
        headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "Content-Type": "application/json"}
        
        # Create DM channel
        dm_data = {"recipient_id": user_id}
        dm_response = requests.post(
            f"{DISCORD_API_BASE}/users/@me/channels",
            headers=headers,
            json=dm_data
        )
        
        if dm_response.status_code != 200:
            return False
        
        channel_id = dm_response.json()['id']
        
        # Create message based on action type
        if action_type == "ban":
            message = f"🚫 **You have been banned from Scoop Creations**\n\n**Reason:** {reason}\n**Moderator:** {moderator_name}\n\nIf you believe this was a mistake, please contact the server staff."
        elif action_type == "kick":
            message = f"👢 **You have been kicked from Scoop Creations**\n\n**Reason:** {reason}\n**Moderator:** {moderator_name}\n\nYou can rejoin the server, but please review the rules."
        elif action_type == "timeout":
            duration_text = duration if duration else "unknown duration"
            message = f"⏱️ **You have been timed out in Scoop Creations**\n\n**Duration:** {duration_text}\n**Reason:** {reason}\n**Moderator:** {moderator_name}\n\nYou will not be able to send messages until the timeout expires."
        elif action_type == "warn":
            message = f"⚠️ **You have been warned in Scoop Creations**\n\n**Reason:** {reason}\n**Moderator:** {moderator_name}\n\nPlease review the server rules to avoid further warnings."
        else:
            message = f"📢 **Moderation Action**\n\n**Action:** {action_type}\n**Reason:** {reason}\n**Moderator:** {moderator_name}"
        
        # Send message
        message_data = {"content": message}
        send_response = requests.post(
            f"{DISCORD_API_BASE}/channels/{channel_id}/messages",
            headers=headers,
            json=message_data
        )
        
        return send_response.status_code in [200, 201]
    except Exception as e:
        print(f"Failed to send DM notification: {e}")
        return False

# ===== DECORATORS =====
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def staff_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('index'))
        
        member = get_guild_member(session['user']['id'])
        if not member or not has_permission(member.get('roles', []), 'support'):
            return jsonify({"error": "Insufficient permissions"}), 403
        
        return f(*args, **kwargs)
    return decorated_function

# ===== ROUTES =====
@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login')
def login():
    return redirect(DISCORD_OAUTH_URL)

@app.route('/callback')
def callback():
    code = request.args.get('code')
    if not code:
        return redirect(url_for('index'))
    
    # Exchange code for access token
    data = {
        'client_id': DISCORD_CLIENT_ID,
        'client_secret': DISCORD_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': DISCORD_REDIRECT_URI
    }
    
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(f"{DISCORD_API_BASE}/oauth2/token", data=data, headers=headers)
    
    if response.status_code == 200:
        tokens = response.json()
        access_token = tokens['access_token']
        
        # Get user info
        user = get_discord_user(access_token)
        if user:
            session['user'] = user
            session['access_token'] = access_token
            return redirect(url_for('dashboard'))
    
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = session['user']
    member = get_guild_member(user['id'])
    
    if not member:
        return "You are not a member of the server!", 403
    
    # Check permissions
    is_staff = has_permission(member.get('roles', []), 'support')
    is_owner = has_permission(member.get('roles', []), 'owner')
    
    return render_template('dashboard.html', 
                         user=user, 
                         member=member, 
                         is_staff=is_staff,
                         is_owner=is_owner)

@app.route('/moderation')
@login_required
@staff_required
def moderation():
    user = session['user']
    member = get_guild_member(user['id'])
    is_owner = has_permission(member.get('roles', []), 'owner')
    
    return render_template('moderation.html', 
                         user=user, 
                         is_owner=is_owner)

# ===== API ENDPOINTS =====
@app.route('/api/members')
@login_required
@staff_required
def api_members():
    """Get all server members"""
    members = get_all_members()
    roles = get_guild_roles()
    
    # Create role lookup
    role_dict = {role['id']: role for role in roles}
    
    # Format member data
    formatted_members = []
    for member in members:
        user = member.get('user', {})
        member_roles = []
        for role_id in member.get('roles', []):
            if role_id in role_dict:
                member_roles.append(role_dict[role_id]['name'])
        
        formatted_members.append({
            'id': user.get('id'),
            'username': user.get('username'),
            'discriminator': user.get('discriminator'),
            'avatar': f"https://cdn.discordapp.com/avatars/{user.get('id')}/{user.get('avatar')}.png" if user.get('avatar') else None,
            'roles': member_roles,
            'joined_at': member.get('joined_at'),
            'nick': member.get('nick')
        })
    
    return jsonify(formatted_members)

@app.route('/api/member/<user_id>')
@login_required
@staff_required
def api_member(user_id):
    """Get specific member info"""
    member = get_guild_member(user_id)
    
    if not member:
        return jsonify({"error": "Member not found"}), 404
    
    # Get warnings for this user
    conn = sqlite3.connect('dashboard.db')
    c = conn.cursor()
    c.execute('SELECT * FROM warnings WHERE user_id = ? ORDER BY timestamp DESC', (user_id,))
    warnings = []
    for row in c.fetchall():
        warnings.append({
            'id': row[0],
            'reason': row[4],
            'severity': row[5],
            'warned_by': row[3],
            'timestamp': row[6]
        })
    conn.close()
    
    member['warnings'] = warnings
    return jsonify(member)

@app.route('/api/ban', methods=['POST'])
@login_required
@staff_required
def api_ban():
    """Ban a user"""
    data = request.json
    user_id = data.get('user_id')
    reason = data.get('reason', 'No reason provided')
    delete_days = data.get('delete_days', 0)
    
    if not user_id:
        return jsonify({"error": "User ID required"}), 400
    
    # Check if moderator can ban this user
    moderator = session['user']
    target_member = get_guild_member(user_id)
    moderator_member = get_guild_member(moderator['id'])
    
    if not has_permission(moderator_member.get('roles', []), 'staff'):
        return jsonify({"error": "Insufficient permissions"}), 403
    
    # Send DM notification BEFORE banning (they need to be in server to receive DM)
    send_dm_notification(user_id, "ban", reason, moderator['username'])
    
    # Execute ban via bot
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
    ban_data = {"delete_message_days": delete_days}
    response = requests.put(
        f"{DISCORD_API_BASE}/guilds/{GUILD_ID}/bans/{user_id}",
        headers=headers,
        json=ban_data,
        params={"reason": reason}
    )
    
    if response.status_code in [200, 204]:
        # Log action
        target_user = target_member.get('user', {})
        log_action('ban', user_id, target_user.get('username', 'Unknown'), 
                  moderator['id'], moderator['username'], reason)
        return jsonify({"success": True, "message": "User banned successfully"})
    else:
        return jsonify({"error": "Failed to ban user", "details": response.text}), 500

@app.route('/api/kick', methods=['POST'])
@login_required
@staff_required
def api_kick():
    """Kick a user"""
    data = request.json
    user_id = data.get('user_id')
    reason = data.get('reason', 'No reason provided')
    
    if not user_id:
        return jsonify({"error": "User ID required"}), 400
    
    moderator = session['user']
    target_member = get_guild_member(user_id)
    
    # Send DM notification BEFORE kicking (they need to be in server to receive DM)
    send_dm_notification(user_id, "kick", reason, moderator['username'])
    
    # Execute kick
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
    response = requests.delete(
        f"{DISCORD_API_BASE}/guilds/{GUILD_ID}/members/{user_id}",
        headers=headers,
        params={"reason": reason}
    )
    
    if response.status_code in [200, 204]:
        target_user = target_member.get('user', {})
        log_action('kick', user_id, target_user.get('username', 'Unknown'),
                  moderator['id'], moderator['username'], reason)
        return jsonify({"success": True, "message": "User kicked successfully"})
    else:
        return jsonify({"error": "Failed to kick user"}), 500

@app.route('/api/timeout', methods=['POST'])
@login_required
@staff_required
def api_timeout():
    """Timeout a user"""
    data = request.json
    user_id = data.get('user_id')
    duration = data.get('duration', 60)  # minutes
    reason = data.get('reason', 'No reason provided')
    
    if not user_id:
        return jsonify({"error": "User ID required"}), 400
    
    moderator = session['user']
    target_member = get_guild_member(user_id)
    
    # Calculate timeout end time
    timeout_until = (datetime.now() + timedelta(minutes=duration)).isoformat()
    
    # Execute timeout
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "Content-Type": "application/json"}
    timeout_data = {"communication_disabled_until": timeout_until}
    response = requests.patch(
        f"{DISCORD_API_BASE}/guilds/{GUILD_ID}/members/{user_id}",
        headers=headers,
        json=timeout_data
    )
    
    if response.status_code == 200:
        # Send DM notification
        duration_text = f"{duration} minutes"
        send_dm_notification(user_id, "timeout", reason, moderator['username'], duration_text)
        
        target_user = target_member.get('user', {})
        log_action('timeout', user_id, target_user.get('username', 'Unknown'),
                  moderator['id'], moderator['username'], reason, duration_text)
        return jsonify({"success": True, "message": "User timed out successfully"})
    else:
        return jsonify({"error": "Failed to timeout user", "details": response.text}), 500

@app.route('/api/warn', methods=['POST'])
@login_required
@staff_required
def api_warn():
    """Warn a user"""
    data = request.json
    user_id = data.get('user_id')
    reason = data.get('reason', 'No reason provided')
    severity = data.get('severity', 'Medium')
    
    if not user_id:
        return jsonify({"error": "User ID required"}), 400
    
    moderator = session['user']
    target_member = get_guild_member(user_id)
    target_user = target_member.get('user', {})
    
    # Add warning to database
    conn = sqlite3.connect('dashboard.db')
    c = conn.cursor()
    c.execute('''INSERT INTO warnings (user_id, user_name, warned_by, warned_by_name, reason, severity, timestamp)
                 VALUES (?, ?, ?, ?, ?, ?, ?)''',
              (user_id, target_user.get('username', 'Unknown'), moderator['id'], 
               moderator['username'], reason, severity, datetime.now().isoformat()))
    conn.commit()
    
    # Check total warnings
    c.execute('SELECT COUNT(*) FROM warnings WHERE user_id = ?', (user_id,))
    warning_count = c.fetchone()[0]
    conn.close()
    
    # Send DM notification
    send_dm_notification(user_id, "warn", reason, moderator['username'])
    
    # Log action
    log_action('warn', user_id, target_user.get('username', 'Unknown'),
              moderator['id'], moderator['username'], reason)
    
    return jsonify({
        "success": True, 
        "message": "User warned successfully",
        "warning_count": warning_count
    })

@app.route('/api/mod-logs')
@login_required
@staff_required
def api_mod_logs():
    """Get moderation logs"""
    conn = sqlite3.connect('dashboard.db')
    c = conn.cursor()
    c.execute('SELECT * FROM mod_logs ORDER BY timestamp DESC LIMIT 100')
    
    logs = []
    for row in c.fetchall():
        logs.append({
            'id': row[0],
            'action_type': row[1],
            'target_user_id': row[2],
            'target_user_name': row[3],
            'moderator_id': row[4],
            'moderator_name': row[5],
            'reason': row[6],
            'duration': row[7],
            'timestamp': row[8]
        })
    
    conn.close()
    return jsonify(logs)

@app.route('/api/warnings/<user_id>')
@login_required
@staff_required
def api_warnings(user_id):
    """Get warnings for a user"""
    conn = sqlite3.connect('dashboard.db')
    c = conn.cursor()
    c.execute('SELECT * FROM warnings WHERE user_id = ? ORDER BY timestamp DESC', (user_id,))
    
    warnings = []
    for row in c.fetchall():
        warnings.append({
            'id': row[0],
            'user_id': row[1],
            'user_name': row[2],
            'warned_by': row[3],
            'warned_by_name': row[4],
            'reason': row[5],
            'severity': row[6],
            'timestamp': row[7]
        })
    
    conn.close()
    return jsonify(warnings)

@app.route('/api/dm', methods=['POST'])
@login_required
@staff_required
def api_dm():
    """Send a DM to a user"""
    data = request.json
    user_id = data.get('user_id')
    message = data.get('message')
    
    if not user_id or not message:
        return jsonify({"error": "User ID and message required"}), 400
    
    moderator = session['user']
    target_member = get_guild_member(user_id)
    
    if not target_member:
        return jsonify({"error": "User not found"}), 404
    
    # Create DM channel with user
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "Content-Type": "application/json"}
    
    # Step 1: Create DM channel
    dm_data = {"recipient_id": user_id}
    dm_response = requests.post(
        f"{DISCORD_API_BASE}/users/@me/channels",
        headers=headers,
        json=dm_data
    )
    
    if dm_response.status_code != 200:
        return jsonify({"error": "Failed to create DM channel", "details": dm_response.text}), 500
    
    dm_channel = dm_response.json()
    channel_id = dm_channel['id']
    
    # Step 2: Send message to DM channel
    message_data = {"content": message}
    send_response = requests.post(
        f"{DISCORD_API_BASE}/channels/{channel_id}/messages",
        headers=headers,
        json=message_data
    )
    
    if send_response.status_code in [200, 201]:
        # Log action
        target_user = target_member.get('user', {})
        log_action('dm', user_id, target_user.get('username', 'Unknown'),
                  moderator['id'], moderator['username'], f"Sent DM: {message[:50]}...")
        return jsonify({"success": True, "message": "DM sent successfully"})
    else:
        return jsonify({"error": "Failed to send DM", "details": send_response.text}), 500

@app.route('/embed-generator')
@login_required
@staff_required
def embed_generator():
    """Embed generator page"""
    user = session['user']
    return render_template('embed_generator.html', user=user)

@app.route('/api/channels')
@login_required
@staff_required
def api_channels():
    """Get all guild channels"""
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}"}
    response = requests.get(f"{DISCORD_API_BASE}/guilds/{GUILD_ID}/channels", headers=headers)
    
    if response.status_code == 200:
        channels = response.json()
        # Filter only text channels
        text_channels = [
            {"id": ch["id"], "name": ch["name"]} 
            for ch in channels 
            if ch["type"] == 0  # 0 = GUILD_TEXT
        ]
        return jsonify(text_channels)
    else:
        return jsonify({"error": "Failed to fetch channels"}), 500

@app.route('/api/send-embed', methods=['POST'])
@login_required
@staff_required
def api_send_embed():
    """Send custom embed to a channel"""
    data = request.json
    channel_id = data.get('channel_id')
    
    if not channel_id:
        return jsonify({"error": "Channel ID required"}), 400
    
    moderator = session['user']
    
    # Build embed object
    embed = {}
    
    if data.get('title'):
        embed['title'] = data['title']
    
    if data.get('description'):
        embed['description'] = data['description']
    
    if data.get('color'):
        # Convert hex to decimal
        try:
            color_hex = data['color'].replace('#', '')
            embed['color'] = int(color_hex, 16)
        except:
            embed['color'] = 0xc8d0d6  # Default brand color
    
    if data.get('author_name'):
        embed['author'] = {'name': data['author_name']}
        if data.get('author_icon'):
            embed['author']['icon_url'] = data['author_icon']
    
    if data.get('image_url'):
        embed['image'] = {'url': data['image_url']}
    
    if data.get('thumbnail_url'):
        embed['thumbnail'] = {'url': data['thumbnail_url']}
    
    if data.get('footer_text'):
        embed['footer'] = {'text': data['footer_text']}
    
    # Build message payload
    message_payload = {"embeds": [embed]}
    
    # Add buttons if provided
    buttons = data.get('buttons', [])
    if buttons:
        components = []
        action_row = {"type": 1, "components": []}  # Action Row
        
        for button in buttons[:5]:  # Max 5 buttons per row
            if button.get('label') and button.get('url'):
                action_row["components"].append({
                    "type": 2,  # Button
                    "style": 5,  # Link button
                    "label": button['label'],
                    "url": button['url']
                })
        
        if action_row["components"]:
            components.append(action_row)
            message_payload["components"] = components
    
    # Send message to channel
    headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "Content-Type": "application/json"}
    response = requests.post(
        f"{DISCORD_API_BASE}/channels/{channel_id}/messages",
        headers=headers,
        json=message_payload
    )
    
    if response.status_code in [200, 201]:
        # Log action
        log_action('embed', channel_id, f"Channel {channel_id}", 
                  moderator['id'], moderator['username'], f"Sent embed: {data.get('title', 'No title')}")
        return jsonify({"success": True, "message": "Embed sent successfully"})
    else:
        return jsonify({"error": "Failed to send embed", "details": response.text}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

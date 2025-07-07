"""
Discord Oversight Request Bot

This bot facilitates the secure submission and handling of English Wikipedia 
Oversight requests within a Discord server. It ensures that only authorized 
Oversighters can view and claim requests, and provides a private, auditable 
workflow for sensitive information.

Key features:
- Submission of oversight requests via slash command with optional role-based gating
- Persistent SQLite database storage with unique numeric ticket IDs
- Per-user rate limiting to prevent spam or abuse
- Oversighters can claim requests, view details, and notify original submitters
- Opt-in ping system for Oversighters to receive mentions on new requests, managed via a 
  simple command in the restricted channel.
- `!OversightBot help` message command listing all available commands.
- Sensitive request content is now delivered via **ephemeral** slash‑command replies 
  instead of user DMs for stronger in‑server privacy.
- All configuration provided via environment variables for security

Dependencies: discord.py >= 2.4, aiosqlite
"""

import asyncio
import logging
import os
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import List, Tuple, Optional, Set, Union

import aiosqlite
import discord
from discord import app_commands
from discord.ext import commands

# =========================== Configuration ============================

def load_config():
    """Load and validate configuration from environment variables."""
    config = {}
    
    # Required environment variables
    try:
        config["token"] = os.environ["DISCORD_TOKEN"]
        config["guild_id"] = int(os.environ["GUILD_ID"])
        config["restricted_channel_id"] = int(os.environ["RESTRICTED_CHANNEL_ID"])
    except KeyError as e:
        raise ValueError(f"Missing required environment variable: {e}")
    except ValueError as e:
        raise ValueError(f"Invalid integer value in environment variable: {e}")
    
    # Optional environment variables with defaults
    config["bot_admins"] = {
        int(x.strip()) for x in os.getenv("BOT_ADMINS", "").split(",") if x.strip()
    }
    
    submitter_role_id = os.getenv("SUBMITTER_ROLE_ID")
    config["submitter_role_id"] = int(submitter_role_id) if submitter_role_id else None
    
    config["cooldown_seconds"] = int(os.getenv("COOLDOWN_SECONDS", "600"))
    config["db_path"] = os.getenv("DB_PATH", "./oversight.sqlite")
    config["reminder_minutes"] = int(os.getenv("REMINDER_MINUTES", "15"))
    config["log_level"] = os.getenv("LOG_LEVEL", "INFO").upper()
    
    return config

# Load configuration
CONFIG = load_config()

# Configuration constants
TOKEN = CONFIG["token"]
GUILD_ID = CONFIG["guild_id"]
RESTRICTED_CHANNEL_ID = CONFIG["restricted_channel_id"]
BOT_ADMINS = CONFIG["bot_admins"]
SUBMITTER_ROLE_ID = CONFIG["submitter_role_id"]
COOLDOWN_SECONDS = CONFIG["cooldown_seconds"]
DB_PATH = CONFIG["db_path"]
REMINDER_MINUTES = CONFIG["reminder_minutes"]

# Setup logging
logging.basicConfig(
    level=CONFIG["log_level"],
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    force=True,
)
logger = logging.getLogger("oversight-bot")

# External ticket IDs start at some offset (currently 0) for user-facing clarity
ID_OFFSET = 0

# =========================== User Interface Messages ============================

# Message templates organized by category
MESSAGES = {
    "errors": {
        "not_authenticated": (
            "You must be authenticated to submit an Oversight request. "
            "Please see <https://en.wikipedia.org/wiki/Wikipedia:Requests_for_oversight> "
            "for other ways to submit an Oversight request."
        ),
        "rate_limit_exceeded": "⏳ Rate limit exceeded – max 2 requests every {cooldown}s.",
        "unknown_request_id": "⚠️ Unknown request ID.",
        "invalid_id": "⚠️ Invalid ID.",
        "already_claimed": "Already claimed by {claimant}. Showing details below instead.",
        "not_oversighter": "You are not configured as an Oversighter.",
        "not_bot_admin": "You are not a bot admin.",
        "only_bot_admins_add": "Only bot admins may add Oversighters.",
        "only_bot_admins_remove": "Only bot admins may remove Oversighters.",
        "only_oversighters_ping": "Only configured Oversighters can change ping settings.",
        "unexpected_error": "Unexpected error occurred.",
    },
    "success": {
        "request_filed": (
            "✅ Your request has been filed with ID #{ticket_id}.\n\n"
            "**You submitted:**\n> {request_text}\n\n"
            "You will be notified when the request is claimed by an Oversighter.\n\n"
            "If the request is not claimed by an Oversighter in ~15 minutes, "
            "please follow the instructions at "
            "<https://en.wikipedia.org/wiki/Wikipedia:Requests_for_oversight>."
        ),
        "no_unclaimed": "✅ No unclaimed requests.",
        "claiming_multiple": "🔄 Claiming {count} unclaimed requests …",
        "added_oversighters": "Added {users} as Oversighter(s).",
        "removed_oversighters": "Removed {users} from Oversighters.",
        "ping_enabled": "You'll be pinged for new Oversight requests.",
        "ping_disabled": "You will no longer receive pings.",
        "follow_up_note": (
            "Please follow up directly with the requester to inform them of the "
            "disposition of their request or to request additional information."
        ),
    },
    "info": {
        "request_claimed_notification": (
            "Your Oversight request #{request_id} was "
            "claimed by Oversighter {claimer}."
        ),
        "reminder_message": (
            "Your Oversight request #{request_id} has not been claimed "
            "by an Oversighter within {minutes} minutes.\n\n"
            "**Your original request:**\n> {request_text}\n\n"
            "Please consider submitting the request through other channels "
            "by following the instructions at "
            "<https://en.wikipedia.org/wiki/Wikipedia:Requests_for_oversight>."
        ),
        "request_details": (
            "**Oversight Request #{request_id}** by <@{author_id}>\n\n"
            "> {text}\n\n"
        ),
        "view_request_details": (
            "**Oversight Request #{request_id}** by <@{author_id}>\n\n"
            "> {text}\n\n"
        ),
        "unclaimed_requests": "**Unclaimed requests:** {ids}",
        "none_available": "*(none)*",
    },
    "restricted": {
        "request": (
            "**Oversight Request**\n"
            "- ID: #{ticket_id}\n"
            "- Status: {status}\n"
            "- From: {user_mention}\n"
            "Oversighters may claim all pending requests with `/claim`."
        ),
        "request_viewed": "{viewer} viewed {status} request #{request_id}.",
        "reminder_sent": (
            "Sent unclaimed-request notice to {user_mention} "
            "for #{request_id} (>{minutes} min old)."
        ),
    },
    "help": {
        "command_reference": (
            "**OversightBot Command Reference**\n"
            "- `/oversight <text>` – Submit an Oversight request (max 2 every "
            "{cooldown}s; *Oversighters & bot-admins exempt*)\n"
            "- `/claim [ID]` – Claim one request or **every** pending request if no ID\n"
            "- `/view <ID>` – View any request by ID (Oversighters only)\n"
            "- `/pending` – List unclaimed request IDs (Oversighters only)\n"
            "- `!OversightBot ping on|off` – Opt‑in/out of pings for new requests "
            "(Oversighters only)\n"
            "- `!OversightBot addos @u` / `removeos @u` – Manage Oversighters "
            "(bot admins only)\n"
            "- `!OversightBot help` – Show this help\n"
        ),
        "usage_addos": "Usage: `!OversightBot addos @user`",
        "usage_removeos": "Usage: `!OversightBot removeos @user`",
        "usage_ping": "Usage: `!OversightBot ping on` or `!OversightBot ping off`",
    }
}



# ===================== Utility and Permission Helpers =====================

def ext_id_to_row(ext_id: int) -> int:
    """Convert external ticket ID to internal DB rowid. Raises ValueError if out of range."""
    internal = ext_id - ID_OFFSET
    if internal <= 0:
        raise ValueError
    return internal

def row_to_ext_id(rowid: int) -> int:
    """Convert internal DB rowid to external ticket ID."""
    return rowid + ID_OFFSET

# ===================  Oversighter & Admin helpers  ====================

async def is_oversighter(user_id: int) -> bool:
    """Return True if user_id is currently an Oversighter."""
    row = await db_manager.fetchone(
        "SELECT 1 FROM oversighters WHERE user_id = ? LIMIT 1", (user_id,)
    )
    return row is not None


def oversighter_check():
    """Decorator that checks current Oversighter status (DB-backed)."""

    async def predicate(interaction: discord.Interaction) -> bool:
        if not await is_oversighter(interaction.user.id):
            raise app_commands.CheckFailure(
                MESSAGES["errors"]["not_oversighter"]
            )
        return True

    return app_commands.check(predicate)


def bot_admin_check():
    """Decorator restricting usage to configured bot-admins only."""

    async def predicate(interaction_or_msg: Union[discord.Interaction, discord.Message]) -> bool:
        uid = (
            interaction_or_msg.user.id
            if isinstance(interaction_or_msg, discord.Interaction)
            else interaction_or_msg.author.id
        )
        if uid not in BOT_ADMINS:
            raise app_commands.CheckFailure(MESSAGES["errors"]["not_bot_admin"])
        return True

    return commands.check(predicate)  # usable for message commands too


async def add_oversighter(user_id: int) -> None:
    """Add a user as an Oversighter (idempotent)."""
    await db_manager.execute_with_commit(
        "INSERT OR IGNORE INTO oversighters (user_id) VALUES (?)", (user_id,)
    )


async def remove_oversighter(user_id: int) -> None:
    """Remove a user from Oversighters."""
    await db_manager.execute_with_commit(
        "DELETE FROM oversighters WHERE user_id = ?", (user_id,)
    )

async def notify_restricted(
    bot: commands.Bot,
    content: str,
) -> None:
    """Send a message to the restricted channel."""
    chan = bot.get_channel(RESTRICTED_CHANNEL_ID)
    if not chan:
        return
    await chan.send(content)

# =========================== Database Layer ==============================

DB_LOCK = asyncio.Lock()  # Prevents concurrent DB schema setup

class DatabaseManager:
    """Manages database connections and operations."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
    
    async def fetchone(self, query: str, params: tuple = ()):
        """Execute a query and return a single row."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = sqlite3.Row
            cur = await db.execute(query, params)
            result = await cur.fetchone()
            return result
    
    async def fetchall(self, query: str, params: tuple = ()):
        """Execute a query and return all rows."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = sqlite3.Row
            cur = await db.execute(query, params)
            result = await cur.fetchall()
            return result
    
    async def execute_with_commit(self, query: str, params: tuple = ()):
        """Execute a query and commit the transaction."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = sqlite3.Row
            cursor = await db.execute(query, params)
            await db.commit()
            return cursor
    
    async def execute(self, query: str, params: tuple = ()):
        """Execute a query and return the cursor."""
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = sqlite3.Row
            return await db.execute(query, params)

# Global database manager instance
db_manager = DatabaseManager(DB_PATH)

async def init_db() -> None:
    """Initialize the database schema if not already present."""
    async with DB_LOCK:
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = sqlite3.Row
            await db.execute(
                """CREATE TABLE IF NOT EXISTS requests (
                       id          INTEGER PRIMARY KEY AUTOINCREMENT,
                       author_id   INTEGER NOT NULL,
                       text        TEXT    NOT NULL,
                       created_at  INTEGER  DEFAULT (strftime('%s','now')),
                       claimed_by  INTEGER,
                       claimed_at  INTEGER,
                       reminded_at INTEGER
                   )"""
            )
            await db.commit()
            
            # Add message_id column for tracking Discord messages (harmless if already exists)
            try:
                await db.execute("ALTER TABLE requests ADD COLUMN message_id INTEGER")
                await db.commit()
            except sqlite3.OperationalError:
                # column already present – ignore
                pass
            
            # Table for Oversighters who opt in to pings on new requests
            await db.execute(
                "CREATE TABLE IF NOT EXISTS ping_subscribers ("
                "user_id INTEGER PRIMARY KEY)"
            )
            await db.commit()

            # Table of authorised Oversighters (managed by bot-admins)
            await db.execute(
                "CREATE TABLE IF NOT EXISTS oversighters ("
                "  user_id INTEGER PRIMARY KEY)"
            )
            await db.commit()

# Ping-subscriber management
async def add_ping_sub(user_id: int) -> None:
    """Add a user to the ping-subscriber list (idempotent)."""
    await db_manager.execute_with_commit(
        "INSERT OR IGNORE INTO ping_subscribers (user_id) VALUES (?)",
        (user_id,),
    )

async def remove_ping_sub(user_id: int) -> None:
    """Remove a user from the ping-subscriber list."""
    await db_manager.execute_with_commit(
        "DELETE FROM ping_subscribers WHERE user_id = ?", (user_id,)
    )

async def get_ping_subs() -> List[int]:
    """Return a list of user IDs who have opted in to pings."""
    rows = await db_manager.fetchall("SELECT user_id FROM ping_subscribers")
    return [r[0] for r in rows]

async def recent_request_count(author_id: int) -> int:
    """Count how many requests a user has submitted within the cooldown window."""
    window_ts = int(datetime.now(timezone.utc).timestamp()) - COOLDOWN_SECONDS
    row = await db_manager.fetchone(
        "SELECT COUNT(*) FROM requests "
        "WHERE author_id = ? AND created_at >= ?",
        (author_id, window_ts),
    )
    return row[0] if row else 0

async def create_request(author_id: int, text: str) -> int:
    """Create a new oversight request, enforcing per-user rate limits."""
    # ── Rate-limit EXEMPTION ────────────────────────────────────────────
    # Skip the limit if the user is an Oversighter or a bot-admin
    if not (author_id in BOT_ADMINS or await is_oversighter(author_id)):
        if await recent_request_count(author_id) >= 2:
            raise RuntimeError(
                MESSAGES["errors"]["rate_limit_exceeded"].format(cooldown=COOLDOWN_SECONDS)
            )
    now_ts = int(datetime.now(timezone.utc).timestamp())
    cursor = await db_manager.execute_with_commit(
        "INSERT INTO requests (author_id, text, created_at) VALUES (?, ?, ?)",
        (author_id, text, now_ts),
    )
    return row_to_ext_id(cursor.lastrowid)

async def fetch_request(row_id: int) -> Optional[sqlite3.Row]:
    """Fetch a request by its internal row ID."""
    return await db_manager.fetchone("SELECT * FROM requests WHERE id = ?", (row_id,))

async def claim_request(row_id: int, claimer_id: int) -> bool:
    """Attempt to atomically claim a request. Returns True if successful, False if already claimed."""
    now_ts = int(datetime.now(timezone.utc).timestamp())
    cur = await db_manager.execute_with_commit(
        "UPDATE requests SET claimed_by = ?, claimed_at = ? "
        "WHERE id = ? AND claimed_by IS NULL",
        (claimer_id, now_ts, row_id),
    )
    return cur.rowcount == 1

async def list_pending() -> List[int]:
    """Return a list of external IDs for all unclaimed requests."""
    rows = await db_manager.fetchall(
        "SELECT id FROM requests WHERE claimed_by IS NULL ORDER BY id"
    )
    return [row_to_ext_id(r[0]) for r in rows]

# ============================= Reminders ==============================

async def reminder_loop(bot: commands.Bot):
    """Poll for stale, unclaimed requests and remind their authors."""
    while not bot.is_closed():
        try:
            await _process_reminders(bot)
        except Exception as e:
            logger.error("Error in reminder loop: %s", e)
        
        await asyncio.sleep(60)  # check each minute

async def _process_reminders(bot: commands.Bot):
    """Process reminders for stale unclaimed requests."""
    cutoff_ts = int(datetime.utcnow().timestamp()) - REMINDER_MINUTES * 60
    
    rows = await db_manager.fetchall(
        "SELECT id, author_id, text FROM requests "
        "WHERE claimed_by IS NULL "
        "  AND created_at < ? "
        "  AND (reminded_at IS NULL)",
        (cutoff_ts,),
    )

    for row in rows:
        await _send_reminder(bot, row)

async def _send_reminder(bot: commands.Bot, row: sqlite3.Row):
    """Send a reminder for a specific request."""
    ext_id = row_to_ext_id(row["id"])
    author = await bot.fetch_user(row["author_id"])
    request_text = row["text"]
    
    msg = MESSAGES["info"]["reminder_message"].format(
        request_id=ext_id,
        minutes=REMINDER_MINUTES,
        request_text=request_text
    )
    
    try:
        await author.send(msg)
    except discord.HTTPException:
        pass

    await notify_restricted(
        bot,
        MESSAGES["restricted"]["reminder_sent"].format(
            user_mention=author.mention,
            request_id=ext_id,
            minutes=REMINDER_MINUTES
        ),
    )

    # Mark as reminded
    now_ts = int(datetime.utcnow().timestamp())
    await db_manager.execute_with_commit(
        "UPDATE requests SET reminded_at = ? WHERE id = ?",
        (now_ts, row["id"]),
    )

# =========================== Discord Bot Setup ===========================

# Enable message content intent for command handling in restricted channel
intents = discord.Intents.default()
intents.message_content = True

class OversightBot(commands.Bot):
    async def setup_hook(self) -> None:
        # Initialize the database and sync commands on startup
        await init_db()
        # kick off reminder loop
        self.reminder_task = asyncio.create_task(reminder_loop(self))
        await self.tree.sync(guild=GUILD_OBJ)

bot = OversightBot(command_prefix="!", intents=intents)
GUILD_OBJ = discord.Object(id=GUILD_ID)

# ========================= Slash Command Handlers =========================

@bot.tree.command(
    name="oversight",
    description="Submit a Wikipedia Oversight request",
    guild=GUILD_OBJ,
)
@app_commands.describe(request_text="Describe what needs to be oversighted.")
async def oversight(interaction: discord.Interaction, request_text: str):
    # Optionally restrict submission to users with a specific role
    if SUBMITTER_ROLE_ID:
        if SUBMITTER_ROLE_ID not in {role.id for role in interaction.user.roles}:
            await interaction.response.send_message(
                MESSAGES["errors"]["not_authenticated"],
                ephemeral=True,
            )
            return

    await interaction.response.defer(ephemeral=True)
    try:
        ticket_id = await create_request(interaction.user.id, request_text)
    except RuntimeError as e:
        await interaction.followup.send(MESSAGES["errors"]["rate_limit_exceeded"].format(cooldown=COOLDOWN_SECONDS), ephemeral=True)
        return

    # Confirm submission and echo back the request for verification
    await interaction.followup.send(
        MESSAGES["success"]["request_filed"].format(ticket_id=ticket_id, request_text=request_text),
        ephemeral=True,
    )

    # Post the request and remember its message-ID
    status_line = "🔴 Unclaimed"
    content = MESSAGES["restricted"]["request"].format(
        ticket_id=ticket_id,
        status=status_line,
        user_mention=interaction.user.mention,
    )

    chan = bot.get_channel(RESTRICTED_CHANNEL_ID)
    # include optional pings
    if (subs := await get_ping_subs()):
        content += " " + " ".join(f"<@{uid}>" for uid in subs)

    msg = await chan.send(content)          # <-- ACTUAL POST
    # remember the message id so we can edit it later
    await db_manager.execute_with_commit(
        "UPDATE requests SET message_id = ? WHERE id = ?",
        (msg.id, ext_id_to_row(ticket_id)),
    )
    
    logger.info("Request %s submitted by %s", ticket_id, interaction.user)

@bot.tree.command(
    name="claim",
    description="Claim and receive an Oversight request",
    guild=GUILD_OBJ,
)
@oversighter_check()
@app_commands.describe(request_id="Ticket ID.  Omit to claim *all* unclaimed.")
async def claim(interaction: discord.Interaction, request_id: Optional[int] = None):
    await interaction.response.defer(ephemeral=True)
    
    if request_id is not None:
        await _claim_single_request(interaction, request_id)
    else:
        await _claim_all_pending_requests(interaction)

async def _claim_single_request(interaction: discord.Interaction, request_id: int):
    """Claim a single request by ID."""
    try:
        row_id = ext_id_to_row(request_id)
    except ValueError:
        await interaction.followup.send(MESSAGES["errors"]["invalid_id"], ephemeral=True)
        return

    await _process_claim(interaction, row_id, is_first=True)

async def _claim_all_pending_requests(interaction: discord.Interaction):
    """Claim all pending requests."""
    pending = await list_pending()
    if not pending:
        await interaction.followup.send(MESSAGES["success"]["no_unclaimed"], ephemeral=True)
        return

    await interaction.followup.send(
        MESSAGES["success"]["claiming_multiple"].format(count=len(pending)), ephemeral=True
    )
    
    for idx, ext_id in enumerate(pending, start=1):
        await _process_claim(interaction, ext_id_to_row(ext_id), is_first=(idx == 1))

async def _process_claim(interaction: discord.Interaction, row_id: int, is_first: bool):
    """Process claiming a single request."""
    req = await fetch_request(row_id)
    if not req:
        if is_first:
            await interaction.followup.send(MESSAGES["errors"]["unknown_request_id"], ephemeral=True)
        return

    # Try to claim atomically
    success = False
    if not req["claimed_by"]:
        success = await claim_request(row_id, interaction.user.id)
        if success:
            req = await fetch_request(row_id)  # refresh with claimer info

    # Handle already claimed requests
    if req["claimed_by"] and not success:
        await _handle_already_claimed(interaction, req, is_first)
        return

    # Handle newly claimed requests
    await _handle_newly_claimed(interaction, req, row_id)

async def _handle_already_claimed(interaction: discord.Interaction, req: sqlite3.Row, is_first: bool):
    """Handle requests that are already claimed."""
    claimant = await bot.fetch_user(req["claimed_by"])
    if is_first:
        await interaction.followup.send(
            MESSAGES["errors"]["already_claimed"].format(claimant=claimant.mention),
            ephemeral=True,
        )
    await interaction.followup.send(
        MESSAGES["info"]["view_request_details"].format(
            request_id=row_to_ext_id(req["id"]),
            text=req["text"],
            author_id=req["author_id"],
        ),
        ephemeral=True,
    )

async def _handle_newly_claimed(interaction: discord.Interaction, req: sqlite3.Row, row_id: int):
    """Handle newly claimed requests."""
    await interaction.followup.send(
        MESSAGES["info"]["request_details"].format(
            request_id=row_to_ext_id(row_id),
            text=req["text"],
            author_id=req["author_id"],
        )
        + f"{MESSAGES['success']['follow_up_note']}",
        ephemeral=True,
    )

    # Notify author
    await _notify_author(interaction, req, row_id)
    
    # Update message status
    await _update_message_status(interaction, req, row_id)

async def _notify_author(interaction: discord.Interaction, req: sqlite3.Row, row_id: int):
    """Notify the original author that their request was claimed."""
    if req["author_id"]:
        try:
            user = await bot.fetch_user(req["author_id"])
            await user.send(
                MESSAGES["info"]["request_claimed_notification"].format(
                    request_id=row_to_ext_id(row_id),
                    claimer=interaction.user.mention,
                )
            )
        except discord.HTTPException:
            pass

async def _update_message_status(interaction: discord.Interaction, req: sqlite3.Row, row_id: int):
    """Update the Discord message status when a request is claimed."""
    msg_id = req["message_id"]
    if msg_id:
        chan = bot.get_channel(RESTRICTED_CHANNEL_ID)
        try:
            msg = await chan.fetch_message(msg_id)
            new_content = MESSAGES["restricted"]["request"].format(
                ticket_id=row_to_ext_id(row_id),
                status=f"✅ Claimed by {interaction.user.mention}",
                user_mention=f"<@{req['author_id']}>",
            )
            await msg.edit(content=new_content)
        except discord.NotFound:
            # fall back silently if the original message vanished
            pass

@bot.tree.command(
    name="view",
    description="View an already‐claimed Oversight request",
    guild=GUILD_OBJ,
)
@oversighter_check()
@app_commands.describe(request_id="Numeric ticket ID.  Omit to view *all* unclaimed.")
async def view(interaction: discord.Interaction, request_id: Optional[int] = None):
    await interaction.response.defer(ephemeral=True)
    # ---------- View ALL unclaimed if no ID ----------
    if request_id is None:
        pending = await list_pending()
        if not pending:
            await interaction.followup.send(MESSAGES["success"]["no_unclaimed"], ephemeral=True)
            return
        for ext_id in pending:
            req = await fetch_request(ext_id_to_row(ext_id))
            await interaction.followup.send(
                MESSAGES["info"]["view_request_details"].format(
                    request_id=ext_id,
                    text=req["text"],
                    author_id=req["author_id"],
                ),
                ephemeral=True,
            )
        return

    # ---------- View single ID ----------
    try:
        row_id = ext_id_to_row(request_id)
    except ValueError:
        await interaction.followup.send(MESSAGES["errors"]["invalid_id"], ephemeral=True)
        return

    req = await fetch_request(row_id)
    if not req:
        await interaction.followup.send(MESSAGES["errors"]["unknown_request_id"], ephemeral=True)
        return

    await interaction.followup.send(
        MESSAGES["info"]["view_request_details"].format(
            request_id=request_id,
            text=req["text"],
            author_id=req["author_id"],
        ),
        ephemeral=True,
    )
    # No channel notification for /view (requirement 4)

@bot.tree.command(
    name="pending",
    description="List all unclaimed Oversight request IDs",
    guild=GUILD_OBJ,
)
@oversighter_check()
async def pending(interaction: discord.Interaction):
    # List all unclaimed requests for Oversighters
    ids = await list_pending()
    text = MESSAGES["info"]["unclaimed_requests"].format(ids=", ".join(f"`{i}`" for i in ids) or MESSAGES["info"]["none_available"])
    await interaction.response.send_message(text, ephemeral=True)

# ========================= Ping Opt-in Command Handler =========================

@bot.event
async def on_message(message: discord.Message):
    """Handle message-based commands in the restricted channel."""
    if not _should_process_message(message):
        return

    text = message.content.strip().lower()
    
    if text.startswith("!oversightbot addos"):
        await _handle_add_oversighters(message)
    elif text.startswith("!oversightbot removeos"):
        await _handle_remove_oversighters(message)
    elif text.startswith("!oversightbot help"):
        await _handle_help_command(message)
    elif text.startswith("!oversightbot ping"):
        await _handle_ping_command(message)
    else:
        await bot.process_commands(message)

def _should_process_message(message: discord.Message) -> bool:
    """Check if a message should be processed by the bot."""
    return (
        not message.author.bot and 
        message.channel.id == RESTRICTED_CHANNEL_ID
    )

async def _handle_add_oversighters(message: discord.Message):
    """Handle adding Oversighters (bot-admins only)."""
    if message.author.id not in BOT_ADMINS:
        await message.reply(MESSAGES["errors"]["only_bot_admins_add"])
        return
    
    if not message.mentions:
        await message.reply(MESSAGES["help"]["usage_addos"])
        return
    
    added = []
    for mention in message.mentions:
        await add_oversighter(mention.id)
        added.append(mention.mention)
    
    await message.reply(
        MESSAGES["success"]["added_oversighters"].format(users=" ".join(added)), 
        mention_author=False
    )

async def _handle_remove_oversighters(message: discord.Message):
    """Handle removing Oversighters (bot-admins only)."""
    if message.author.id not in BOT_ADMINS:
        await message.reply(MESSAGES["errors"]["only_bot_admins_remove"])
        return
    
    if not message.mentions:
        await message.reply(MESSAGES["help"]["usage_removeos"])
        return
    
    removed = []
    for mention in message.mentions:
        await remove_oversighter(mention.id)
        removed.append(mention.mention)
    
    await message.reply(
        MESSAGES["success"]["removed_oversighters"].format(users=" ".join(removed)),
        mention_author=False,
    )

async def _handle_help_command(message: discord.Message):
    """Handle the help command."""
    help_text = MESSAGES["help"]["command_reference"].format(cooldown=COOLDOWN_SECONDS)
    await message.reply(help_text, mention_author=False)
    await bot.process_commands(message)

async def _handle_ping_command(message: discord.Message):
    """Handle ping opt-in/out commands (Oversighters only)."""
    if not await is_oversighter(message.author.id):
        await message.reply(
            MESSAGES["errors"]["only_oversighters_ping"],
            mention_author=False,
        )
        return

    parts = message.content.strip().lower().split()
    if len(parts) < 3 or parts[2] not in ("on", "off"):
        await message.reply(
            MESSAGES["help"]["usage_ping"],
            mention_author=False,
        )
        return

    if parts[2] == "on":
        await add_ping_sub(message.author.id)
        await message.reply(
            MESSAGES["success"]["ping_enabled"],
            mention_author=False,
        )
    else:  # "off"
        await remove_ping_sub(message.author.id)
        await message.reply(
            MESSAGES["success"]["ping_disabled"],
            mention_author=False,
        )

    await bot.process_commands(message)

# ========================= Error Handling and Startup =========================

@claim.error
@view.error
@pending.error
async def oversight_error(interaction: discord.Interaction, error):
    # Handle permission errors and log unexpected exceptions
    if isinstance(error, app_commands.CheckFailure):
        await interaction.response.send_message(MESSAGES["errors"]["not_oversighter"], ephemeral=True)
    else:
        logger.exception("Unhandled error:", exc_info=error)
        await interaction.response.send_message(MESSAGES["errors"]["unexpected_error"], ephemeral=True)

@bot.event
async def on_ready():
    # Log successful bot startup
    logger.info("Logged in as %s (%s)", bot.user, bot.user.id)
    logger.info("Commands synced to guild %s", GUILD_ID)

bot.run(TOKEN)

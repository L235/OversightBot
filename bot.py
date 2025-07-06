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
from typing import List, Tuple, Optional, Set

import aiosqlite
import discord
from discord import app_commands
from discord.ext import commands

# =========================== Configuration ============================

TOKEN: str = os.environ["DISCORD_TOKEN"]
GUILD_ID: int = int(os.environ["GUILD_ID"])
RESTRICTED_CHANNEL_ID: int = int(os.environ["RESTRICTED_CHANNEL_ID"])

# ---------------------------------------------------------------------
# IDs provided via ENV are now **bot-admins** only.  Oversighters live
# in the DB and are maintained at runtime by the bot-admins.
# ---------------------------------------------------------------------
BOT_ADMINS: Set[int] = {
    int(x.strip()) for x in os.getenv("BOT_ADMINS", "").split(",") if x.strip()
}

# Optional role required to submit oversight requests
SUBMITTER_ROLE_ID: Optional[int] = (
    int(os.getenv("SUBMITTER_ROLE_ID")) if os.getenv("SUBMITTER_ROLE_ID") else None
)

COOLDOWN_SECONDS: int = int(os.getenv("COOLDOWN_SECONDS", "600"))
DB_PATH: str = os.getenv("DB_PATH", "./oversight.sqlite")

# Default (minutes) before an unclaimed request triggers a reminder DM
REMINDER_MINUTES: int = int(os.getenv("REMINDER_MINUTES", "15"))

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    force=True,
)
logger = logging.getLogger("oversight-bot")

# External ticket IDs start at some offset (currently 0) for user-facing clarity
ID_OFFSET = 0

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
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT 1 FROM oversighters WHERE user_id = ? LIMIT 1", (user_id,)
        )
        return await cur.fetchone() is not None


def oversighter_check():
    """Decorator that checks current Oversighter status (DB-backed)."""

    async def predicate(interaction: discord.Interaction) -> bool:
        if not await is_oversighter(interaction.user.id):
            raise app_commands.CheckFailure(
                "You are not configured as an Oversighter."
            )
        return True

    return app_commands.check(predicate)


def bot_admin_check():
    """Decorator restricting usage to configured bot-admins only."""

    async def predicate(interaction_or_msg):
        uid = (
            interaction_or_msg.user.id
            if isinstance(interaction_or_msg, discord.Interaction)
            else interaction_or_msg.author.id
        )
        if uid not in BOT_ADMINS:
            raise app_commands.CheckFailure("You are not a bot admin.")
        return True

    return commands.check(predicate)  # usable for message commands too


async def add_oversighter(user_id: int) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR IGNORE INTO oversighters (user_id) VALUES (?)", (user_id,)
        )
        await db.commit()


async def remove_oversighter(user_id: int) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM oversighters WHERE user_id = ?", (user_id,))
        await db.commit()

async def notify_restricted(
    bot: commands.Bot,
    content: str,
    ping_new: bool = False,
) -> None:
    """Send a message to the restricted channel, optionally pinging opted-in 
    Oversighters."""
    chan = bot.get_channel(RESTRICTED_CHANNEL_ID)
    if not chan:
        return
    if ping_new:
        subs = await get_ping_subs()
        if subs:
            content += " " + " ".join(f"<@{uid}>" for uid in subs)
    await chan.send(content)

# =========================== Database Layer ==============================

DB_LOCK = asyncio.Lock()  # Prevents concurrent DB schema setup

async def init_db() -> None:
    """Initialize the database schema if not already present."""
    async with DB_LOCK:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """CREATE TABLE IF NOT EXISTS requests (
                       id          INTEGER PRIMARY KEY AUTOINCREMENT,
                       author_id   INTEGER NOT NULL,
                       text        TEXT    NOT NULL,
                       created_at  DATETIME DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                       claimed_by  INTEGER,
                       claimed_at  DATETIME,
                       reminded_at DATETIME
                   )"""
            )
            await db.commit()
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
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR IGNORE INTO ping_subscribers (user_id) VALUES (?)",
            (user_id,),
        )
        await db.commit()

async def remove_ping_sub(user_id: int) -> None:
    """Remove a user from the ping-subscriber list."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "DELETE FROM ping_subscribers WHERE user_id = ?", (user_id,)
        )
        await db.commit()

async def get_ping_subs() -> List[int]:
    """Return a list of user IDs who have opted in to pings."""
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT user_id FROM ping_subscribers")
        rows = await cur.fetchall()
        return [r[0] for r in rows]

async def recent_request_count(db, author_id: int) -> int:
    """Count how many requests a user has submitted within the cooldown window."""
    window = datetime.now(timezone.utc) - timedelta(seconds=COOLDOWN_SECONDS)
    cur = await db.execute(
        "SELECT COUNT(*) FROM requests "
        "WHERE author_id = ? AND created_at >= ?",
        (author_id, window.isoformat(timespec="seconds")),
    )
    (cnt,) = await cur.fetchone()
    return cnt

async def create_request(author_id: int, text: str) -> int:
    """Create a new oversight request, enforcing per-user rate limits."""
    async with aiosqlite.connect(DB_PATH) as db:
        # ── Rate-limit EXEMPTION ────────────────────────────────────────────
        # Skip the limit if the user is an Oversighter or a bot-admin
        if not (author_id in BOT_ADMINS or await is_oversighter(author_id)):
            if await recent_request_count(db, author_id) >= 2:
                raise RuntimeError(
                    f"Rate limit exceeded – max 2 requests every {COOLDOWN_SECONDS}s."
                )
        cur = await db.execute(
            "INSERT INTO requests (author_id, text) VALUES (?, ?)",
            (author_id, text),
        )
        await db.commit()
        return row_to_ext_id(cur.lastrowid)

async def fetch_request(row_id: int) -> Optional[sqlite3.Row]:
    """Fetch a request by its internal row ID."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        cur = await db.execute("SELECT * FROM requests WHERE id = ?", (row_id,))
        return await cur.fetchone()

async def claim_request(row_id: int, claimer_id: int) -> bool:
    """Attempt to atomically claim a request. Returns True if successful, False if already claimed."""
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "UPDATE requests SET claimed_by = ?, claimed_at = CURRENT_TIMESTAMP "
            "WHERE id = ? AND claimed_by IS NULL",
            (claimer_id, row_id),
        )
        await db.commit()
        return cur.rowcount == 1

async def list_pending() -> List[int]:
    """Return a list of external IDs for all unclaimed requests."""
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT id FROM requests WHERE claimed_by IS NULL ORDER BY id"
        )
        rows = await cur.fetchall()
        return [row_to_ext_id(r[0]) for r in rows]

# ============================= Reminders ==============================

async def reminder_loop(bot: commands.Bot):
    """Poll for stale, unclaimed requests and remind their authors."""
    while not bot.is_closed():
        cutoff = datetime.utcnow() - timedelta(minutes=REMINDER_MINUTES)
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = sqlite3.Row
            cur = await db.execute(
                "SELECT id, author_id, text FROM requests "
                "WHERE claimed_by IS NULL "
                "  AND datetime(created_at) < ? "
                "  AND (reminded_at IS NULL)",
                (cutoff.isoformat(timespec='seconds'),),
            )
            rows = await cur.fetchall()

            for row in rows:
                ext_id = row_to_ext_id(row["id"])
                author = await bot.fetch_user(row["author_id"])
                request_text = row["text"]
                msg = (
                    f"⏰ Your Oversight request #**{ext_id}** has not been claimed "
                    f"within {REMINDER_MINUTES} minutes.\n\n"
                    f"**Your original request:**\n> {request_text}\n\n"
                    "Please consider submitting the request through other channels "
                    "by following the instructions at "
                    "<https://en.wikipedia.org/wiki/Wikipedia:Requests_for_oversight>."
                )
                try:
                    await author.send(msg)
                except discord.HTTPException:
                    pass

                await notify_restricted(
                    bot,
                    f"⚠️ Sent unclaimed-request reminder to {author.mention} "
                    f"for `{ext_id}` (>{REMINDER_MINUTES} min old).",
                )

                await db.execute(
                    "UPDATE requests SET reminded_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (row["id"],),
                )
            await db.commit()

        await asyncio.sleep(60)  # check each minute

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
                "You must be authenticated to submit an Oversight request. "
                "Please see <https://en.wikipedia.org/wiki/Wikipedia:Requests_for_oversight> "
                "for other ways to submit an Oversight request.",
                ephemeral=True,
            )
            return

    await interaction.response.defer(ephemeral=True)
    try:
        ticket_id = await create_request(interaction.user.id, request_text)
    except RuntimeError as e:
        await interaction.followup.send(f"⏳ {e}", ephemeral=True)
        return

    # Confirm submission and echo back the request for verification
    await interaction.followup.send(
        f"✅ Your request has been filed with ID **{ticket_id}**.\n\n"
        f"**You submitted:**\n> {request_text}\n\n"
        "If the request is not processed by an Oversighter in ~15 minutes, "
        "please follow the instructions at "
        "<https://en.wikipedia.org/wiki/Wikipedia:Requests_for_oversight>.",
        ephemeral=True,
    )

    # Notify Oversighters in the restricted channel, pinging opted-in users
    await notify_restricted(
        bot,
        (
            "**New Oversight Request**\n"
            f"• ID: `{ticket_id}`\n"
            f"• From: {interaction.user.mention}\n"
            "Oversighters may claim all pending requests with `/claim`."
        ),
        ping_new=True,
    )
    logger.info("Request %s submitted by %s", ticket_id, interaction.user)

@bot.tree.command(
    name="claim",
    description="Claim and receive an Oversight request",
    guild=GUILD_OBJ,
)
@oversighter_check()
@app_commands.describe(request_id="Ticket ID.  Omit to claim *all* unclaimed.")
# Make the argument optional
async def claim(interaction: discord.Interaction, request_id: Optional[int] = None):
    # Helper that actually performs the single-request claim flow
    async def _claim_one(_row_id: int, first: bool):
        req = await fetch_request(_row_id)
        if not req:
            if first:
                await interaction.followup.send("⚠️ Unknown request ID.", ephemeral=True)
            return

        # Attempt to claim atomically
        if not req["claimed_by"]:
            success = await claim_request(_row_id, interaction.user.id)
            if not success:
                req = await fetch_request(_row_id)

        if req["claimed_by"] and req["claimed_by"] != interaction.user.id:
            claimant = await bot.fetch_user(req["claimed_by"])
            if first:
                await interaction.followup.send(
                    f"❌ Already claimed by {claimant.mention}.", ephemeral=True
                )
            return

        # Send details (ephemeral) – only on first or if multiple, show separator
        await interaction.followup.send(
            f"**Oversight Request #{row_to_ext_id(_row_id)}**\n\n"
            f"{req['text']}\n\n"
            f"_Submitted by <@{req['author_id']}>_",
            ephemeral=True,
        )

        # Notify author only on initial claim
        if req["author_id"]:
            try:
                user = await bot.fetch_user(req["author_id"])
                await user.send(
                    f"👁️‍🗨️ Your Oversight request #**{row_to_ext_id(_row_id)}** was "
                    f"claimed by Oversighter {interaction.user.mention}."
                )
            except discord.HTTPException:
                pass

        await notify_restricted(
            bot,
            f"✅ Request #`{row_to_ext_id(_row_id)}` claimed by {interaction.user.mention}.",
        )

    # Defer the response to avoid race conditions
    await interaction.response.defer(ephemeral=True)
    # ---------------- Single-ID path ----------------
    if request_id is not None:
        try:
            row_id = ext_id_to_row(request_id)
        except ValueError:
            await interaction.followup.send("⚠️ Invalid ID.", ephemeral=True)
            return

        await _claim_one(row_id, True)
        return

    # ---------------- Bulk-claim path (/claim with no args) ---------------
    pending = await list_pending()
    if not pending:
        await interaction.followup.send("✅ No unclaimed requests.", ephemeral=True)
        return

    await interaction.followup.send(
        f"🔄 Claiming **{len(pending)}** unclaimed requests …", ephemeral=True
    )
    for idx, ext_id in enumerate(pending, start=1):
        await _claim_one(ext_id_to_row(ext_id), idx == 1)

@bot.tree.command(
    name="view",
    description="View an already‐claimed Oversight request",
    guild=GUILD_OBJ,
)
@oversighter_check()
@app_commands.describe(request_id="Numeric ticket ID")
async def view(interaction: discord.Interaction, request_id: int):
    await interaction.response.defer(ephemeral=True)
    try:
        row_id = ext_id_to_row(request_id)
    except ValueError:
        await interaction.followup.send("⚠️ Invalid ID.", ephemeral=True)
        return

    req = await fetch_request(row_id)
    if not req:
        await interaction.followup.send("⚠️ Unknown request ID.", ephemeral=True)
        return
    unclaimed = req["claimed_by"] is None

    # Send the request details to the Oversighter inline (ephemeral)
    await interaction.followup.send(
        f"📄 **Oversight Request {request_id}**\n\n"
        f"{req['text']}\n\n"
        f"_Submitted by <@{req['author_id']}>_",
        ephemeral=True,
    )

    # Announce the view in the restricted channel, indicating claim status
    status = "unclaimed" if unclaimed else "claimed"
    await notify_restricted(
        bot,
        f"👓 {interaction.user.mention} viewed {status} request `{request_id}`."
    )
    logger.info("Request %s viewed by %s (status: %s)", request_id, interaction.user, status)

@bot.tree.command(
    name="pending",
    description="List all unclaimed Oversight request IDs",
    guild=GUILD_OBJ,
)
@oversighter_check()
async def pending(interaction: discord.Interaction):
    # List all unclaimed requests for Oversighters
    ids = await list_pending()
    text = "🔗 **Unclaimed requests:** " + (", ".join(f"`{i}`" for i in ids) or "*(none)*")
    await interaction.response.send_message(text, ephemeral=True)

# ========================= Ping Opt-in Command Handler =========================

@bot.event
async def on_message(message: discord.Message):
    # Handle opt-in/out for Oversighter pings in the restricted channel
    if message.author.bot:
        return
    if message.channel.id != RESTRICTED_CHANNEL_ID:
        return

    text = message.content.strip()

    # ---------------- Oversighter management (bot-admins only) -------------
    if text.lower().startswith("!oversightbot addos"):
        if message.author.id not in BOT_ADMINS:
            await message.reply("Only bot admins may add Oversighters.")
            return
        if not message.mentions:
            await message.reply("Usage: `!OversightBot addos @user`")
            return
        added = []
        for m in message.mentions:
            await add_oversighter(m.id)
            added.append(m.mention)
        await message.reply(
            f"✅ Added {' '.join(added)} as Oversighter(s).", mention_author=False
        )
        return

    if text.lower().startswith("!oversightbot removeos"):
        if message.author.id not in BOT_ADMINS:
            await message.reply("Only bot admins may remove Oversighters.")
            return
        if not message.mentions:
            await message.reply("Usage: `!OversightBot removeos @user`")
            return
        removed = []
        for m in message.mentions:
            await remove_oversighter(m.id)
            removed.append(m.mention)
        await message.reply(
            f"🗑️ Removed {' '.join(removed)} from Oversighters.",
            mention_author=False,
        )
        return

    # ----------------------------- HELP COMMAND -----------------------------
    if text.lower().startswith("!oversightbot help"):
        help_text = (
            f"**OversightBot Command Reference**\n"
            f"• `/oversight <text>` – Submit an Oversight request (max 2 every "
            f"{COOLDOWN_SECONDS}s; *Oversighters & bot-admins exempt*)\n"
            "• `/claim [ID]` – Claim one request or **every** pending request if no ID\n"
            "• `/view <ID>` – View any request by ID (Oversighters only)\n"
            "• `/pending` – List unclaimed request IDs (Oversighters only)\n"
            "• `!OversightBot ping on|off` – Opt‑in/out of pings for new requests "
            "(Oversighters only)\n"
            "• `!OversightBot addos @u` / `removeos @u` – Manage Oversighters "
            "(bot admins only)\n"
            "• `!OversightBot help` – Show this help\n"
        )
        await message.reply(help_text, mention_author=False)
        await bot.process_commands(message)
        return

    if not text.lower().startswith("!oversightbot ping"):
        return

    # Only Oversighters may toggle pings
    if not await is_oversighter(message.author.id):
        await message.reply(
            "Only configured Oversighters can change ping settings.",
            mention_author=False,
        )
        return

    parts = text.lower().split()
    if len(parts) < 3 or parts[2] not in ("on", "off"):
        await message.reply(
            "Usage: `!OversightBot ping on` or `!OversightBot ping off`",
            mention_author=False,
        )
        return

    if parts[2] == "on":
        await add_ping_sub(message.author.id)
        await message.reply(
            "🔔 You'll be pinged for new Oversight requests.",
            mention_author=False,
        )
    else:  # "off"
        await remove_ping_sub(message.author.id)
        await message.reply(
            "🔕 You will no longer receive pings.",
            mention_author=False,
        )

    # Allow further command processing if needed
    await bot.process_commands(message)

# ========================= Error Handling and Startup =========================

@claim.error
@view.error
@pending.error
async def oversight_error(interaction: discord.Interaction, error):
    # Handle permission errors and log unexpected exceptions
    if isinstance(error, app_commands.CheckFailure):
        await interaction.response.send_message(str(error), ephemeral=True)
    else:
        logger.exception("Unhandled error:", exc_info=error)
        await interaction.response.send_message("Unexpected error occurred.", ephemeral=True)

@bot.event
async def on_ready():
    # Log successful bot startup
    logger.info("Logged in as %s (%s)", bot.user, bot.user.id)
    logger.info("Commands synced to guild %s", GUILD_ID)

bot.run(TOKEN)

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
from discord.ui import Button, View, Modal, TextInput
from discord.ext import commands

# =========================== User Interface Messages ============================

# Error and status messages
ERRORS = {
    "not_authenticated": (
        "You must be authenticated to submit an Oversight request. "
        "Please see <https://en.wikipedia.org/wiki/Wikipedia:Requests_for_oversight> "
        "for other ways to submit an Oversight request."
    ),
    "rate_limit_exceeded": "⏳ Rate limit exceeded – max 2 requests every {cooldown}s.",
    "unknown_request_id": "⚠️ Unknown request ID.",
    "invalid_id": "⚠️ Invalid ID.",
    "already_claimed": "Already claimed by {claimant}.",
    "not_oversighter": "You are not configured as an Oversighter.",
    "not_bot_admin": "You are not a bot admin.",
    "only_bot_admins_add": "Only bot admins may add Oversighters.",
    "only_bot_admins_remove": "Only bot admins may remove Oversighters.",
    "only_oversighters_ping": "Only configured Oversighters can change ping settings.",
    "unexpected_error": "Unexpected error occurred.",
}

# Success and confirmation messages
SUCCESS = {
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
}

# Information and notification messages
INFO = {
    "request_claimed_notification": (
        "Your Oversight request #{request_id} was "
        "viewed by Oversighter {claimer}."
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
}

# Restricted channel notifications
RESTRICTED = {
    "request": (
        "**Oversight Request**\n"
        "- ID: #{ticket_id}\n"
        "- Status: {status}\n"
        "- From: {user_mention}\n"
        "- Text:\n> {request_text}\n\n"
        "Oversighters may claim all pending requests with `/claim`."
    ),
    "request_viewed": "{viewer} viewed {status} request #{request_id}.",
    "reminder_sent": (
        "Sent unclaimed-request notice to {user_mention} "
        "for #{request_id} (>{minutes} min old)."
    ),
}

# Help and usage messages
HELP = {
    "command_reference": (
        "**OversightBot Command Reference**\n"
        "- `/oversight <text>` – Submit an Oversight request (max 2 every "
        "{cooldown}s; *Oversighters & bot-admins exempt*)\n"
        "- `/claim [ID]` – Claim one request or **every** pending request if no ID\n"
        "- `/respond <ID> <text>` – Send a response to a request (Oversighters only)\n"
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

# =========================== Configuration ============================

TOKEN: str = os.environ["DISCORD_TOKEN"]

# ────────────────────────────────────────────────────────────────
# Dual‑guild deployment
#   SUBMISSION_GUILD_ID – guild/server where users invoke /oversight
#   CLAIM_GUILD_ID      – guild/server that hosts the restricted
#                         channel and where Oversighters process
#                         requests with /claim, /pending, etc.
# ────────────────────────────────────────────────────────────────
SUBMISSION_GUILD_ID: int = int(os.environ["SUBMISSION_GUILD_ID"])
CLAIM_GUILD_ID: int = int(os.environ["CLAIM_GUILD_ID"])

# Restricted channel now lives on the *CLAIM* guild (different
# from where /oversight is run) – channel IDs are still globally
# unique so only its ID is required here.
RESTRICTED_CHANNEL_ID: int = int(os.environ["RESTRICTED_CHANNEL_ID"])

# Optional Discord role that automatically grants Oversighter
# privileges (in addition to DB‑listed Oversighters)
OVERSIGHT_ROLE_ID: Optional[int] = (
    int(os.getenv("OVERSIGHT_ROLE_ID")) if os.getenv("OVERSIGHT_ROLE_ID") else None
)

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
ID_OFFSET = 1000

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

# ---------------------------------------------------------------------------
#  🔧  COMMON HELPER FOR SENDING OVERSIGHT RESPONSES
# ---------------------------------------------------------------------------
async def _send_oversight_response(
    interaction: discord.Interaction,
    ext_id: int,
    response_text: str,
) -> None:
    """DM the requester and copy the response to the restricted channel."""
    try:
        row_id = ext_id_to_row(ext_id)
    except ValueError:
        await interaction.response.send_message(ERRORS["invalid_id"], ephemeral=True)
        return

    req = await fetch_request(row_id)
    if not req:
        await interaction.response.send_message(ERRORS["unknown_request_id"], ephemeral=True)
        return

    # -------- DM the original submitter ------------------------------------
    try:
        user = await bot.fetch_user(req["author_id"])
        await user.send(f"Response from the oversight team on Oversight request #{ext_id}: {response_text}")
    except discord.HTTPException:
        pass

    # --- link to the original request message -----------------------------
    if req["message_id"]:
        req_url = (
            f"https://discord.com/channels/"
            f"{CLAIM_GUILD_ID}/{RESTRICTED_CHANNEL_ID}/{req['message_id']}"
        )
        req_ref = f"[request #{ext_id}]({req_url})"
    else:
        req_ref = f"request #{ext_id}"

    await notify_restricted(
        bot,
        f"Oversighter {interaction.user.mention} responded to {req_ref} "
        f"with the following:\n> {response_text}",
    )

    await interaction.response.send_message("✅ Response sent.", ephemeral=True)


# ---------------------------------------------------------------------------
#  🔧  UI – Buttons & Modal attached to each request message
# ---------------------------------------------------------------------------

class RespondModal(Modal, title="Respond to request"):
    """Modal shown after the **Respond** button is clicked."""

    def __init__(self, ext_id: int):
        super().__init__(timeout=180, title=f"Respond to request #{ext_id}")
        self.ext_id = ext_id

        # One multiline textbox
        self.response: TextInput = TextInput(
            label="Response",
            placeholder="Enter your response…",
            style=discord.TextStyle.paragraph,
        )
        self.add_item(self.response)

    async def on_submit(self, interaction: discord.Interaction):
        """Called when the modal is submitted."""
        await _send_oversight_response(
            interaction,
            self.ext_id,
            self.response.value,
        )


class RequestView(View):
    """Interactive view added to every freshly-posted request."""

    def __init__(self, ext_id: int):
        super().__init__(timeout=None)
        self.ext_id = ext_id
        self.message: Optional[discord.Message] = None  # filled in after send

        # ---- CLAIM BUTTON --------------------------------------------------
        async def _claim_cb(inter: discord.Interaction):
            # Role‑based oversighter (fast‑path)
            if OVERSIGHT_ROLE_ID and any(r.id == OVERSIGHT_ROLE_ID for r in inter.user.roles):
                pass
            # Fallback to DB‑listed oversighters
            elif not await is_oversighter(inter.user.id):
                await inter.response.send_message(ERRORS["not_oversighter"], ephemeral=True)
                return

            # Same effect as /claim <id>
            if not await claim_request(ext_id_to_row(self.ext_id), inter.user.id):
                await inter.response.send_message(
                    ERRORS["already_claimed"].format(claimant="someone"),
                    ephemeral=True,
                )
                return

            await inter.response.send_message(
                f"Request #{self.ext_id} claimed. {SUCCESS['follow_up_note']}",
                ephemeral=True,
            )

            # Update the visible status line & remove the Claim button
            if self.message:
                new_content = self.message.content.replace(
                    "🔴 Unclaimed",
                    f"✅ Claimed by {inter.user.mention}",
                )
                self.remove_item(self.children[0])  # remove Claim button
                await self.message.edit(content=new_content, view=self)

        claim_btn = Button(
            label="Claim",
            style=discord.ButtonStyle.success,
            custom_id=f"claim_{ext_id}",
        )
        claim_btn.callback = _claim_cb
        self.add_item(claim_btn)

        # ---- RESPOND BUTTON ------------------------------------------------
        async def _respond_cb(inter: discord.Interaction):
            # Role‑based oversighter (fast‑path)
            if OVERSIGHT_ROLE_ID and any(r.id == OVERSIGHT_ROLE_ID for r in inter.user.roles):
                pass
            # Fallback to DB‑listed oversighters
            elif not await is_oversighter(inter.user.id):
                await inter.response.send_message(ERRORS["not_oversighter"], ephemeral=True)
                return
            await inter.response.send_modal(RespondModal(self.ext_id))

        respond_btn = Button(
            label="Respond",
            style=discord.ButtonStyle.primary,
            custom_id=f"respond_{ext_id}",
        )
        respond_btn.callback = _respond_cb
        self.add_item(respond_btn)


# ===================  Oversighter & Admin helpers  ====================

async def is_oversighter(user_id: int) -> bool:
    """Return True if user_id is currently an Oversighter."""
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT 1 FROM oversighters WHERE user_id = ? LIMIT 1", (user_id,)
        )
        return await cur.fetchone() is not None


def oversighter_check():
    """Decorator that checks current Oversighter status (DB **or role**)."""

    async def predicate(interaction: discord.Interaction) -> bool:
        # Role‑based oversighter (fast‑path)
        if OVERSIGHT_ROLE_ID and any(r.id == OVERSIGHT_ROLE_ID for r in interaction.user.roles):
            return True
        # Fallback to DB‑listed oversighters
        if await is_oversighter(interaction.user.id):
            return True
        raise app_commands.CheckFailure(ERRORS["not_oversighter"])

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
            raise app_commands.CheckFailure(ERRORS["not_bot_admin"])
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
) -> None:
    """Send a message to the restricted channel."""
    chan = bot.get_channel(RESTRICTED_CHANNEL_ID)
    if not chan:
        return
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
    window_ts = int(datetime.now(timezone.utc).timestamp()) - COOLDOWN_SECONDS
    cur = await db.execute(
        "SELECT COUNT(*) FROM requests "
        "WHERE author_id = ? AND created_at >= ?",
        (author_id, window_ts),
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
                    ERRORS["rate_limit_exceeded"].format(cooldown=COOLDOWN_SECONDS)
                )
        now_ts = int(datetime.now(timezone.utc).timestamp())
        cur = await db.execute(
            "INSERT INTO requests (author_id, text, created_at) VALUES (?, ?, ?)",
            (author_id, text, now_ts),
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
        now_ts = int(datetime.now(timezone.utc).timestamp())
        cur = await db.execute(
            "UPDATE requests SET claimed_by = ?, claimed_at = ? "
            "WHERE id = ? AND claimed_by IS NULL",
            (claimer_id, now_ts, row_id),
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
        cutoff_ts = int(datetime.utcnow().timestamp()) - REMINDER_MINUTES * 60
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = sqlite3.Row
            # include message_id so we can build a link
            cur = await db.execute(
                "SELECT id, author_id, text, message_id FROM requests "
                "WHERE claimed_by IS NULL "
                "  AND created_at < ? "
                "  AND (reminded_at IS NULL)",
                (cutoff_ts,),
            )
            rows = await cur.fetchall()

            for row in rows:
                ext_id = row_to_ext_id(row["id"])

                # Build a markdown link to the original request, if known
                if row["message_id"]:
                    req_url = (
                        f"https://discord.com/channels/"
                        f"{CLAIM_GUILD_ID}/{RESTRICTED_CHANNEL_ID}/{row['message_id']}"
                    )
                    req_ref = f"[request #{ext_id}]({req_url})"
                else:
                    req_ref = f"request #{ext_id}"

                author = await bot.fetch_user(row["author_id"])
                request_text = row["text"]
                msg = INFO["reminder_message"].format(
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
                    f"Sent unclaimed-request notice to {author.mention} for "
                    f"{req_ref} (>{REMINDER_MINUTES} min old).",
                )

                now_ts = int(datetime.utcnow().timestamp())
                await db.execute(
                    "UPDATE requests SET reminded_at = ? WHERE id = ?",
                    (now_ts, row["id"]),
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
        # Sync commands to *both* guilds (they host different command sets)
        await self.tree.sync(guild=SUBMISSION_GUILD_OBJ)
        await self.tree.sync(guild=CLAIM_GUILD_OBJ)

bot = OversightBot(command_prefix="!", intents=intents)
SUBMISSION_GUILD_OBJ = discord.Object(id=SUBMISSION_GUILD_ID)
CLAIM_GUILD_OBJ = discord.Object(id=CLAIM_GUILD_ID)

# ========================= Slash Command Handlers =========================

@bot.tree.command(
    name="oversight",
    description="Submit a Wikipedia Oversight request",
    guild=SUBMISSION_GUILD_OBJ,
)
@app_commands.describe(request_text="Describe what needs to be oversighted.")
async def oversight(interaction: discord.Interaction, request_text: str):
    # Optionally restrict submission to users with a specific role
    if SUBMITTER_ROLE_ID:
        if SUBMITTER_ROLE_ID not in {role.id for role in interaction.user.roles}:
            await interaction.response.send_message(
                ERRORS["not_authenticated"],
                ephemeral=True,
            )
            return

    await interaction.response.defer(ephemeral=True)
    try:
        ticket_id = await create_request(interaction.user.id, request_text)
    except RuntimeError as e:
        await interaction.followup.send(ERRORS["rate_limit_exceeded"].format(cooldown=COOLDOWN_SECONDS), ephemeral=True)
        return

    # Confirm submission and echo back the request for verification
    await interaction.followup.send(
        SUCCESS["request_filed"].format(ticket_id=ticket_id, request_text=request_text),
        ephemeral=True,
    )

    # Post the request and remember its message-ID
    status_line = "🔴 Unclaimed"
    content = RESTRICTED["request"].format(
        ticket_id=ticket_id,
        status=status_line,
        user_mention=interaction.user.mention,
        request_text=request_text,
    )

    chan = bot.get_channel(RESTRICTED_CHANNEL_ID)
    # include optional pings
    if (subs := await get_ping_subs()):
        content += " " + " ".join(f"<@{uid}>" for uid in subs)

    # Attach buttons
    view = RequestView(ticket_id)
    msg = await chan.send(content, view=view)  # POST with interactive buttons
    view.message = msg                        # store for later edits
    # remember the message id so we can edit it later
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE requests SET message_id = ? WHERE id = ?",
            (msg.id, ext_id_to_row(ticket_id)),
        )
        await db.commit()
    
    logger.info("Request %s submitted by %s", ticket_id, interaction.user)

@bot.tree.command(
    name="claim",
    description="Claim and receive an Oversight request",
    guild=CLAIM_GUILD_OBJ,
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
                await interaction.followup.send(ERRORS["unknown_request_id"], ephemeral=True)
            return

        # Try to claim atomically
        success = False
        if not req["claimed_by"]:
            success = await claim_request(_row_id, interaction.user.id)
            if success:
                req = await fetch_request(_row_id)  # refresh with claimer info

        # ----- If already claimed (by anyone), show details like /view -----
        if req["claimed_by"] and not success:
            claimant = await bot.fetch_user(req["claimed_by"])
            if first:
                await interaction.followup.send(
                    ERRORS["already_claimed"].format(claimant=claimant.mention),
                    ephemeral=True,
                )
            return

        # ----- Newly claimed by the caller -----
        await interaction.followup.send(
            f"Request #{row_to_ext_id(_row_id)} claimed. "
            + f"{SUCCESS['follow_up_note']}",
            ephemeral=True,
        )

        # Notify author only on *new* claim
        if req["author_id"]:
            try:
                user = await bot.fetch_user(req["author_id"])
                await user.send(
                    INFO["request_claimed_notification"].format(
                        request_id=row_to_ext_id(_row_id),
                        claimer=interaction.user.mention,
                    )
                )
            except discord.HTTPException:
                pass

        # Edit the status when a request is claimed
        msg_id = req["message_id"]
        if msg_id:
            chan = bot.get_channel(RESTRICTED_CHANNEL_ID)
            try:
                msg = await chan.fetch_message(msg_id)
                new_content = RESTRICTED["request"].format(
                    ticket_id=row_to_ext_id(_row_id),
                    status=f"✅ Claimed by {interaction.user.mention}",
                    user_mention=f"<@{req['author_id']}>",
                    request_text=req["text"],
                )
                await msg.edit(content=new_content)
            except discord.NotFound:
                # fall back silently if the original message vanished
                pass

    # Defer the response to avoid race conditions
    await interaction.response.defer(ephemeral=True)
    # ---------------- Single-ID path ----------------
    if request_id is not None:
        try:
            row_id = ext_id_to_row(request_id)
        except ValueError:
            await interaction.followup.send(ERRORS["invalid_id"], ephemeral=True)
            return

        await _claim_one(row_id, True)
        return

    # ---------------- Bulk-claim path (/claim with no args) ---------------
    pending = await list_pending()
    if not pending:
        await interaction.followup.send(SUCCESS["no_unclaimed"], ephemeral=True)
        return

    await interaction.followup.send(
        SUCCESS["claiming_multiple"].format(count=len(pending)), ephemeral=True
    )
    for idx, ext_id in enumerate(pending, start=1):
        await _claim_one(ext_id_to_row(ext_id), idx == 1)

# ---------------------------------------------------------------------------
#  /respond – Send a response to the requester (claim guild only)
# ---------------------------------------------------------------------------
@bot.tree.command(
    name="respond",
    description="Send a response to an Oversight request",
    guild=CLAIM_GUILD_OBJ,
)
@oversighter_check()
@app_commands.describe(
    request_id="Ticket ID you are responding to",
    response_text="Your response text",
)
async def respond(
    interaction: discord.Interaction,
    request_id: int,
    response_text: str,
):
    await _send_oversight_response(interaction, request_id, response_text)

# /view command removed – full request text is always available in the restricted
# channel, making a separate viewer unnecessary.

@bot.tree.command(
    name="pending",
    description="List all unclaimed Oversight request IDs",
    guild=CLAIM_GUILD_OBJ,
)
@oversighter_check()
async def pending(interaction: discord.Interaction):
    # List all unclaimed requests for Oversighters
    ids = await list_pending()
    text = INFO["unclaimed_requests"].format(ids=", ".join(f"`{i}`" for i in ids) or INFO["none_available"])
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
            await message.reply(ERRORS["only_bot_admins_add"])
            return
        if not message.mentions:
            await message.reply(HELP["usage_addos"])
            return
        added = []
        for m in message.mentions:
            await add_oversighter(m.id)
            added.append(m.mention)
        await message.reply(
            SUCCESS["added_oversighters"].format(users=" ".join(added)), mention_author=False
        )
        return

    if text.lower().startswith("!oversightbot removeos"):
        if message.author.id not in BOT_ADMINS:
            await message.reply(ERRORS["only_bot_admins_remove"])
            return
        if not message.mentions:
            await message.reply(HELP["usage_removeos"])
            return
        removed = []
        for m in message.mentions:
            await remove_oversighter(m.id)
            removed.append(m.mention)
        await message.reply(
            SUCCESS["removed_oversighters"].format(users=" ".join(removed)),
            mention_author=False,
        )
        return

    # ----------------------------- HELP COMMAND -----------------------------
    if text.lower().startswith("!oversightbot help"):
        help_text = HELP["command_reference"].format(cooldown=COOLDOWN_SECONDS)
        await message.reply(help_text, mention_author=False)
        await bot.process_commands(message)
        return

    if not text.lower().startswith("!oversightbot ping"):
        return

    # Only Oversighters may toggle pings
    if not (
        await is_oversighter(message.author.id)
        or (OVERSIGHT_ROLE_ID and OVERSIGHT_ROLE_ID in {r.id for r in getattr(message.author, "roles", [])})
    ):
        await message.reply(
            ERRORS["only_oversighters_ping"],
            mention_author=False,
        )
        return

    parts = text.lower().split()
    if len(parts) < 3 or parts[2] not in ("on", "off"):
        await message.reply(
            HELP["usage_ping"],
            mention_author=False,
        )
        return

    if parts[2] == "on":
        await add_ping_sub(message.author.id)
        await message.reply(
            SUCCESS["ping_enabled"],
            mention_author=False,
        )
    else:  # "off"
        await remove_ping_sub(message.author.id)
        await message.reply(
            SUCCESS["ping_disabled"],
            mention_author=False,
        )

    # Allow further command processing if needed
    await bot.process_commands(message)

# ========================= Error Handling and Startup =========================

@claim.error
@pending.error
async def oversight_error(interaction: discord.Interaction, error):
    # Handle permission errors and log unexpected exceptions
    if isinstance(error, app_commands.CheckFailure):
        await interaction.response.send_message(ERRORS["not_oversighter"], ephemeral=True)
    else:
        logger.exception("Unhandled error:", exc_info=error)
        await interaction.response.send_message(ERRORS["unexpected_error"], ephemeral=True)

@bot.event
async def on_ready():
    # Log successful bot startup
    logger.info("Logged in as %s (%s)", bot.user, bot.user.id)
    logger.info("Commands synced to guilds %s (submit) and %s (claim)", SUBMISSION_GUILD_ID, CLAIM_GUILD_ID)

bot.run(TOKEN)

# oversight_bot.py
#
# A Discord bot to intake English‑Wikipedia Oversight requests and deliver them
# only to users who hold the "Oversighter" role in a designated restricted
# channel.  Secrets and configuration come exclusively from environment vars.
# oversight_bot.py  – v2
#
# A Discord bot for handling English‑Wikipedia Oversight requests.
# Changes from v1:
#   • Oversighters listed in ENV rather than role‑based gating
#   • Author is notified when a request is *viewed* by a named Oversighter
#   • /pending – list all unclaimed requests
#   • /view  – lets Oversighters read an already‑claimed request (logged privately)
#   • Numeric ticket IDs, starting at 101
#   • Per‑user rate‑limit: max 2 requests per <COOLDOWN_SECONDS>
#   • Requests stored in a lightweight SQLite file (path from ENV)

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

# ───────────────────────── 1 • Configuration ────────────────────────── #

TOKEN: str = os.environ["DISCORD_TOKEN"]

GUILD_ID: int = int(os.environ["GUILD_ID"])
RESTRICTED_CHANNEL_ID: int = int(os.environ["RESTRICTED_CHANNEL_ID"])

OVERSIGHTERS: Set[int] = {
    int(x.strip()) for x in os.environ["OVERSIGHTERS"].split(",") if x.strip()
}

# Optional role required to *submit* /oversight (leave unset to disable)
SUBMITTER_ROLE_ID: Optional[int] = (
    int(os.getenv("SUBMITTER_ROLE_ID")) if os.getenv("SUBMITTER_ROLE_ID") else None
)

COOLDOWN_SECONDS: int = int(os.getenv("COOLDOWN_SECONDS", "600"))
DB_PATH: str = os.getenv("DB_PATH", "./oversight.sqlite")

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    force=True,
)
logger = logging.getLogger("oversight-bot")

# Numeric IDs start at 101
ID_OFFSET = 100  # external‑ID 101 corresponds to internal rowid 1

# ──────────────────── 2 • Utility / permission helpers ───────────────── #

def ext_id_to_row(ext_id: int) -> int:
    """User‑facing ID → DB rowid (raises ValueError if out of range)."""
    internal = ext_id - ID_OFFSET
    if internal <= 0:
        raise ValueError
    return internal

def row_to_ext_id(rowid: int) -> int:
    return rowid + ID_OFFSET

def oversighter_check():
    async def predicate(interaction: discord.Interaction) -> bool:
        if interaction.user.id not in OVERSIGHTERS:
            raise app_commands.CheckFailure(
                "You are not configured as an Oversighter."
            )
        return True
    return app_commands.check(predicate)

async def notify_restricted(
    bot: commands.Bot,
    content: str,
    ping_new: bool = False,      # ping only on brand-new requests
) -> None:
    chan = bot.get_channel(RESTRICTED_CHANNEL_ID)
    if not chan:
        return

    if ping_new:
        subs = await get_ping_subs()
        if subs:  # append mentions
            content += " " + " ".join(f"<@{uid}>" for uid in subs)

    await chan.send(content)

# ───────────────────────── 3 • Database layer (SQLite) ────────────────── #

DB_LOCK = asyncio.Lock()   # avoids simultaneous schema setup on first run

async def init_db() -> None:
    async with DB_LOCK:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """CREATE TABLE IF NOT EXISTS requests (
                       id          INTEGER PRIMARY KEY AUTOINCREMENT,
                       author_id   INTEGER NOT NULL,
                       text        TEXT    NOT NULL,
                       created_at  DATETIME DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
                       claimed_by  INTEGER,
                       claimed_at  DATETIME
                   )"""
            )
            await db.commit()

            # ── NEW: table to store ping-opt-in users ─────────────────── #
            await db.execute(
                "CREATE TABLE IF NOT EXISTS ping_subscribers ("
                "user_id INTEGER PRIMARY KEY)"
            )
            await db.commit()

# ─────────────────────── Ping-subscriber helpers ─────────────────────── #

async def add_ping_sub(user_id: int) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR IGNORE INTO ping_subscribers (user_id) VALUES (?)",
            (user_id,),
        )
        await db.commit()

async def remove_ping_sub(user_id: int) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "DELETE FROM ping_subscribers WHERE user_id = ?", (user_id,)
        )
        await db.commit()

async def get_ping_subs() -> List[int]:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT user_id FROM ping_subscribers")
        rows = await cur.fetchall()
        return [r[0] for r in rows]

async def recent_request_count(db, author_id: int) -> int:
    window = datetime.now(timezone.utc) - timedelta(seconds=COOLDOWN_SECONDS)
    cur = await db.execute(
        "SELECT COUNT(*) FROM requests "
        "WHERE author_id = ? AND created_at >= ?",
        (author_id, window.isoformat(timespec="seconds")),
    )
    (cnt,) = await cur.fetchone()
    return cnt

async def create_request(author_id: int, text: str) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        # Rate‑limit check
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
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = sqlite3.Row
        cur = await db.execute("SELECT * FROM requests WHERE id = ?", (row_id,))
        return await cur.fetchone()

async def claim_request(row_id: int, claimer_id: int) -> bool:
    """
    Attempt to atomically claim a request.
    Returns True on success, False if already claimed.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "UPDATE requests SET claimed_by = ?, claimed_at = CURRENT_TIMESTAMP "
            "WHERE id = ? AND claimed_by IS NULL",
            (claimer_id, row_id),
        )
        await db.commit()
        return cur.rowcount == 1

async def list_pending() -> List[int]:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT id FROM requests WHERE claimed_by IS NULL ORDER BY id"
        )
        rows = await cur.fetchall()
        return [row_to_ext_id(r[0]) for r in rows]

# ───────────────────────── 4 • Discord bot setup ──────────────────────── #

# We now need message-content intent for the "!OversightBot ping" commands
intents = discord.Intents.default()
intents.message_content = True

class OversightBot(commands.Bot):
    async def setup_hook(self) -> None:
        # Runs before the bot logs in & syncs commands
        await init_db()
        await self.tree.sync(guild=GUILD_OBJ)

bot = OversightBot(command_prefix="!", intents=intents)
GUILD_OBJ = discord.Object(id=GUILD_ID)

# ───────────────────────── 5 • /oversight command ─────────────────────── #

@bot.tree.command(
    name="oversight",
    description="Submit a Wikipedia Oversight request",
    guild=GUILD_OBJ,
)
@app_commands.describe(request_text="Describe what needs to be oversighted.")
async def oversight(interaction: discord.Interaction, request_text: str):
    # ── Optional role gate ───────────────────────────────────────────── #
    if SUBMITTER_ROLE_ID:
        # interaction.user is a Member inside the guild for slash cmds
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

    # Confirm to the submitter
    await interaction.followup.send(
        f"✅ Your request has been filed with ID **{ticket_id}**.\n\n"
        f"**You submitted:**\n> {request_text}",
        ephemeral=True,
    )

    # Notify restricted channel (metadata only)
    await notify_restricted(
        bot,
        (
            "🔔 **New Oversight Request**\n"
            f"• ID: `{ticket_id}`\n"
            f"• From: {interaction.user.mention}\n"
            "Oversighters may claim it with `/claim <ID>`."
        ),
        ping_new=True,          # ← trigger optional pings
    )
    logger.info("Request %s submitted by %s", ticket_id, interaction.user)

# ──────────────────────── 6 • /claim (Oversighters) ───────────────────── #

@bot.tree.command(
    name="claim",
    description="Claim and receive an Oversight request",
    guild=GUILD_OBJ,
)
@oversighter_check()
@app_commands.describe(request_id="Numeric ticket ID (see restricted channel)")
async def claim(interaction: discord.Interaction, request_id: int):
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

    # Attempt atomic claim
    if not req["claimed_by"]:
        success = await claim_request(row_id, interaction.user.id)
        if not success:
            # Race: someone else claimed a millisecond earlier
            req = await fetch_request(row_id)

    if req["claimed_by"] and req["claimed_by"] != interaction.user.id:
        claimant = await bot.fetch_user(req["claimed_by"])
        await interaction.followup.send(
            f"❌ Already claimed by {claimant.mention}. "
            "Use `/view` if you still need to read it.",
            ephemeral=True,
        )
        return

    # Send DM with the request text
    try:
        await interaction.user.send(
            f"📄 **Oversight Request {request_id}**\n\n"
            f"{req['text']}\n\n"
            f"_Submitted by <@{req['author_id']}>_"
        )
    except discord.HTTPException:
        await interaction.followup.send(
            "❌ Couldn't send you a DM. Check your privacy settings.", ephemeral=True
        )
        return

    # Let the author know who viewed it (only first time)
    if req["author_id"]:
        try:
            user = await bot.fetch_user(req["author_id"])
            await user.send(
                f"👁️‍🗨️ Your Oversight request **{request_id}** was claimed by "
                f"{interaction.user.mention}."
            )
        except discord.HTTPException:
            pass  # ignore if author doesn't accept DMs

    # Announce in restricted channel
    await notify_restricted(
        bot,
        f"✅ Request `{request_id}` claimed by {interaction.user.mention}."
    )
    await interaction.followup.send("📬 I've sent the request to your DMs.", ephemeral=True)
    logger.info("Request %s claimed by %s", request_id, interaction.user)

# ───────────────────────── 7 • /view (claimed) ────────────────────────── #

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

    # DM the Oversighter
    try:
        await interaction.user.send(
            f"📄 **Oversight Request {request_id}**\n\n"
            f"{req['text']}\n\n"
            f"_Submitted by <@{req['author_id']}>_"
        )
    except discord.HTTPException:
        await interaction.followup.send(
            "❌ Couldn't DM you. Check your privacy settings.", ephemeral=True
        )
        return

    # Notify restricted channel (no author ping; indicate if still unclaimed)
    status = "unclaimed" if unclaimed else "claimed"
    await notify_restricted(
        bot,
        f"👓 {interaction.user.mention} viewed {status} request `{request_id}`."
    )
    await interaction.followup.send("✅ Check your DMs – request delivered.", ephemeral=True)
    logger.info("Request %s viewed by %s (status: %s)", request_id, interaction.user, status)

# ──────────────────────── 8 • /pending (unclaimed) ────────────────────── #

@bot.tree.command(
    name="pending",
    description="List all unclaimed Oversight request IDs",
    guild=GUILD_OBJ,
)
@oversighter_check()
async def pending(interaction: discord.Interaction):
    ids = await list_pending()
    text = "🔗 **Unclaimed requests:** " + (", ".join(f"`{i}`" for i in ids) or "*(none)*")
    await interaction.response.send_message(text, ephemeral=True)

# ─────────────────────── "!OversightBot ping" handler ─────────────────── #

@bot.event
async def on_message(message: discord.Message):
    if message.author.bot:
        return
    if message.channel.id != RESTRICTED_CHANNEL_ID:
        return

    text = message.content.strip()
    if not text.lower().startswith("!oversightbot ping"):
        return

    # Only configured Oversighters may opt-in/out
    if message.author.id not in OVERSIGHTERS:
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

    # Let slash-command processing continue (not strictly needed here)
    await bot.process_commands(message)

# ───────────────────────── 9 • Error handler ──────────────────────────── #

@claim.error
@view.error
@pending.error
async def oversight_error(interaction: discord.Interaction, error):
    if isinstance(error, app_commands.CheckFailure):
        await interaction.response.send_message(str(error), ephemeral=True)
    else:
        logger.exception("Unhandled error:", exc_info=error)
        await interaction.response.send_message("Unexpected error occurred.", ephemeral=True)

# ───────────────────────── 10 • Start‑up hooks ────────────────────────── #

@bot.event
async def on_ready():
    logger.info("Logged in as %s (%s)", bot.user, bot.user.id)
    logger.info("Commands synced to guild %s", GUILD_ID)

bot.run(TOKEN)

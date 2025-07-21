"""
Discord Oversight Request Bot  –  Modmail-style edition  (2025-07-21)

New workflow highlights
────────────────────────────────────────────────────────────────────────────
• Every request spawns a **private thread** in the restricted channel.
  – Thread title  :  “Request #<ID>”
  – First post    :  Same embed/message that appears in the main channel
• Main-channel message AND thread header both show live status.
  (“🟢 Open”, “✅ Resolved”, “✅ Resolved – follow-up sent”)
• Buttons & commands
    – **Resolve**  (button or  `/resolve`)   → marks request resolved
    – **Respond**  (button or  `/respond`)   → sends reply but keeps status
• All acknowledgements go to the requester via **DMs** (not ephemerals)
  – DMs include a **“Follow-up”** button so the user can message Oversight;
    their follow-up is posted to the thread and status flips to
    “Resolved – follow-up sent”.
• All main-channel request messages are **pinned while open** and un-pinned
  on resolution.
• Database schema simplified:  no “claimed” fields, instead
      status TEXT  ('open' | 'resolved' | 'resolved_followup')
      thread_id INTEGER
      message_id INTEGER
      resolved_by INTEGER
      resolved_at INTEGER
────────────────────────────────────────────────────────────────────────────
Dependencies: discord.py ≥ 2.4, aiosqlite
"""

import asyncio
import logging
import os
import sqlite3
from datetime import datetime, timezone
from typing import Optional, Set, List

import aiosqlite
import discord
from discord import app_commands
from discord.ui import View, Button, Modal, TextInput
from discord.ext import commands
import re
from discord import MessageType

# Configuration
TOKEN                    = os.environ["DISCORD_TOKEN"]
SUBMISSION_GUILD_ID      = int(os.environ["SUBMISSION_GUILD_ID"])
CLAIM_GUILD_ID           = int(os.environ["CLAIM_GUILD_ID"])
RESTRICTED_CHANNEL_ID    = int(os.environ["RESTRICTED_CHANNEL_ID"])
OVERSIGHT_ROLE_ID: Set[int] = {
    int(x) for x in os.getenv("OVERSIGHT_ROLE_ID", "").split(",") if x.strip()
}
BOT_ADMINS: Set[int]     = {
    int(x) for x in os.getenv("BOT_ADMINS", "").split(",") if x.strip()
}
SUBMITTER_ROLE_ID: Set[int] = {
    int(x) for x in os.getenv("SUBMITTER_ROLE_ID", "").split(",") if x.strip()
}
COOLDOWN_SECONDS = int(os.getenv("COOLDOWN_SECONDS", "600"))
REMINDER_MINUTES = int(os.getenv("REMINDER_MINUTES", "15"))
DB_PATH          = os.getenv("DB_PATH", "./oversight.sqlite")
ID_OFFSET        = 1000

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    force=True,
)
log = logging.getLogger("oversight-modmail")

# ─────────────── ticket lifecycle labels ────────────────
# NB: “pending” keeps a placeholder; the actor/target names are
#     appended dynamically in update_status().
STATUSES = {
    "open":              "🟡 Open",
    "pending":           "🕒 Pending response by requester",
    "resolved":          "🟢 Resolved",
    "resolved_followup": "🟡 Reopened by requester",
}

# Database schema and helpers
CREATE_SQL = """
CREATE TABLE IF NOT EXISTS requests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id       INTEGER NOT NULL,
    text            TEXT    NOT NULL,
    created_at      INTEGER DEFAULT (strftime('%s','now')),
    status          TEXT    DEFAULT 'open',
    thread_id       INTEGER,
    message_id      INTEGER,
    resolved_by     INTEGER,
    resolved_at     INTEGER,
    last_oversighter_id INTEGER,           -- who last replied
    reminded_at     INTEGER
);
CREATE TABLE IF NOT EXISTS oversighters      (user_id INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS ping_subscribers (user_id INTEGER PRIMARY KEY);
"""

async def init_db() -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        for stmt in CREATE_SQL.strip().split(";"):
            if stmt.strip():
                await db.execute(stmt)
        # Idempotent migration for older installs
        try:
            await db.execute("ALTER TABLE requests ADD COLUMN last_oversighter_id INTEGER")
        except aiosqlite.OperationalError:
            pass  # already present
        await db.commit()

def ext2row(ext_id: int) -> int:
    val = ext_id - ID_OFFSET
    if val <= 0:
        raise ValueError
    return val

def row2ext(row_id: int) -> int:
    return row_id + ID_OFFSET

# Utility helpers
async def add_ping(uid: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT OR IGNORE INTO ping_subscribers VALUES (?)", (uid,))
        await db.commit()

async def rm_ping(uid: int):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM ping_subscribers WHERE user_id = ?", (uid,))
        await db.commit()

async def ping_list() -> List[int]:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT user_id FROM ping_subscribers")
        return [r[0] for r in await cur.fetchall()]

async def is_oversighter(uid: int) -> bool:
    if uid in BOT_ADMINS:
        return True
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT 1 FROM oversighters WHERE user_id = ? LIMIT 1", (uid,))
        if await cur.fetchone():
            return True
    return False

async def has_oversight_perm(member: discord.Member) -> bool:
    if await is_oversighter(member.id):
        return True
    return any(role.id in OVERSIGHT_ROLE_ID for role in member.roles)

# Bot setup
intents = discord.Intents.default()
intents.message_content = True        # still need this for content inspection
intents.members = True                # ← enables .roles on interaction.user

class OversightBot(commands.Bot):
    async def setup_hook(self) -> None:
        await init_db()
        self.reminder = asyncio.create_task(reminder_loop(self))
        await self.tree.sync(guild=discord.Object(SUBMISSION_GUILD_ID))
        await self.tree.sync(guild=discord.Object(CLAIM_GUILD_ID))

bot = OversightBot(command_prefix="!", intents=intents)
SUBMISSION_GUILD = discord.Object(SUBMISSION_GUILD_ID)
CLAIM_GUILD      = discord.Object(CLAIM_GUILD_ID)

# Message rendering and status updates
async def render_request(ticket_id: int,
                        author_mention: str,
                        text: str,
                        status: str,
                        thread_link: str | None = None) -> str:
    return (
        f"**Oversight Request**\n"
        f"- ID: #{ticket_id}\n"
        f"- Status: {status}\n"
        f"- From: {author_mention}\n"
        f"- Text:\n> {text}\n\n"
        f"(Thread: {thread_link or f'<#{RESTRICTED_CHANNEL_ID}>'})"
    )

# ────────────────────────────────────────────────────────────────────
# Utilities for tidy status handling
# ────────────────────────────────────────────────────────────────────

def _replace_status_block(lines: List[str], fresh: str) -> List[str]:
    """
    Remove *all* existing “Status:” lines and insert the fresh one right after
    the “- ID:” line.  This guarantees exactly one status line every time.
    """
    cleaned, inserted = [], False
    for ln in lines:
        if re.match(r"^-?\s*Status:", ln.strip()):
            continue                                   # drop stale status lines
        cleaned.append(ln)
        if not inserted and ln.strip().startswith("- ID:"):
            cleaned.append(fresh)
            inserted = True
    if not inserted:                                  # malformed message; fall‑back
        cleaned.insert(1, fresh)
    return cleaned

async def _thread_header(thread: discord.Thread, bot: commands.Bot) -> Optional[discord.Message]:
    """
    Return the first **regular** (non‑system) message in the thread that was
    authored by *this* bot.  That is the header we want to keep updating.
    """
    async for m in thread.history(limit=20, oldest_first=True):
        if m.type is MessageType.default and m.author.id == bot.user.id:
            return m
    return None

async def update_status(
    bot: commands.Bot,
    row_id: int,
    new_status: str,
    *,
    actor_id: int | None = None,   # oversighter performing the action
    target_id: int | None = None,  # user waiting to reply
) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT message_id, thread_id FROM requests WHERE id = ?", (row_id,))
        row = await cur.fetchone()
    if not row:
        return
    main_msg_id, thread_id = row
    chan = bot.get_channel(RESTRICTED_CHANNEL_ID)
    thread = bot.get_channel(thread_id) if thread_id else None
    
    if new_status == "resolved":
        fresh = f"- Status: {STATUSES[new_status]} by Oversighter <@{actor_id}>"
    elif new_status == "pending":
        fresh = (f"- Status: {STATUSES[new_status]} "
                    f"to Oversighter <@{target_id}>")
    else:
        fresh = f"- Status: {STATUSES[new_status]}"
    
    if chan and main_msg_id:
        try:
            # fetch FIRST, then read / patch
            main_msg: discord.Message = await chan.fetch_message(main_msg_id)
            patched = _replace_status_block(main_msg.content.splitlines(), fresh)
            await main_msg.edit(content="\n".join(patched))

            # pin / un‑pin -------------------------------------------------
            try:
                if new_status == "resolved":
                    await main_msg.unpin()
                else:
                    await main_msg.pin()
            except discord.HTTPException:
                pass
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            pass
    if thread:
        try:
            header = await _thread_header(thread, bot)
            if header:
                fixed = _replace_status_block(header.content.splitlines(), fresh)
                await header.edit(content="\n".join(fixed))
        except (discord.NotFound, discord.Forbidden, discord.HTTPException):
            pass

# UI views
class RespondModal(Modal, title="Send response"):
    def __init__(self, ticket_id: int):
        super().__init__(timeout=180)
        self.ticket_id = ticket_id
        self.body = TextInput(
            label="Response",
            style=discord.TextStyle.paragraph,
            placeholder="Type your response...",
        )
        self.add_item(self.body)

        # “Checkbox” (TextInput because Modals only accept TextInput)
        self.res_flag = TextInput(
            label="Resolve request? (y/N)",
            style=discord.TextStyle.short,
            required=False,
            max_length=1,
        )
        self.add_item(self.res_flag)

    async def on_submit(self, interaction: discord.Interaction):
        # Defer right away so we get 15 min instead of 3 s
        await interaction.response.defer(ephemeral=True, thinking=True)

        resolve_it = (self.res_flag.value or "").lower() == "y"
        await send_oversight_response(
            interaction, self.ticket_id, self.body.value, mark_resolved=resolve_it
        )

class FollowUpModal(Modal, title="Send a follow-up to Oversight"):
    def __init__(self, ticket_id: int):
        super().__init__(timeout=180)
        self.ticket_id = ticket_id
        self.msg = TextInput(
            label="Your message",
            style=discord.TextStyle.paragraph,
            placeholder="Type your follow-up...",
        )
        self.add_item(self.msg)

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, thinking=True)
        await post_followup_from_user(interaction, self.ticket_id, self.msg.value)

class RequestView(View):
    def __init__(self, ticket_id: int):
        super().__init__(timeout=None)
        self.ticket_id = ticket_id

        # Resolve button -------------------------------------------------
        async def _resolve_cb(inter: discord.Interaction):
            if not await has_oversight_perm(inter.user):
                await inter.response.send_message("Not authorised.", ephemeral=True)
                return
            await inter.response.defer(ephemeral=True, thinking=True)
            await resolve_request(inter, self.ticket_id)
        resolve_btn = Button(
            label="Resolve",
            style=discord.ButtonStyle.success,
            custom_id=f"resolve_{ticket_id}",
        )
        resolve_btn.callback = _resolve_cb
        self.add_item(resolve_btn)

        # Respond button --------------------------------------------------
        async def _respond_cb(inter: discord.Interaction):
            if not await has_oversight_perm(inter.user):
                await inter.response.send_message("Not authorised.", ephemeral=True)
                return
            await inter.response.send_modal(RespondModal(self.ticket_id))
        respond_btn = Button(
            label="Respond",
            style=discord.ButtonStyle.primary,
            custom_id=f"respond_{ticket_id}",
        )
        respond_btn.callback = _respond_cb
        self.add_item(respond_btn)

class FollowUpButtonView(View):
    """DM view for requester to send follow-up to Oversight."""
    def __init__(self, ticket_id: int):
        super().__init__(timeout=None)
        self.ticket_id = ticket_id

        async def _follow_cb(inter: discord.Interaction):
            await inter.response.send_modal(FollowUpModal(self.ticket_id))
        follow_btn = Button(
            label="Send a follow-up message (will reopen request)",
            style=discord.ButtonStyle.secondary,
            custom_id=f"follow_{ticket_id}",
        )
        follow_btn.callback = _follow_cb
        self.add_item(follow_btn)

# Core actions
async def create_request_record(author_id: int, text: str) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        ts = int(datetime.now(timezone.utc).timestamp())
        cur = await db.execute(
            "INSERT INTO requests (author_id, text, created_at) VALUES (?,?,?)",
            (author_id, text, ts),
        )
        await db.commit()
        return row2ext(cur.lastrowid)

async def resolve_request(inter: discord.Interaction, ticket_id: int):
    row_id = ext2row(ticket_id)

    # ── short‑circuit if already resolved ───────────────────────────────
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT status FROM requests WHERE id=?", (row_id,))
        row = await cur.fetchone()
    if not row:
        await _reply_ephemeral(inter, "Unknown request ID.")
        return
    if row[0] == "resolved":
        await _reply_ephemeral(inter, "That request is already resolved.")
        return

    ts = int(datetime.now(timezone.utc).timestamp())
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE requests SET status='resolved', resolved_by=?, resolved_at=? "
            "WHERE id=? AND status='open'",
            (inter.user.id, ts, row_id),
        )
        await db.commit()

    await update_status(bot, row_id, "resolved", actor_id=inter.user.id)

    # Notify requester
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT author_id, thread_id FROM requests WHERE id=?", (row_id,))
        (uid, thread_id) = await cur.fetchone()
    user = await bot.fetch_user(uid)
    await user.send(
        f"Your Oversight request **#{ticket_id}** has been **resolved** by a member of the Oversight team.",
        view=FollowUpButtonView(ticket_id),
    )

    # Post a note inside the thread for context
    thread = bot.get_channel(thread_id) if (thread_id := thread_id) else None
    if thread:
        await thread.send(f"✅ Ticket #{ticket_id} resolved by {inter.user.mention}.")
    await _reply_ephemeral(inter, "✅ Resolved.")

async def send_oversight_response(
    inter: discord.Interaction,
    ticket_id: int,
    text: str,
    *,
    mark_resolved: bool = False,
):
    row_id = ext2row(ticket_id)
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT author_id, thread_id, status FROM requests WHERE id=?", (row_id,)
        )
        row = await cur.fetchone()
    if not row:
        await _reply_ephemeral(inter, "Unknown ID."); return
    author_id, thread_id, status = row

    # DM the user
    user = await bot.fetch_user(author_id)
    if mark_resolved:
        await user.send(
            (
                f"**Your Oversight request **#{ticket_id}** has been **resolved** by a member of the Oversight team."
                f"\n\n Message from the Oversight team:\n> {text}"
            ),
            view=FollowUpButtonView(ticket_id),
        )
    else:
        await user.send(
            f"**Message from the Oversight team on request #{ticket_id}:**\n>{text}",
            view=FollowUpButtonView(ticket_id),
        )

    # Echo into thread
    thread = bot.get_channel(thread_id)
    if thread:
        await thread.send(f"**Response to requester by Oversighter {inter.user.mention}:**\n> {text}")

    if mark_resolved:
        ts_now = int(datetime.now(timezone.utc).timestamp())
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "UPDATE requests SET status='resolved', resolved_by=?, resolved_at=?, "
                "last_oversighter_id=? WHERE id=?",
                (inter.user.id, ts_now, inter.user.id, row_id),
            )
            await db.commit()
        await update_status(bot, row_id, "resolved", actor_id=inter.user.id)
    else:
        # ► pending
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "UPDATE requests SET status='pending', last_oversighter_id=? WHERE id=?",
                (inter.user.id, row_id),
            )
            await db.commit()
        await update_status(
            bot, row_id, "pending", actor_id=inter.user.id, target_id=author_id
        )

    # If it *used to be* “follow‑up resolved”, drop the extra flag
    if status == "resolved_followup":
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "UPDATE requests SET status='resolved' WHERE id=?", (row_id,)
            )
            await db.commit()
        await update_status(bot, row_id, "resolved")

    await _reply_ephemeral(
        inter,
        "\u2705 Response sent."
        if not mark_resolved
        else "\u2705 Response sent and request resolved.",
    )

async def post_followup_from_user(inter: discord.Interaction, ticket_id: int, body: str):
    row_id = ext2row(ticket_id)
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT thread_id, status, last_oversighter_id FROM requests WHERE id=?", (row_id,)
        )
        row = await cur.fetchone()
    if not row:
        await _reply_ephemeral(inter, "Sorry, I couldn't find that request."); return
    thread_id, status, last_ov = row
    thread = bot.get_channel(thread_id)
    if not thread:
        await _reply_ephemeral(inter, "Thread no longer exists."); return

    ping = f"<@{last_ov}> " if last_ov else ""
    await thread.send(f"{ping}**Follow‑up from <@{inter.user.id}>:**\n> {body}")

    # Transition matrix
    if status == "pending":
        # awaiting oversighter – reopen
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "UPDATE requests SET status='open', last_oversighter_id=NULL WHERE id=?",
                (row_id,),
            )
            await db.commit()
        await update_status(bot, row_id, "open")
    elif status == "resolved":
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "UPDATE requests SET status='resolved_followup' WHERE id=?", (row_id,)
            )
            await db.commit()
        await update_status(bot, row_id, "resolved_followup")

    await _reply_ephemeral(inter, f"Your follow-up has been sent to the Oversight team: \n> {body}")

# Slash commands
def oversighter_only():
    async def pred(ix: discord.Interaction):
        if await has_oversight_perm(ix.user):
            return True
        raise app_commands.CheckFailure("You must be an Oversighter.")
    return app_commands.check(pred)

@bot.tree.command(name="oversight", description="Submit a Wikipedia Oversight request", guild=SUBMISSION_GUILD)
@app_commands.describe(request_text="Describe what needs to be oversighted.")
async def oversight_cmd(ix: discord.Interaction, request_text: str):
    # Gate by role if configured
    if SUBMITTER_ROLE_ID and not any(r.id in SUBMITTER_ROLE_ID for r in ix.user.roles):
        await ix.response.send_message(
            "You are not authorised to submit Oversight requests here.",
            ephemeral=True,
        )
        return

    # Rate limiting (Oversighters & admins exempt)
    async with aiosqlite.connect(DB_PATH) as db:
        cutoff = int(datetime.now(timezone.utc).timestamp()) - COOLDOWN_SECONDS
        cur = await db.execute(
            "SELECT COUNT(*) FROM requests WHERE author_id=? AND created_at>=?",
            (ix.user.id, cutoff),
        )
        (cnt,) = await cur.fetchone()
        if cnt >= 2 and not await has_oversight_perm(ix.user):
            await ix.response.send_message(
                f"⏳ You may only file 2 requests every {COOLDOWN_SECONDS}s.",
                ephemeral=True,
            )
            return

    # All long‑running work begins here – immediately defer so the token
    # stays valid (>3 s rule).
    await ix.response.defer(ephemeral=True)

    ticket_id = await create_request_record(ix.user.id, request_text)

    # First draft (thread doesn’t exist yet)
    content = await render_request(
        ticket_id, ix.user.mention, request_text, STATUSES["open"]
    )
    chan = bot.get_channel(RESTRICTED_CHANNEL_ID)
    main_msg = await chan.send(content, view=RequestView(ticket_id))
    await main_msg.pin()
    # Create a (public) thread – no `type=` kw‑arg needed
    thread = await main_msg.create_thread(name=f"Request #{ticket_id}")
    thread_link = f"<#{thread.id}>"

    # Re‑render with a correct link **after** the thread exists
    content = await render_request(
        ticket_id, ix.user.mention, request_text, STATUSES["open"], thread_link
    )
    await main_msg.edit(content=content)
    thread_msg = await thread.send(content, view=RequestView(ticket_id))

    # Save locations
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE requests SET message_id=?, thread_id=? WHERE id=?",
            (main_msg.id, thread.id, ext2row(ticket_id)),
        )
        await db.commit()

    # Ping subscribers
    if (subs := await ping_list()):
        await chan.send(" ".join(f"<@{uid}>" for uid in subs))

    # DM acknowledgement
    await ix.user.send(
        f"Your Oversight request **#{ticket_id}** has been filed with the following text:\n\n> {request_text}",
        view=FollowUpButtonView(ticket_id),
    )
    await ix.followup.send("Oversight request filed.", ephemeral=True)

@bot.tree.command(name="respond", description="Send a response to a request", guild=CLAIM_GUILD)
@oversighter_only()
@app_commands.describe(request_id="Ticket ID", response_text="Your response")
async def respond_cmd(ix: discord.Interaction, request_id: int, response_text: str):
    await ix.response.defer(ephemeral=True, thinking=True)
    await send_oversight_response(ix, request_id, response_text)

@bot.tree.command(name="resolve", description="Resolve an Oversight request", guild=CLAIM_GUILD)
@oversighter_only()
@app_commands.describe(request_id="Ticket ID to resolve")
async def resolve_cmd(ix: discord.Interaction, request_id: int):
    await ix.response.defer(ephemeral=True, thinking=True)
    await resolve_request(ix, request_id)

@bot.tree.command(name="pending", description="List open requests", guild=CLAIM_GUILD)
@oversighter_only()
async def pending_cmd(ix: discord.Interaction):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT id FROM requests WHERE status='open' ORDER BY id")
        ids = [row2ext(r[0]) for r in await cur.fetchall()]
    if not ids:
        await ix.response.send_message("✅ No open requests.", ephemeral=True)
    else:
        await ix.response.send_message(
            "Open requests: " + ", ".join(f"`{i}`" for i in ids),
            ephemeral=True,
        )

# Reminder loop
async def reminder_loop(bot: commands.Bot):
    while not bot.is_closed():
        cutoff = int(datetime.now(timezone.utc).timestamp()) - REMINDER_MINUTES * 60
        async with aiosqlite.connect(DB_PATH) as db:
            cur = await db.execute(
                "SELECT id, author_id, text FROM requests "
                "WHERE status='open' AND created_at<? AND reminded_at IS NULL",
                (cutoff,),
            )
            rows = await cur.fetchall()
            for row_id, author_id, text in rows:
                ext_id = row2ext(row_id)
                user = await bot.fetch_user(author_id)
                try:
                    await user.send(
                        f"⏰ Heads-up: your Oversight request #{ext_id} "
                        f"has not yet been resolved.\n\n> {text}\n\n"
                        "An Oversighter will review it as soon as possible."
                    )
                except discord.HTTPException:
                    pass
                await db.execute(
                    "UPDATE requests SET reminded_at=strftime('%s','now') WHERE id=?",
                    (row_id,),
                )
            await db.commit()
        await asyncio.sleep(60)

# Event hooks
@bot.event
async def on_ready():
    log.info("Logged in as %s (%s)", bot.user, bot.user.id)

# Safely send an ephemeral acknowledgement, regardless of whether the
# interaction was already answered/deferred.
async def _reply_ephemeral(inter: discord.Interaction, content: str):
    if inter.response.is_done():
        await inter.followup.send(content, ephemeral=True)
    else:
        await inter.response.send_message(content, ephemeral=True)

bot.run(TOKEN)

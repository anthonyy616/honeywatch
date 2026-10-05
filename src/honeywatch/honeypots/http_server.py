"""Fake HTTP honeypot built on aiohttp.

Every request is captured. POSTed credentials are observations only and login
always fails. Uploads are never written to disk; at most the configured body
byte budget is read into a bounded snippet.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
from collections.abc import Callable

from aiohttp import web

from ..config import HTTPConfig
from ..models import MAX_BODY_SNIPPET, MAX_PATH, MAX_QUERY, MAX_USER_AGENT, Event, EventType, Service, utcnow
from ..sanitize import safe_text

logger = logging.getLogger(__name__)

EmitFn = Callable[[Event], None]

LOGIN_PATHS = frozenset({"/wp-login.php", "/phpmyadmin/", "/phpmyadmin/index.php", "/admin"})

FAKE_ENV = """APP_NAME="Laravel"
APP_ENV=production
APP_KEY=base64:ZGVjb3lfd2ViX2tleV9ub3RfdGhlX3JlYWw=
APP_DEBUG=false
APP_URL=https://example.invalid

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=cms_staging
DB_USERNAME=cms_user
DB_PASSWORD=NotARealPassword123

MAIL_MAILER=smtp
MAIL_HOST=smtp.example.invalid
MAIL_PORT=587

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

FAKE_GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
[remote "origin"]
\turl = https://github.example.invalid/team/internal-cms.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""

FAKE_WP_CONFIG_BAK = """<?php
define( 'DB_NAME', 'wordpress_staging' );
define( 'DB_USER', 'wp_admin' );
define( 'DB_PASSWORD', 'WpPlaceholderPassword' );
define( 'DB_HOST', 'localhost' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'WP_DEBUG', false );
$table_prefix = 'wp_';
"""

ROBOTS_TXT = """User-agent: *
Disallow: /wp-admin/
Disallow: /wp-login.php
Disallow: /phpmyadmin/
Disallow: /.env
Disallow: /backup/
Disallow: /config.php.bak
Allow: /

Sitemap: https://example.invalid/sitemap.xml
"""

NOT_FOUND_BODY = (
    "<!DOCTYPE HTML>\n<html><head>\n<title>404 Not Found</title>\n</head><body>\n"
    "<center><h1>404 Not Found</h1></center>\n<hr><center>nginx/1.18.0 "
    "(Ubuntu)</center>\n</body></html>\n"
)

LOGIN_PAGE = (
    "<!DOCTYPE html>\n<html><head><title>Log In</title></head><body>\n"
    "<form name='loginform' id='loginform' action='{action}' method='post'>\n"
    "<p><label for='user_login'>Username or Email Address</label>\n"
    "<input type='text' name='log' id='user_login' value='' /></p>\n"
    "<p><label for='user_pass'>Password</label>\n"
    "<input type='password' name='pwd' id='user_pass' value='' /></p>\n"
    "<p class='submit'><input type='submit' name='wp-submit' id='wp-submit' "
    "value='Log In' /></p>\n</form>\n</body></html>\n"
)

ADMIN_LOGIN_PAGE = (
    "<!DOCTYPE html>\n<html><head><title>phpMyAdmin</title></head><body>\n"
    "<form method='post' action='index.php' name='login_form'>\n"
    "<input type='text' name='pma_username' id='input_username' value='' />\n"
    "<input type='password' name='pma_password' id='input_password' value='' />\n"
    "<input type='submit' name='input_go' value='Go' />\n</form>\n</body></html>\n"
)


def _client_ip(request: web.Request) -> tuple[str, int | None]:
    peer = request.transport.get_extra_info("peername") if request.transport else None
    if peer:
        return str(peer[0]), int(peer[1])
    return str(request.remote or "0.0.0.0"), None


async def read_bounded_body(request: web.Request, limit: int) -> str:
    """Read at most ``limit`` bytes and decode with replacement.

    Uploaded content is never written anywhere; only the bounded snippet is
    returned for the event record.
    """
    if limit <= 0:
        return ""
    try:
        raw = await request.content.readexactly(limit + 1)
        truncated = len(raw) > limit
        raw = raw[:limit]
    except asyncio.IncompleteReadError as exc:
        raw = exc.partial
        truncated = False
    except (ValueError, ConnectionResetError, OSError):  # pragma: no cover - client abort
        return ""
    text = raw.decode("utf-8", errors="replace")
    if truncated:
        text += "...[truncated]"
    return text[:MAX_BODY_SNIPPET]


def parse_form_fields(body: str, content_type: str) -> tuple[str | None, str | None]:
    """Best-effort credential extraction from a bounded body snippet."""
    if not body or "multipart/form-data" in content_type:
        return None, None
    from urllib.parse import parse_qsl

    try:
        pairs = parse_qsl(body, keep_blank_values=True)
    except ValueError:
        return None, None
    username_keys = {"log", "user", "username", "pma_username", "user_login", "usr", "account"}
    password_keys = {"pwd", "pass", "password", "pma_password", "user_pass", "pw"}
    username = password = None
    for key, value in pairs:
        lowered = key.casefold()
        if username is None and lowered in username_keys:
            username = value
        elif password is None and lowered in password_keys:
            password = value
    return (safe_text(username, limit=256) or None, safe_text(password, limit=256) or None)


class HTTPService:
    """Network-facing fake HTTP service with personas and a catch-all."""

    def __init__(self, config: HTTPConfig, emit: EmitFn) -> None:
        self.config = config
        self.emit = emit
        self.app = self._build_app()
        self._runner: web.AppRunner | None = None
        self._site: web.TCPSite | None = None

    # ---- app construction ---------------------------------------------

    def _build_app(self) -> web.Application:
        app = web.Application(client_max_size=self.config.max_body_bytes or 1024)
        app.router.add_post("/{tail:.*}", self._handle_post)
        app.router.add_get("/{tail:.*}", self._handle_get)
        app.router.add_route("*", "/", self._handle_generic)
        app.on_response_prepare.append(self._stamp_headers)
        return app

    async def _stamp_headers(self, request: web.Request, response: web.StreamResponse) -> None:
        response.headers["Server"] = self.config.server_header
        response.headers["X-Powered-By"] = "PHP/7.4.33"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"

    # ---- helpers -------------------------------------------------------

    def _base_event(self, request: web.Request, event_type: EventType) -> Event:
        ip, port = _client_ip(request)
        return Event(
            ts=utcnow(),
            service=Service.HTTP,
            event_type=event_type,
            src_ip=ip,
            src_port=port,
            session_id=secrets.token_hex(4),
            http_method=request.method,
            path=safe_text(request.path, limit=MAX_PATH),
            query=safe_text(request.query_string, limit=MAX_QUERY) or None,
            user_agent=safe_text(request.headers.get("User-Agent", ""), limit=MAX_USER_AGENT) or None,
            client_banner=safe_text(request.headers.get("User-Agent", ""), limit=MAX_USER_AGENT)
            or None,
        )

    def _handle_get(self, request: web.Request) -> web.StreamResponse:
        event = self._base_event(request, EventType.HTTP_REQUEST)
        self.emit(event)
        return self._persona_response(request.path)

    async def _handle_post(self, request: web.Request) -> web.StreamResponse:
        body = await read_bounded_body(request, self.config.max_body_bytes)
        content_type = request.headers.get("Content-Type", "")
        username, password = parse_form_fields(body, content_type)
        is_login = request.path in LOGIN_PATHS

        event = self._base_event(
            request,
            EventType.HTTP_LOGIN_ATTEMPT if is_login else EventType.HTTP_REQUEST,
        )
        event.username = username
        event.password = password
        event.body_snippet = safe_text(body, limit=MAX_BODY_SNIPPET) or None
        self.emit(event)
        return self._persona_response(request.path, login_failed=is_login)

    async def _handle_generic(self, request: web.Request) -> web.StreamResponse:
        body = ""
        if request.can_read_body:
            body = await read_bounded_body(request, self.config.max_body_bytes)
        event = self._base_event(request, EventType.HTTP_REQUEST)
        event.body_snippet = safe_text(body, limit=MAX_BODY_SNIPPET) or None
        self.emit(event)
        return self._persona_response(request.path)

    # ---- personas ------------------------------------------------------

    def _persona_response(self, path: str, *, login_failed: bool = False) -> web.StreamResponse:
        text = str(path or "/")
        if text in {"/", "/index.php", "/index.html"}:
            return web.Response(
                text=LOGIN_PAGE.format(action="/wp-login.php"),
                content_type="text/html",
                status=200,
            )
        if text in {"/wp-login.php"}:
            if login_failed:
                return web.Response(
                    text=LOGIN_PAGE.format(action="/wp-login.php").replace(
                        "</form>",
                        "<div id='login_error'>Error: The username or password you entered "
                        "is incorrect.</div></form>",
                    ),
                    content_type="text/html",
                    status=200,
                )
            return web.Response(
                text=LOGIN_PAGE.format(action="/wp-login.php"),
                content_type="text/html",
                status=200,
            )
        if text.startswith("/wp-admin"):
            return web.Response(text=LOGIN_PAGE.format(action="/wp-login.php"), content_type="text/html", status=200)
        if text.startswith("/phpmyadmin"):
            return web.Response(
                text=ADMIN_LOGIN_PAGE + (
                    "<div id='pma_errortext'>#2002 - No such file or directory</div>"
                    if login_failed
                    else ""
                ),
                content_type="text/html",
                status=200,
            )
        if text.rstrip("/") in {"/admin", "/admin/index", "/login"}:
            return web.Response(text=ADMIN_LOGIN_PAGE, content_type="text/html", status=200)
        if text == "/robots.txt":
            return web.Response(text=ROBOTS_TXT, content_type="text/plain", status=200)
        if text in {"/.env", "/.env.backup", "/.env.bak"}:
            return web.Response(text=FAKE_ENV, content_type="text/plain", status=200)
        if text in {"/.git/config", "/.git/HEAD", "/.gitignore"}:
            return web.Response(text=FAKE_GIT_CONFIG, content_type="text/plain", status=200)
        if text in {"/wp-config.php.bak", "/wp-config.php.save", "/config.php.bak"}:
            return web.Response(text=FAKE_WP_CONFIG_BAK, content_type="text/plain", status=200)
        return web.Response(text=NOT_FOUND_BODY, content_type="text/html", status=404)

    # ---- lifecycle -----------------------------------------------------

    async def start(self) -> None:
        """Bind the listener.

        Raises:
            OSError: The address is unavailable (reported clearly by the CLI).
        """
        self._runner = web.AppRunner(self.app, access_log=None)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self.config.bind, self.config.port)
        await self._site.start()
        logger.info("http honeypot listening on %s:%s", self.config.bind, self.config.port)

    async def stop(self) -> None:
        """Stop the listener and release the port."""
        if self._runner is not None:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._runner.cleanup(), timeout=5)
            self._runner = None
            self._site = None


__all__ = ["HTTPService", "parse_form_fields", "read_bounded_body"]
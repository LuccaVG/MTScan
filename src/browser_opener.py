"""Helpers for opening local dashboard URLs in a desktop session."""

from __future__ import annotations

import os
import shutil
import subprocess
import webbrowser
from pathlib import Path
from typing import Dict, List, Optional

try:
    import pwd
except ImportError:  # pragma: no cover - pwd is only available on Unix.
    pwd = None  # type: ignore[assignment]


OPEN_WAIT_SECONDS = 1.0


def open_url(url: str) -> bool:
    """Open a URL, handling sudo/root launches against a regular user desktop."""
    desktop_user = _desktop_user_for_root_session()
    if desktop_user is not None:
        for command in _opener_commands(url):
            if _spawn_as_user(command, desktop_user):
                return True
        return False

    for command in _opener_commands(url):
        if _spawn(command):
            return True

    try:
        return bool(webbrowser.open(url, new=2))
    except Exception:
        return False


def _desktop_user_for_root_session():
    if pwd is None or not _running_as_root():
        return None

    sudo_user = os.environ.get("SUDO_USER")
    user = _lookup_non_root_user(sudo_user)
    if user is not None:
        return user

    xauthority = os.environ.get("XAUTHORITY")
    if xauthority:
        try:
            uid = Path(xauthority).stat().st_uid
            if uid != 0:
                return pwd.getpwuid(uid)
        except (KeyError, OSError):
            return None

    return None


def _running_as_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return callable(geteuid) and geteuid() == 0


def _lookup_non_root_user(username: Optional[str]):
    if pwd is None or not username or username == "root":
        return None
    try:
        user = pwd.getpwnam(username)
    except KeyError:
        return None
    return user if user.pw_uid != 0 else None


def _desktop_environment(user) -> Dict[str, str]:
    env: Dict[str, str] = {
        "HOME": user.pw_dir,
        "LOGNAME": user.pw_name,
        "USER": user.pw_name,
    }

    for key in ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS"):
        value = os.environ.get(key)
        if value:
            env[key] = value

    user_xauthority = Path(user.pw_dir) / ".Xauthority"
    if "XAUTHORITY" not in env and user_xauthority.exists():
        env["XAUTHORITY"] = str(user_xauthority)

    runtime_dir = Path("/run/user") / str(user.pw_uid)
    if runtime_dir.exists():
        env.setdefault("XDG_RUNTIME_DIR", str(runtime_dir))
        env.setdefault("DBUS_SESSION_BUS_ADDRESS", f"unix:path={runtime_dir}/bus")

    return env


def _opener_commands(url: str) -> List[List[str]]:
    candidates = [
        ("xdg-open", [url]),
        ("gio", ["open", url]),
        ("sensible-browser", [url]),
        ("firefox", [url]),
        ("google-chrome", [url]),
        ("chromium", [url]),
        ("chromium-browser", [url]),
    ]
    commands: List[List[str]] = []
    for name, args in candidates:
        path = shutil.which(name)
        if path:
            commands.append([path, *args])
    return commands


def _spawn_as_user(command: List[str], user) -> bool:
    sudo = shutil.which("sudo")
    if not sudo:
        return False

    env_args = [f"{key}={value}" for key, value in _desktop_environment(user).items()]
    return _spawn([sudo, "-H", "-u", user.pw_name, "env", *env_args, *command])


def _spawn(command: List[str]) -> bool:
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except Exception:
        return False

    try:
        return process.wait(timeout=OPEN_WAIT_SECONDS) == 0
    except subprocess.TimeoutExpired:
        return True

# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")

"""
Console output and command input.

Output may be printed while the operator types a command, so the prompt is
redrawn after each message (like `rlprintf` in the C version). Commands come
from standard input (interactive or not) and optionally from a unix socket
control server, which returns the output of each command to its client.
"""

from __future__ import annotations

import asyncio
import contextvars
import os
import socket
import sys
import threading
import time
from typing import Any, Callable, List, Optional

try:
    import readline
except ImportError:
    readline = None  # type: ignore[assignment]

try:
    import termios
except ImportError:
    termios = None  # type: ignore[assignment]

PROMPT = "sbd # "

#: Command handler: receives one command line.
Dispatch = Callable[[str], None]


class Console:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._prompt_active = False
        self._capture: contextvars.ContextVar[Optional[List[str]]] = (
            contextvars.ContextVar("pysbd_capture", default=None)
        )
        self._histfile: Optional[str] = None
        self._termios: Optional[list] = None
        self._stdin_buffer = b""
        #: Prefix the printed lines with the time (command replies never).
        self.timestamps = False

    def write(self, text: str, error: bool = False) -> None:
        """Print one message (a newline is appended)."""
        captured = self._capture.get()
        if captured is not None:
            captured.append(text)

        if self.timestamps:
            now = time.time()
            prefix = "{}.{:03d} ".format(
                time.strftime("%H:%M:%S", time.localtime(now)), int(now * 1000) % 1000
            )
            text = "\n".join(prefix + line for line in text.split("\n"))

        stream = sys.stderr if error else sys.stdout
        with self._lock:
            if self._prompt_active:
                sys.stdout.write("\r\x1b[K")
                sys.stdout.flush()

            stream.write(text + "\n")
            stream.flush()

            if self._prompt_active:
                line = readline.get_line_buffer() if readline else ""
                sys.stdout.write(PROMPT + line)
                sys.stdout.flush()

    def run_captured(self, func: Callable[..., Any], *args: Any) -> str:
        """Call `func` and return everything it printed."""
        captured: List[str] = []
        token = self._capture.set(captured)
        try:
            func(*args)
        finally:
            self._capture.reset(token)

        return "".join(text + "\n" for text in captured)

    #
    # Standard input.
    #
    def start_stdin(
        self,
        loop: asyncio.AbstractEventLoop,
        dispatch: Dispatch,
        on_eof: Callable[[], None],
    ) -> None:
        """Read commands from standard input."""
        if sys.stdin.isatty():
            if termios:
                try:
                    self._termios = termios.tcgetattr(sys.stdin.fileno())
                except termios.error:
                    self._termios = None

            if readline:
                self._histfile = os.path.join(
                    os.environ.get("HOME", "/tmp"), ".sbd_history"
                )
                try:
                    readline.read_history_file(self._histfile)
                except OSError:
                    pass

            thread = threading.Thread(
                target=self._interactive,
                args=(loop, dispatch, on_eof),
                name="pysbd-stdin",
                daemon=True,
            )
            thread.start()
            return

        loop.add_reader(
            sys.stdin.fileno(), self._stdin_readable, loop, dispatch, on_eof
        )

    def _interactive(
        self,
        loop: asyncio.AbstractEventLoop,
        dispatch: Dispatch,
        on_eof: Callable[[], None],
    ) -> None:
        while True:
            with self._lock:
                self._prompt_active = True
            try:
                line: Optional[str] = input(PROMPT)
            except EOFError:
                line = None
            finally:
                with self._lock:
                    self._prompt_active = False

            if line is None:
                loop.call_soon_threadsafe(on_eof)
                return

            loop.call_soon_threadsafe(dispatch, line)

    def _stdin_readable(
        self,
        loop: asyncio.AbstractEventLoop,
        dispatch: Dispatch,
        on_eof: Callable[[], None],
    ) -> None:
        try:
            data = os.read(sys.stdin.fileno(), 4096)
        except (BlockingIOError, InterruptedError):
            return

        if not data:
            loop.remove_reader(sys.stdin.fileno())
            if self._stdin_buffer:
                dispatch(self._stdin_buffer.decode(errors="replace"))
                self._stdin_buffer = b""
            on_eof()
            return

        self._stdin_buffer += data
        while b"\n" in self._stdin_buffer:
            line, self._stdin_buffer = self._stdin_buffer.split(b"\n", 1)
            dispatch(line.decode(errors="replace").rstrip("\r"))

    def teardown(self) -> None:
        if readline and self._histfile:
            try:
                readline.write_history_file(self._histfile)
            except OSError:
                pass

        if termios and self._termios:
            try:
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self._termios)
            except termios.error:
                pass

    #
    # Control socket: each line received is a command, its output is sent
    # back. The connection ends when the client closes its side.
    #
    async def start_control(
        self, path: str, dispatch: Dispatch
    ) -> asyncio.AbstractServer:
        async def client(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                while True:
                    line = await reader.readline()
                    if not line:
                        break

                    text = self.run_captured(
                        dispatch, line.decode(errors="replace").rstrip("\r\n")
                    )
                    writer.write(text.encode())
                    await writer.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                writer.close()

        return await asyncio.start_unix_server(client, path=path)


console = Console()


def send_command(path: str, command: str, timeout: float = 10.0) -> str:
    """
    Run `command` in the `pysbd` listening on the control socket `path`
    and return its output.
    """
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(path)
        sock.sendall(command.encode() + b"\n")
        sock.shutdown(socket.SHUT_WR)

        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)

    return b"".join(chunks).decode(errors="replace")

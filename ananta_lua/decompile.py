"""Run LJD in isolation and publish only complete, successful output files."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from typing import BinaryIO


DIAGNOSTIC_LIMIT = 8192
RUNNER_PATH = Path(__file__).with_name("ljd_runner.py")
_FAILURE_MARKERS = (
    b"decompilation error",
    b"decompilation failed",
    b"error occurred during decompilation",
    b"exception in",
    b"traceback (most recent call last)",
    b"failed to read",
    b"invalid prototypes stack order",
    b"stopped before whole file was read",
    b"i/o error while reading dump",
    b"interrupted",
)
_SOURCE_FAILURE_MARKERS = (
    b"-- decompilation error in this vicinity:",
    b"-- exception in function building!",
)
_PUBLICATION_RETRY_DELAYS = (0.05, 0.1, 0.2, 0.4, 0.8)


def _publish_output(temporary_path: Path, destination: Path) -> None:
    """Retry transient Windows locks when atomically replacing output."""
    for attempt in range(len(_PUBLICATION_RETRY_DELAYS) + 1):
        try:
            temporary_path.replace(destination)
            return
        except OSError as exc:
            if (getattr(exc, "winerror", None) not in (32, 33)
                    or attempt == len(_PUBLICATION_RETRY_DELAYS)):
                raise
            time.sleep(_PUBLICATION_RETRY_DELAYS[attempt])


def _diagnostics(stream: BinaryIO, markers=_FAILURE_MARKERS) -> tuple[str, bool]:
    """Scan the full log for errors and return a bounded excerpt."""
    stream.seek(0)
    error = False
    carry = b""
    while block := stream.read(65536):
        text = (carry + block).lower()
        error = error or any(marker in text for marker in markers)
        carry = text[-128:]
    length = stream.tell()
    stream.seek(0)
    if length <= DIAGNOSTIC_LIMIT:
        data = stream.read()
    else:
        head = stream.read(DIAGNOSTIC_LIMIT // 2)
        stream.seek(-DIAGNOSTIC_LIMIT // 2, os.SEEK_END)
        data = head + b"\n... diagnostics truncated ...\n" + stream.read()
    return data.decode("utf-8", errors="replace").strip(), error


def decompile_file(
    bytecode_path: Path,
    output_path: Path,
    decompiler_root: Path,
    timeout: float = 120,
) -> dict:
    """Decompile with strict assertions; keep prior output on failure.

    ``ok`` requires nonempty source and no known error diagnostics.
    The caller must check syntax separately; recovered code is never executed.
    """
    started = time.monotonic()
    result = {"status": "failed"}
    temporary_path = None
    try:
        source = Path(bytecode_path).resolve(strict=True)
        destination = Path(output_path).resolve()
        vendor = Path(decompiler_root).resolve(strict=True)
        entrypoint = vendor / "main.py"
        if not source.is_file():
            raise ValueError(f"Bytecode input is not a file: {source}")
        if not entrypoint.is_file():
            raise ValueError(f"LJD main.py is missing: {entrypoint}")
        if not RUNNER_PATH.is_file():
            raise ValueError(f"LJD compatibility runner is missing: {RUNNER_PATH}")
        if timeout <= 0:
            raise ValueError("Decompiler timeout must be positive")
        if source == destination or (destination.exists() and source.samefile(destination)):
            raise ValueError("Source and decompiled output must be different files")
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp.lua", dir=destination.parent,
        )
        os.close(descriptor)
        temporary_path = Path(name)
        temporary_path.unlink()
        command = [
            sys.executable, str(RUNNER_PATH), str(vendor), "-f", str(source),
            "-o", str(temporary_path), "--function_def_sugar", "false",
        ]
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            try:
                process = subprocess.run(
                    command, cwd=vendor, env=env, stdin=subprocess.DEVNULL,
                    stdout=stdout, stderr=stderr, timeout=timeout,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    check=False,
                )
            except subprocess.TimeoutExpired:
                result.update(status="timeout", error=f"LJD exceeded {timeout:g} seconds")
                process = None
            stdout_text, stdout_failed = _diagnostics(stdout)
            stderr_text, stderr_failed = _diagnostics(stderr)
            if stdout_text:
                result["stdout"] = stdout_text
            if stderr_text:
                result["stderr"] = stderr_text
            if process is None:
                return result
            result["returncode"] = process.returncode
            if process.returncode:
                result["error"] = f"LJD exited with code {process.returncode}"
            elif stdout_failed or stderr_failed:
                result["error"] = "LJD reported a parser or decompilation failure"
            elif not temporary_path.is_file() or temporary_path.stat().st_size == 0:
                result["error"] = "LJD did not produce nonempty Lua source"
            else:
                # Reject partial output even if LJD suppressed its exception.
                with temporary_path.open("rb") as written:
                    _, partial = _diagnostics(written, _SOURCE_FAILURE_MARKERS)
                if partial:
                    result["error"] = "LJD output contains decompilation failure markers"
                else:
                    size = temporary_path.stat().st_size
                    _publish_output(temporary_path, destination)
                    result.update(status="ok", output_bytes=size)
        return result
    except (OSError, ValueError) as exc:
        result["error"] = str(exc)[:DIAGNOSTIC_LIMIT]
        return result
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        result["duration_seconds"] = round(time.monotonic() - started, 3)

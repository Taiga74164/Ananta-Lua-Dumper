"""Extract packaged scripts, normalize bytecode, and recover readable Lua."""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import tempfile
import time

from . import __version__
from .carve import iter_chunks, read_chunk
from .decompile import decompile_file
from .normalize import RuntimeCipher, SyntaxChecker, normalize_chunk, source_path
from .opcodes import recover_opcode_map


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_FORMAT = 1


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(data)
    return digest.hexdigest()


def _strip_legacy_header(data: bytes, record: dict) -> bytes:
    """Remove the exact generated header from hash-verified older output."""
    header = (f"-- Original chunk: {record['chunk_name']}\n"
              f"-- Decompiled from: {record['normalized_file']}\n\n").encode("utf-8")
    return data.removeprefix(header)


def _target(root: Path, relative: str | Path) -> Path:
    path = (root / relative).resolve()
    # Concurrent directory creation can leave a Windows extended path prefix.
    # Compare equivalent DOS/UNC paths after resolving links.
    def comparable(value: Path) -> Path:
        text = str(value)
        if os.name == "nt":
            if text.startswith("\\\\?\\UNC\\"):
                return Path("\\\\" + text[8:])
            if text.startswith("\\\\?\\") and len(text) > 6 and text[5:7] == ":\\":
                return Path(text[4:])
        return value

    if comparable(path) == comparable(root) or not comparable(path).is_relative_to(comparable(root)):
        raise ValueError(f"Output path escapes its directory: {relative} resolved to {path}, outside {root}")
    return path


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.",
                                         suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _decompiler_info(root: Path) -> dict:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" not in path.parts:
            digest.update(path.relative_to(root).as_posix().encode("utf-8") + b"\0")
            digest.update(path.read_bytes())
    compatibility = hashlib.sha256()
    for path in sorted(Path(__file__).parent.glob("ljd_*.py")):
        compatibility.update(path.name.encode("utf-8") + b"\0" + path.read_bytes())
    return {"path": str(root), "python_sha256": digest.hexdigest(),
            "compatibility_sha256": compatibility.hexdigest(),
            "options": ["--function_def_sugar", "false"]}


def _previous_manifest(output: Path) -> dict:
    try:
        value = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        return {}
    if (isinstance(value, dict) and value.get("tool") == "ananta-lua"
            and value.get("format") == MANIFEST_FORMAT and isinstance(value.get("scripts"), list)):
        return value
    return {}


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract and decompile Lua from Ananta's game archives.",
        epilog='Example: python dump.py --game-root "D:\\Games\\Ananta"',
    )
    parser.add_argument("--game-root", type=Path, metavar="PATH", default=PROJECT_ROOT.parent,
                        help="game folder (default: parent of this project)")
    parser.add_argument("-o", "--output", type=Path, metavar="PATH", default=PROJECT_ROOT / "output",
                        help="output folder (default: output/ in this project)")
    parser.add_argument("--resume", action="store_true",
                        help="reuse checked output and retry incomplete scripts")
    parser.add_argument("--extract-only", action="store_true", help="save bytecode without decompiling")
    parser.add_argument("--workers", type=int, metavar="N", default=4,
                        help="parallel decompilers (default: 4)")
    parser.add_argument("--timeout", type=float, metavar="SECONDS", default=600,
                        help="time limit per script (default: 600 seconds)")
    parser.add_argument("--version", action="version", version=__version__)
    advanced = parser.add_argument_group("input overrides")
    advanced.add_argument("--block", type=Path, metavar="PATH", action="append",
                          help="scan this archive; repeat for multiple archives")
    advanced.add_argument("--runtime", type=Path, metavar="PATH", help="path to the matching tolua.dll")
    advanced.add_argument("--ljd", type=Path, metavar="PATH", default=PROJECT_ROOT / "vendor" / "ljd",
                          help="LJD checkout (default: vendor/ljd in this project)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _arguments(argv)
    game = args.game_root.resolve()
    output = args.output.resolve()
    runtime_path = (args.runtime or game / "Ananta_Data/Plugins/x86_64/tolua.dll").resolve()
    vendor = args.ljd.resolve()
    checker = None
    started = time.monotonic()
    try:
        blocks = sorted({p.resolve() for p in args.block}) if args.block else sorted(
            (game / "Ananta_Data/StreamingAssets/AssetsNotPatch/Blocks").glob("vfc_*"))
        if not blocks or any(not path.is_file() for path in blocks):
            raise ValueError("No usable block files; set --game-root or --block")
        if not runtime_path.is_file():
            raise ValueError(f"Matching game runtime is missing: {runtime_path}")
        if args.workers < 1 or not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ValueError("--workers and --timeout must be finite and positive")
        if not args.extract_only and not (vendor / "main.py").is_file():
            raise ValueError(f"LJD is missing at {vendor}; run 'git submodule update --init --recursive' "
                             "from the project folder, or set --ljd to an existing checkout")
        # Protect inputs from output writes and cleanup.
        for path in [runtime_path, *blocks]:
            if path.is_relative_to(output):
                raise ValueError(f"Output directory contains an input: {path}")
        if vendor.is_relative_to(output) or output.is_relative_to(vendor):
            raise ValueError(f"Output overlaps the LJD checkout: {vendor}")
        output.mkdir(parents=True, exist_ok=True)
        previous = _previous_manifest(output)
        old_scripts = {r.get("path"): r for r in previous.get("scripts", []) if isinstance(r, dict)}
        print(f"Recovering LuaJIT opcodes and string decoding from {runtime_path}", flush=True)
        opcode_map = recover_opcode_map(runtime_path)
        cipher = RuntimeCipher(runtime_path)
        decompiler = _decompiler_info(vendor) if not args.extract_only else None
        manifest = {"tool": "ananta-lua", "tool_version": __version__, "format": MANIFEST_FORMAT,
                    "started_utc": datetime.now(timezone.utc).isoformat(),
                    "scope": "uncompressed LuaJIT chunks in the selected packaged block files",
                    "runtime": {"path": str(runtime_path), "sha256": _file_hash(runtime_path)},
                    "opcode_map": {str(k): v for k, v in sorted(opcode_map.items())},
                    "decompiler": decompiler, "blocks": [], "scripts": []}
        records = manifest["scripts"]

        def checkpoint():
            manifest["counts"] = dict(sorted(Counter(r["status"] for r in records).items()))
            manifest["elapsed_seconds"] = round(time.monotonic() - started, 2)
            _write(_target(output, "manifest.json"),
                   (json.dumps(manifest, ensure_ascii=True, indent=2) + "\n").encode("utf-8"))

        seen = set()
        for block in blocks:
            print(f"Scanning {block.name} ({block.stat().st_size:,} bytes)", flush=True)
            block_info = {"path": str(block), "bytes": block.stat().st_size,
                          "sha256": _file_hash(block), "chunks": 0}
            manifest["blocks"].append(block_info)
            for chunk in iter_chunks(block):
                block_info["chunks"] += 1
                record = {"block": str(block), "offset": chunk.offset, "bytes": chunk.size,
                          "prototypes": chunk.prototype_count, "status": "extraction_failed"}
                records.append(record)
                raw = read_chunk(block, chunk)
                record["raw_sha256"] = _sha256(raw)
                # Retain bytecode even when its name or normalization is unsupported.
                fallback = f"raw/_unnamed/{len(records):05d}-{chunk.offset:x}.luajit"
                try:
                    name = cipher.transform(chunk.raw_name)
                    relative = source_path(name)
                    key = relative.as_posix()
                    if key.casefold() in seen:
                        raise ValueError(f"Duplicate script path: {key}")
                    seen.add(key.casefold())
                    record.update(path=key, chunk_name=name.decode("utf-8"))
                    raw_file = (Path("raw") / relative.with_suffix(".luajit")).as_posix()
                    _write(_target(output, raw_file), raw)
                    record["raw_file"] = raw_file
                    normalized = normalize_chunk(raw, cipher, opcode_map)
                    normalized_file = (Path("normalized") / relative.with_suffix(".luajit")).as_posix()
                    _write(_target(output, normalized_file), normalized)
                    record.update(normalized_file=normalized_file, normalized_sha256=_sha256(normalized),
                                  status="extracted" if args.extract_only else "pending")
                except (ValueError, UnicodeError) as exc:
                    if "raw_file" not in record:
                        _write(_target(output, fallback), raw)
                        record["raw_file"] = fallback
                    record["error"] = str(exc)
            print(f"  Extracted {block_info['chunks']:,} chunks", flush=True)
        checkpoint()
        if not records:
            raise ValueError("No complete supported LuaJIT chunks found in the selected files")

        if not args.extract_only:
            checker = SyntaxChecker(cipher)
            resume_compatible = (args.resume and previous.get("tool_version") == __version__
                                 and previous.get("runtime") == manifest["runtime"]
                                 and previous.get("decompiler") == decompiler)
            pending = []
            for record in records:
                if record["status"] != "pending":
                    continue
                relative = Path("lua") / record["path"]
                destination = _target(output, relative)
                old = old_scripts.get(record["path"], {})
                if (resume_compatible and old.get("status") == "ok"
                        and old.get("normalized_sha256") == record["normalized_sha256"]
                        and destination.is_file() and _file_hash(destination) == old.get("source_sha256")):
                    original = destination.read_bytes()
                    data = _strip_legacy_header(original, record)
                    error = checker.check(data, record["path"])
                    if error is None:
                        if data != original:
                            _write(destination, data)
                        record.update(status="ok", lua_file=relative.as_posix(),
                                      source_sha256=_sha256(data), resumed=True,
                                      output_bytes=len(data))
                        continue
                pending.append(record)
            reused = sum(r.get("resumed", False) for r in records)
            print(f"Decompiling {len(pending):,} scripts; reusing {reused:,} checked files", flush=True)
            with tempfile.TemporaryDirectory(dir=output, prefix=".decompile-") as temporary:
                staging = Path(temporary).resolve()
                if not staging.is_relative_to(output):
                    raise ValueError("Temporary output escaped the output directory")
                with ThreadPoolExecutor(max_workers=args.workers) as executor:
                    futures = {executor.submit(decompile_file, _target(output, r["normalized_file"]),
                                               _target(staging, r["path"]), vendor, args.timeout): r
                               for r in pending}
                    completed = 0
                    last_progress = time.monotonic()
                    for future in as_completed(futures):
                        record = futures[future]
                        result = future.result()
                        candidate = _target(staging, record["path"])
                        if result["status"] == "ok":
                            data = candidate.read_bytes()
                            error = checker.check(data, record["path"])
                            if error is not None:
                                result.update(status="syntax_failed", error=error)
                            else:
                                relative = Path("lua") / record["path"]
                                _write(_target(output, relative), data)
                                result.update(lua_file=relative.as_posix(), source_sha256=_sha256(data),
                                              output_bytes=len(data))
                        record.update(result)
                        candidate.unlink(missing_ok=True)
                        completed += 1
                        if completed % 100 == 0 or time.monotonic() - last_progress > 10:
                            checkpoint()
                            print(f"  {completed:,}/{len(pending):,}: {manifest['counts']}", flush=True)
                            last_progress = time.monotonic()
            # Remove stale generated files only when their contents are unchanged.
            readable = {r["path"] for r in records if r["status"] == "ok"}
            for name, old in old_scripts.items():
                if isinstance(name, str) and name not in readable and old.get("status") == "ok":
                    destination = _target(output, Path("lua") / source_path(name.encode("utf-8")))
                    if destination.is_file() and _file_hash(destination) == old.get("source_sha256"):
                        destination.unlink()
        manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
        checkpoint()
        counts = manifest["counts"]
        print(f"Saved {len(records):,} scripts to {output}: {counts}", flush=True)
        return 2 if any(r["status"] not in ("ok", "extracted") for r in records) else 0
    except (OSError, ValueError, AttributeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        if checker is not None:
            checker.close()

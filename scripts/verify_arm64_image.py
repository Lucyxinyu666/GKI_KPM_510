#!/usr/bin/env python3
"""Reject malformed ARM64 boot images before they are packaged."""

import argparse
import gzip
import struct
from pathlib import Path


ARM64_MAGIC = b"ARM\x64"
KPM_MAGIC = b"KP1158\0\0"
KPM_PAGE = 4096


def boot_entry(image: bytes) -> int:
    if len(image) < 64 or image[56:60] != ARM64_MAGIC:
        raise ValueError("not a raw ARM64 Image")
    # With EFI enabled the first word carries the MZ signature; the branch
    # is then the second word. The B immediate is a signed word offset.
    pc = 4 if image.startswith(b"MZ") else 0
    instruction = struct.unpack_from("<I", image, pc)[0]
    if instruction >> 26 != 0b000101:
        raise ValueError(f"expected ARM64 B at {pc:#x}, got {instruction:#010x}")
    displacement = instruction & 0x03ffffff
    if displacement & 0x02000000:
        displacement -= 0x04000000
    target = pc + displacement * 4
    if not 64 <= target <= len(image) - 4:
        raise ValueError(f"boot entry {target:#x} is outside Image (length {len(image):#x})")
    if image[target:target + 4] in (b"\0" * 4, b"\xff" * 4):
        raise ValueError(f"boot entry {target:#x} points to padding")
    return target


def verify_kpm(image: bytes, target: int, original: Path, kpimg: Path) -> None:
    old_size = original.stat().st_size
    payload = kpimg.read_bytes()
    if not payload.startswith(KPM_MAGIC) or len(payload) < KPM_PAGE + 4:
        raise ValueError("kpimg lacks a KernelPatch header or entry code")
    # The pinned kptools appends kpimg at the next 4 KiB boundary. It updates
    # setup fields within the first page, so compare magic and entry separately.
    start = (old_size + KPM_PAGE - 1) & -KPM_PAGE
    if len(image) < start + len(payload) or image[start:start + len(KPM_MAGIC)] != KPM_MAGIC:
        raise ValueError(f"missing or truncated KernelPatch payload at {start:#x}")
    if target != start + KPM_PAGE:
        raise ValueError(f"boot entry {target:#x} does not target the appended KPM code")
    if image[target:start + len(payload)] != payload[KPM_PAGE:]:
        raise ValueError(f"KernelPatch code at {target:#x} does not match kpimg")
    if "CONFIG_KPM=y" not in embedded_config(image):
        raise ValueError("missing CONFIG_KPM=y")


def embedded_config(image: bytes) -> set[str]:
    start = image.find(b"IKCFG_ST")
    end = image.find(b"IKCFG_ED", start + 8) if start >= 0 else -1
    if end < 0:
        raise ValueError("missing embedded IKCONFIG")
    return set(gzip.decompress(image[start + 8:end]).decode().splitlines())


def verify_susfs(image: bytes) -> None:
    config = embedded_config(image)
    for name in ("KSU_SUSFS", "KSU_SUSFS_SUS_PATH", "KSU_SUSFS_SUS_MOUNT", "KSU_SUSFS_SPOOF_UNAME"):
        if f"CONFIG_{name}=y" not in config:
            raise ValueError(f"missing CONFIG_{name}=y")
    if "CONFIG_KSU_MANUAL_SU=y" in config:
        raise ValueError("unexpected CONFIG_KSU_MANUAL_SU=y in SukiSU builtin Image")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--kpm", nargs=2, type=Path, metavar=("ORIGINAL", "KPIMG"))
    parser.add_argument("--susfs", action="store_true")
    args = parser.parse_args()
    try:
        image = args.image.read_bytes()
        target = boot_entry(image)
        if args.kpm:
            verify_kpm(image, target, *args.kpm)
        if args.susfs:
            verify_susfs(image)
    except (OSError, ValueError, EOFError) as exc:
        parser.exit(1, f"::error::{args.image}: {exc}\n")
    print(f"OK: {args.image}: ARM64 entry {target:#x}, Image length {len(image):#x}")


if __name__ == "__main__":
    main()

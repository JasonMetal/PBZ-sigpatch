"""命令行入口。补丁描述走一个 JSON 文件，不内置任何具体补丁。"""

import argparse
import json
import os
import sys

from .fsutil import BACKUP_SUFFIX, ensure_backup, sha256_file, write_atomic
from .patch import Patch, PatchError, apply_patches, describe_offset, find_all, locate
from .pe import PEFormatError, PEImage

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2


def load_patchfile(path):
    """读 JSON，返回 (target 路径, [Patch])。

    格式：
        {
          "target": "relative/or/absolute/path.dll",
          "patches": [
            {"label": "修复 A", "signature": "488b...", "at": 18,
             "expect": "e8aabbccdd", "replacement": "e811223344"}
          ]
        }
    """
    with open(path, "r", encoding="utf-8-sig") as f:
        spec = json.load(f)
    if "target" not in spec:
        raise ValueError("补丁文件缺 target 字段")
    raw_patches = spec.get("patches") or []
    if not raw_patches:
        raise ValueError("补丁文件里 patches 是空的")

    patches = []
    for i, item in enumerate(raw_patches):
        try:
            sig = bytes.fromhex(item["signature"])
            rep = bytes.fromhex(item["replacement"])
            exp = bytes.fromhex(item["expect"]) if item.get("expect") else None
        except KeyError as e:
            raise ValueError("第 %d 条补丁缺字段 %s" % (i + 1, e))
        except ValueError as e:
            raise ValueError("第 %d 条补丁的十六进制写错了：%s" % (i + 1, e))
        patches.append(Patch(
            signature=sig,
            replacement=rep,
            at=int(item.get("at", 0)),
            expect=exp,
            label=item.get("label") or "patch#%d" % (i + 1),
        ))
    return spec["target"], patches


def resolve_target(spec_path, target):
    if os.path.isabs(target):
        return target
    return os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(spec_path)), target))


def cmd_find(args):
    """只报位置，不改文件。"""
    target, patches = load_patchfile(args.spec)
    target = resolve_target(args.spec, target)
    data = open(target, "rb").read()
    print("目标: %s\nSHA256: %s\n" % (target, sha256_file(target)))
    try:
        print(PEImage(data).describe() + "\n")
    except PEFormatError as e:
        print("PE 解析失败（不是可执行文件也无所谓，继续按字节找）: %s\n" % e)

    failures = 0
    for p in patches:
        try:
            off = locate(data, p)
            print("[命中] %-20s %s" % (p.label, describe_offset(data, off)))
            if p.expect is not None:
                print("       当前字节 %s（与 expect 一致）" % p.expect.hex())
        except PatchError as e:
            print("[失败] %s" % e)
            failures += 1
    return EXIT_FAIL if failures else EXIT_OK


def cmd_apply(args):
    target, patches = load_patchfile(args.spec)
    target = resolve_target(args.spec, target)
    if not os.path.exists(target):
        print("目标不存在: %s" % target, file=sys.stderr)
        return EXIT_USAGE

    data = open(target, "rb").read()
    try:
        new_data, applied = apply_patches(data, patches)
    except PatchError as e:
        print("拒绝打补丁，文件未改动。\n  %s" % e, file=sys.stderr)
        return EXIT_FAIL

    if new_data == data:
        print("目标已经是打过补丁的状态，不需要改。")
        return EXIT_OK

    if not args.dry_run:
        ensure_backup(target)
        write_atomic(target, new_data)

    verb = "将" if args.dry_run else "已"
    for off, p in applied:
        print("%s %-20s @ %s" % (verb, p.label, describe_offset(new_data, off)))
    if args.dry_run:
        print("\n--dry-run：只报告，没写盘。")
    else:
        print("\n原件已留: %s%s" % (target, BACKUP_SUFFIX))
        print("新 SHA256: %s" % sha256_file(target))
    return EXIT_OK


def cmd_verify(args):
    """核对目标是否已经处于补丁后状态。"""
    target, patches = load_patchfile(args.spec)
    target = resolve_target(args.spec, target)
    data = open(target, "rb").read()
    bad = 0
    for p in patches:
        hits = find_all(data, p.signature)
        if not hits:
            print("[失败] %s: 连特征码都找不到" % p.label)
            bad += 1
            continue
        patched = sum(1 for h in hits
                      if bytes(data[h + p.at:h + p.at + len(p.replacement)]) == p.replacement)
        if patched == len(hits) and hits:
            print("[通过] %s: %d 处已是补丁后状态" % (p.label, patched))
        else:
            print("[失败] %s: %d/%d 处未打补丁" % (p.label, len(hits) - patched, len(hits)))
            bad += 1
    return EXIT_FAIL if bad else EXIT_OK


def cmd_restore(args):
    target = args.target
    backup = target + BACKUP_SUFFIX
    if not os.path.exists(backup):
        print("没有 %s，没法还原。不猜。" % backup, file=sys.stderr)
        return EXIT_FAIL
    if not args.yes:
        print("将用 %s 覆盖 %s。加 --yes 确认。" % (backup, target))
        return EXIT_USAGE
    data = open(backup, "rb").read()
    write_atomic(target, data)
    print("已还原: %s\nSHA256: %s" % (target, sha256_file(target)))
    return EXIT_OK


def build_parser():
    p = argparse.ArgumentParser(
        prog="sigpatch",
        description="按签名定位的二进制补丁。任何校验不过就整体拒绝，一个字节都不写。")
    sub = p.add_subparsers(dest="command")

    f = sub.add_parser("find", help="只报告特征码命中位置，不改文件")
    f.add_argument("spec")
    f.set_defaults(func=cmd_find)

    a = sub.add_parser("apply", help="校验并写盘")
    a.add_argument("spec")
    a.add_argument("--dry-run", action="store_true", help="只报告将要改哪些位置")
    a.set_defaults(func=cmd_apply)

    v = sub.add_parser("verify", help="核对目标是否已是补丁后状态")
    v.add_argument("spec")
    v.set_defaults(func=cmd_verify)

    r = sub.add_parser("restore", help="用 .orig-backup 还原")
    r.add_argument("target")
    r.add_argument("--yes", action="store_true")
    r.set_defaults(func=cmd_restore)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_USAGE
    return args.func(args)

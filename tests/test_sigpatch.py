# -*- coding: utf-8 -*-
"""sigpatch 的单元测试。所有样本都是现场合成的假 PE，不读任何真实二进制。"""

import json
import os
import shutil
import struct
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from sigpatch.cli import main
from sigpatch.fsutil import BACKUP_SUFFIX, ensure_backup, write_atomic
from sigpatch.patch import Patch, PatchError, apply_patches, find_all, locate
from sigpatch.pe import PEFormatError, PEImage
from tests.pebuilder import build_pe


# 签名只取补丁点之前的上下文。把 e8 也放进签名是错的：那四个字节正是要改的，
# 打完补丁签名就没了。这个形状就是工具要求的样子。
SIG = bytes.fromhex("4883ec28488bc84c8d4c24")
AT = len(SIG)                # 补丁紧跟在签名后面
OLD = bytes.fromhex("e8aabbccdd")
NEW = bytes.fromhex("e811223344")


def make_sample(prefix=b"\x90" * 0x100, suffix=b"\xcc" * 0x100):
    body = prefix + SIG + OLD + suffix
    data, desc = build_pe([(".text", body), (".data", b"\x00" * 0x40)])
    return data, desc


class PEImageTests(unittest.TestCase):
    def test_sections_parsed(self):
        data, _ = make_sample()
        im = PEImage(data)
        self.assertEqual(im.bitness, 64)
        self.assertEqual([s.name for s in im.sections], [".text", ".data"])

    def test_rva_roundtrip(self):
        data, desc = make_sample()
        im = PEImage(data)
        text_vaddr, text_raw, _ = desc[0][2], desc[0][4], desc[0][1]
        for delta in (0, 1, 0x10, 0x1FF):
            self.assertEqual(im.off_to_rva(text_raw + delta), text_vaddr + delta)
            self.assertEqual(im.rva_to_off(text_vaddr + delta), text_raw + delta)

    def test_rejects_non_pe(self):
        with self.assertRaises(PEFormatError):
            PEImage(b"not a pe file at all, just some bytes")
        with self.assertRaises(PEFormatError):
            PEImage(b"MZ" + b"\x00" * 0x40)

    def test_rva_into_zero_fill_rejected(self):
        # 第二段构造一个 vsize 远大于 rsize 的节区：虚拟空间有，文件里没有。
        data, desc = build_pe([(".text", b"\x90" * 0x10)])
        buf = bytearray(data)
        header = PEImage(buf).sections[0].header_off
        struct.pack_into("<I", buf, header + 8, 0x2000)   # VirtualSize
        struct.pack_into("<I", buf, header + 16, 0x10)    # SizeOfRawData 保持很小
        im = PEImage(buf)
        with self.assertRaises(PEFormatError):
            im.rva_to_off(im.sections[0].vaddr + 0x100)

    def test_unknown_section(self):
        im = PEImage(make_sample()[0])
        with self.assertRaises(PEFormatError):
            im.section(".nope")


class FindTests(unittest.TestCase):
    def test_finds_overlapping_hits(self):
        data = b"ababab"
        self.assertEqual(find_all(data, b"abab"), [0, 2])

    def test_multiple_hits_reported(self):
        data = b"xxSIGxxSIGxx".replace(b"SIG", SIG)
        self.assertEqual(len(find_all(data, SIG)), 2)


class LocateTests(unittest.TestCase):
    def test_unique_hit(self):
        data, _ = make_sample()
        p = Patch(SIG, NEW, at=AT, expect=OLD, label="t")
        off = locate(data, p)
        self.assertEqual(data[off:off + len(OLD)], OLD)

    def test_zero_hits_refused(self):
        data, _ = make_sample()
        p = Patch(b"\xde\xad\xbe\xef", NEW, at=4, label="t")
        with self.assertRaises(PatchError) as cm:
            locate(data, p)
        self.assertIn("找不到特征码", str(cm.exception))

    def test_ambiguous_signature_refused(self):
        # 同一段签名出现两次，必须拒绝，不能悄悄取第一个。
        body = b"\x90" * 0x40 + SIG + b"\x90" * 0x40 + SIG + b"\x90" * 0x40
        data, _ = build_pe([(".text", body)])
        p = Patch(SIG, NEW, at=AT, label="t")
        with self.assertRaises(PatchError) as cm:
            locate(data, p)
        self.assertIn("不再唯一", str(cm.exception))

    def test_expect_mismatch_refused(self):
        data, _ = make_sample()
        p = Patch(SIG, NEW, at=AT, expect=b"\x00\x00\x00\x00\x00", label="t")
        with self.assertRaises(PatchError) as cm:
            locate(data, p)
        self.assertIn("预期不符", str(cm.exception))

    def test_expect_length_must_match(self):
        with self.assertRaises(ValueError):
            Patch(SIG, NEW, expect=b"\x00", label="t")

    def test_out_of_bounds_refused(self):
        data, _ = make_sample()
        p = Patch(SIG, b"\x00" * 0x1000, at=len(SIG), label="t")
        with self.assertRaises(PatchError):
            locate(data, p)


class ApplyTests(unittest.TestCase):
    def test_single_patch(self):
        data, _ = make_sample()
        out, applied = apply_patches(data, [Patch(SIG, NEW, at=AT, expect=OLD, label="t")])
        self.assertEqual(len(applied), 1)
        off, _p = applied[0]
        self.assertEqual(out[off:off + len(NEW)], NEW)
        self.assertEqual(out[:off], data[:off])
        self.assertEqual(out[off + len(NEW):], data[off + len(NEW):])

    def test_failure_leaves_input_untouched(self):
        data, _ = make_sample()
        original = bytes(data)
        with self.assertRaises(PatchError):
            apply_patches(data, [Patch(b"\x00" * 8, b"\xff" * 8, at=8, label="bad")])
        self.assertEqual(bytes(data), original)

    def test_overlapping_patches_refused(self):
        data, _ = make_sample()
        p1 = Patch(SIG, b"\x11\x22\x33\x44\x55", at=AT, label="p1")
        p2 = Patch(SIG, b"\x99\x98\x97\x96\x95", at=AT + 2, label="p2")
        with self.assertRaises(PatchError) as cm:
            apply_patches(data, [p1, p2])
        self.assertIn("重叠", str(cm.exception))

    def test_two_non_overlapping_patches(self):
        tail = b"\x48\x89\x5c\x24\x08" + b"\x90" * 0x20
        body = b"\x90" * 0x40 + SIG + b"\x90" * 0x40 + tail + b"\x90" * 0x40
        data, _ = build_pe([(".text", body)])
        p1 = Patch(SIG, NEW, at=AT, label="p1")
        p2 = Patch(b"\x48\x89\x5c\x24\x08", b"\x48\x89\x5c\x24\x10", at=5, label="p2")
        out, applied = apply_patches(data, [p1, p2])
        self.assertEqual(len(applied), 2)
        # applied 按偏移升序返回，方便人读
        self.assertLess(applied[0][0], applied[1][0])

    def test_idempotent(self):
        data, _ = make_sample()
        once, _ = apply_patches(data, [Patch(SIG, NEW, at=AT, expect=OLD, label="t")])
        twice, _ = apply_patches(once, [Patch(SIG, NEW, at=AT, expect=NEW, label="t")])
        self.assertEqual(once, twice)

    def test_patch_requires_bytes(self):
        with self.assertRaises(ValueError):
            Patch(SIG, b"")
        with self.assertRaises(ValueError):
            Patch(b"", b"\x00")

    def test_signature_may_not_overlap_patch_region(self):
        # at 落在签名内部，等于把要改的字节也写进了签名，打完就再也找不到。
        with self.assertRaises(ValueError) as cm:
            Patch(SIG, NEW, at=AT - 1, label="t")
        self.assertIn("签名必须整段落在补丁点之前", str(cm.exception))

        # at == len(signature) 是允许的：签名紧贴在补丁点左边。
        Patch(SIG, NEW, at=len(SIG), label="ok")


class FsUtilTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="sigpatch-test-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_atomic_write(self):
        path = os.path.join(self.dir, "a.bin")
        write_atomic(path, b"hello")
        self.assertEqual(open(path, "rb").read(), b"hello")
        write_atomic(path, b"world")
        self.assertEqual(open(path, "rb").read(), b"world")
        self.assertFalse(os.path.exists(path + ".sigpatch-tmp"))

    def test_backup_created_once(self):
        path = os.path.join(self.dir, "b.bin")
        write_atomic(path, b"original")
        backup = ensure_backup(path)
        self.assertEqual(backup, path + BACKUP_SUFFIX)
        write_atomic(path, b"patched")
        ensure_backup(path)          # 第二次不能再覆盖原件
        self.assertEqual(open(backup, "rb").read(), b"original")

    def test_restore_refuses_without_backup(self):
        target = os.path.join(self.dir, "c.bin")
        write_atomic(target, b"x")
        self.assertEqual(main(["restore", target, "--yes"]), 1)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="sigpatch-cli-")
        self.target = os.path.join(self.dir, "sample.exe")
        data, _ = make_sample()
        write_atomic(self.target, data)
        self.spec = os.path.join(self.dir, "spec.json")
        with open(self.spec, "w", encoding="utf-8") as f:
            json.dump({
                "target": "sample.exe",
                "patches": [{
                    "label": "call 重定向",
                    "signature": SIG.hex(),
                    "at": AT,
                    "expect": OLD.hex(),
                    "replacement": NEW.hex(),
                }],
            }, f)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_find(self):
        self.assertEqual(main(["find", self.spec]), 0)

    def test_apply_and_verify(self):
        self.assertEqual(main(["apply", self.spec]), 0)
        self.assertTrue(os.path.exists(self.target + BACKUP_SUFFIX))
        self.assertEqual(main(["verify", self.spec]), 0)

    def test_apply_again_is_noop(self):
        main(["apply", self.spec])
        before = open(self.target, "rb").read()
        self.assertEqual(main(["apply", self.spec]), 0)
        self.assertEqual(open(self.target, "rb").read(), before)

    def test_dry_run_does_not_write(self):
        before = open(self.target, "rb").read()
        self.assertEqual(main(["apply", self.spec, "--dry-run"]), 0)
        self.assertEqual(open(self.target, "rb").read(), before)

    def test_restore(self):
        original = open(self.target, "rb").read()
        main(["apply", self.spec])
        self.assertNotEqual(open(self.target, "rb").read(), original)
        self.assertEqual(main(["restore", self.target, "--yes"]), 0)
        self.assertEqual(open(self.target, "rb").read(), original)

    def test_bad_signature_refuses_and_file_unchanged(self):
        spec = os.path.join(self.dir, "bad.json")
        with open(spec, "w", encoding="utf-8") as f:
            json.dump({"target": "sample.exe", "patches": [
                {"signature": "0011223344556677", "at": 8, "replacement": "8899aabbccddeeff"}
            ]}, f)
        before = open(self.target, "rb").read()
        self.assertEqual(main(["apply", spec]), 1)
        self.assertEqual(open(self.target, "rb").read(), before)

    def test_no_command(self):
        self.assertEqual(main([]), 2)


class ExampleSpecTests(unittest.TestCase):
    """examples/ 里的示例得真的能用。README 是照着它教的，错了会带偏读者。

    之前这里踩过一次：签名 11 字节，at 写成了 12，单测全绿，但照 README
    操作的人第一步 find 就失败。
    """

    def setUp(self):
        root = os.path.dirname(HERE)
        self.example = os.path.join(root, "examples", "spec.example.json")
        self.dir = tempfile.mkdtemp(prefix="sigpatch-example-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_example_spec_is_consistent(self):
        with open(self.example, encoding="utf-8") as f:
            spec = json.load(f)
        self.assertIn("target", spec)
        for item in spec["patches"]:
            sig = bytes.fromhex(item["signature"])
            rep = bytes.fromhex(item["replacement"])
            exp = bytes.fromhex(item["expect"]) if item.get("expect") else None
            at = int(item.get("at", 0))
            self.assertGreaterEqual(at, len(sig),
                                    "示例里 at 落在签名内部，打完补丁签名就没了")
            if exp is not None:
                self.assertEqual(len(exp), len(rep),
                                 "示例里 expect 与 replacement 长度不一致")

    def test_example_spec_applies_to_matching_binary(self):
        # 用示例里的签名和 at 现场造一个目标，走一遍 find → apply → verify。
        with open(self.example, encoding="utf-8") as f:
            spec = json.load(f)
        item = spec["patches"][0]
        sig = bytes.fromhex(item["signature"])
        old = bytes.fromhex(item["expect"])
        at = int(item["at"])

        body = b"\x90" * 0x100 + sig + old + b"\xcc" * 0x100
        data, _ = build_pe([(".text", body)])
        target = os.path.join(self.dir, "demo.dll")
        write_atomic(target, data)

        spec["target"] = "demo.dll"
        spec_path = os.path.join(self.dir, "spec.json")
        with open(spec_path, "w", encoding="utf-8") as f:
            json.dump(spec, f, ensure_ascii=False)

        self.assertEqual(main(["find", spec_path]), 0)
        self.assertEqual(main(["apply", spec_path]), 0)
        self.assertEqual(main(["verify", spec_path]), 0)
        self.assertEqual(main(["restore", target, "--yes"]), 0)
        self.assertEqual(open(target, "rb").read(), data)


if __name__ == "__main__":
    unittest.main(verbosity=2)

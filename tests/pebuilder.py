"""造一个能过解析的假 PE，用来测。不含任何真实 DLL 的内容。"""

import struct


def build_pe(sections, bitness=64, file_align=0x200, sect_align=0x1000):
    """sections: [(name, bytes), ...]，按顺序铺，虚拟地址按 sect_align 对齐。"""
    e_lfanew = 0x80
    nsec = len(sections)
    opt_size = 0xF0 if bitness == 64 else 0xE0
    headers_size = e_lfanew + 24 + opt_size + nsec * 40
    first_raw = (headers_size + file_align - 1) // file_align * file_align

    desc = []
    raw_cursor = first_raw
    vaddr_cursor = sect_align
    for name, content in sections:
        raw_size = (len(content) + file_align - 1) // file_align * file_align
        vsize = max(len(content), 1)
        desc.append((name, len(content), vaddr_cursor, raw_size, raw_cursor))
        raw_cursor += raw_size
        vaddr_cursor += (vsize + sect_align - 1) // sect_align * sect_align

    total = raw_cursor
    buf = bytearray(total)

    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf[e_lfanew:e_lfanew + 4] = b"PE\0\0"
    struct.pack_into("<H", buf, e_lfanew + 4, 0x8664 if bitness == 64 else 0x14C)
    struct.pack_into("<H", buf, e_lfanew + 6, nsec)
    struct.pack_into("<H", buf, e_lfanew + 20, opt_size)

    opt = e_lfanew + 24
    struct.pack_into("<H", buf, opt, 0x20B if bitness == 64 else 0x10B)

    table = opt + opt_size
    for i, (name, size, vaddr, raw_size, raw_off) in enumerate(desc):
        o = table + i * 40
        buf[o:o + 8] = name.encode("ascii")[:8].ljust(8, b"\0")
        struct.pack_into("<I", buf, o + 8, size)       # VirtualSize
        struct.pack_into("<I", buf, o + 12, vaddr)     # VirtualAddress
        struct.pack_into("<I", buf, o + 16, raw_size)  # SizeOfRawData
        struct.pack_into("<I", buf, o + 20, raw_off)   # PointerToRawData
        struct.pack_into("<I", buf, o + 36, 0x60000020)  # 代码+可执行+可读

    for (name, content), (_, _size, _vaddr, _raw_size, raw_off) in zip(sections, desc):
        buf[raw_off:raw_off + len(content)] = content

    return bytes(buf), desc


def section_offsets(desc):
    return {name: (vaddr, raw_off, size) for name, size, vaddr, _rs, raw_off in desc}

"""最小的 PE 头解析，够做 RVA 与文件偏移互换就行。

不反汇编，不解析导入导出表。这里只负责一件事：给一个 RVA，算出它落在
文件里的第几个字节；反过来也一样。补丁工具需要的就这么多。
"""

import struct


class PEFormatError(Exception):
    pass


class Section(object):
    __slots__ = ("name", "header_off", "vsize", "vaddr", "rsize", "rptr")

    def __init__(self, name, header_off, vsize, vaddr, rsize, rptr):
        self.name = name
        self.header_off = header_off
        self.vsize = vsize
        self.vaddr = vaddr
        self.rsize = rsize
        self.rptr = rptr

    def __repr__(self):
        return "Section(%r vaddr=%#x vsize=%#x rptr=%#x rsize=%#x)" % (
            self.name, self.vaddr, self.vsize, self.rptr, self.rsize)


class PEImage(object):
    """只读视图。构造时把头部全校验一遍，后面出错就直接抛。"""

    def __init__(self, data):
        self.data = bytes(data)
        if len(self.data) < 0x40:
            raise PEFormatError("文件太短，装不下 DOS 头")
        if self.data[:2] != b"MZ":
            raise PEFormatError("缺 MZ 签名")

        e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        if e_lfanew + 24 > len(self.data):
            raise PEFormatError("e_lfanew 指向文件外")
        if self.data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise PEFormatError("缺 PE 签名")
        self.e_lfanew = e_lfanew

        nsec = struct.unpack_from("<H", self.data, e_lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", self.data, e_lfanew + 20)[0]
        self.opt_off = opt = e_lfanew + 24
        if self.opt_off + 2 > len(self.data):
            raise PEFormatError("可选头越界")

        magic = struct.unpack_from("<H", self.data, opt)[0]
        if magic == 0x20B:
            self.bitness = 64
            self.section_table_off = 0xF0
        elif magic == 0x10B:
            self.bitness = 32
            self.section_table_off = 0xE0
        else:
            raise PEFormatError("不认识的可选头 magic %#x" % magic)

        if self.section_table_off > opt_size:
            raise PEFormatError("可选头太小，放不下节表")
        table = opt + self.section_table_off
        if table + nsec * 40 > len(self.data):
            raise PEFormatError("节表越界")

        self.sections = []
        for i in range(nsec):
            o = table + i * 40
            name = self.data[o:o + 8].rstrip(b"\0").decode("ascii", "replace")
            vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", self.data, o + 8)
            self.sections.append(Section(name, o, vsize, vaddr, rsize, rptr))

    def section(self, name):
        for s in self.sections:
            if s.name == name:
                return s
        raise PEFormatError("找不到节区 %r" % name)

    @staticmethod
    def span(s):
        return max(s.vsize, s.rsize)

    def rva_to_off(self, rva):
        for s in self.sections:
            if s.rsize == 0:
                continue
            if s.vaddr <= rva < s.vaddr + self.span(s):
                off = rva - s.vaddr + s.rptr
                if off >= s.rptr + s.rsize:
                    raise PEFormatError(
                        "RVA %#x 落在 %s 的零填充区，没有对应的文件内容" % (rva, s.name))
                return off
        raise PEFormatError("RVA %#x 不在任何节区内" % rva)

    def off_to_rva(self, off):
        for s in self.sections:
            if s.rsize and s.rptr <= off < s.rptr + s.rsize:
                return off - s.rptr + s.vaddr
        raise PEFormatError("文件偏移 %#x 不在任何节区的原始数据里" % off)

    def describe(self):
        lines = ["PE%d, %d 个节区" % (self.bitness, len(self.sections))]
        for s in self.sections:
            lines.append("  %-8s vaddr=%#-10x vsize=%#-10x rptr=%#-10x rsize=%#-10x"
                         % (s.name, s.vaddr, s.vsize, s.rptr, s.rsize))
        return "\n".join(lines)

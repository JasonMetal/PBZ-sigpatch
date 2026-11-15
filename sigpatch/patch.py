"""按签名定位的补丁。所有检查都在写之前做完，任何一条不过就整体放弃。

规则只有四条：

1. 特征码必须在目标文件里唯一。零次或多次都算失败，不做「取第一个」这种事。
2. 给了 expect 就必须逐字节吻合，用来确认这个位置在预期版本上。
3. 特征码只能当上下文用，不许覆盖到自己要改的区间。
4. 多条补丁的覆盖范围不许重叠。

第 3 条不是洁癖。签名一旦包含被改的字节，打过补丁之后签名就不存在了：
verify 会报「连特征码都找不到」，apply 也没法判断是不是已经打过了。
签名取补丁点之前的一段字节、at 指向它后面，这个工具才幂等。
拿捏不准的时候，宁可把签名往左多扩几个字节。

四条有任何一条不满足，apply_patches 抛异常，返回的原始数据一个字节都没动。
"""


class PatchError(Exception):
    pass


class Patch(object):
    """一条补丁。signature 用来定位，at 是相对签名起点的偏移。

    replacement 是替换后的字节。开了 expect 复核时长度必须和 replacement 一致，
    因为等长替换是这个工具唯一支持的形态。
    """

    def __init__(self, signature, replacement, at=0, expect=None, label=""):
        if not signature:
            raise ValueError("signature 不能为空")
        if not replacement:
            raise ValueError("replacement 不能为空")
        if at < 0:
            raise ValueError("at 不能是负数")
        if expect is not None and len(expect) != len(replacement):
            raise ValueError("expect 与 replacement 长度不一致，只支持等长替换")
        if at < len(signature):
            raise ValueError(
                "补丁区间从 %d 开始，落在签名 [0, %d) 内部。签名必须整段落在补丁点之前，"
                "否则打完补丁签名就没了，verify 和幂等检查都会失效。"
                % (at, len(signature)))
        self.signature = bytes(signature)
        self.replacement = bytes(replacement)
        self.at = at
        self.expect = bytes(expect) if expect is not None else None
        self.label = label or "<patch>"

    def __repr__(self):
        return "Patch(%s, at=%#x, len=%d)" % (self.label, self.at, len(self.replacement))


def find_all(data, needle):
    """找出全部出现位置，重叠的也算。re.finditer 会跳过重叠匹配，所以手写。"""
    hits = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            return hits
        hits.append(i)
        start = i + 1


def resolve_offset(data, patch):
    """只做定位：签名唯一、覆盖范围不越界。返回绝对偏移。

    不碰 expect。expect 说的是「这里应该还是旧字节」，而 already-applied
    也是一种合法状态，那件事交给调用方判断。
    """
    hits = find_all(data, patch.signature)
    if not hits:
        raise PatchError("%s: 找不到特征码。这不是该补丁针对的构建。" % patch.label)
    if len(hits) > 1:
        raise PatchError(
            "%s: 特征码出现 %d 次（%s），不再唯一。拒绝盲改。"
            % (patch.label, len(hits), ", ".join("%#x" % h for h in hits[:8])))

    off = hits[0] + patch.at
    end = off + len(patch.replacement)
    if end > len(data):
        raise PatchError("%s: 覆盖范围 %#x-%#x 越过文件尾" % (patch.label, off, end))
    return off


def locate(data, patch):
    """定位并核对 expect。给 find / verify 这类只读命令用。"""
    off = resolve_offset(data, patch)
    if patch.expect is not None:
        actual = bytes(data[off:off + len(patch.replacement)])
        if actual != patch.expect:
            raise PatchError(
                "%s: %#x 处的字节和预期不符，不敢写。\n  预期 %s\n  实际 %s"
                % (patch.label, off, patch.expect.hex(), actual.hex()))
    return off


def apply_patches(data, patches):
    """返回 (新字节, [(偏移, patch), ...])。全部校验通过才会返回。

    已经是补丁后状态的条目会跳过，所以重复调用是安全的。返回列表里只含真正
    需要改的那些；没有任何一条要改时，返回的字节和输入完全相同。
    """
    image = bytes(data)
    resolved = []
    for p in patches:
        off = resolve_offset(image, p)
        current = image[off:off + len(p.replacement)]
        if current == p.replacement:
            continue                      # 已经打过，跳过
        if p.expect is not None and current != p.expect:
            raise PatchError(
                "%s: %#x 处的字节和预期不符，不敢写。\n  预期 %s\n  实际 %s"
                % (patch.label, off, p.expect.hex(), current.hex()))
        resolved.append((off, off + len(p.replacement), p))

    resolved.sort(key=lambda t: t[0])
    for a, b in zip(resolved, resolved[1:]):
        if b[0] < a[1]:
            raise PatchError(
                "%s 和 %s 的覆盖范围重叠（%#x-%#x / %#x-%#x）"
                % (a[2].label, b[2].label, a[0], a[1], b[0], b[1]))

    out = bytearray(image)
    for off, _end, p in resolved:
        out[off:off + len(p.replacement)] = p.replacement
    return bytes(out), [(off, p) for off, _end, p in resolved]


def describe_offset(image, off):
    """把文件偏移翻成 RVA，方便和反汇编器里的地址对照。"""
    from .pe import PEFormatError, PEImage
    try:
        return "%#x (RVA %#x)" % (off, PEImage(image).off_to_rva(off))
    except PEFormatError:
        return "%#x (不在任何节区，无法换算 RVA)" % off
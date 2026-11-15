"""sigpatch —— 按签名定位、校验不过就整体拒绝的二进制补丁骨架。"""

from .pe import PEFormatError, PEImage, Section
from .patch import Patch, PatchError, apply_patches, find_all, locate

__all__ = [
    "PEFormatError", "PEImage", "Section",
    "Patch", "PatchError", "apply_patches", "find_all", "locate",
]

__version__ = "0.1.0"

"""落盘的两件事：先写临时文件再替换，以及只写一次的原件备份。"""

import hashlib
import os
import shutil

BACKUP_SUFFIX = ".orig-backup"


def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest().upper()


def write_atomic(path, data):
    """写到同目录的临时文件，fsync 之后 os.replace。

    临时文件和目标同目录，os.replace 才是原子改名；跨盘会退化成复制。
    """
    tmp = path + ".sigpatch-tmp"
    try:
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def ensure_backup(path, suffix=BACKUP_SUFFIX):
    """第一次调用时把当前文件留一份一份，之后不覆盖。

    返回备份路径。备份已存在就原样返回，这样重复 apply 不会把原件换成打过补丁的版本。
    """
    backup = path + suffix
    if not os.path.exists(backup):
        shutil.copy2(path, backup)
    return backup

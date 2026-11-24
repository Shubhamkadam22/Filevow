"""File type, permissions and ownership.

On Windows the owner and the access-control list come from the security descriptor
(via pywin32). Elsewhere we fall back to POSIX ownership and mode bits. Failures to
read security information return ``None`` instead of crashing a verification run.
"""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from filevow.db.enums import FileType

IS_WINDOWS = sys.platform == "win32"


@dataclass(frozen=True, slots=True)
class SecurityInfo:
    owner: str | None
    acl_hash: str | None


def detect_file_type(path: str | os.PathLike[str]) -> FileType:
    """Classify a path without following links."""
    target = Path(path)
    try:
        info = target.lstat()
    except FileNotFoundError:
        return FileType.MISSING
    if stat.S_ISLNK(info.st_mode):
        return FileType.LINK
    if _is_junction(target):
        return FileType.JUNCTION
    if stat.S_ISDIR(info.st_mode):
        return FileType.DIRECTORY
    return FileType.REGULAR


def describe_permissions(mode: int) -> str:
    if IS_WINDOWS:
        # Windows only reports the read-only attribute through st_mode; real rights live in the ACL.
        return "ro" if not mode & stat.S_IWRITE else "rw"
    return oct(stat.S_IMODE(mode))


def read_security_info(path: str | os.PathLike[str]) -> SecurityInfo:
    try:
        return _read_windows_security(path) if IS_WINDOWS else _read_posix_security(path)
    except Exception:
        # Best effort: the content hash still protects the file even without owner/ACL data.
        return SecurityInfo(owner=None, acl_hash=None)


def _is_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)  # Python 3.12+
    return bool(is_junction and is_junction())


def _read_windows_security(path: str | os.PathLike[str]) -> SecurityInfo:
    import win32security

    flags = win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION
    descriptor = win32security.GetFileSecurity(os.fspath(path), flags)
    owner_sid = descriptor.GetSecurityDescriptorOwner()
    name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
    sddl = win32security.ConvertSecurityDescriptorToStringSecurityDescriptor(
        descriptor, win32security.SDDL_REVISION_1, flags
    )
    owner = f"{domain}\\{name}" if domain else name
    return SecurityInfo(owner=owner, acl_hash=hashlib.sha256(sddl.encode("utf-8")).hexdigest())


def _read_posix_security(path: str | os.PathLike[str]) -> SecurityInfo:
    info = os.stat(path)
    fingerprint = f"{info.st_uid}:{info.st_gid}:{stat.S_IMODE(info.st_mode):o}"
    return SecurityInfo(
        owner=_posix_owner_name(info.st_uid), acl_hash=hashlib.sha256(fingerprint.encode()).hexdigest()
    )


def _posix_owner_name(uid: int) -> str:
    if sys.platform == "win32":
        return str(uid)
    import pwd

    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)

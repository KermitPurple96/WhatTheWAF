"""TCP fingerprint evasion — modify OS-level TCP/IP stack to match Windows profile.

p0f and similar tools fingerprint the OS by examining:
- TTL (Linux=64, Windows=128, macOS=64)
- TCP Window Size (varies by OS and version)
- TCP Options order (MSS, NOP, Window Scale, SACK, Timestamps)
- DF bit (Don't Fragment)
- Window scaling factor

This module modifies iptables and sysctl to make Linux traffic look like Windows.
Requires root/sudo.
"""

import subprocess
import os


# Windows 10/11 TCP profile
WINDOWS_PROFILE = {
    "ttl": 128,
    "window_size": 65535,
    "tcp_window_scaling": 1,
    "tcp_sack": 1,
    "tcp_timestamps": 1,
    "mss": 1460,
}

# macOS profile
MACOS_PROFILE = {
    "ttl": 64,
    "window_size": 65535,
    "tcp_window_scaling": 1,
    "tcp_sack": 1,
    "tcp_timestamps": 1,
    "mss": 1460,
}

PROFILES = {
    "windows": WINDOWS_PROFILE,
    "macos": MACOS_PROFILE,
}


def check_current_fingerprint():
    """Check current TCP fingerprint values.

    Returns dict with current TTL, window size, and TCP options.
    """
    result = {
        "ttl": 0,
        "tcp_window_scaling": 0,
        "tcp_sack": 0,
        "tcp_timestamps": 0,
        "rmem_default": 0,
        "wmem_default": 0,
        "has_sudo": False,
        "iptables_rules": [],
    }

    # Read current sysctl values
    sysctl_keys = {
        "net.ipv4.ip_default_ttl": "ttl",
        "net.ipv4.tcp_window_scaling": "tcp_window_scaling",
        "net.ipv4.tcp_sack": "tcp_sack",
        "net.ipv4.tcp_timestamps": "tcp_timestamps",
        "net.core.rmem_default": "rmem_default",
        "net.core.wmem_default": "wmem_default",
    }

    for sysctl_key, result_key in sysctl_keys.items():
        try:
            proc = subprocess.run(
                ["sysctl", "-n", sysctl_key],
                capture_output=True, text=True, timeout=5,
            )
            if proc.returncode == 0:
                result[result_key] = int(proc.stdout.strip())
        except Exception:
            pass

    # Check if we have sudo
    try:
        proc = subprocess.run(
            ["sudo", "-n", "true"],
            capture_output=True, timeout=5,
        )
        result["has_sudo"] = proc.returncode == 0
    except Exception:
        pass

    # Check existing iptables TTL rules
    try:
        proc = subprocess.run(
            ["sudo", "-n", "iptables", "-t", "mangle", "-L", "POSTROUTING", "-n", "--line-numbers"],
            capture_output=True, text=True, timeout=5,
        )
        if proc.returncode == 0:
            for line in proc.stdout.split("\n"):
                if "TTL" in line:
                    result["iptables_rules"].append(line.strip())
    except Exception:
        pass

    return result


def apply_profile(profile_name="windows", sudo_password=None, interface=None):
    """Apply a TCP fingerprint profile to make traffic match target OS.

    Args:
        profile_name: "windows" or "macos"
        sudo_password: password for sudo (if needed)
        interface: network interface (optional, applies to all if None)

    Returns dict with: success, changes_made, errors, revert_commands
    """
    profile = PROFILES.get(profile_name, WINDOWS_PROFILE)
    result = {
        "success": True,
        "changes_made": [],
        "errors": [],
        "revert_commands": [],
        "profile": profile_name,
    }

    def _sudo_run(cmd):
        """Run command with sudo."""
        full_cmd = ["sudo"]
        if sudo_password:
            full_cmd = ["sudo", "-S"]
        full_cmd.extend(cmd)

        try:
            proc = subprocess.run(
                full_cmd,
                input=f"{sudo_password}\n" if sudo_password else None,
                capture_output=True, text=True, timeout=10,
            )
            return proc.returncode == 0, proc.stderr.strip()
        except Exception as e:
            return False, str(e)

    # 1. Change TTL via iptables (most important for p0f)
    ttl = profile["ttl"]
    ok, err = _sudo_run(["iptables", "-t", "mangle", "-A", "POSTROUTING", "-j", "TTL", "--ttl-set", str(ttl)])
    if ok:
        result["changes_made"].append(f"TTL set to {ttl} (iptables mangle POSTROUTING)")
        result["revert_commands"].append(f"sudo iptables -t mangle -D POSTROUTING -j TTL --ttl-set {ttl}")
    else:
        result["errors"].append(f"Failed to set TTL: {err}")
        result["success"] = False

    # 2. Set TCP window scaling
    sysctl_changes = [
        ("net.ipv4.tcp_window_scaling", str(profile["tcp_window_scaling"])),
        ("net.ipv4.tcp_sack", str(profile["tcp_sack"])),
        ("net.ipv4.tcp_timestamps", str(profile["tcp_timestamps"])),
    ]

    for key, value in sysctl_changes:
        # Get current value for revert
        try:
            proc = subprocess.run(["sysctl", "-n", key], capture_output=True, text=True, timeout=5)
            old_value = proc.stdout.strip()
        except Exception:
            old_value = ""

        ok, err = _sudo_run(["sysctl", "-w", f"{key}={value}"])
        if ok:
            result["changes_made"].append(f"{key} = {value}")
            if old_value:
                result["revert_commands"].append(f"sudo sysctl -w {key}={old_value}")
        else:
            result["errors"].append(f"Failed to set {key}: {err}")

    # 3. Set default window size
    window_size = profile["window_size"]
    for buf_key in ["net.core.rmem_default", "net.core.wmem_default"]:
        try:
            proc = subprocess.run(["sysctl", "-n", buf_key], capture_output=True, text=True, timeout=5)
            old_value = proc.stdout.strip()
        except Exception:
            old_value = ""

        ok, err = _sudo_run(["sysctl", "-w", f"{buf_key}={window_size}"])
        if ok:
            result["changes_made"].append(f"{buf_key} = {window_size}")
            if old_value:
                result["revert_commands"].append(f"sudo sysctl -w {buf_key}={old_value}")

    return result


def revert_profile(sudo_password=None):
    """Revert TCP fingerprint changes back to Linux defaults.

    Returns dict with: success, changes_reverted
    """
    result = {"success": True, "changes_reverted": []}

    def _sudo_run(cmd):
        full_cmd = ["sudo"]
        if sudo_password:
            full_cmd = ["sudo", "-S"]
        full_cmd.extend(cmd)
        try:
            proc = subprocess.run(
                full_cmd,
                input=f"{sudo_password}\n" if sudo_password else None,
                capture_output=True, text=True, timeout=10,
            )
            return proc.returncode == 0, proc.stderr.strip()
        except Exception as e:
            return False, str(e)

    # Flush TTL rules
    ok, _ = _sudo_run(["iptables", "-t", "mangle", "-F", "POSTROUTING"])
    if ok:
        result["changes_reverted"].append("Flushed iptables mangle POSTROUTING (TTL rules removed)")

    # Restore Linux defaults
    linux_defaults = [
        ("net.ipv4.ip_default_ttl", "64"),
        ("net.ipv4.tcp_window_scaling", "1"),
        ("net.ipv4.tcp_sack", "1"),
        ("net.ipv4.tcp_timestamps", "1"),
        ("net.core.rmem_default", "212992"),
        ("net.core.wmem_default", "212992"),
    ]

    for key, value in linux_defaults:
        ok, _ = _sudo_run(["sysctl", "-w", f"{key}={value}"])
        if ok:
            result["changes_reverted"].append(f"{key} = {value}")

    return result


def get_status():
    """Get current TCP fingerprint status and what OS it resembles.

    Returns dict with: current_ttl, looks_like, profile_active, details
    """
    current = check_current_fingerprint()

    ttl = current.get("ttl", 64)
    if ttl == 128:
        looks_like = "Windows"
    elif ttl == 64:
        looks_like = "Linux/macOS"
    elif ttl == 255:
        looks_like = "Cisco/Network device"
    else:
        looks_like = f"Custom (TTL={ttl})"

    profile_active = "none"
    if current.get("iptables_rules"):
        for rule in current["iptables_rules"]:
            if "128" in rule:
                profile_active = "windows"
            elif "64" in rule:
                profile_active = "linux (explicit)"

    return {
        "current_ttl": ttl,
        "looks_like": looks_like,
        "profile_active": profile_active,
        "has_sudo": current["has_sudo"],
        "tcp_window_scaling": current.get("tcp_window_scaling"),
        "tcp_sack": current.get("tcp_sack"),
        "tcp_timestamps": current.get("tcp_timestamps"),
        "iptables_ttl_rules": current.get("iptables_rules", []),
    }

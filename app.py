# ==============================================================
#  Firewall Policy Engine (FPE) - FPE VERSION: 1.2.1
#  Author: Mohammad Shahazaad Ahmed
#
#  LEGAL DISCLAIMER:
#  This software is provided for educational and research use only.
#  It is NOT intended for use on production environments or
#  unauthorized systems.
#
#  Any damage, misconfiguration, or security impact caused by
#  using this tool is solely the user's responsibility.
#
#  Proceed with caution.
# ==============================================================
import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import threading
from pathlib import Path
from tkinter import messagebox

import customtkinter as ctk


parser = argparse.ArgumentParser()
parser.add_argument("--demo", action="store_true", help="Run without changing the system firewall.")
args = parser.parse_args()
DEMO_MODE = args.demo


class NFTManager:
    """Controlled interface to nftables."""

    def __init__(self, nft_bin="nft", demo=False):
        self.nft_bin = nft_bin
        self.demo = demo

    def _build_command(self, args, use_sudo=False):
        if use_sudo:
            return ["sudo", self.nft_bin] + args
        return [self.nft_bin] + args

    def _run(self, args, input_text=None, use_sudo=False, timeout=15):
        if self.demo:
            return 0, "Demo mode: nftables operation simulated; no system changes.", ""

        cmd = self._build_command(args, use_sudo)
        if shutil.which(cmd[0]) is None:
            return 127, "", f"Executable not found: {cmd[0]}"

        try:
            proc = subprocess.run(
                cmd,
                input=input_text,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
            )
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            return 124, "", f"Command timed out after {timeout} seconds."
        except OSError as exc:
            return 126, "", str(exc)

    def list_ruleset(self):
        rc, out, err = self._run(["list", "ruleset"])
        if rc != 0:
            raise RuntimeError(err.strip() or "Unable to list nftables ruleset.")
        return out

    def check_ruleset(self, ruleset_text):
        """Non-destructive nftables validation using check mode."""
        rc, out, err = self._run(["-c", "-f", "-"], input_text=ruleset_text)
        return rc == 0, out if rc == 0 else err

    def apply_ruleset(self, ruleset_text):
        """Actually apply the ruleset. This is the only privileged operation."""
        if self.demo:
            return True, "Demo mode: deployment simulated; no changes made."

        rc, out, err = self._run(
            ["-f", "-"],
            input_text=ruleset_text,
            use_sudo=True,
            timeout=20,
        )
        return rc == 0, out if rc == 0 else err


class PolicyDB:
    def __init__(self, path="policies_customtk.db"):
        self.path = path
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.lock = threading.RLock()
        self._ensure()

    def _ensure(self):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS policies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    content TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    policy_id INTEGER,
                    detail TEXT,
                    content_hash TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            # Lightweight schema migration for databases created by older FPE versions.
            # SQLite does not support adding a column through CREATE TABLE IF NOT EXISTS.
            cur.execute("PRAGMA table_info(policies)")
            policy_columns = {row[1] for row in cur.fetchall()}
            if "content_hash" not in policy_columns:
                cur.execute("ALTER TABLE policies ADD COLUMN content_hash TEXT")

            cur.execute("PRAGMA table_info(audit)")
            audit_columns = {row[1] for row in cur.fetchall()}
            if "content_hash" not in audit_columns:
                cur.execute("ALTER TABLE audit ADD COLUMN content_hash TEXT")

            self.conn.commit()

    def save_policy(self, name, content):
        digest = sha256_text(content)
        now = utc_now()
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO policies (name, content, content_hash, created_at) VALUES (?, ?, ?, ?)",
                (name, content, digest, now),
            )
            pid = cur.lastrowid
            cur.execute(
                """INSERT INTO audit
                   (action, policy_id, detail, content_hash, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                ("save", pid, f"Saved policy '{name}'", digest, now),
            )
            self.conn.commit()
            return pid

    def list_policies(self, limit=200):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT id, name, created_at FROM policies ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            return cur.fetchall()

    def get_policy(self, pid):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT id, name, content, created_at FROM policies WHERE id=?",
                (pid,),
            )
            return cur.fetchone()

    def delete_policy(self, pid):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM policies WHERE id=?", (pid,))
            self.conn.commit()

    def log_audit(self, action, policy_id, detail="", content_hash=None):
        with self.lock:
            self.conn.execute(
                """INSERT INTO audit
                   (action, policy_id, detail, content_hash, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (action, policy_id, detail, content_hash, utc_now()),
            )
            self.conn.commit()

    def list_audit(self, limit=200):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                """SELECT id, action, policy_id, detail, content_hash, created_at
                   FROM audit ORDER BY id DESC LIMIT ?""",
                (limit,),
            )
            return cur.fetchall()


    def close(self):
        with self.lock:
            try:
                self.conn.close()
            except Exception:
                pass


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


    def close(self):
        with self.lock:
            try:
                self.conn.close()
            except Exception:
                pass


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def strip_comments(text):
    # nftables comments can contain '#' outside quoted strings. This lightweight
    # normalization is intentionally conservative and is not a full nft parser.
    lines = []
    for line in text.splitlines():
        in_quote = False
        escaped = False
        output = []
        for ch in line:
            if ch == '"' and not escaped:
                in_quote = not in_quote
            if ch == "#" and not in_quote:
                break
            output.append(ch)
            escaped = (ch == "\\" and not escaped)
            if ch != "\\":
                escaped = False
        cleaned = "".join(output).strip()
        if cleaned:
            lines.append(cleaned)
    return "\n".join(lines)


def extract_chain_blocks(text):
    """Return simple chain blocks for security analysis.

    This is intentionally not used as an nftables parser. nft -c remains the
    authoritative syntax/semantic validator.
    """
    normalized = strip_comments(text)
    blocks = []
    for match in re.finditer(r"\bchain\s+([A-Za-z0-9_.:-]+)\s*\{", normalized, re.I):
        name = match.group(1)
        start = match.end()
        depth = 1
        i = start
        while i < len(normalized) and depth:
            if normalized[i] == "{":
                depth += 1
            elif normalized[i] == "}":
                depth -= 1
            i += 1
        if depth == 0:
            blocks.append((name, normalized[start:i - 1]))
    return blocks


def analyze_policy(text):
    """Static safety analysis. Results are advisory, not proof of safety."""
    findings = []
    normalized = strip_comments(text)
    lowered = normalized.lower()

    if not normalized.strip():
        findings.append(("CRITICAL", "Policy is empty."))

    if "table " not in lowered:
        findings.append(("HIGH", "No nftables table declaration was detected."))

    chains = extract_chain_blocks(text)
    input_chains = [(n, b) for n, b in chains if re.search(r"\bhook\s+input\b", b, re.I)]

    if not input_chains:
        findings.append(("MEDIUM", "No base input chain with an input hook was detected."))

    for name, body in input_chains:
        policy_match = re.search(r"\bpolicy\s+(accept|drop|queue|continue)\b", body, re.I)
        policy = policy_match.group(1).lower() if policy_match else None

        if policy == "accept":
            findings.append(("HIGH", f"Input chain '{name}' uses policy accept."))

        if policy == "drop":
            if not re.search(r"\btcp\s+dport\s+22\b[^\n;]*\baccept\b", body, re.I):
                findings.append((
                    "HIGH",
                    f"Input chain '{name}' has policy drop but no obvious TCP/22 accept rule."
                ))

        # Broad management exposure.
        for port, service in [("22", "SSH"), ("3389", "RDP"), ("5900", "VNC")]:
            pattern = rf"(?:ip6?\s+saddr\s+)?(?:[0-9a-fA-F:./]+|0\.0\.0\.0/0|::/0)?\s*tcp\s+dport\s+{port}\b[^\n;]*\baccept\b"
            if re.search(pattern, body, re.I):
                if re.search(rf"\btcp\s+dport\s+{port}\b[^\n;]*\baccept\b", body, re.I):
                    # Warn if no explicit source restriction appears on the same rule.
                    for line in body.splitlines():
                        if re.search(rf"\btcp\s+dport\s+{port}\b", line, re.I) and re.search(r"\baccept\b", line, re.I):
                            if not re.search(r"\bsaddr\b", line, re.I):
                                findings.append((
                                    "HIGH",
                                    f"{service} port {port} appears accepted without a source-address restriction."
                                ))

        if re.search(r"\bct\s+state\s+established,related\s+accept\b", body, re.I):
            findings.append(("INFO", f"Input chain '{name}' permits established/related traffic."))

        if re.search(r"\biif\s+lo\s+accept\b", body, re.I):
            findings.append(("INFO", f"Input chain '{name}' permits loopback traffic."))

    if re.search(r"\b(?:0\.0\.0\.0/0|::/0)\b", normalized):
        findings.append(("MEDIUM", "A rule explicitly references an unrestricted network range."))

    # Potentially dangerous management/system actions are outside the expected
    # ruleset-management scope. nft -c is still the final authority.
    suspicious = [
        r"\bflush\s+ruleset\b",
        r"\bdelete\s+table\b",
        r"\bdelete\s+chain\b",
    ]
    for pattern in suspicious:
        if re.search(pattern, normalized, re.I):
            findings.append(("MEDIUM", f"Policy contains potentially destructive nftables operation: {pattern}"))

    return findings


def format_findings(findings):
    if not findings:
        return "No advisory findings detected."
    return "\n".join(f"[{severity}] {message}" for severity, message in findings)


def check_ssh_safe(ruleset_text):
    """Compatibility wrapper returning a conservative advisory result."""
    findings = analyze_policy(ruleset_text)
    ssh_findings = [f for f in findings if "SSH" in f[1] or "TCP/22" in f[1] or "port 22" in f[1]]
    high = any(sev in ("HIGH", "CRITICAL") for sev, _ in ssh_findings)
    if high:
        return False, "SSH-related safety finding detected."
    return True, "No obvious SSH safety finding detected; this is not a guarantee of accessibility."


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class App(ctk.CTk):
    def __init__(self, manager, db):
        super().__init__()
        self.manager = manager
        self.db = db
        self.title("Firewall Policy Engine — FPE")
        self.geometry("1280x760")

        header = ctk.CTkFrame(self, height=80)
        header.pack(fill="x", padx=12, pady=(12, 6))
        ctk.CTkLabel(
            header, text="Firewall Policy Engine (FPE)",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(side="left", padx=12)
        mode_label = "DEMO MODE — NO SYSTEM CHANGES" if self.manager.demo else "REAL MODE"
        ctk.CTkLabel(
            header, text=mode_label, fg_color=("gray20", "gray30"),
            corner_radius=10, padx=10
        ).pack(side="right", padx=12)

        content = ctk.CTkFrame(self)
        content.pack(fill="both", expand=True, padx=12, pady=6)

        left = ctk.CTkFrame(content)
        left.pack(side="left", fill="both", expand=True, padx=6, pady=6)

        ctk.CTkLabel(left, text="Ruleset Editor").pack(anchor="w", padx=6, pady=(6, 0))
        self.editor = ctk.CTkTextbox(left, width=1)
        sample = (
            "# Sample nftables ruleset\n"
            "table inet filter {\n"
            "  chain input {\n"
            "    type filter hook input priority 0;\n"
            "    policy drop;\n"
            "    ct state established,related accept\n"
            "    iif lo accept\n"
            "    ip saddr 192.168.1.0/24 tcp dport 22 accept\n"
            "  }\n"
            "}\n"
        )
        self.editor.insert("0.0", sample)
        self.editor.pack(fill="both", expand=True, padx=6, pady=(4, 6))

        btn_frame = ctk.CTkFrame(left, height=44)
        btn_frame.pack(fill="x", padx=6, pady=(0, 6))
        ctk.CTkButton(btn_frame, text="Save Version", command=self.save_version, width=120).pack(side="left", padx=6, pady=6)
        ctk.CTkButton(btn_frame, text="Validate", command=self.on_dry_run, width=100).pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="Analyze", command=self.on_analyze, width=100).pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="Simulate", command=self.on_simulate, width=100).pack(side="left", padx=6)
        self.deploy_btn = ctk.CTkButton(btn_frame, text="Deploy", command=self.on_deploy, fg_color="red", width=100)
        self.deploy_btn.pack(side="right", padx=6)

        center = ctk.CTkFrame(content, width=440)
        center.pack(side="left", fill="both", padx=6, pady=6, expand=False)

        ctk.CTkLabel(center, text="Preview / Current ruleset").pack(anchor="w", padx=6, pady=(6, 0))
        self.preview = ctk.CTkTextbox(center)
        self.preview.configure(state="normal")
        self.preview.insert("0.0", self.editor.get("0.0", "end"))
        self.preview.configure(state="disabled")
        self.preview.pack(fill="both", expand=True, padx=6, pady=(4, 6))

        ctk.CTkLabel(center, text="Audit Log").pack(anchor="w", padx=6)
        self.audit = ctk.CTkTextbox(center, height=160)
        self.audit.configure(state="disabled")
        self.audit.pack(fill="both", padx=6, pady=(4, 6))

        right = ctk.CTkFrame(content, width=320)
        right.pack(side="right", fill="y", padx=(6, 12), pady=6)

        ctk.CTkLabel(right, text="Saved Versions").pack(anchor="w", padx=6, pady=(6, 0))
        self.tree = ctk.CTkScrollableFrame(right)
        self.tree.pack(fill="both", expand=True, padx=6, pady=(4, 6))
        self._load_version_buttons()

        status = ctk.CTkFrame(self, height=28)
        status.pack(fill="x", side="bottom")
        self.status_var = ctk.StringVar(value="Ready")
        ctk.CTkLabel(status, textvariable=self.status_var, anchor="w").pack(side="left", padx=8)

        self.editor.bind("<<Modified>>", self._on_edit_modified)
        self._refresh_audit_log()
        self.protocol("WM_DELETE_WINDOW", self.close)

    def _set_status(self, text):
        self.status_var.set(text)
        self.update_idletasks()

    def _on_edit_modified(self, event=None):
        try:
            self.editor.edit_modified(False)
        except Exception:
            pass
        self.preview.configure(state="normal")
        self.preview.delete("0.0", "end")
        self.preview.insert("0.0", self.editor.get("0.0", "end"))
        self.preview.configure(state="disabled")

    def _load_version_buttons(self):
        for w in self.tree.winfo_children():
            w.destroy()
        rows = self.db.list_policies(limit=100)
        if not rows:
            ctk.CTkLabel(self.tree, text="(no saved versions)").pack(padx=6, pady=6)
            return

        for pid, name, created in rows:
            txt = f"{pid}: {name} ({created.split('T')[0]} {created.split('T')[1][:8]})"
            frame = ctk.CTkFrame(self.tree)
            frame.pack(fill="x", padx=6, pady=4)
            ctk.CTkLabel(frame, text=txt, anchor="w").pack(side="left", padx=6, fill="x", expand=True)
            ctk.CTkButton(frame, text="Load", width=60, command=lambda p=pid: self.load_policy(p)).pack(side="right", padx=4)
            ctk.CTkButton(frame, text="Del", width=50, command=lambda p=pid: self.delete_policy(p)).pack(side="right", padx=4)

    def _refresh_audit_log(self):
        rows = self.db.list_audit(limit=200)
        self.audit.configure(state="normal")
        self.audit.delete("0.0", "end")
        for id_, action, pid, detail, digest, created in rows:
            short_hash = (digest or "")[:12]
            self.audit.insert(
                "0.0",
                f"[{created}] {action} pid={pid} hash={short_hash} {detail}\n"
                + self.audit.get("0.0", "end")
            )
        self.audit.configure(state="disabled")

    def _current_content(self):
        return self.editor.get("0.0", "end").strip()

    def save_version(self):
        content = self._current_content()
        if not content:
            messagebox.showwarning("Empty", "Cannot save an empty ruleset.")
            return
        name = f"policy-{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        pid = self.db.save_policy(name, content)
        self.db.log_audit("save_ui", pid, "Saved via FPE UI", sha256_text(content))
        self._set_status(f"Saved policy {pid}")
        self._load_version_buttons()
        self._refresh_audit_log()

    def load_policy(self, pid):
        rec = self.db.get_policy(pid)
        if not rec:
            messagebox.showerror("Not found", "Policy not found.")
            return
        _, name, content, created = rec
        self.editor.delete("0.0", "end")
        self.editor.insert("0.0", content)
        self._set_status(f"Loaded policy {pid}")

    def delete_policy(self, pid):
        if not messagebox.askyesno("Delete policy", f"Delete saved policy {pid}?"):
            return
        rec = self.db.get_policy(pid)
        digest = sha256_text(rec[2]) if rec else None
        self.db.delete_policy(pid)
        self.db.log_audit("delete_ui", pid, "Deleted via FPE UI", digest)
        self._set_status(f"Deleted {pid}")
        self._load_version_buttons()
        self._refresh_audit_log()

    def on_analyze(self):
        content = self._current_content()
        findings = analyze_policy(content)
        messagebox.showinfo(
            "Security Analysis",
            format_findings(findings)
        )
        self.db.log_audit(
            "analysis",
            None,
            format_findings(findings),
            sha256_text(content),
        )
        self._refresh_audit_log()

    def on_simulate(self):
        content = self._current_content()
        findings = analyze_policy(content)
        ok, validation = self.manager.check_ruleset(content)

        msg = (
            f"nftables validation: {'PASS' if ok else 'FAIL'}\n\n"
            f"Security analysis:\n{format_findings(findings)}\n\n"
            f"Validation output:\n{validation}"
        )
        messagebox.showinfo("Simulation", msg)

        pid = self.db.save_policy(
            "sim-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S"),
            content,
        )
        self.db.log_audit("simulate", pid, msg, sha256_text(content))
        self._refresh_audit_log()
        self._load_version_buttons()
        self._set_status("Simulation complete")

    def on_dry_run(self):
        content = self._current_content()
        self._set_status("Checking ruleset...")
        def job():
            ok, output = self.manager.check_ruleset(content)
            self.after(0, lambda: self._after_validation(ok, output, content))
        threading.Thread(target=job, daemon=True).start()

    def _after_validation(self, ok, output, content):
        if ok:
            messagebox.showinfo(
                "Validation",
                "nftables check passed. No firewall rules were applied."
            )
            self._set_status("Validation OK — no changes made")
        else:
            messagebox.showerror("Validation failed", f"nftables rejected the ruleset:\n\n{output}")
            self._set_status("Validation failed")

        self.db.log_audit(
            "validation",
            None,
            "PASS" if ok else f"FAIL: {output}",
            sha256_text(content),
        )
        self._refresh_audit_log()

    def on_deploy(self):
        content = self._current_content()
        if not content:
            messagebox.showwarning("Empty", "Cannot deploy an empty ruleset.")
            return

        # Validate the exact immutable snapshot that will be deployed.
        valid, validation_output = self.manager.check_ruleset(content)
        if not valid:
            messagebox.showerror(
                "Deployment blocked",
                f"nftables validation failed. The ruleset was NOT deployed.\n\n{validation_output}"
            )
            self.db.log_audit(
                "deploy_blocked",
                None,
                f"nft validation failed: {validation_output}",
                sha256_text(content),
            )
            self._refresh_audit_log()
            return

        findings = analyze_policy(content)
        high_risk = [f for f in findings if f[0] in ("HIGH", "CRITICAL")]

        analysis_text = format_findings(findings)
        if high_risk:
            if not messagebox.askyesno(
                "Security warnings",
                "The policy passed nftables validation but has security warnings:\n\n"
                f"{analysis_text}\n\nProceed anyway?"
            ):
                self._set_status("Deployment aborted")
                self.db.log_audit(
                    "deploy_aborted",
                    None,
                    "User rejected security warnings",
                    sha256_text(content),
                )
                self._refresh_audit_log()
                return

        if not messagebox.askyesno(
            "Confirm deployment",
            "This will apply the validated ruleset to the system firewall.\n\n"
            "Make sure you have console access in case the policy blocks network access.\n\n"
            "Proceed?"
        ):
            self._set_status("Deployment cancelled")
            return

        self.deploy_btn.configure(state="disabled")
        self._set_status("Deploying...")
        snapshot_hash = sha256_text(content)

        def job():
            try:
                # Re-check immediately before privileged application.
                valid_now, validation_now = self.manager.check_ruleset(content)
                if not valid_now:
                    success = False
                    output = f"Final validation failed: {validation_now}"
                else:
                    success, output = self.manager.apply_ruleset(content)
            except Exception as exc:
                success = False
                output = str(exc)
            self.after(0, lambda: self._after_deploy(success, output, content, snapshot_hash))

        threading.Thread(target=job, daemon=True).start()

    def _after_deploy(self, success, output, content, digest):
        self.deploy_btn.configure(state="normal")
        if success:
            messagebox.showinfo("Deployed", "Ruleset deployed successfully.")
            pid = self.db.save_policy(
                "deployed-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S"),
                content,
            )
            self.db.log_audit("deploy", pid, "Deployment succeeded", digest)
            self._set_status("Deployed")
        else:
            messagebox.showerror("Deploy failed", f"Deployment failed:\n\n{output}")
            self.db.log_audit("deploy_failed", None, output, digest)
            self._set_status("Deploy failed")

        self._refresh_audit_log()
        self._load_version_buttons()

    def close(self):
        try:
            self.db.close()
        except Exception:
            pass
        self.destroy()



def main():
    manager = NFTManager(demo=DEMO_MODE)
    db = None
    app = None
    try:
        db = PolicyDB()
        app = App(manager, db)
        app.mainloop()
    except Exception as exc:
        # Keep startup failures readable instead of silently crashing.
        try:
            messagebox.showerror("FPE Startup Error", str(exc))
        except Exception:
            print(f"FPE startup error: {exc}")
        raise
    finally:
        # App.close() normally closes the database; this covers startup failures.
        if app is None and db is not None:
            db.close()


if __name__ == "__main__":
    main()

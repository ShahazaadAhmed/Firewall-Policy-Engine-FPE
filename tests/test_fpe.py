import os
import tempfile
import unittest
from app import PolicyDB, analyze_policy, sha256_text


class SafetyAnalysisTests(unittest.TestCase):
    def test_empty_policy(self):
        findings = analyze_policy("")
        self.assertTrue(any(level == "CRITICAL" for level, _ in findings))

    def test_accept_policy_warns(self):
        rules = """
        table inet filter {
            chain input {
                type filter hook input priority 0;
                policy accept;
            }
        }
        """
        findings = analyze_policy(rules)
        self.assertTrue(any(level == "HIGH" for level, _ in findings))

    def test_drop_without_ssh_warns(self):
        rules = """
        table inet filter {
            chain input {
                type filter hook input priority 0;
                policy drop;
                ct state established,related accept
            }
        }
        """
        findings = analyze_policy(rules)
        self.assertTrue(any("SSH" in msg for _, msg in findings))

    def test_restricted_ssh_is_not_flagged_as_unrestricted(self):
        rules = """
        table inet filter {
            chain input {
                type filter hook input priority 0;
                policy drop;
                ip saddr 192.168.1.0/24 tcp dport 22 accept
            }
        }
        """
        findings = analyze_policy(rules)
        self.assertFalse(any(
            "SSH port 22 appears accepted without" in msg
            for _, msg in findings
        ))

    def test_comment_is_not_treated_as_rule(self):
        rules = """
        table inet filter {
            chain input {
                type filter hook input priority 0;
                policy drop;
                # tcp dport 22 accept
            }
        }
        """
        findings = analyze_policy(rules)
        self.assertTrue(any("SSH" in msg for _, msg in findings))

    def test_hash_is_stable(self):
        self.assertEqual(sha256_text("abc"), sha256_text("abc"))
        self.assertNotEqual(sha256_text("abc"), sha256_text("abd"))


class DatabaseTests(unittest.TestCase):
    def test_save_and_retrieve_policy(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            db = PolicyDB(path)
            pid = db.save_policy("test", "table inet filter {}")
            row = db.get_policy(pid)
            self.assertIsNotNone(row)
            self.assertEqual(row[1], "test")
            self.assertEqual(row[2], "table inet filter {}")
            self.assertTrue(row[3])
        finally:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    unittest.main()

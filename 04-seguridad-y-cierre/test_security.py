"""Pruebas del límite entre una solicitud emitida y una aprobada por el host."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from security import ConfirmationPendingApproval, ConfirmationStore
import server
from security import AuditLog


class ConfirmationStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = ConfirmationStore()
        self.activity_id = "2"
        self.email = "persona@untdf.edu.ar"

    def test_issued_token_cannot_register_until_host_approves_it(self) -> None:
        token = self.store.issue(self.activity_id, self.email)

        self.assertIsNotNone(
            self.store.approval_failure_reason(token, self.activity_id, self.email)
        )
        with self.assertRaises(ConfirmationPendingApproval):
            self.store.consume(token, self.activity_id, self.email)

        approval = self.store.approve_from_host(token, "host-session:42")

        self.assertTrue(approval.newly_approved)
        self.assertEqual(approval.approved_by, "host-session:42")
        self.assertIsNone(
            self.store.approval_failure_reason(token, self.activity_id, self.email)
        )
        self.store.consume(token, self.activity_id, self.email)

    def test_approval_is_idempotent_but_consumption_is_not(self) -> None:
        token = self.store.issue(self.activity_id, self.email)

        first = self.store.approve_from_host(token, "host-session:42")
        repeated = self.store.approve_from_host(token, "host-session:42")

        self.assertTrue(first.newly_approved)
        self.assertFalse(repeated.newly_approved)
        self.store.consume(token, self.activity_id, self.email)
        self.assertIsNotNone(
            self.store.approval_failure_reason(token, self.activity_id, self.email)
        )


class ServerConfirmationFlowTests(unittest.TestCase):
    def test_registration_needs_approved_token_and_audits_the_approver(self) -> None:
        with TemporaryDirectory() as directory:
            original_audit_log = server.audit_log
            audit_path = Path(directory) / "audit.jsonl"
            server.audit_log = AuditLog(path=str(audit_path))
            try:
                email = "aprobacion-host@untdf.edu.ar"
                issued = server.request_registration_confirmation("1", email)
                token = issued["confirmation_id"]

                rejected = server.register_for_activity("1", email, token)
                self.assertEqual(rejected["status"], "confirmation_invalid")

                approved = server.approve_registration_confirmation_from_host(
                    token, "host-session:42"
                )
                registered = server.register_for_activity("1", email, token)

                self.assertEqual(approved["status"], "confirmation_approved")
                self.assertEqual(registered["status"], "registered")
                audit = audit_path.read_text(encoding="utf-8")
                self.assertIn('"result": "confirmation_approved"', audit)
                self.assertIn('"approved_by": "host-session:42"', audit)
            finally:
                server.audit_log = original_audit_log


if __name__ == "__main__":
    unittest.main()

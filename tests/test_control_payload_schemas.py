import copy
import unittest

from jsonschema import Draft202012Validator

from lib.ask_herdr_control_payloads import (
    CONTROL_PAYLOAD_OPERATIONS,
    build_control_payload_schemas,
)


UUID_A = "00000000-0000-4000-8000-000000000001"
UUID_B = "00000000-0000-4000-8000-000000000002"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


def payload(operation, **fields):
    return {"schema": f"ask_herdr.{operation}.payload.v1", **fields}


RELEASE_MANIFEST = {
    "schema": "ask_herdr.release_manifest_ref.v1",
    "manifest_id": UUID_A,
    "manifest_digest": DIGEST_A,
}

RETIREMENT_MANIFEST = {
    "schema": "ask_herdr.retirement_manifest_ref.v1",
    "manifest_id": UUID_A,
    "manifest_digest": DIGEST_A,
}

VALID_PAYLOADS = {
    "query.status": payload(
        "query.status",
        selector={
            "schema": "ask_herdr.query.status.selector.v1",
            "kind": "lane",
            "lane_id": UUID_A,
        },
        advisory="summary",
        limit=50,
        cursor=None,
    ),
    "query.result": payload(
        "query.result",
        operation_id=UUID_A,
        expected_request_digest=DIGEST_A,
    ),
    "query.evidence": payload(
        "query.evidence",
        evidence_ref_id=UUID_A,
        expected_evidence_digest=DIGEST_A,
        selection={
            "schema": "ask_herdr.evidence_selection.v1",
            "mode": "range",
            "offset": 0,
            "length": 1_048_576,
        },
    ),
    "system.preflight": payload(
        "system.preflight",
        profiles=[
            {
                "schema": "ask_herdr.profile_selector.v1",
                "provider": "claude",
                "profile": "cc-claude",
            },
            {
                "schema": "ask_herdr.profile_selector.v1",
                "provider": "codex",
                "profile": "codex",
            },
        ],
    ),
    "topology.release.workspace.preview": payload(
        "topology.release.workspace.preview",
        lane_id=UUID_A,
        generation=1,
        expected_release_eligibility_state_digest=DIGEST_A,
    ),
    "topology.release.workspace.execute": payload(
        "topology.release.workspace.execute",
        manifest=RELEASE_MANIFEST,
    ),
    "topology.release.workspace.resume": payload(
        "topology.release.workspace.resume",
        original_operation_id=UUID_B,
        manifest=RELEASE_MANIFEST,
        expected_current_release_state_digest=DIGEST_B,
    ),
    "topology.release.session.preview": payload(
        "topology.release.session.preview",
        release_set={
            "schema": "ask_herdr.release_set.v1",
            "namespace_generation": 2,
            "lanes": [
                {
                    "schema": "ask_herdr.release_set.entry.v1",
                    "lane_id": UUID_A,
                    "generation": 1,
                    "state_digest": DIGEST_A,
                }
            ],
        },
    ),
    "topology.release.session.execute": payload(
        "topology.release.session.execute",
        manifest=RELEASE_MANIFEST,
    ),
    "topology.release.session.resume": payload(
        "topology.release.session.resume",
        original_operation_id=UUID_B,
        manifest=RELEASE_MANIFEST,
        expected_current_release_state_digest=DIGEST_B,
    ),
    "recovery.reconcile": payload(
        "recovery.reconcile",
        selector={
            "schema": "ask_herdr.recovery_scope_selector.v1",
            "kind": "lane",
            "lane_id": UUID_A,
            "generation": 3,
        },
        expected_recovery_state_digest=DIGEST_A,
    ),
    "recovery.rebuild_topology": payload(
        "recovery.rebuild_topology",
        source_reconciliation_operation_id=UUID_A,
        topology_rebuild_eligible_state_digest=DIGEST_A,
        topology_recovery_set_digest=DIGEST_B,
        expected_namespace={
            "schema": "ask_herdr.expected_namespace_generation.v1",
            "state": "retired",
            "generation": 4,
        },
    ),
    "recovery.retire.lane.preview": payload(
        "recovery.retire.lane.preview",
        lane_id=UUID_A,
        generation=3,
        expected_retirement_state_digest=DIGEST_A,
        acknowledge_abandon_unresolved=True,
    ),
    "recovery.retire.lane.execute": payload(
        "recovery.retire.lane.execute",
        manifest=RETIREMENT_MANIFEST,
    ),
    "recovery.retire.namespace.preview": payload(
        "recovery.retire.namespace.preview",
        retirement_set={
            "schema": "ask_herdr.retirement_set.v1",
            "namespace_generation": 4,
            "lanes": [
                {
                    "schema": "ask_herdr.retirement_set.entry.v1",
                    "lane_id": UUID_A,
                    "generation": 3,
                    "abandoned_unresolved_tombstone_digest": DIGEST_A,
                    "topology_binding_digest": DIGEST_B,
                }
            ],
        },
        expected_retirement_state_digest=DIGEST_C,
    ),
    "recovery.retire.namespace.execute": payload(
        "recovery.retire.namespace.execute",
        manifest=RETIREMENT_MANIFEST,
    ),
    "process.interrupt.graceful": payload(
        "process.interrupt.graceful",
        source_operation_id=UUID_A,
        expected_active_state_digest=DIGEST_A,
        expected_adapter_supervisor_start_receipt_digest=DIGEST_B,
    ),
    "process.interrupt.force": payload(
        "process.interrupt.force",
        original_interruption_operation_id=UUID_B,
        source_operation_id=UUID_A,
        graceful_signal_receipt_digest=DIGEST_A,
        expected_still_running_state_digest=DIGEST_B,
        graceful_window_elapsed_proof_digest=DIGEST_C,
    ),
}


def walk_dicts(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_dicts(child)


def contains_key(value, key):
    if isinstance(value, dict):
        return key in value or any(contains_key(child, key) for child in value.values())
    if isinstance(value, list):
        return any(contains_key(child, key) for child in value)
    return False


class ControlPayloadSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schemas = build_control_payload_schemas()

    def test_builder_returns_the_exact_eighteen_operation_mapping(self):
        self.assertEqual(tuple(sorted(VALID_PAYLOADS)), CONTROL_PAYLOAD_OPERATIONS)
        self.assertEqual(set(VALID_PAYLOADS), set(self.schemas))

    def test_every_schema_is_standalone_draft_2020_12_and_accepts_its_fixture(self):
        for operation, fixture in VALID_PAYLOADS.items():
            with self.subTest(operation=operation):
                schema = self.schemas[operation]
                Draft202012Validator.check_schema(schema)
                self.assertEqual(
                    schema["$schema"],
                    "https://json-schema.org/draft/2020-12/schema",
                )
                self.assertFalse(contains_key(schema, "$ref"))
                Draft202012Validator(schema).validate(fixture)

    def test_every_payload_and_nested_object_is_closed_and_version_tagged(self):
        for operation, fixture in VALID_PAYLOADS.items():
            validator = Draft202012Validator(self.schemas[operation])
            for index, nested in enumerate(walk_dicts(fixture)):
                with self.subTest(operation=operation, nested=index):
                    self.assertRegex(nested["schema"], r"^ask_herdr\..+\.v1$")
                    invalid = copy.deepcopy(fixture)
                    target = list(walk_dicts(invalid))[index]
                    target["unknown"] = True
                    self.assertFalse(validator.is_valid(invalid))

    def test_query_variants_and_bounds_are_exact(self):
        validator = Draft202012Validator(self.schemas["query.status"])
        for kind, fields in (
            ("project", {}),
            ("key", {"consultant_key": "reviewer"}),
            ("lane", {"lane_id": UUID_A}),
            ("operation", {"operation_id": UUID_A}),
        ):
            fixture = copy.deepcopy(VALID_PAYLOADS["query.status"])
            fixture["selector"] = {
                "schema": "ask_herdr.query.status.selector.v1",
                "kind": kind,
                **fields,
            }
            with self.subTest(kind=kind):
                self.assertTrue(validator.is_valid(fixture))

        for limit in (0, 201):
            invalid = copy.deepcopy(VALID_PAYLOADS["query.status"])
            invalid["limit"] = limit
            self.assertFalse(validator.is_valid(invalid))

        for valid_key in ("a", "reviewer-", "a" + "-" * 63):
            fixture = copy.deepcopy(VALID_PAYLOADS["query.status"])
            fixture["selector"] = {
                "schema": "ask_herdr.query.status.selector.v1",
                "kind": "key",
                "consultant_key": valid_key,
            }
            self.assertTrue(validator.is_valid(fixture))

        for invalid_key in ("Reviewer", "a" + "-" * 64):
            fixture = copy.deepcopy(VALID_PAYLOADS["query.status"])
            fixture["selector"] = {
                "schema": "ask_herdr.query.status.selector.v1",
                "kind": "key",
                "consultant_key": invalid_key,
            }
            self.assertFalse(validator.is_valid(fixture))

        evidence = Draft202012Validator(self.schemas["query.evidence"])
        whole = copy.deepcopy(VALID_PAYLOADS["query.evidence"])
        whole["selection"] = {
            "schema": "ask_herdr.evidence_selection.v1",
            "mode": "whole",
        }
        self.assertTrue(evidence.is_valid(whole))
        for offset, length in ((-1, 1), (0, 0), (0, 1_048_577)):
            invalid = copy.deepcopy(VALID_PAYLOADS["query.evidence"])
            invalid["selection"]["offset"] = offset
            invalid["selection"]["length"] = length
            self.assertFalse(evidence.is_valid(invalid))

    def test_preflight_profile_pairs_and_release_sets_are_structurally_exact(self):
        preflight = Draft202012Validator(self.schemas["system.preflight"])
        without_profiles = payload("system.preflight")
        self.assertTrue(preflight.is_valid(without_profiles))
        incomplete = copy.deepcopy(VALID_PAYLOADS["system.preflight"])
        del incomplete["profiles"][0]["profile"]
        self.assertFalse(preflight.is_valid(incomplete))

        release = Draft202012Validator(
            self.schemas["topology.release.session.preview"]
        )
        duplicate = copy.deepcopy(
            VALID_PAYLOADS["topology.release.session.preview"]
        )
        duplicate["release_set"]["lanes"].append(
            copy.deepcopy(duplicate["release_set"]["lanes"][0])
        )
        self.assertFalse(release.is_valid(duplicate))

    def test_recovery_scope_and_namespace_state_unions_are_closed(self):
        reconcile = Draft202012Validator(self.schemas["recovery.reconcile"])
        for kind, fields in (
            ("operation", {"operation_id": UUID_A}),
            ("lane", {"lane_id": UUID_A, "generation": 1}),
            ("namespace", {"namespace_generation": 1}),
            ("policy", {}),
        ):
            fixture = copy.deepcopy(VALID_PAYLOADS["recovery.reconcile"])
            fixture["selector"] = {
                "schema": "ask_herdr.recovery_scope_selector.v1",
                "kind": kind,
                **fields,
            }
            with self.subTest(kind=kind):
                self.assertTrue(reconcile.is_valid(fixture))

        rebuild = Draft202012Validator(
            self.schemas["recovery.rebuild_topology"]
        )
        absent = copy.deepcopy(VALID_PAYLOADS["recovery.rebuild_topology"])
        absent["expected_namespace"] = {
            "schema": "ask_herdr.expected_namespace_generation.v1",
            "state": "absent",
            "generation": None,
        }
        self.assertTrue(rebuild.is_valid(absent))
        absent["expected_namespace"]["generation"] = 1
        self.assertFalse(rebuild.is_valid(absent))

    def test_interruption_payloads_forbid_caller_process_and_topology_controls(self):
        forbidden = ("pid", "signal", "pane_id", "workspace_id", "session_id", "path")
        for operation in (
            "process.interrupt.graceful",
            "process.interrupt.force",
        ):
            validator = Draft202012Validator(self.schemas[operation])
            for field in forbidden:
                with self.subTest(operation=operation, field=field):
                    invalid = copy.deepcopy(VALID_PAYLOADS[operation])
                    invalid[field] = "forbidden"
                    self.assertFalse(validator.is_valid(invalid))

    def test_builder_returns_fresh_unshared_documents(self):
        first = build_control_payload_schemas()
        second = build_control_payload_schemas()
        first["query.status"]["properties"]["limit"]["maximum"] = 999
        self.assertEqual(second["query.status"]["properties"]["limit"]["maximum"], 200)


if __name__ == "__main__":
    unittest.main()

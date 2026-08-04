#!/usr/bin/env python3
"""Focused deterministic tests for metadata-derived scenario generation."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from generate_profile_scenarios import (  # noqa: E402
    DEFAULT_LIBRARY_PATH,
    ScenarioGenerationError,
    assign_split,
    build_artifacts,
    derive_domains,
    generate_artifacts,
)
from holdout_firewall import holdout_leak_reasons  # noqa: E402
from query_policy import validate_query_args  # noqa: E402
from question_intelligence import (  # noqa: E402
    extract_explicit_dataset_locks,
    validate_query_dataset_locks,
)
from spl_plan_compiler import compile_analytical_plan  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = ROOT / "benchmarks" / "fixtures" / "scenario_environment_profile.json"
GENERATED_DIR = ROOT / "benchmarks" / "scenario_splits" / "generated"
PROTECTED_CASES_PATH = ROOT / "benchmarks" / "holdout_eval21_cases.json"
EXPECTED_FAMILIES = {
    "top_n_cardinality",
    "multivalue_intersection",
    "time_bin_anomaly",
    "part_to_whole",
    "cross_event_correlation",
    "cloud_api_result_comparison",
    "dns_diversity_mapping",
}
EXPECTED_MUTATIONS = {
    "base",
    "paraphrase",
    "time_shift",
    "scope_removal",
    "field_synonym",
    "negative_platform",
}


def _all_scenarios(artifacts: dict[str, dict]) -> list[dict]:
    return [
        scenario
        for split in ("train", "dev", "holdout")
        for scenario in artifacts[split]["scenarios"]
    ]


class ProfileScenarioGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.artifacts, cls.manifest = build_artifacts(
            profile_path=PROFILE_PATH,
            library_path=DEFAULT_LIBRARY_PATH,
        )
        cls.scenarios = _all_scenarios(cls.artifacts)

    def test_generates_all_composition_and_mutation_families(self) -> None:
        self.assertEqual(self.manifest["domain_count"], 10)
        self.assertEqual(self.manifest["composition_group_count"], 54)
        self.assertEqual(self.manifest["scenario_count"], 324)
        self.assertEqual(set(self.manifest["families"]), EXPECTED_FAMILIES)
        self.assertEqual(set(self.manifest["mutations"]), EXPECTED_MUTATIONS)
        self.assertEqual(
            self.manifest["split_counts"],
            {"train": 210, "dev": 42, "holdout": 72},
        )
        self.assertEqual(
            set(self.artifacts["train"]["family_counts"]),
            EXPECTED_FAMILIES,
        )
        self.assertEqual(
            set(self.artifacts["holdout"]["family_counts"]),
            EXPECTED_FAMILIES,
        )
        self.assertEqual(self.manifest["collision_promoted_group_count"], 3)

    def test_reference_plans_recompile_exactly(self) -> None:
        for scenario in self.scenarios:
            with self.subTest(scenario=scenario["id"]):
                self.assertEqual(
                    compile_analytical_plan(scenario["reference_plan"]),
                    scenario["reference_spl"],
                )
                self.assertEqual(
                    scenario["expected_constraints"]["required_output_fields"],
                    scenario["reference_plan"]["analysis"]["output_fields"],
                )

    def test_reference_spl_is_structurally_policy_safe(self) -> None:
        for scenario in self.scenarios:
            execution = scenario["reference_plan"]["execution"]
            valid, reason = validate_query_args(
                {
                    "query": scenario["reference_spl"],
                    "earliest_time": execution["earliest"],
                    "latest_time": execution["latest"],
                    "row_limit": execution["row_limit"],
                },
                question="",
            )
            with self.subTest(scenario=scenario["id"]):
                self.assertTrue(valid, reason)

    def test_cross_event_explicit_multi_sourcetype_locks_integrate(self) -> None:
        explicit = [
            scenario
            for scenario in self.scenarios
            if scenario["family"] == "cross_event_correlation"
            and scenario["expected_constraints"]["explicit_scope_in_question"]
            and len(extract_explicit_dataset_locks(scenario["question"])["sourcetypes"]) == 2
        ]
        self.assertGreaterEqual(len(explicit), 20)
        for scenario in explicit:
            locks = extract_explicit_dataset_locks(scenario["question"])
            expected = scenario["expected_constraints"]["dataset_locks"]
            with self.subTest(scenario=scenario["id"]):
                self.assertEqual(
                    {item.casefold() for item in locks["sourcetypes"]},
                    {item["sourcetype"].casefold() for item in expected},
                )
                self.assertEqual(
                    validate_query_dataset_locks(
                        scenario["question"],
                        scenario["reference_spl"],
                    ),
                    (True, "dataset_locks_ok"),
                )

    def test_split_assignment_is_stable_and_lineage_atomic(self) -> None:
        assignment = self.manifest["assignment"]
        groups: dict[str, list[dict]] = {}
        for scenario in self.scenarios:
            groups.setdefault(scenario["group_id"], []).append(scenario)
            expected = assign_split(
                scenario["domain"]["domain_id"],
                scenario["family"],
                seed=assignment["seed"],
                train_percent=assignment["train_percent"],
                dev_percent=assignment["dev_percent"],
            )
            self.assertEqual(scenario["provenance"]["initial_hash_split"], expected)
            restriction = {"train": 0, "dev": 1, "holdout": 2}
            self.assertGreaterEqual(
                restriction[scenario["split"]],
                restriction[expected],
            )

        split_groups = {
            split: set(self.manifest["groups_by_split"][split])
            for split in ("train", "dev", "holdout")
        }
        self.assertFalse(split_groups["train"] & split_groups["dev"])
        self.assertFalse(split_groups["train"] & split_groups["holdout"])
        self.assertFalse(split_groups["dev"] & split_groups["holdout"])
        for group in groups.values():
            self.assertEqual({row["split"] for row in group}, {group[0]["split"]})
            self.assertEqual({row["mutation"] for row in group}, EXPECTED_MUTATIONS)

    def test_mutations_retain_dataset_locks_and_plan_shape(self) -> None:
        groups: dict[str, dict[str, dict]] = {}
        for scenario in self.scenarios:
            groups.setdefault(scenario["group_id"], {})[scenario["mutation"]] = scenario
        for group_id, mutations in groups.items():
            base = mutations["base"]
            for mutation_name, scenario in mutations.items():
                with self.subTest(group=group_id, mutation=mutation_name):
                    self.assertEqual(
                        scenario["reference_plan"]["datasets"],
                        base["reference_plan"]["datasets"],
                    )
                    self.assertEqual(
                        scenario["reference_plan"]["analysis"],
                        base["reference_plan"]["analysis"],
                    )
                    if mutation_name == "time_shift":
                        self.assertEqual(
                            scenario["reference_plan"]["execution"]["earliest"],
                            "-7d",
                        )
                        self.assertIn("last 7 days", scenario["question"])
                    else:
                        self.assertEqual(
                            scenario["reference_plan"],
                            base["reference_plan"],
                        )
            scope_free_question = mutations["scope_removal"]["question"].casefold()
            self.assertNotIn("index ", scope_free_question)
            self.assertNotIn("sourcetype ", scope_free_question)
            self.assertTrue(
                mutations["negative_platform"]["expected_constraints"]["forbidden_platform"]
            )

    def test_learning_eligibility_and_fingerprints_do_not_cross_splits(self) -> None:
        for split, payload in self.artifacts.items():
            expected = split == "train"
            self.assertEqual(payload["learning_eligible"], expected)
            self.assertTrue(
                all(row["learning_eligible"] is expected for row in payload["scenarios"])
            )
        for fingerprint_name in (
            "question_sha256",
            "reference_plan_sha256",
            "reference_spl_sha256",
        ):
            values = {
                split: {
                    row["fingerprints"][fingerprint_name]
                    for row in self.artifacts[split]["scenarios"]
                }
                for split in ("train", "dev", "holdout")
            }
            self.assertFalse(values["train"] & values["dev"])
            self.assertFalse(values["train"] & values["holdout"])
            self.assertFalse(values["dev"] & values["holdout"])

    def test_artifacts_are_reproducible_and_match_checked_in_files(self) -> None:
        second_artifacts, second_manifest = build_artifacts(
            profile_path=PROFILE_PATH,
            library_path=DEFAULT_LIBRARY_PATH,
        )
        self.assertEqual(second_artifacts, self.artifacts)
        self.assertEqual(second_manifest, self.manifest)
        for split in ("train", "dev", "holdout"):
            checked_in = json.loads(
                (GENERATED_DIR / f"{split}.json").read_text(encoding="utf-8")
            )
            self.assertEqual(checked_in, self.artifacts[split])
        checked_manifest = json.loads(
            (GENERATED_DIR / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(checked_manifest, self.manifest)

        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            generate_artifacts(
                profile_path=PROFILE_PATH,
                library_path=DEFAULT_LIBRARY_PATH,
                output_dir=first,
            )
            generate_artifacts(
                profile_path=PROFILE_PATH,
                library_path=DEFAULT_LIBRARY_PATH,
                output_dir=second,
            )
            for name in ("train.json", "dev.json", "holdout.json", "manifest.json"):
                self.assertEqual(
                    (Path(first) / name).read_bytes(),
                    (Path(second) / name).read_bytes(),
                )

    def test_protected_eval21_is_forbidden_as_input_and_absent_from_outputs(self) -> None:
        with self.assertRaisesRegex(
            ScenarioGenerationError,
            "protected_holdout_input_forbidden",
        ):
            build_artifacts(
                profile_path=PROTECTED_CASES_PATH,
                library_path=DEFAULT_LIBRARY_PATH,
            )
        self.assertFalse(self.manifest["protected_eval21_generation_input"])
        self.assertEqual(holdout_leak_reasons(self.scenarios), [])

    def test_domains_and_questions_change_with_metadata(self) -> None:
        profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        library = yaml.safe_load(DEFAULT_LIBRARY_PATH.read_text(encoding="utf-8"))
        original_domains = derive_domains(profile, library)
        reduced = copy.deepcopy(profile)
        reduced["sourcetype_to_indexes"].pop("stream:dns")
        reduced_domains = derive_domains(reduced, library)
        self.assertEqual(len(original_domains), len(reduced_domains) + 1)


if __name__ == "__main__":
    unittest.main()

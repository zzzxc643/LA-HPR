"""Offline checks for shared review caching, errors and sample accounting."""
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

import review

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "repair_validation_prep"))


SETTINGS = dict(model="qwen3.8-max-0902", enable_thinking=False,
                max_output_tokens=3072, context_limit=1000000)


def pool(sample="one", group="codet5_local", code="int f() { return 1; }"):
    return dict(sample_id=sample, group=group, original_function="int f() { return 0; }",
        vulnerable_line=1, counts={}, generation={}, candidates=[dict(cand_id=1,
            diff="-return 0;\n+return 1;\n" + sample, patched_code=code,
            source="codet5", generation_arm="codet5_local", rank=1)], generation_audit=[])


class Client:
    def __init__(self, verdict="PASS", error=None):
        self.verdict, self.error, self.calls = verdict, error, 0
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def create(self, **request):
        self.calls += 1
        if self.error:
            raise self.error
        flags = dict(PASS=(True, True, True), FAIL=(False, True, True),
                     UNCERTAIN=(None, True, True))[self.verdict]
        content = json.loads(request["messages"][1]["content"])
        payload = dict(reviews=[dict(cand_id=c["cand_id"], vul_eliminated=flags[0],
            func_preserved=flags[1], no_new_bug=flags[2], result=self.verdict,
            reason="offline fixture") for c in content["candidates"]],
            selected_cand_id=content["candidates"][0]["cand_id"] if self.verdict == "PASS" else None,
            selection_reason="offline fixture")
        return SimpleNamespace(id="fixture", model=request["model"], usage=None,
            choices=[SimpleNamespace(finish_reason="stop",
                message=SimpleNamespace(content=json.dumps(payload)))])


class ReviewTests(unittest.TestCase):
    def test_cross_group_request_reuse_and_selected_patch(self):
        a, b = pool(), pool(group="combined")
        empty = dict(pool(sample="empty"), candidates=[])
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp)
            pools = {"codet5_local": [a, empty], "combined": [b]}
            requests, records, results = review.plan(pools, SETTINGS, cache)
            self.assertEqual(len(requests), 1)
            client = Client()
            self.assertFalse(review.execute(requests, records, SETTINGS, cache, 6, client))
            self.assertEqual(client.calls, 1)
            for group, rows in pools.items():
                summary = review.summarize(group, rows, results[group], records, SETTINGS)
                self.assertTrue(summary["complete"])
                self.assertEqual(results[group][0]["selected_patch"], a["candidates"][0]["patched_code"])
            self.assertEqual(summary["successful_samples"], 1)
            self.assertFalse(results["codet5_local"][1]["success"])
            _, cached, _ = review.plan(pools, SETTINGS, cache)
            self.assertFalse(review.execute(requests, cached, SETTINGS, cache, 6, client))
            self.assertEqual(client.calls, 1)

    def test_valid_negative_verdicts_are_final(self):
        for verdict in ("FAIL", "UNCERTAIN"):
            with self.subTest(verdict=verdict), tempfile.TemporaryDirectory() as tmp:
                cache = Path(tmp)
                requests, records, results = review.plan({"codet5_local": [pool()]}, SETTINGS, cache)
                client = Client(verdict)
                review.execute(requests, records, SETTINGS, cache, 6, client)
                _, cached, _ = review.plan({"codet5_local": [pool()]}, SETTINGS, cache)
                review.execute(requests, cached, SETTINGS, cache, 6, client)
                self.assertEqual(client.calls, 1)
                summary = review.summarize("codet5_local", [pool()], results["codet5_local"], cached, SETTINGS)
                self.assertTrue(summary["complete"])
                self.assertEqual(summary["llm_sfr"], 0)

    def test_auth_failure_halts_new_requests_without_false_fail(self):
        class AuthenticationError(Exception):
            status_code = 401
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp)
            pools = {"codet5_local": [pool("first"), pool("second")]}
            requests, records, results = review.plan(pools, SETTINGS, cache)
            client = Client(error=AuthenticationError())
            self.assertTrue(review.execute(requests, records, SETTINGS, cache, 1, client))
            self.assertEqual(client.calls, 1)
            summary = review.summarize("codet5_local", pools["codet5_local"],
                results["codet5_local"], records, SETTINGS)
            self.assertEqual([r["success"] for r in results["codet5_local"]], [None, None])
            self.assertFalse(summary["complete"])
            self.assertIsNone(summary["llm_sfr"])
            self.assertEqual(summary["unresolved_errors"], 2)


if __name__ == "__main__":
    unittest.main()

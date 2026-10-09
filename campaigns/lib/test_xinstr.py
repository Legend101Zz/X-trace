import pathlib
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import xinstr  # noqa: E402


def rec(method, path, status, symbols=("OwnerController.showOwner", "OwnerRepository.findById"), src=True, kind="responded",
        resp_symbol=None):
    evs = [{"kind": "recording_event_kind:request_update", "symbol": f"http.request {method} {path}", "interaction": {"method": method}, "source": None}]
    for sy in symbols:
        evs.append({"kind": "recording_event_kind:frame_enter", "symbol": sy, "interaction": {},
                    "source": {"path": "src/main/java/X.java", "startLine": 3, "status": "matched"} if src else None})
    evs.append({"kind": "recording_event_kind:response", "symbol": resp_symbol or f"http.response {status}", "interaction": {}, "source": None})
    return {"events": evs, "outcome": {"kind": kind, "httpStatus": status if kind == "responded" else None}}


class T(unittest.TestCase):
    def test_percentile(self):
        self.assertIsNone(xinstr.percentile([], 50))
        self.assertEqual(xinstr.percentile([5, 1, 3, 2, 4], 50), 3)
        self.assertEqual(xinstr.percentile(list(range(1, 101)), 95), 95)
        self.assertEqual(xinstr.percentile([7], 95), 7)

    def test_readiness_wrapped_and_plain(self):
        t = "x\n" + '{"ok":true,"data":{"kind":"viewer_ready","origin":"http://127.0.0.1:5","url":"http://127.0.0.1:5/#' + "A" * 43 + '"}}'
        r = xinstr.parse_readiness(t)
        self.assertEqual(r["origin"], "http://127.0.0.1:5")
        self.assertEqual(xinstr.bootstrap_token(r["url"]), "A" * 43)
        self.assertIsNone(xinstr.parse_readiness("no json"))

    def test_route_regex(self):
        rx = xinstr.route_regex("/owners/{ownerId}/edit")
        self.assertTrue(rx.match("/owners/12/edit"))
        self.assertFalse(rx.match("/owners/12"))

    def test_analyze_pass_and_each_failure(self):
        exp = {"s": [{"method": "GET", "route": "/owners/{ownerId}", "status": 200, "layers": ["controller", "repository"]}]}
        ok = xinstr.analyze({"a": rec("GET", "/owners/4", 200)}, exp)
        self.assertTrue(ok["s"]["passed"], ok)
        self.assertEqual(xinstr.analyze({}, exp)["s"]["expectations"][0]["problems"], ["no-recording-for-route"])
        bad = xinstr.analyze({"a": rec("GET", "/owners/4", 500)}, exp)["s"]["expectations"][0]["problems"]
        self.assertTrue(bad[0].startswith("http-outcome-mismatch"))
        nof = xinstr.analyze({"a": rec("GET", "/owners/4", 200, symbols=())}, exp)["s"]["expectations"][0]["problems"]
        self.assertIn("no-controller-frame", nof)
        self.assertIn("no-repository-frame", nof)
        un = xinstr.analyze({"a": rec("GET", "/owners/4", 200, kind="unobserved")}, exp)["s"]["expectations"][0]["problems"]
        self.assertEqual(un, ["outcome-unobserved"])
        nos = xinstr.analyze({"a": rec("GET", "/owners/4", 200, src=False)}, exp)["s"]["expectations"][0]["problems"]
        self.assertEqual(nos, ["no-source-file-line"])
        self.assertEqual(xinstr.problem_classes(xinstr.analyze({"a": rec("GET", "/owners/4", 500)}, exp)),
                         {"http-outcome-mismatch": 1})

    def test_method_must_match(self):
        exp = {"s": [{"method": "POST", "route": "/owners/new", "status": 302, "layers": []}]}
        self.assertEqual(xinstr.analyze({"a": rec("GET", "/owners/new", 302)}, exp)["s"]["expectations"][0]["problems"],
                         ["no-recording-for-route"])

    def test_min_count(self):
        exp = {"s": [{"method": "GET", "route": "/owners/{id}", "status": 200, "layers": [], "minCount": 3}]}
        two = {"a": rec("GET", "/owners/1", 200), "b": rec("GET", "/owners/2", 200)}
        self.assertFalse(xinstr.analyze(two, exp)["s"]["passed"])
        two["c"] = rec("GET", "/owners/3", 200)
        self.assertTrue(xinstr.analyze(two, exp)["s"]["passed"])


if __name__ == "__main__":
    unittest.main()

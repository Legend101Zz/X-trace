"""Run repository unittests with a private JSON result channel, separate from logs."""

import argparse
import json
import os
import pathlib
import sys
import unittest


class StructuredResult(unittest.TextTestResult):
    """Extract identities from TestCase objects, without formatting captured data."""

    def summary(self) -> dict:
        identities = []
        for outcome, tests in (("FAIL", [test for test, _ in self.failures]),
                               ("ERROR", [test for test, _ in self.errors]),
                               ("UNEXPECTED_SUCCESS", self.unexpectedSuccesses)):
            for test in tests:
                # Subtest ids/descriptions include parameter values. Only the
                # enclosing TestCase's class and method identify the failure.
                if isinstance(test, unittest.case._SubTest):
                    test = test.test_case
                # Class/module setup errors use unittest's _ErrorHolder rather
                # than a TestCase. Its description is prose, so name only the
                # holder type and retain the independently recorded error count.
                identities.append({"outcome": outcome, "method": getattr(test, "_testMethodName", "unverified"),
                                   "class": f"{type(test).__module__}.{type(test).__qualname__}"})
        return {"identities": identities, "counts": {
            "testsRun": self.testsRun, "failures": len(self.failures), "errors": len(self.errors),
            "skipped": len(self.skipped), "expectedFailures": len(self.expectedFailures),
            "unexpectedSuccesses": len(self.unexpectedSuccesses),
        }}


class StructuredRunner(unittest.TextTestRunner):
    resultclass = StructuredResult


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result", required=True, type=pathlib.Path)
    parser.add_argument("unittest_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    # Refuse to overwrite an earlier result. The workflow supplies fresh paths
    # in the job's private scratch directory and keeps raw logs separate.
    descriptor = os.open(args.result, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        program = unittest.main(module=None, argv=[sys.argv[0], *args.unittest_args],
                                testRunner=StructuredRunner, exit=False)
        json.dump(program.result.summary(), stream, sort_keys=True)
        stream.write("\n")
    return 0 if program.result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())

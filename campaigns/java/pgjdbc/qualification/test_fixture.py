"""Hosted-only helper checks. None creates a process, network or database."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from owned_postgres import FixtureFailure, OwnedPostgres, created_container, identifier
from project import LIMITS, STAGES, STEPS, base, project

A, B = '1'*64, '2'*64
ENV = dict(PRODUCT='a'*40, FIXTURE='b'*40, GITHUB_SHA='c'*40, GITHUB_RUN_ID='17', GITHUB_RUN_ATTEMPT='1')


class Ownership(unittest.TestCase):
    def test_exact_creation_receipts(self):
        self.assertEqual(created_container(A, (A+'\n').encode(), True), A)
        self.assertEqual(created_container(A, None, False), A)
        self.assertEqual(created_container(A, b'', True), A)
        self.assertIsNone(created_container(None, A.encode(), False))
        self.assertIsNone(identifier(A[:12].encode()))
        with self.assertRaises(FixtureFailure):
            created_container(A, B.encode(), True)
        with self.assertRaises(FixtureFailure):
            created_container(None, b'', True)


class Release(unittest.TestCase):
    def test_only_created_resource_ids_are_used(self):
        with TemporaryDirectory() as scratch:
            report = {}
            owned = OwnedPostgres(Path(scratch), {}, report, lambda: None)
            owned.container, owned.network = A, B
            calls = []
            def operation(args, timeout=45):
                calls.append(args)
                if args[0] == 'inspect':
                    return (A+' '+('running' if len(calls) == 1 else 'exited')+' 0\n').encode()
                if args[0] == 'wait':
                    self.assertTrue((owned.control/'stop.request').is_file())
                    self.assertEqual(timeout, 30)
                    return b'0\n'
                return b''
            with patch.object(owned, 'checked', side_effect=operation):
                owned.release()
            self.assertEqual([cmd[0] for cmd in calls],
                             ['inspect','wait','inspect','rm','container','network','network'])
            self.assertEqual(calls[3], ['rm','-v', A])
            self.assertEqual(calls[5], ['network','rm', B])
            self.assertEqual(report, dict(databaseStop='passed',containerRelease='passed',
                                          networkRelease='passed'))

    def test_cannot_resolve_by_substitution_or_force_after_uncertain_stop(self):
        with TemporaryDirectory() as scratch:
            report = {}
            owned = OwnedPostgres(Path(scratch), {}, report, lambda: None)
            owned.container, owned.network = A, B
            calls = []
            def operation(args, timeout=45):
                calls.append(args)
                if args[0]=='inspect':
                    return (A+' running 0\n').encode()
                raise FixtureFailure('unavailable')
            with patch.object(owned, 'checked', side_effect=operation):
                owned.release()
            self.assertEqual([c[0] for c in calls], ['inspect','wait','network'])
            self.assertEqual(report, dict(databaseStop='attempted',containerRelease='unverified',
                                          networkRelease='unverified'))

    def test_unknown_id_never_enters_engine(self):
        with TemporaryDirectory() as scratch:
            owned = OwnedPostgres(Path(scratch), {}, {}, lambda: None)
            with patch.object(owned, 'checked') as commands:
                owned.release()
            commands.assert_not_called()


class Projection(unittest.TestCase):
    def row(self):
        row = base(ENV)
        row.update({k: 'owned' if k.endswith('Create') else 'passed' for k in STAGES})
        row.update(LIMITS, privacyFiles=13, privacyFilesMatched=0, status='passed')
        return row

    def test_complete_receipt(self):
        self.assertEqual(project(self.row(), ['success']*len(STEPS), ENV)['verdict'], 'passed')

    def test_missing_receipt(self):
        for outcome in ('failure', 'cancelled', 'skipped'):
            with self.subTest(outcome=outcome):
                out = project(None, ['success'] * 5 + [outcome], ENV)
                expected = 'unreached' if outcome == 'skipped' else 'unavailable'
                self.assertTrue(all(out[key] == expected for key in STAGES))
                self.assertTrue(all(out[key] is None for key in LIMITS))
                self.assertEqual(out['receipt'], 'unavailable')
                self.assertEqual(out['verdict'], 'incomplete')
        with self.assertRaises(ValueError):
            project(None, ['success'] * len(STEPS), ENV)

    def test_completed_probe_before_job_interruption(self):
        for outcome in ('cancelled', 'failure'):
            with self.subTest(outcome=outcome):
                out = project(self.row(), ['success'] * 5 + [outcome], ENV)
                self.assertEqual(out['receipt'], 'observed')
                self.assertEqual(out['status'], 'passed')
                self.assertEqual(out['checkedJdbcStarts'], 8)
                self.assertEqual(out['jobSteps']['pgjdbc'], outcome)
                self.assertEqual(out['verdict'], 'incomplete')

    def test_false_or_unbounded_claims(self):
        for change in ({'checkedRecordings': 1}, {'privacyFilesMatched': True}, {'other': 'private'},
                       {'containerRelease': 'unreached'}, {'fixture': 'c'*40}, {'readback': 'private'}):
            with self.subTest(keys=list(change)), self.assertRaises(ValueError):
                project({**self.row(), **change}, ['success']*len(STEPS), ENV)


if __name__ == '__main__':
    unittest.main()

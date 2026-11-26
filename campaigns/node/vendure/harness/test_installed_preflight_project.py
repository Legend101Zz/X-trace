"""Hosted regressions for fixed-schema preflight evidence projection."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('preflight_project', Path(__file__).with_name('installed-preflight-project.py'))
project = importlib.util.module_from_spec(spec)
spec.loader.exec_module(project)
SOURCE = 'a' * 40


def passed():
    return dict(schemaVersion=1, kind='vendure-installed-preflight-only', source=SOURCE, releaseAcceptance=False,
                package='verified', preflight='passed', observation=dict(phase='receipt', status='passed', code=None, signal=None),
                attachExit=0, processExit=0, receiptValid=True, cleanup='passed', status='passed')


class ProjectTest(unittest.TestCase):
    def test_complete_success_requires_both_process_observations(self):
        doc = passed()
        self.assertTrue(project.validate(doc, SOURCE))
        for field, value in (('attachExit', 1), ('processExit', 1), ('receiptValid', False), ('cleanup', 'retained')):
            broken = dict(doc, **{field: value})
            self.assertFalse(project.validate(broken, SOURCE))

    def test_failed_phase_and_signal_remain_distinct(self):
        doc = passed()
        doc.update(preflight='failed', observation=dict(phase='init', status='failed', code=None, signal='SIGTERM'),
                   attachExit=1, processExit=143, receiptValid=False, status='incomplete')
        self.assertTrue(project.validate(doc, SOURCE))
        doc['observation']['code'] = 1
        self.assertFalse(project.validate(doc, SOURCE))

    def test_partial_documents_cannot_claim_unreached_work(self):
        partial = dict(passed(), status='incomplete', cleanup='retained')
        self.assertTrue(project.validate(partial, SOURCE))
        for field, value in (('package', 'failed'), ('attachExit', 1), ('processExit', None), ('receiptValid', False)):
            self.assertFalse(project.validate(dict(partial, **{field: value}), SOURCE))
        empty = dict(passed(), package='running', preflight='unreached', cleanup='unreached', observation=None,
                     attachExit=None, processExit=None, receiptValid=None, status='incomplete')
        self.assertTrue(project.validate(empty, SOURCE))
        for field, value in (('cleanup', 'passed'), ('attachExit', 0), ('receiptValid', False)):
            self.assertFalse(project.validate(dict(empty, **{field: value}), SOURCE))
        started = dict(empty, package='verified', preflight='running', observation=dict(phase='list', status='running', code=None, signal=None))
        self.assertTrue(project.validate(started, SOURCE))
        self.assertFalse(project.validate(dict(started, cleanup='passed'), SOURCE))
        self.assertIsNone(project.reached_document(passed(), SOURCE, 'skipped', True))
        self.assertIsNone(project.reached_document(passed(), SOURCE, 'failure', False))
        self.assertEqual(project.reached_document(started, SOURCE, 'cancelled', True), started)

    def test_extra_or_nonstructural_values_are_rejected(self):
        doc = passed()
        self.assertFalse(project.validate(dict(doc, extra='private'), SOURCE))
        doc['observation']['phase'] = []
        self.assertFalse(project.validate(doc, SOURCE))
        doc = passed()
        doc['observation']['signal'] = 'SIGPRIVATE'
        self.assertFalse(project.validate(doc, SOURCE))
        self.assertFalse(project.validate(passed(), 'b' * 40))


if __name__ == '__main__':
    unittest.main()

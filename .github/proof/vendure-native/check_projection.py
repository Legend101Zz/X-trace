"""Deterministic offline receipt-shape checks run on the GitHub-hosted runner."""
import unittest
import project

def complete():
    row = dict(kind='vendure-native-ordinary', leg='installed', releaseAcceptance=False,
        preflight=dict(phase='receipt',status='passed',code=None,signal=None),
        stages=dict.fromkeys(project.STAGES,'passed'),startupEvidence={**dict.fromkeys(project.STARTUP,True),'serverAtJointReady':'live-match'},
        serverStop=dict(live=True,signalled=True,closed=True,code=0,signal=None,nodeBeforeStop="live-match",nodeGone=True),
        workerStop=dict(live=True,signalled=True,closed=True,code=None,signal='SIGTERM',nodeBeforeStop=None,nodeGone=None),
        captureIncompleteNotice=False,databaseRelease='passed',status='passed')
    return dict(schemaVersion=1, kind='native-vendure-direct-child', source='3bc74469d586ab1cb421c85e98eff8e3a9d515a9', fixture='a'*40, wrapper='b'*40,runId=1,attempt=1,
                releaseAcceptance=False,actions=dict.fromkeys(project.ACTIONS,'success'),
                stageMarkers=dict.fromkeys((*project.PACKAGE,*project.PREP),'success'),checkpointStatus='observed',
                checkpoint=row,preflightFileStatus="observed",preflightFile=row["preflight"].copy(),complete=True)

class Contracts(unittest.TestCase):
    def test_full_observed_pass(self):
        project.validate(complete())

    def test_launcher_143_remains_a_failure(self):
        doc = complete()
        doc['actions']['campaign'] = doc['stageMarkers']['native'] = 'failure'
        doc['complete'] = False
        row = doc['checkpoint']
        row['status'] = 'incomplete'
        row['stages']['serverStop'] = 'failed'
        row['serverStop']['code'] = 143
        row['captureIncompleteNotice'] = True
        project.validate(doc)
        doc['complete'] = True
        with self.assertRaises(ValueError):
            project.validate(doc)

    def test_completed_sample_survives_cancelled_action(self):
        doc = complete()
        doc['actions']['campaign'] = 'cancelled'
        doc['complete'] = False
        project.validate(doc)

    def test_only_worker_context_observed(self):
        doc = complete()
        doc['actions']['campaign'] = 'cancelled'
        doc['stageMarkers']['native'] = 'running'
        doc['complete'] = False
        row = doc['checkpoint']
        row.update(databaseRelease='unreached',status='incomplete',serverStop=None,workerStop=None,captureIncompleteNotice=None)
        row['startupEvidence'].update(serverProcessMatched=False,serverListenBanner=False,serverAtJointReady=None)
        row['stages'] = {k: ('running' if k=='startup' else 'passed') for k in project.STAGES[:6]}
        project.validate(doc)

    def test_stale_stock_process_does_not_qualify_server_stop(self):
        for state in ('already-exited','unverified'):
            doc = complete()
            doc['checkpoint']['serverStop']['nodeBeforeStop'] = state
            with self.assertRaises(ValueError):
                project.validate(doc)

    def test_interrupted_preflight_preserves_independent_phase(self):
        doc = complete()
        doc.update(complete=False,preflightFile=dict(phase='init',status='running',code=None,signal=None))
        doc['actions']['campaign'] = 'cancelled'
        doc['stageMarkers']['native'] = 'running'
        row = doc['checkpoint']
        row.update(status='incomplete',stages=dict(install='passed',initEmptyList='running'),preflight=None,
                   startupEvidence={**dict.fromkeys(project.STARTUP,False),'serverAtJointReady':None},
                   serverStop=None,workerStop=None,captureIncompleteNotice=None,databaseRelease='unreached')
        project.validate(doc)

    def test_missing_checkpoint_is_distinct_from_observed(self):
        doc = complete()
        doc.update(complete=False,checkpointStatus='unavailable',checkpoint=None)
        doc['actions']['campaign'] = 'failure'
        doc['stageMarkers']['native'] = 'failure'
        project.validate(doc)

    def test_unreached_preparation_cannot_support_native_receipt(self):
        doc = complete()
        doc['stageMarkers']['seed'] = None
        with self.assertRaises(ValueError):
            project.validate(doc)

    def test_arbitrary_fields_and_unowned_stop_rejected(self):
        for key,value in [('signalled',False),('other','arbitrary')]:
            doc = complete()
            doc['checkpoint']['serverStop'][key] = value
            with self.assertRaises(ValueError):
                project.validate(doc)

if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Contracts)
    expected = {'test_full_observed_pass','test_launcher_143_remains_a_failure',
                'test_completed_sample_survives_cancelled_action','test_only_worker_context_observed',
                'test_missing_checkpoint_is_distinct_from_observed',
                'test_unreached_preparation_cannot_support_native_receipt','test_arbitrary_fields_and_unowned_stop_rejected',
                'test_stale_stock_process_does_not_qualify_server_stop','test_interrupted_preflight_preserves_independent_phase'}
    names = [t.id().split('.')[-1] for t in suite]
    if len(names) != len(expected) or set(names) != expected:
        raise SystemExit('incomplete native unit inventory')
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.testsRun != len(expected) or result.skipped or result.expectedFailures or result.unexpectedSuccesses:
        raise SystemExit('native unit prerequisites failed')

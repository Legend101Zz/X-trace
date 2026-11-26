"""Hosted-only receipt privacy fixtures; no browser, process, request or plan execution."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('focus_followup_owner_plan', Path(__file__).parent / 'plan-helpers/owner_plan.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

IDENTITY = dict(sourceSha='a'*40, sourceTree='b'*40, wrapperSha='c'*40, runId=1, attempt=1, receiptId='d'*64)


def receipt():
    return dict(schemaVersion=1, kind='owner-plan-browser', **IDENTITY, status='failed', stage='focus-trap',
        cells=[dict(width=320,height=640,pointer='fine',status='failed',checks={key:'failed' if key=='focus-trap' else 'unreached' for key in policy.CHECKS})],
        routes=dict.fromkeys(policy.ACTIONS,0),observedRoutes=dict.fromkeys(policy.ACTIONS,0),
        routeCountMeaning='verified-authenticated-response',externalRequests=0,blockedSameOriginWrites=0,missingInputFailure=None,consoleErrors=0,downloads=0,privateLeaks=0,
        expiry='unreached',serverExpiredDrafts=0,pendingWriteClose='unreached',
        focusDiagnostic=dict(subcheck='forward-tab-close',state='failed',activeRole='disclosure-summary',activeTabIndex='negative',
            insideModal=True,nativeModal=True,moreExpanded=True,moreVisible=True,activeDisabled=False,planBusy=False,
            openerVisible=True,openerFocused=False),
        failureLocation=dict(file='owner-plan-browser.mjs',line=1,column=1))


class FocusReceipt(unittest.TestCase):
    def test_fixed_focus_failure_is_admitted_without_values(self):
        value=receipt()
        self.assertEqual(policy.browser_receipt(value,IDENTITY),value)

    def test_unknown_nested_or_top_level_private_fields_are_refused(self):
        for target in ('top','diagnostic','location'):
            value=receipt()
            selected=value if target=='top' else value['focusDiagnostic' if target=='diagnostic' else 'failureLocation']
            selected['privateText']='PRIVATE_BODY_MARKER'
            with self.assertRaises(ValueError):policy.browser_receipt(value,IDENTITY)

    def test_roles_subchecks_states_locations_and_flags_are_closed(self):
        for name,field,bad in (
            ('focusDiagnostic','activeRole','PRIVATE_FIELD_VALUE'),
            ('focusDiagnostic','subcheck','PRIVATE_FIELD_VALUE'),
            ('focusDiagnostic','state','PRIVATE_FIELD_VALUE'),
            ('focusDiagnostic','activeTabIndex','0'),
            ('focusDiagnostic','planBusy','PRIVATE_FIELD_VALUE'),
            ('focusDiagnostic','insideModal',1),
            ('failureLocation','file','private/path'),
            ('failureLocation','line',True),
            ('failureLocation','column',10001),
        ):
            value=receipt();value[name][field]=bad
            with self.subTest(name=name,field=field),self.assertRaises(ValueError):policy.browser_receipt(value,IDENTITY)

    def test_diagnostics_cannot_turn_partial_checks_into_success(self):
        value=receipt();value.update(status='passed',stage='complete',serverExpiredDrafts=1,pendingWriteClose='passed',expiry='server-expired-and-approval-unavailable')
        value['focusDiagnostic']['state']='passed';value['failureLocation']=None
        with self.assertRaises(ValueError):policy.browser_receipt(value,IDENTITY)

    def test_unavailable_snapshot_remains_explicit_failure_evidence(self):
        value=receipt();value['focusDiagnostic']['state']='snapshot-unavailable';value['failureLocation']=None
        self.assertEqual(policy.browser_receipt(value,IDENTITY)['focusDiagnostic']['state'],'snapshot-unavailable')


    def test_missing_response_and_unverified_rejection_remain_distinct(self):
        value=self.missing_failure()
        self.assertEqual(policy.browser_receipt(value,IDENTITY),value)
        self.assertEqual(value['routes']['create'],0)
        value['missingInputFailure'].update(checkpoint='http-status',httpStatus=403,problem='origin')
        self.assertEqual(policy.browser_receipt(value,IDENTITY),value)
        value['missingInputFailure'].update(checkpoint='rendered-identity',httpStatus=200,problem=None)
        self.assertEqual(policy.browser_receipt(value,IDENTITY),value)

    def test_missing_failure_refuses_open_data_and_inconsistent_counters(self):
        for key,bad in (('action','private-value'),('checkpoint','private-detail'),('httpStatus',True),
                        ('problem','private-message'),('raw','private-body')):
            value=self.missing_failure()
            value['missingInputFailure'][key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):policy.browser_receipt(value,IDENTITY)
        for count in (True,-1,10001):
            value=self.missing_failure()
            value['blockedSameOriginWrites']=count
            with self.assertRaises(ValueError):policy.browser_receipt(value,IDENTITY)
        value=self.missing_failure()
        value['observedRoutes']['create']=0
        value['missingInputFailure'].update(checkpoint='http-status',httpStatus=403,problem='origin')
        with self.assertRaises(ValueError):policy.browser_receipt(value,IDENTITY)

    def test_missing_failure_must_belong_to_failed_cell_and_stage(self):
        for change in ('cell','stage','verdict','problem-on-success','checkpoint-before-response'):
            value=self.missing_failure()
            if change=='cell':value['cells'][0]['checks']['missing-inputs']='passed'
            if change=='stage':value['stage']='focus-trap'
            if change=='verdict':value['status']='passed'
            if change=='problem-on-success':value['missingInputFailure'].update(checkpoint='cache-policy',httpStatus=200,problem='origin')
            if change=='checkpoint-before-response':value['missingInputFailure']['httpStatus']=200
            with self.subTest(change=change),self.assertRaises(ValueError):policy.browser_receipt(value,IDENTITY)

    def test_first_cell_counts_follow_response_and_document_admission(self):
        for action, point, code, problem, create, review in (
            ('create','http-status',403,'origin',1,0),
            ('create','unresolved-body-input',200,None,0,0),
            ('review','http-status',403,'origin',0,0),
            ('review','unavailable-approval',200,None,1,0),
        ):
            value=self.missing_failure()
            value['missingInputFailure'].update(action=action,checkpoint=point,httpStatus=code,problem=problem)
            value['routes'].update(create=create,review=review)
            value['observedRoutes'][action]=1
            with self.subTest(point=point,action=action),self.assertRaises(ValueError):
                policy.browser_receipt(value,IDENTITY)
        value=self.missing_failure()
        value['missingInputFailure'].update(checkpoint='document-counted',httpStatus=200)
        value['routes']['create']=1
        self.assertEqual(policy.browser_receipt(value,IDENTITY),value)

    def test_previous_cells_do_not_credit_the_current_unverified_response(self):
        value=self.missing_failure()
        prior=dict(width=320,height=640,pointer='fine',status='passed',checks=dict.fromkeys(policy.CHECKS,'passed'))
        value['cells'][0]['pointer']='coarse'
        value['cells'].insert(0,prior)
        value['routes']=dict(create=2,edit=2,show=4,review=3,approve=2)
        value['observedRoutes']=dict(value['routes'],review=4)
        value['missingInputFailure'].update(action='review',checkpoint='http-status',httpStatus=403,problem='origin')
        self.assertEqual(policy.browser_receipt(value,IDENTITY),value)
        value['observedRoutes']['review']=3
        with self.assertRaises(ValueError):
            policy.browser_receipt(value,IDENTITY)

    def missing_failure(self):
        value=receipt()
        value.update(stage='missing-inputs',missingInputFailure=dict(action='create',checkpoint='await-response',
                     httpStatus=None,problem=None))
        value['cells'][0]['checks'].update({'selection':'passed','opener':'passed','focus-trap':'passed','missing-inputs':'failed'})
        value['focusDiagnostic'].update(state='passed',subcheck='modal-fit')
        value['observedRoutes']['create']=1
        return value

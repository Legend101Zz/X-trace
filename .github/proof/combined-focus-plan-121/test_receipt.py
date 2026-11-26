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
        routeCountMeaning='verified-authenticated-response',externalRequests=0,consoleErrors=0,downloads=0,privateLeaks=0,
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

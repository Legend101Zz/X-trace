"""Closed public receipt cells shared by producer and offline verifier."""
import math
import statistics


def need(ok):
    if not ok:
        raise ValueError('invalid bounded receipt cell')


PHASES = {'initial_steps','initial_map','initial_steps_return','later_steps','later_map','later_steps_return','failure-observation'}
DOM = {'apiLastPageEvents','apiEventsReturnedCumulative','mountedStepRows','visibleStepRows','loadedRailLabelCount',
       'mapSvgNodes','visibleMapSvgNodes','mapTreeRows','visibleMapTreeRows','documentElements'}
SAMPLE_STAGES = {'viewer_start','browser_start','catalog','initial_click_response','initial_visible_paint_opportunity',
 'initial_steps','later_steps','page_observations','complete','browser_cleanup','viewer_cleanup','timed_viewer_traffic',
 'initial_map','initial_steps_return','later_map','later_steps_return',
 'initial_steps_navigation','initial_map_navigation','later_steps_navigation','later_map_navigation',
 'other', None} | {'load_later_'+str(i) for i in range(1,13)}
SUBSTAGES = {'mode_click','mode_pressed','selection_wait','dom_snapshot','dom_assertions','next_click','next_selection_wait',
 'back_click','back_selection_wait','response','row_click','load_click','detail_response','details_identity','details_click',
 'reveal_row','identity_paint','next_event_lookup','default_inspector','other',None}


def count(value, maximum):
    need(type(value) is int and 0 <= value <= maximum)
    return value


def num(value):
    need(type(value) in (int,float) and math.isfinite(value) and value >= 0)
    return value


def validate_sample(item, index):
    need(set(item) == {'sample','status','stage','substage','initial','failures','laterPages','dom','timedTraffic','pageErrors','externalRequests'})
    need(item['sample'] == index and item['status'] in ('exercised','failed')
         and item['stage'] in SAMPLE_STAGES and item['substage'] in SUBSTAGES)
    initial = item['initial']
    if initial is not None:
        need(set(initial) == {'fullInspectorIdentityReadableAtBothFrames','detailsTabClickIncluded','detailsTabClickOffsetMs',
                             'elapsedMs','over1500Ms','firstPageEvents'})
        need(initial['fullInspectorIdentityReadableAtBothFrames'] is True and count(initial['firstPageEvents'],200) > 0)
        ms = num(initial['elapsedMs'])
        clicked, offset = initial['detailsTabClickIncluded'], initial['detailsTabClickOffsetMs']
        need(type(clicked) is bool and (num(offset) <= ms if clicked else offset is None)
             and initial['over1500Ms'] is (ms > 1500))
    count(item['laterPages'],12)
    for field in ('pageErrors','externalRequests'):
        if item[field] is not None:
            count(item[field],100000)
    traffic = item['timedTraffic']
    if traffic is not None:
        need(set(traffic) == {'authExchanges','refused'})
        for value in traffic.values():
            count(value,100000)
    need(type(item['failures']) is list and len(item['failures']) <= 4)
    for failure in item['failures']:
        need(set(failure) == {'stage','substage','code'} and failure['stage'] in SAMPLE_STAGES
             and failure['substage'] in SUBSTAGES
             and failure['code'] in ('journey_failed_or_unreached','cleanup_failed','unexpected_traffic_or_missing_exchange'))
    need(type(item['dom']) is list and len(item['dom']) <= 16)
    for row in item['dom']:
        need(row['phase'] in PHASES and row['heapStatus'] in ('measured','unavailable'))
        heap = {'heapUsedBytes','heapTotalBytes'} if row['heapStatus'] == 'measured' else set()
        need(set(row) == DOM | {'phase','heapStatus'} | heap)
        for key in heap:
            num(row[key])
        for key in DOM:
            if row[key] is not None:
                count(row[key],1000000)
    if item['status'] == 'exercised':
        need(initial is not None and item['stage'] == 'complete' and not item['failures'] and item['laterPages'] == 12
             and item['pageErrors'] == item['externalRequests'] == 0 and traffic == {'authExchanges':1,'refused':0}
             and [row['phase'] for row in item['dom']] == ['initial_steps','initial_map','initial_steps_return','later_steps',
                                                           'later_map','later_steps_return'])
    else:
        need(bool(item['failures']))


def valid_sample(value,index):
    try:
        validate_sample(value,index)
    except (AttributeError, KeyError, OverflowError, TypeError, ValueError):
        return False
    return True


def timing_summary(samples):
    times = [item['initial']['elapsedMs'] for item in samples if item['initial'] is not None]
    complete = sum(item['status'] == 'exercised' for item in samples)
    return dict(functionalFailures=5-complete,completeJourneySamples=complete,validInitialSamples=len(times),
        medianMs=statistics.median(times) if times else None,maxMs=max(times) if times else None,
        samplesOver1500Ms=sum(time>1500 for time in times),
        aggregationDecision='unsettled; descriptive statistics only',memoryThreshold='unsettled')

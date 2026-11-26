"""Require executed test cases in both complete Gradle suites before the real installed journey."""
from pathlib import Path
from xml.etree import ElementTree
import sys


REQUIRED = {
    'agent-bootstrap': {
        ('dev.xtrace.agent.bootstrap.XTraceAgentTest',
         'jdbcBoundaryRequiresRequestContextAndOnlyItsOwnerCanCloseIt'),
    },
    'agent-runtime': {
        ('dev.xtrace.agent.runtime.FixtureInstrumentationTest',
         'pgJdbcTransformationFailureStopsOnlyTheProfileThatRequestsItsProbe'),
        ('dev.xtrace.agent.runtime.RecordingWriterTest', 'pgjdbcFailureHasOnlyDriverAndMethodMetadata'),
    },
}


def verify(product):
    for module, named in REQUIRED.items():
        counts = {key: 0 for key in named}
        executed = 0
        for path in (product/'adapters/java'/module/'build/test-results/test').glob('TEST-*.xml'):
            root = ElementTree.parse(path).getroot()
            cases = root.findall('testcase')
            if len(cases) != int(root.attrib['tests']) or any(int(root.attrib[key]) for key in
                                                               ('errors', 'failures', 'skipped')):
                raise ValueError('incomplete Java suite')
            for case in cases:
                if any(case.find(key) is not None for key in ('skipped', 'failure', 'error')):
                    raise ValueError('incomplete Java case')
                executed += 1
                key = (case.attrib['classname'], case.attrib['name'].removesuffix('()'))
                if key in counts:
                    counts[key] += 1
        if executed < 1 or any(value != 1 for value in counts.values()):
            raise ValueError('named Java prerequisite unavailable')


if __name__ == '__main__':
    try:
        verify(Path(sys.argv[1]))
    except (OSError, ValueError, KeyError, ElementTree.ParseError):
        raise SystemExit('Java prerequisite evidence incomplete') from None

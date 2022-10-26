#!/usr/bin/env python3

import re
import signal
import subprocess
import sys

LOG_PREFIX = r'^(?P<time>\d+\.\d+)\s+(?P<hostname>\S+)\s+'
LOG_START_RE = re.compile(LOG_PREFIX + r'START$')
LOG_STOP_RE = re.compile(LOG_PREFIX + r'STOP$')
LOG_FRAME_RECV_RE = re.compile(LOG_PREFIX + \
        r'Received frame on\s+(?P<intf>\S+): ' + \
        r'(?P<src>[0-9a-f]{2}(:[0-9a-f]{2}){5}) -> ' + \
        r'(?P<dst>[0-9a-f]{2}(:[0-9a-f]{2}){5})$')

NEXT_ITERATION_SLACK = 0.15 # 150 ms
MAX_INTERVAL = 0.5 # 500 ms

class LinkLayerLabTester:
    cmd = []
    observing_hosts = []

    def evaluate(self, iteration, time_seen, observing_hosts):
        if iteration >= len(self.observing_hosts):
            # not evaluated
            return None

        solution = self.observing_hosts[iteration]
        if solution is None:
            # not evaluated
            return None

        solution = sorted(solution)
        submission = sorted(observing_hosts)
        if solution != submission:
            sys.stderr.write(('At time %0.3f, frame seen by: %s\n  ' + \
                    '(should be %s)\n') % \
                    (time_seen, ', '.join(submission), ', '.join(solution)))
            return False
        return True


    def evaluate_lines(self, lines):
        # initialize
        start_time = None
        max_time = None
        next_time = None
        iteration = None
        hosts_seen = None

        evaluated = 0
        success = 0

        for line in lines:
            m = LOG_START_RE.search(line)
            if m is not None:
                start_time = float(m.group('time')) + 1.0
                max_time = start_time + MAX_INTERVAL
                next_time = start_time + (1 - NEXT_ITERATION_SLACK)
                iteration = 0
                hosts_seen = []

            m = LOG_FRAME_RECV_RE.search(line)
            if m is not None:
                hostname = m.group('hostname')
            else:
                m = LOG_STOP_RE.search(line)
                if m is not None:
                    hostname = ''

            if m is not None:
                mytime = float(m.group('time'))

                while mytime > max_time:
                    if not hosts_seen:
                        # if we have gone through the loop more than once, then
                        # don't reduce by NEXT_ITERATION_SLACK
                        start_time = start_time + NEXT_ITERATION_SLACK
                        next_time = next_time + NEXT_ITERATION_SLACK

                    # evaluate
                    result = self.evaluate(iteration, start_time, hosts_seen)
                    if result is not None:
                        evaluated += 1
                        if result:
                            success += 1

                    # reset
                    iteration += 1
                    start_time = next_time

                    max_time = start_time + MAX_INTERVAL
                    next_time = start_time + (1.0 - NEXT_ITERATION_SLACK)
                    hosts_seen = []

                if not hosts_seen:
                    # if this is the first host seen, then save the time
                    start_time = mytime
                    max_time = start_time + MAX_INTERVAL
                    next_time = start_time + (1.0 - NEXT_ITERATION_SLACK)
                hosts_seen.append(hostname)

        # evaluate
        result = self.evaluate(iteration, start_time, hosts_seen)
        if result is not None:
            evaluated += 1
            if result:
                success += 1

        return success, evaluated

    def run(self):
        p = None
        try:
            p = subprocess.Popen(self.cmd, stdout=subprocess.PIPE)
            p.wait()
        except KeyboardInterrupt:
            p.send_signal(signal.SIGINT)
            p.wait()
            raise

        output = p.stdout.read().decode('utf-8')
        output_lines = output.splitlines()
        return self.evaluate_lines(output_lines)

class Scenario1(LinkLayerLabTester):
    cmd = ['cougarnet', '--stop=22', '--disable-ipv6',
            '--terminal=none', 'scenario1.cfg']
    observing_hosts = [
            ['b', 'c', 'd', 'e'],
            ['a'],
            ['c'],
            ['b', 'c', 'd', 'e'],
            ['a'],
            ['e'],
            ['a'],
            ['c'],
            None,
            None,
            ['a'],
            ['b', 'c', 'd', 'e'],
            ]

class Scenario2(LinkLayerLabTester):
    cmd = ['cougarnet', '--stop=22', '--disable-ipv6',
            '--terminal=none', 'scenario2.cfg']
    observing_hosts = [
            ['b', 'c', 'd', 'e'],
            ['a'],
            ['c'],
            ['b', 'c', 'd', 'e'],
            ['a'],
            ['e'],
            ['a'],
            ['c'],
            None,
            None,
            ['a'],
            ['b', 'c', 'd', 'e'],
            ]

class Scenario3(LinkLayerLabTester):
    cmd = ['cougarnet', '--stop=22', '--disable-ipv6',
            '--terminal=none', 'scenario3.cfg']
    observing_hosts = [
            ['c', 'e'],
            ['a'],
            ['c'],
            ['c', 'e'],
            ['a'],
            ['e'],
            ['a'],
            ['c'],
            None,
            None,
            ['a'],
            ['c', 'e'],
            ]

def main():
    try:
        for scenario in Scenario1, Scenario2, Scenario3:
            print(f'Running {scenario.__name__}...')
            tester = scenario()
            success, total = tester.run()
            sys.stderr.write(f'  Result: {success}/{total}\n')
    except KeyboardInterrupt:
        sys.stderr.write('Interrupted\n')

if __name__ == '__main__':
    main()
    
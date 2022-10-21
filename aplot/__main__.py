#!/usr/bin/env python3
# coding: utf-8

""" Atop log data analyzer.

Usage:
  {cmd} metrics [-c <cmd>] [-p <path>] [-e <time>] [-r <hours>]
  {cmd} (csv|json|table) [-c <cmd>] [-p <path>] [-e <time>] [-r <hours>] [<metric>...]
  {cmd} (diagram|gnuplot) [-c <cmd>] [-p <path>] [-e <time>] [-r <hours>] [-x <lines>] [-y <lines>] [<metric>...]

Options:

    diagram                       Print the results as a braille character diagram (default).
    gnuplot                       Print the results using a gnuplot subprocess.
    table                         Print the results as ascii table.
    csv                           Print the results as csv table.
    json                          Print the results as json datagram.

    metrics                       Print a list of all possible metric_path's.

    -e <time>, --end=<time>       The latest value to plot in ISO8601 format. Defaults to now. [default: {now}]
    -r <hours>, --range=<hours>   Number of hours, backwards from --stop, top plot. [default: 6]
    -x <lines>, --width=<lines>   Width of plotted graphs in text lines. [default: 59]
    -y <lines>, --height=<lines>  Height of plotted graphs in text lines. [default: 9]
    -p <path>, --path=<path>      Path to atop raw logs with date placeholders. [default: /var/log/atop/atop_%Y%m%d]
    -c <cmd>, --cmd <cmd>         Command to call with the raw files. [default: atop -f -r {{path}}]


    <metric>...                   The metric to display. Defaults to display CPL.avg5


"""

from datetime import datetime, timedelta
from collections import OrderedDict
import iso8601
import re
import sys
import glob
import decimal
import humanfriendly
import pydash as py_
import subprocess


class AtopParser(object):

    _entry_regex = re.compile(r'^ATOP - (?P<HOST>\S+)\s*(?P<TIME>\d+/\d+/\d+\s+\d+:\d+:\d+)\s.*')
    _metric_regex = re.compile(r'^(?P<metric>(PRC|CPU|CPL|MEM|SWP|PAG|DSK|NET))\s(?P<details>.+)$')
    _field_regex = re.compile(r'\|\s+([^|\s]*)\s+([^|]+)\s+')

    _size_fields = [('MEM', 'buff'),
                    ('MEM', 'cache'),
                    ('MEM', 'free'),
                    ('MEM', 'slab'),
                    ('MEM', 'tot'),
                    ('SWP', 'free'),
                    ('SWP', 'tot'),
                    ('SWP', 'vmcom'),
                    ('SWP', 'vmlim'),
                    ('NET', 'si'),
                    ('NET', 'so')]

    _time_span_fields = [('DSK', 'avio'),
                         ('PRC', 'sys'),
                         ('PRC', 'user')]

    _percentage_fields = [('CPU', 'idle'),
                          ('CPU', 'irq'),
                          ('CPU', 'sys'),
                          ('CPU', 'user'),
                          ('CPU', 'wait'),
                          ('DSK', 'busy')]

    _float_fields = [('CPL', 'avg1'),
                     ('CPL', 'avg5'),
                     ('CPL', 'avg15')]

    _integer_fields = [('CPL', 'csw'),
                       ('CPL', 'intr'),
                       ('DSK', 'read'),
                       ('DSK', 'write'),
                       ('NET', 'pcki'),
                       ('NET', 'pcko'),
                       ('NET', 'si'),
                       ('NET', 'so'),
                       ('NET', 'deliv'),
                       ('NET', 'ipfrw'),
                       ('NET', 'ipi'),
                       ('NET', 'ipo'),
                       ('NET', 'tcpi'),
                       ('NET', 'tcpo'),
                       ('NET', 'udpi'),
                       ('NET', 'udpo'),
                       ('PAG', 'scan'),
                       ('PAG', 'stall'),
                       ('PAG', 'swin'),
                       ('PAG', 'swout'),
                       ('PRC', 'exit'),
                       ('PRC', 'proc'),
                       ('PRC', 'sys'),
                       ('PRC', 'user'),
                       ('PRC', 'zombie')]

    def __init__(self, min_date=None, max_date=None):
        self.min_date = min_date
        self.max_date = max_date
        self.current_time = None
        self.current_data = None
        self.result = OrderedDict()

    def _reset_current_entry(self):
        self.current_time = None
        self.current_data = None

    def _append_current_entry(self):
        if self.current_data is not None:
            self.result[self.current_time] = self.current_data
        self._reset_current_entry()

    def __enter__(self, ):
        self._reset_current_entry()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):

        if exc_type is None and exc_val is not None and exc_tb is not None:
            self._append_current_entry()

        return False

    @property
    def available_metrics_tuples(self):

        result = set()

        for entry in self.result.values():
            py_.map_values_deep(entry, lambda __, path: result.add(tuple(path)))

        return sorted(result)

    @property
    def available_metric_paths(self):

        return ['.'.join(p) for p in self.available_metrics_tuples]

    def _parse_field(self, field_metric, field_key, field_value):

        try:

            # sizes
            if (field_metric, field_key) in self._size_fields:
                return humanfriendly.parse_size(field_value)

            # time spans
            elif (field_metric, field_key) in self._time_span_fields:
                return sum(humanfriendly.parse_timespan(v)
                           if v else 0
                           for v in re.findall(r'([\d,\.]+\s*\D+)', field_value))

            # percentages
            elif (field_metric, field_key) in self._percentage_fields:
                return int(field_value.replace('%', '').strip())

            # floats
            elif (field_metric, field_key) in self._float_fields:
                return float(decimal.Decimal(field_value))

            # integers
            elif (field_metric, field_key) in self._integer_fields:
                return int(decimal.Decimal(field_value))

        except ValueError:
            pass

    def add_line(self, atop_line):

        match = self._entry_regex.match(atop_line)
        if match:
            # this is a new entry

            if self.current_data is not None:
                self._append_current_entry()

            entry_time = datetime.strptime(match.group('TIME'), '%Y/%m/%d %H:%M:%S')

            if self.min_date and entry_time < self.min_date:
                return False

            if self.max_date and entry_time > self.max_date:
                return False

            self.current_time = entry_time
            self.current_data = {}

            return True

        elif self.current_data is not None:
            # this is a new metric line

            match = self._metric_regex.match(atop_line)
            if match:

                line_metric = match.group('metric')
                line_details = match.group('details')
                metric_name = None
                row = {}

                for metric_key, metric_value in (m.groups() for m in self._field_regex.finditer(line_details)):

                    metric_key = metric_key.strip().replace('#', '') if metric_key.strip() else None
                    metric_value = metric_value.strip() if metric_value.strip() else None

                    if metric_key is None and metric_value is None:
                        continue

                    self.current_data[line_metric] = self.current_data.get(line_metric, {})

                    if line_metric in ('NET', 'DSK'):

                        if not metric_name:
                            if line_metric == 'NET':
                                metric_name = metric_key
                            elif line_metric == 'DSK' and metric_key is None:
                                metric_name = metric_value
                            self.current_data[line_metric][metric_name] = row
                        else:
                            parsed_value = self._parse_field(line_metric, metric_key, metric_value)
                            if parsed_value is not None:
                                row[metric_key] = parsed_value

                    else:
                        parsed_value = self._parse_field(line_metric, metric_key, metric_value)
                        if parsed_value is not None:
                            self.current_data[line_metric][metric_key] = parsed_value

                return True

        return False


class AtopReader(object):

    def __init__(self, path_schema, atop_binary="atop -f -r {path}"):
        self._atop_binary = atop_binary
        self._path_schema = path_schema

    def required_file_paths(self, begin, end):

        file_name_list = glob.glob(re.sub(r'%[aAwdbBmyYHIpMSfzZjUWcxX]', '*', self._path_schema).replace('**', '*'))
        available_times = sorted(datetime.strptime(file_name, self._path_schema) for file_name in file_name_list)

        for file_index, file_time in enumerate(available_times):
            if file_time < end:
                if len(available_times) > file_index + 1 and available_times[file_index + 1] > begin:
                    # the next item is within the time frame,
                    yield file_time.strftime(self._path_schema)
                elif len(available_times) == file_index + 1:
                    # there is no next item but this is the last item within the time frame
                    yield file_time.strftime(self._path_schema)

    def atop_log_files(self, begin, end):
        for file_path in self.required_file_paths(begin, end):
            yield subprocess.Popen(self._atop_binary.format(path=file_path), stdout=subprocess.PIPE, shell=True).stdout


def main():

    from docopt import docopt
    arguments = docopt(__doc__.format(cmd=__file__,
                                      now=datetime.now().replace(second=0, microsecond=0).isoformat()))

    time_range = int(arguments['--range'])
    metrics = arguments['<metric>'] or ['CPL.avg5']
    end = iso8601.parse_date(arguments['--end'], default_timezone=None)
    begin = end - timedelta(hours=time_range)
    reader = AtopReader(arguments['--path'], arguments['--cmd'])

    with AtopParser(begin, end) as parser:

        for log_file in reader.atop_log_files(begin, end):
            for line in log_file:
                    parser.add_line(line.decode())

    if not len(parser.result):
        sys.stderr.write('empty result\n')
        sys.exit(1)

    elif arguments['metrics']:

        for metric in parser.available_metric_paths:
            print(metric)

    elif arguments['table']:

        from tabulate import tabulate
        print(tabulate([[time] + [py_.get(value, metric) for metric in metrics]
                        for time, value in parser.result.items()],
                       ['time'] + metrics, tablefmt="plain"))

    elif arguments['json']:

        from json import dumps
        print(dumps({time.isoformat(): {metric: py_.get(value, metric) for metric in metrics}
                     for time, value in parser.result.items()}))

    elif arguments['csv']:

        import csv
        writer = csv.writer(sys.stdout)
        writer.writerow(['time'] + metrics)
        for time, value in parser.result.items():
            writer.writerow([time.isoformat()] + [py_.get(value, metric) for metric in metrics])

    elif arguments['gnuplot']:

        for metric in metrics:

            width = int(arguments['--width'])
            height = int(arguments['--height'])

            process = subprocess.Popen(["gnuplot"], stdin=subprocess.PIPE)

            process.stdin.write(b"set term dumb %d %d \n" % (width, height))
            process.stdin.write(b"unset border \n")
            process.stdin.write(b"unset ytics \n")
            process.stdin.write(b"unset xtics \n")
            process.stdin.write(b"set xtics nomirror \n")
            process.stdin.write(b"unset key \n")

            process.stdin.write(b"set xdata time \n")
            process.stdin.write(b"set format x '%H' \n")
            process.stdin.write(b"set timefmt '%Y-%m-%dT%H:%M:%S' \n")

            process.stdin.write(b"set datafile sep '\t' \n")
            process.stdin.write(b"plot '-' using 1:2 notitle with linespoints \n")

            for time, value in parser.result.items():
                process.stdin.write(b"%s\t%s\n" % (str(time.isoformat()).encode('utf-8'),
                                                   str(py_.get(value, metric)).encode('utf-8')))

            process.stdin.write(b"e\n")
            process.stdin.flush()
            process.stdin.close()
            process.wait()

    elif arguments['diagram']:

        import diagram

        width = int(arguments['--width'])
        height = int(arguments['--height'])

        class DiagramOptions(object):
            axis = True
            batch = False
            color = False
            encoding = 'utf-8'
            function = None  # None or any of diagram.FUNCTION.keys()
            legend = True
            palette = None  # None or any of diagram.PALETTE.keys()
            reverse = False

            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        for metric in metrics:
            engine = diagram.AxisGraph(diagram.Point((width, height)), DiagramOptions())
            engine.update([py_.get(value, metric) for value in parser.result.values()])
            if hasattr(sys.stdout, 'buffer'):
                engine.render(sys.stdout.buffer)
            else:
                engine.render(sys.stdout)


if __name__ == '__main__':
    main()

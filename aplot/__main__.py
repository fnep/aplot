#!/usr/bin/env python3
# coding: utf-8

""" Atop log data analyzer.

Usage:
  {cmd} metrics [-p <path>] [-e <time>] [-r <hours>]
  {cmd} (csv|json|table) [-p <path>] [-e <time>] [-r <hours>] [<metric>...]
  {cmd} (diagram|gnuplot) [-p <path>] [-e <time>] [-r <hours>] [-x <lines>] [-y <lines>] [<metric>...]

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


    <metric>...                   The metric to display. Defaults to display CPL.avg5


"""

from datetime import datetime, timedelta
from collections import OrderedDict
import iso8601
import re
import sys
import glob
import struct
import zlib
import pydash as py_


# Struct layout constants derived empirically from atop 1.26 binary files.
# All values little-endian. count_t fields are int64; cpunr is int32 (packed, no alignment pad).

_RECORD_SIZE = 76
_RECORD_FMT = '<IHHHHiiiiiii'  # curtime flags sf0 sf1 sf2 scomplen pcomplen interval nlist npresent _ nexit
_SSTAT_MEM_OFF = 7096          # offset of memstat within decompressed sstat
_SSTAT_INTF_OFF = 8176         # offset of IntfStat (nrintf + intf array)
_PERINTF_SIZE = 248
_SSTAT_DSK_OFF = 16116         # offset of DskStat (ndsk + dsk array)
_PERDSK_SIZE = 112
_MAXDSKNAM = 32


def _read_record(f):
    """Read one raw record header. Returns None on EOF."""
    raw = f.read(_RECORD_SIZE)
    if not raw or len(raw) < _RECORD_SIZE:
        return None
    vals = struct.unpack_from(_RECORD_FMT, raw)
    return {
        'curtime': vals[0],
        'scomplen': vals[5],
        'pcomplen': vals[6],
        'nlist': vals[8],
        'nexit': vals[11],
    }


def _parse_sstat(data, pagesize):
    """Extract system-level metrics from a decompressed sstat buffer."""
    result = {}

    # CPL: load averages and context switches
    nrcpu = struct.unpack_from('<q', data, 0)[0]
    devint = struct.unpack_from('<q', data, 8)[0]
    csw = struct.unpack_from('<q', data, 16)[0]
    lavg1 = struct.unpack_from('<f', data, 32)[0]
    lavg5 = struct.unpack_from('<f', data, 36)[0]
    lavg15 = struct.unpack_from('<f', data, 40)[0]
    result['CPL'] = {
        'avg1': round(float(lavg1), 2),
        'avg5': round(float(lavg5), 2),
        'avg15': round(float(lavg15), 2),
        'csw': int(csw),
        'intr': int(devint),
    }

    # CPU: percentages from 'all' percpu struct (packed layout, starts at offset 76)
    # cpunr(int32)@76 + stime(int64)@80 + utime@88 + ntime@96 + itime@104 + wtime@112 + Itime@120 + ...
    all_off = 76
    all_stime = struct.unpack_from('<q', data, all_off + 4)[0]
    all_utime = struct.unpack_from('<q', data, all_off + 12)[0]
    all_ntime = struct.unpack_from('<q', data, all_off + 20)[0]
    all_itime = struct.unpack_from('<q', data, all_off + 28)[0]
    all_wtime = struct.unpack_from('<q', data, all_off + 36)[0]
    all_Itime = struct.unpack_from('<q', data, all_off + 44)[0]
    total = all_stime + all_utime + all_ntime + all_itime + all_wtime + all_Itime
    if total > 0:
        result['CPU'] = {
            'sys': int(100 * all_stime / total),
            'user': int(100 * (all_utime + all_ntime) / total),
            'idle': int(100 * all_itime / total),
            'wait': int(100 * all_wtime / total),
            'irq': int(100 * all_Itime / total),
        }

    # MEM and SWP
    M = _SSTAT_MEM_OFF
    physmem = struct.unpack_from('<q', data, M)[0] * pagesize
    freemem = struct.unpack_from('<q', data, M + 8)[0] * pagesize
    buffermem = struct.unpack_from('<q', data, M + 16)[0] * pagesize
    slabmem = struct.unpack_from('<q', data, M + 24)[0] * pagesize
    cachemem = struct.unpack_from('<q', data, M + 32)[0] * pagesize
    totswap = struct.unpack_from('<q', data, M + 48)[0] * pagesize
    freeswap = struct.unpack_from('<q', data, M + 56)[0] * pagesize
    pgscans = struct.unpack_from('<q', data, M + 64)[0]
    allocstall = struct.unpack_from('<q', data, M + 72)[0]
    swouts = struct.unpack_from('<q', data, M + 80)[0]
    swins = struct.unpack_from('<q', data, M + 88)[0]
    commitlim = struct.unpack_from('<q', data, M + 96)[0] * pagesize
    committed = struct.unpack_from('<q', data, M + 104)[0] * pagesize
    result['MEM'] = {
        'tot': physmem,
        'free': freemem,
        'buff': buffermem,
        'cache': cachemem,
        'slab': slabmem,
    }
    result['SWP'] = {
        'tot': totswap,
        'free': freeswap,
        'vmcom': committed,
        'vmlim': commitlim,
    }
    result['PAG'] = {
        'scan': int(pgscans),
        'stall': int(allocstall),
        'swout': int(swouts),
        'swin': int(swins),
    }

    # NET interfaces
    nrintf = struct.unpack_from('<i', data, _SSTAT_INTF_OFF)[0]
    net = {}
    for i in range(nrintf):
        base = _SSTAT_INTF_OFF + 4 + i * _PERINTF_SIZE
        name = data[base:base + 16].rstrip(b'\x00').decode(errors='ignore')
        if not name:
            continue
        rbyte = struct.unpack_from('<q', data, base + 16)[0]
        rpack = struct.unpack_from('<q', data, base + 24)[0]
        sbyte = struct.unpack_from('<q', data, base + 112)[0]
        spack = struct.unpack_from('<q', data, base + 120)[0]
        net[name] = {
            'pcki': int(rpack),
            'pcko': int(spack),
            'si': int(rbyte),
            'so': int(sbyte),
        }
    if net:
        result['NET'] = net

    # DSK
    ndsk = struct.unpack_from('<i', data, _SSTAT_DSK_OFF)[0]
    dsk = {}
    for i in range(ndsk):
        base = _SSTAT_DSK_OFF + 16 + i * _PERDSK_SIZE
        name = data[base:base + _MAXDSKNAM].rstrip(b'\x00').decode(errors='ignore')
        if not name:
            continue
        nread = struct.unpack_from('<q', data, base + _MAXDSKNAM)[0]
        nwrite = struct.unpack_from('<q', data, base + _MAXDSKNAM + 8)[0]
        io_ms = struct.unpack_from('<q', data, base + _MAXDSKNAM + 16)[0]
        dsk[name] = {
            'read': int(nread),
            'write': int(nwrite),
            'avio': io_ms / 1000.0 if io_ms else 0.0,
        }
    if dsk:
        result['DSK'] = dsk

    return result


class AtopBinaryReader(object):

    def __init__(self, path_schema):
        self._path_schema = path_schema
        # When no strptime placeholders are present, the path is a literal file/glob,
        # so the time-range filter should not be applied.
        self._filter_by_time = '%' in path_schema

    def required_file_paths(self, begin, end):
        if not self._filter_by_time:
            for path in sorted(glob.glob(self._path_schema) or [self._path_schema]):
                yield path
            return

        file_name_list = glob.glob(re.sub(r'%[aAwdbBmyYHIpMSfzZjUWcxX]', '*', self._path_schema).replace('**', '*'))
        available_times = sorted(datetime.strptime(fn, self._path_schema) for fn in file_name_list)

        for file_index, file_time in enumerate(available_times):
            if file_time < end:
                if len(available_times) > file_index + 1 and available_times[file_index + 1] > begin:
                    yield file_time.strftime(self._path_schema)
                elif len(available_times) == file_index + 1:
                    yield file_time.strftime(self._path_schema)

    def read(self, begin, end):
        """Yield (datetime, metrics_dict) for each sample in [begin, end]."""
        from atoparser.structs import atop_1_26
        import ctypes

        for path in self.required_file_paths(begin, end):
            try:
                f = open(path, 'rb')
            except OSError:
                continue

            with f:
                header = atop_1_26.Header()
                f.readinto(header)
                pagesize = header.pagesize

                first_record = True
                while True:
                    rec = _read_record(f)
                    if rec is None:
                        break

                    try:
                        sstat_raw = zlib.decompress(f.read(rec['scomplen']))
                        f.read(rec['pcomplen'])  # skip pstat (per-process data)
                    except zlib.error:
                        break

                    ts = datetime.fromtimestamp(rec['curtime'])

                    # Skip the first record in each file: it holds cumulative-since-boot
                    # counters rather than per-interval deltas.
                    if first_record:
                        first_record = False
                        continue

                    if self._filter_by_time and (ts < begin or ts > end):
                        continue

                    metrics = _parse_sstat(sstat_raw, pagesize)
                    metrics['PRC'] = {
                        'proc': rec['nlist'],
                        'exit': rec['nexit'],
                    }
                    yield ts, metrics


def main():

    from docopt import docopt
    arguments = docopt(__doc__.format(cmd=__file__,
                                      now=datetime.now().replace(second=0, microsecond=0).isoformat()))

    time_range = int(arguments['--range'])
    metrics = arguments['<metric>'] or ['CPL.avg5']
    end = iso8601.parse_date(arguments['--end'], default_timezone=None)
    begin = end - timedelta(hours=time_range)
    reader = AtopBinaryReader(arguments['--path'])

    result = OrderedDict()
    for ts, data in reader.read(begin, end):
        result[ts] = data

    if not len(result):
        sys.stderr.write('empty result\n')
        sys.exit(1)

    elif arguments['metrics']:

        metric_paths = set()
        for entry in result.values():
            py_.map_values_deep(entry, lambda __, path: metric_paths.add(tuple(path)))
        for path in sorted(metric_paths):
            print('.'.join(path))

    elif arguments['table']:

        from tabulate import tabulate
        print(tabulate([[time] + [py_.get(value, metric) for metric in metrics]
                        for time, value in result.items()],
                       ['time'] + metrics, tablefmt="plain"))

    elif arguments['json']:

        from json import dumps
        print(dumps({time.isoformat(): {metric: py_.get(value, metric) for metric in metrics}
                     for time, value in result.items()}))

    elif arguments['csv']:

        import csv
        writer = csv.writer(sys.stdout)
        writer.writerow(['time'] + metrics)
        for time, value in result.items():
            writer.writerow([time.isoformat()] + [py_.get(value, metric) for metric in metrics])

    elif arguments['gnuplot']:

        for metric in metrics:

            width = int(arguments['--width'])
            height = int(arguments['--height'])

            import subprocess as sp
            process = sp.Popen(["gnuplot"], stdin=sp.PIPE)

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

            for time, value in result.items():
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
            function = None
            legend = True
            palette = None
            reverse = False

            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)

        for metric in metrics:
            engine = diagram.AxisGraph(diagram.Point((width, height)), DiagramOptions())
            engine.update([py_.get(value, metric) for value in result.values()])
            if hasattr(sys.stdout, 'buffer'):
                engine.render(sys.stdout.buffer)
            else:
                engine.render(sys.stdout)


if __name__ == '__main__':
    main()

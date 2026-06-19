#!/usr/bin/env python3
# coding: utf-8

from datetime import datetime, timedelta
from collections import OrderedDict
import argparse
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


# Offsets within a 604-byte pstat record (verified empirically).
# GEN sub-struct starts at 0, CPU at 256, MEM at 416.
_PSTAT_SIZE = 604
_PSTAT_PID_OFF = 0        # int32
_PSTAT_RUID_OFF = 8       # int32
_PSTAT_NAME_OFF = 44      # char[15] (PNAMLEN)
_PSTAT_STATE_OFF = 60     # char
_PSTAT_CPU_UTIME_OFF = 244   # count_t (int64, ticks); GEN is 244 bytes (not 256)
_PSTAT_CPU_STIME_OFF = 252   # count_t
_PSTAT_MEM_VMEM_OFF = 428    # count_t (pages): MEM@404 + vmem@24
_PSTAT_MEM_RMEM_OFF = 436    # count_t (pages): MEM@404 + rmem@32


def _parse_pstat(data, nprocs, pagesize, hertz, uid_filter=None):
    """Parse per-process records and aggregate by uid.

    Returns a dict keyed by uid, each value a dict with aggregated metrics.
    If uid_filter is set, only that uid is included.
    """
    by_uid = {}
    for i in range(nprocs):
        base = i * _PSTAT_SIZE
        ruid = struct.unpack_from('<i', data, base + _PSTAT_RUID_OFF)[0]
        if uid_filter is not None and ruid != uid_filter:
            continue
        name = data[base + _PSTAT_NAME_OFF:base + _PSTAT_NAME_OFF + 15].rstrip(b'\x00').decode(errors='ignore')
        utime = struct.unpack_from('<q', data, base + _PSTAT_CPU_UTIME_OFF)[0]
        stime = struct.unpack_from('<q', data, base + _PSTAT_CPU_STIME_OFF)[0]
        vmem = struct.unpack_from('<q', data, base + _PSTAT_MEM_VMEM_OFF)[0] * pagesize
        rmem = struct.unpack_from('<q', data, base + _PSTAT_MEM_RMEM_OFF)[0] * pagesize

        entry = by_uid.setdefault(ruid, {'procs': 0, 'utime': 0, 'stime': 0, 'vmem': 0, 'rmem': 0})
        entry['procs'] += 1
        entry['utime'] += utime
        entry['stime'] += stime
        entry['vmem'] += vmem
        entry['rmem'] += rmem
    return by_uid


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

    def _iter_records(self, begin, end):
        """Low-level iterator yielding (ts, rec, sstat_raw, pstat_raw) for each sample."""
        from atoparser.structs import atop_1_26

        for path in self.required_file_paths(begin, end):
            try:
                f = open(path, 'rb')
            except OSError:
                continue

            with f:
                header = atop_1_26.Header()
                f.readinto(header)
                pagesize = header.pagesize
                hertz = header.hertz

                first_record = True
                while True:
                    rec = _read_record(f)
                    if rec is None:
                        break

                    try:
                        sstat_raw = zlib.decompress(f.read(rec['scomplen']))
                        pstat_raw = zlib.decompress(f.read(rec['pcomplen']))
                    except zlib.error:
                        break

                    # Skip the first record: it holds cumulative-since-boot counters.
                    if first_record:
                        first_record = False
                        continue

                    ts = datetime.fromtimestamp(rec['curtime'])
                    if self._filter_by_time and (ts < begin or ts > end):
                        continue

                    yield ts, rec, sstat_raw, pstat_raw, pagesize, hertz

    def read(self, begin, end):
        """Yield (datetime, metrics_dict) for each sample in [begin, end]."""
        for ts, rec, sstat_raw, pstat_raw, pagesize, hertz in self._iter_records(begin, end):
            metrics = _parse_sstat(sstat_raw, pagesize)
            metrics['PRC'] = {
                'proc': rec['nlist'],
                'exit': rec['nexit'],
            }
            yield ts, metrics

    def read_uids(self, begin, end):
        """Return a set of all UIDs seen across all samples in [begin, end]."""
        uids = set()
        for ts, rec, sstat_raw, pstat_raw, pagesize, hertz in self._iter_records(begin, end):
            by_uid = _parse_pstat(pstat_raw, rec['nlist'], pagesize, hertz)
            uids.update(by_uid)
        return uids

    def read_user(self, begin, end, uid):
        """Yield (datetime, user_metrics_dict) aggregated for a single uid."""
        for ts, rec, sstat_raw, pstat_raw, pagesize, hertz in self._iter_records(begin, end):
            by_uid = _parse_pstat(pstat_raw, rec['nlist'], pagesize, hertz, uid_filter=uid)
            yield ts, by_uid.get(uid, {'procs': 0, 'utime': 0, 'stime': 0, 'vmem': 0, 'rmem': 0})


def main():

    now = datetime.now().replace(second=0, microsecond=0).isoformat()

    global_opts = argparse.ArgumentParser(add_help=False)
    global_opts.add_argument('-p', '--path', default='/var/log/atop/atop_%Y%m%d',
                             help='Path to atop raw logs with date placeholders. (default: %(default)s)')
    global_opts.add_argument('-e', '--end', default=now,
                             help='Latest value to plot in ISO8601 format. (default: now)')
    global_opts.add_argument('-r', '--range', type=int, default=6, dest='range',
                             help='Hours backwards from --end to plot. (default: %(default)s)')

    parser = argparse.ArgumentParser(description='Atop log data analyzer.', parents=[global_opts])
    subparsers = parser.add_subparsers(dest='command')
    subparsers.required = True

    subparsers.add_parser('metrics', help="Print a list of all possible metric paths.",
                          parents=[global_opts])
    subparsers.add_parser('users', help="Print all user IDs (and names) seen in the data.",
                          parents=[global_opts])

    for cmd, help_text in [
        ('csv',  'Print results as CSV.'),
        ('json', 'Print results as JSON.'),
        ('table', 'Print results as an ASCII table.'),
    ]:
        sub = subparsers.add_parser(cmd, help=help_text, parents=[global_opts])
        sub.add_argument('metric', nargs='*', default=['CPL.avg5'],
                         help='Metrics to display. (default: CPL.avg5)')
        sub.add_argument('-u', '--user', metavar='USER',
                         help='Show per-interval aggregated stats for a user (name or UID).')

    for cmd, help_text in [
        ('diagram', 'Print results as a braille character diagram.'),
        ('gnuplot', 'Print results using gnuplot.'),
    ]:
        sub = subparsers.add_parser(cmd, help=help_text, parents=[global_opts])
        sub.add_argument('metric', nargs='*', default=['CPL.avg5'],
                         help='Metrics to display. (default: CPL.avg5)')
        sub.add_argument('-u', '--user', metavar='USER',
                         help='Show per-interval aggregated stats for a user (name or UID).')
        sub.add_argument('-x', '--width', type=int, default=59,
                         help='Graph width in columns. (default: %(default)s)')
        sub.add_argument('-y', '--height', type=int, default=9,
                         help='Graph height in lines. (default: %(default)s)')

    args = parser.parse_args()

    end = datetime.fromisoformat(args.end)
    begin = end - timedelta(hours=args.range)
    reader = AtopBinaryReader(args.path)
    metrics = getattr(args, 'metric', [])

    if args.command == 'users':
        import pwd
        uids = reader.read_uids(begin, end)
        if not uids:
            sys.stderr.write('empty result\n')
            sys.exit(1)
        for uid in sorted(uids):
            try:
                name = pwd.getpwuid(uid).pw_name
            except KeyError:
                name = ''
            print(f'{uid}\t{name}' if name else str(uid))
        return

    user_arg = getattr(args, 'user', None)
    if user_arg is not None:
        try:
            uid = int(user_arg)
        except ValueError:
            import pwd
            try:
                uid = pwd.getpwnam(user_arg).pw_uid
            except KeyError:
                sys.stderr.write(f'unknown user: {user_arg}\n')
                sys.exit(1)
        user_fields = ['procs', 'utime', 'stime', 'vmem', 'rmem']
        user_metrics = args.metric if args.metric != ['CPL.avg5'] else user_fields
        rows = list(reader.read_user(begin, end, uid))
        if not rows:
            sys.stderr.write('empty result\n')
            sys.exit(1)
        headers = ['time'] + user_metrics

        if args.command == 'table':
            from tabulate import tabulate
            print(tabulate([[ts] + [data[m] for m in user_metrics] for ts, data in rows],
                           headers=headers, tablefmt='plain'))
        elif args.command == 'json':
            from json import dumps
            print(dumps({ts.isoformat(): {m: data[m] for m in user_metrics} for ts, data in rows}))
        elif args.command == 'csv':
            import csv
            writer = csv.writer(sys.stdout)
            writer.writerow(headers)
            for ts, data in rows:
                writer.writerow([ts.isoformat()] + [data[m] for m in user_metrics])
        elif args.command in ('diagram', 'gnuplot'):
            result = OrderedDict((ts, data) for ts, data in rows)
            metrics = user_metrics
            get_value = lambda value, metric: value[metric]
        if args.command not in ('diagram', 'gnuplot'):
            return

    if user_arg is None:
        result = OrderedDict()
        for ts, data in reader.read(begin, end):
            result[ts] = data
        get_value = py_.get

    if not result:
        sys.stderr.write('empty result\n')
        sys.exit(1)

    if args.command == 'metrics':

        metric_paths = set()
        for entry in result.values():
            py_.map_values_deep(entry, lambda __, path: metric_paths.add(tuple(path)))
        for path in sorted(metric_paths):
            print('.'.join(path))

    elif args.command == 'table':

        from tabulate import tabulate
        print(tabulate([[time] + [py_.get(value, metric) for metric in metrics]
                        for time, value in result.items()],
                       ['time'] + metrics, tablefmt="plain"))

    elif args.command == 'json':

        from json import dumps
        print(dumps({time.isoformat(): {metric: py_.get(value, metric) for metric in metrics}
                     for time, value in result.items()}))

    elif args.command == 'csv':

        import csv
        writer = csv.writer(sys.stdout)
        writer.writerow(['time'] + metrics)
        for time, value in result.items():
            writer.writerow([time.isoformat()] + [py_.get(value, metric) for metric in metrics])

    elif args.command == 'gnuplot':

        for metric in metrics:

            import subprocess as sp
            process = sp.Popen(["gnuplot"], stdin=sp.PIPE)

            process.stdin.write(b"set term dumb %d %d \n" % (args.width, args.height))
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
                                                    str(get_value(value, metric)).encode('utf-8')))

            process.stdin.write(b"e\n")
            process.stdin.flush()
            process.stdin.close()
            process.wait()

    elif args.command == 'diagram':

        import diagram

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
            engine = diagram.AxisGraph(diagram.Point((args.width, args.height)), DiagramOptions())
            engine.update([get_value(value, metric) for value in result.values()])
            if hasattr(sys.stdout, 'buffer'):
                engine.render(sys.stdout.buffer)
            else:
                engine.render(sys.stdout)


if __name__ == '__main__':
    main()

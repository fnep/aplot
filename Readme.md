Read and show single metrics from [atop](http://www.atoptool.nl/) raw logs. This is for example nice to show average CPU load in a nice text mode diagram using unicode braille characters (what is the default) on login. 

The script supports python3.5+. It allows to dump the data as csv, json or ascii table and to plot simple graphs via [gnuplot subprocess](http://www.gnuplot.info/) or [diagram](https://github.com/tehmaze/diagram).
 
### Warning

* __No batteries included__ ... this is just the code i use. __It's not actively maintained__. It's just here in case it's useful for somebody.
* __Require same machine__ run this code in same machine when using atop write. sometimes atop can't decode the binary files _it seems different machine have different binary file, i was logging atop from raspberry pi(raspi-os) and process it with virtualbox(ubuntu 17)_
 
### Requirements

* This script extracts its data from a raw logfile that has been recorded by __atop__. If you install atop on a Ubuntu or RedHat / CentOS like linux distribution (`apt-get install atop` / `yum install atop`), it comes with a [cronjob](http://linux.die.net/man/1/crontab) which writes the required data to `/var/log/atop/atop_YYYYMMDD` (where YYYYMMDD reflects the date) every few minutes. Otherwise you may need to do this yourself using [`atop -w`](http://linux.die.net/man/1/atop).

### Installation

1. Checkout the repository and install via `pip3 install ./aplot` (where `./aplot` is a path to checkout).
2. (optional) Add your preferred call to your `~/.profile` to show it on login.

### Usage

    Usage:
    
      python3 -m aplot metrics [-c <cmd>] [-p <path>] [-e <time>] [-r <hours>]
      python3 -m aplot (csv|json|table) [-c <cmd>] [-p <path>] [-e <time>] [-r <hours>] [<metric>...]
      python3 -m aplot (diagram|gnuplot) [-c <cmd>] [-p <path>] [-e <time>] [-r <hours>] [-x <lines>] [-y <lines>] [<metric>...]
    
    Options:
    
        diagram                       Print the results as a braille character diagram (default).
        gnuplot                       Print the results using a gnuplot subprocess.
        table                         Print the results as ascii table.
        csv                           Print the results as csv table.
        json                          Print the results as json datagram.
    
        metrics                       Print a list of all possible metric_path's.
    
        -e <time>, --end=<time>       The latest value to plot in ISO8601 format. Defaults to now. [default: now]
        -r <hours>, --range=<hours>   Number of hours, backwards from --stop, top plot. [default: 6]
        -x <lines>, --width=<lines>   Width of plotted graphs in text lines. [default: 59]
        -y <lines>, --height=<lines>  Height of plotted graphs in text lines. [default: 9]
        -p <path>, --path=<path>      Path to atop raw logs with date placeholders. [default: /var/log/atop/atop_%Y%m%d]
        -c <cmd>, --cmd <cmd>         Command to call with the raw files. [default: atop -f -r {path}]
    
    
        <metric>...                   The metric to display. Defaults to display CPL.avg5    

#### Metrics

Which metrics are availbale depends on your atop installation, but in general you can assume something like:
* CPL.avg1, CPL.avg15, CPL.avg5, CPL.csw, CPL.intr, CPU.idle, CPU.irq, CPU.sys, CPU.user, CPU.wait
* DSK.sd_.avio, DSK.sd_.busy, DSK.sd_.read, DSK.sd_.write
* MEM.buff, MEM.cache, MEM.free, MEM.slab, MEM.tot
* NET.eth_.pcki, NET.eth_.pcko, NET.eth_.si, NET.eth_.so
* NET.network.deliv, NET.network.ipfrw, NET.network.ipi, NET.network.ipo
* NET.transport.tcpi, NET.transport.tcpo, NET.transport.udpi, NET.transport.udpo
* PAG.scan, PAG.stall, PAG.swin, PAG.swout, PRC.exit, PRC.proc, PRC.sys, PRC.user, PRC.zombie
* SWP.free, SWP.tot, SWP.vmcom, SWP.vmlim

### Examples

##### `$ ./aplot.py diagram` 
 
  ![example](example.png)


##### `$ ./aplot.py json CPL.avg5 SWP.free MEM.free --range 1 | json_pp`

```

{
   "2016-08-06T12:09:57" : {
      "CPL.avg5" : 0.14,
      "MEM.free" : 878077542,
      "SWP.free" : 15998753177
   },
   "2016-08-06T12:19:57" : {
      "CPL.avg5" : 0.11,
      "MEM.free" : 875560960,
      "SWP.free" : 15998753177
   },
   "2016-08-06T12:29:57" : {
      "CPL.avg5" : 0.1,
      "MEM.free" : 877867827,
      "SWP.free" : 15998753177
   },
   "2016-08-06T12:39:57" : {
      "CPL.avg5" : 0.12,
      "MEM.free" : 878811545,
      "SWP.free" : 15998753177
   },
   "2016-08-06T12:49:57" : {
      "CPL.avg5" : 0.05,
      "MEM.free" : 879126118,
      "SWP.free" : 15998753177
   }
}
```

### Related

* The tool `atopsar` also allows to get reports and statistics from atop raw logfiles.

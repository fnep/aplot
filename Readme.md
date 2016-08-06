Read and show single metrics from [atop](http://www.atoptool.nl/) raw logs. This is for example nice to show average CPU load in a nice text mode diagram using unicode braille characters (what is the default) on login. 

The script supports python2.7+ and python3.5+. It allows to dump the data as csv, json or ascii table and to plot simple graphs via [gnuplot subprocess](http://www.gnuplot.info/) or [diagram](https://github.com/tehmaze/diagram).
 
### Requirements

* This script extracts its data from a raw logfile that has been recorded by __atop__. If you install atop on a Ubuntu or RedHat / CentOS like linux distribution (`apt-get install atop` / `yum install atop`), it comes with a [cronjob](http://linux.die.net/man/1/crontab) which writes the required data to `/var/log/atop/atop_YYYYMMDD` (where YYYYMMDD reflects the date) every few minutes. Otherwise you may need to do this yourself using [`atop -w`](http://linux.die.net/man/1/atop).

### Installation

1. Copy the `aplot.py` to your preferred destination and give it execute permissions.
2. Install requirements: `pip3 install -r requirements.txt`
3. (optional) Add your preferred call to your `~/.profile` to show it on login.

### Usage

    Usage:
    
      ./aplot.py metrics [-c <cmd>] [-p <path>] [-e <time>] [-r <hours>]
      ./aplot.py (csv|json|table) [-c <cmd>] [-p <path>] [-e <time>] [-r <hours>] [<metric>...]
      ./aplot.py (diagram|gnuplot) [-c <cmd>] [-p <path>] [-e <time>] [-r <hours>] [-x <lines>] [-y <lines>] [<metric>...]
    
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

### Example

* `$ ./aplot.py diagram` 
 
  ![example](example.png)


### Related:

* The tool `atopsar` also allows to get reports and statistics from atop raw logfiles.

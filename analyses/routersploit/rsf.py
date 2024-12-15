#!/usr/bin/env python3

from __future__ import print_function
import logging.handlers
import sys
if sys.version_info.major < 3:
    print("RouterSploit supports only Python3. Rerun application in Python3 environment.")
    exit(0)

from routersploit.interpreter import RoutersploitInterpreter

log_handler = logging.handlers.RotatingFileHandler(filename="routersploit.log", maxBytes=500000)
log_formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s       %(message)s")
log_handler.setFormatter(log_formatter)
LOGGER = logging.getLogger()
LOGGER.setLevel(logging.DEBUG)
LOGGER.addHandler(log_handler)


def routersploit(target_ip = None, exploit = None, cmd = None):
    rsf = RoutersploitInterpreter()
    if not target_ip:
        rsf.start()
    elif exploit:
        rsf.run_command('use {}'.format(exploit))
        rsf.run_command('set target %s' % target_ip)
        rsf.run_command('run')
    else:
        rsf.run_command('use scanners/autopwn')
        rsf.run_command('set check_creds false')
        rsf.run_command('set threads 1')
        rsf.run_command('set target %s' % target_ip)
        rsf.run_command('run')

if __name__ == "__main__":
    try:
        if len(sys.argv) == 2:
            routersploit(sys.argv[1])
        elif len(sys.argv) == 3:
            routersploit(sys.argv[1], sys.argv[2])
        else:
            routersploit()
    except (KeyboardInterrupt, SystemExit):
        pass

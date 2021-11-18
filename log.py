import sys
import os
import inspect
from enum import IntEnum

class LogLevel(IntEnum):
    ERROR   = 0
    INFO    = 1
    VERBOSE = 5
    DEBUG   = 9

class Logger:
    def __init__(self, level=LogLevel.INFO, outfile=sys.stderr):
        self.LOG_LEVEL = level
        self.outfile = outfile
        if os.getenv('LOGLEVEL') in LogLevel._member_names_:
            self.LOG_LEVEL = LogLevel[os.getenv('LOGLEVEL')]

    def LOG(self, lvl, str):
        if lvl <= self.LOG_LEVEL:
            if lvl == LogLevel.INFO:
                print (str, file=sys.stdout)
            print (str, file=self.outfile)

    def ERROR(self, str):
        self.LOG(LogLevel.ERROR, str)

    def INFO(self, str):
        self.LOG(LogLevel.INFO, str)

    def VERBOSE(self, str):
        self.LOG(LogLevel.VERBOSE, str)

    def DEBUG(self, str):
        frame = inspect.stack()[1]
        debug_str = 'DEBUG: '
        if 'self' in frame.frame.f_locals.keys():
            debug_str += type(frame.frame.f_locals['self']).__name__
        debug_str += '::' + frame.function + ' ' + str
        self.LOG(LogLevel.DEBUG, debug_str)

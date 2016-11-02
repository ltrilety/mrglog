# -*- coding: utf8 -*-
# vim: colorcolumn=80:

""" Log API """

# Copyright 2016 Luboš Tříletý <ltrilety@redhat.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# takes name convention from logging and from previous code
# pylint: disable=C0103,C0302

import csv
import os
from datetime import datetime
import sys
import socket
import xml.sax
import xml.sax.saxutils
import logging
import copy
from collections import OrderedDict

LOG_LEVEL = 60
PASS_LEVEL = 61
FAIL_LEVEL = 62
WAIVE_LEVEL = 63
INFO = logging.INFO
CRITICAL = logging.CRITICAL
DEBUG = logging.DEBUG
ERROR = logging.ERROR
FATAL = logging.FATAL
WARNING = logging.WARNING
WARN = WARNING
NOTSET = logging.NOTSET

LINE_LENGTH = 87

logging.addLevelName(LOG_LEVEL, 'LOG')
logging.addLevelName(PASS_LEVEL, 'PASS')
logging.addLevelName(FAIL_LEVEL, 'FAIL')
logging.addLevelName(WAIVE_LEVEL, 'WAIVE')


def passed(self, message, *args, **kws):
    """ log pass """
    # Yes, logger takes its '*args' as 'args'.
    self._log(PASS_LEVEL, message, args, **kws)  # pylint: disable=W0212
logging.Logger.passed = passed


def failed(self, message, *args, **kws):
    """ log fail """
    self._log(FAIL_LEVEL, message, args, **kws)  # pylint: disable=W0212
logging.Logger.failed = failed


def waived(self, message, *args, **kws):
    """ log waive """
    self._log(WAIVE_LEVEL, message, args, **kws)  # pylint: disable=W0212
logging.Logger.waived = waived


TIME_FORMAT = "%H:%M:%S"
# use for example "%H:%M:%S:%f" to enable millisecond logging
if sys.version_info < (2, 5):
    TIME_FORMAT_MS = TIME_FORMAT
else:
    TIME_FORMAT_MS = TIME_FORMAT + ",%f"

STD_VARIABLE = ' [ %(levelname)-18s ] %(name)s::'
STD_FORMAT = '[%(asctime)s,%(msecs).03d]' + STD_VARIABLE + ' %(message)s'
XML_FORMAT = '%(message)s'
XML_FORMATTER = logging.Formatter(XML_FORMAT)

IS_LINUX = (os.sys.platform == 'linux' or os.sys.platform == 'linux2')

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

# The background is set with 40 plus the number of the color,
# and the foreground with 30

# These are the sequences need to get colored ouput
RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
BOLD_SEQ = "\033[1m"

COLORS = {
    'WARNING': YELLOW,
    'INFO': WHITE,
    'DEBUG': BLUE,
    'CRITICAL': RED,
    'ERROR': RED,
    'FAIL': RED,
    'PASS': GREEN,
    'LOG': WHITE,
    'WAIVE': CYAN,
}


class ColorFormatter(logging.Formatter):
    """ Class for formatting coloured logging output. """
    def __init__(self, *args, **kwargs):
        # can't do super(...) here because Formatter is an old school class
        logging.Formatter.__init__(self, *args, **kwargs)

    def format(self, record):
        """
        Color log output (PASS,FAIL,...)
        """
        color = COLOR_SEQ % (30 + COLORS[record.levelname])
        rec = copy.copy(record)
        rec.levelname = color + record.levelname + RESET_SEQ
        rec.name = BOLD_SEQ + record.name + RESET_SEQ
        message = logging.Formatter.format(self, rec)
        return message + RESET_SEQ

    @staticmethod
    def format_color(text, color):
        """
        Color given text.
        """
        color_seq = COLOR_SEQ % (30 + color)
        text = color_seq + text
        # text = BOLD_SEQ + text
        text = text + RESET_SEQ
        return text

    @staticmethod
    def format_bold(text):
        """
        Format given text to bold.
        """
        text = BOLD_SEQ + text
        text = text + RESET_SEQ
        return text

TXT_FORMATTER = logging.Formatter(STD_FORMAT, TIME_FORMAT)
STD_FORMATTER = ColorFormatter(STD_FORMAT, TIME_FORMAT)


class MRGLoggerException(Exception):
    """
    Exception for MRGLog module.
    """
    def __init__(self, value):
        Exception.__init__(self)
        self.value = value

    def __str__(self):
        return repr(self.value)


class XmlHandler(logging.FileHandler):
    """ Handler for xml file """
    def __init__(self, xml_file):
        """ init """
        logging.FileHandler.__init__(self, xml_file)

    def emit(self, record):
        """ emit message to xml """
        if sys.version_info < (2, 5):
            if extra:
                for key in extra.keys():
                    setattr(record, key, extra[key])

        # need to run self.formatter.format
        # otherwise record.message is not filled
        formatted_message = self.formatter.format(record)
        if hasattr(record, 'tag'):
            # there will be used tag
            attr_str = ''
            if hasattr(record, 'attrs'):
                for attr_name in record.attrs:
                    attr_str += ' %s=%s' % (
                        attr_name,
                        xml.sax.saxutils.quoteattr(record.attrs[attr_name]))
            if hasattr(record, 'starttag'):
                if record.starttag:
                    self.stream.write('<%s%s>\n' % (record.tag, attr_str))
                else:
                    self.stream.write('</%s>\n' % record.tag)
            else:
                self.stream.write('<%s%s>%s</%s>\n' % (
                    record.tag,
                    attr_str,
                    xml.sax.saxutils.escape(record.message),
                    record.tag))
        else:
            if record.levelname == 'PASS' or record.levelname == 'FAIL':
                # assert, or result of test
                self.stream.write('<test message=%s>%s</test>\n' % (
                    xml.sax.saxutils.quoteattr(record.message),
                    xml.sax.saxutils.escape(record.levelname)))
            else:
                # typical message
                self.stream.write(
                    '<message severity=%s timestamp=%s>%s</message>\n' % (
                        xml.sax.saxutils.quoteattr(record.levelname),
                        xml.sax.saxutils.quoteattr(datetime.strftime(
                            datetime.now(), TIME_FORMAT_MS)),
                        xml.sax.saxutils.escape(formatted_message),
                        )
                    )
        self.flush()


class MRGLogger(logging.Logger, object):
    """ Special MRG Logger """

    def get_handlers(self):
        """
        Get logger handlers.
        """
        if isinstance(self.parent, MRGLog):
            return self.parent.usm_handlers
        else:
            return self.handlers

    def set_handlers(self, handlers):
        """
        Set logger handlers.
        """
        if isinstance(self.parent, MRGLog):
            self.parent.usm_handlers = handlers
        else:
            self.handlers = handlers

    usm_handlers = property(get_handlers, set_handlers)

    def __txt_format_log(self, txt_format, lvl, msg, *args, **kwargs):
        """ use different format """
        if self.usm_handlers:
            # set format
            aux_std_formatter = logging.Formatter(txt_format, TIME_FORMAT)
            for handler in self.usm_handlers:
                if not isinstance(handler, XmlHandler):
                    handler.setFormatter(aux_std_formatter)
            logging.Logger.log(self, lvl, msg, *args, **kwargs)
            # put format back
            for handler in self.usm_handlers:
                if not isinstance(handler, XmlHandler) and \
                   not isinstance(handler, logging.FileHandler):
                    handler.setFormatter(STD_FORMATTER)

    def log(self, lvl, msg, *args, **kwargs):
        """ log message """
        if lvl == LOG_LEVEL:
            std_format = STD_FORMAT

            if sys.version_info < (2, 5):
                # remove extra if python version is less than 2.5
                global extra
                extra = kwargs.pop('extra', None)
            else:
                extra = kwargs.get('extra', None)

            if extra and 'tag' in extra:
                # print special format
                # if beginning or ending tag log only xml
                if extra['tag'] == 'log':
                    handlers = copy.copy(self.usm_handlers)
                    txtonly_handlers = []
                    for handler in handlers:
                        if not isinstance(handler, XmlHandler):
                            self.removeHandler(handler)
                            txtonly_handlers.append(handler)
                    if self.usm_handlers:
                        logging.Logger.log(self, lvl, msg, *args, **kwargs)
                    # if phase beginning log starttime to txt handlers
                    self.usm_handlers = copy.copy(handlers)
                    return
                else:
                    # if needed print tag as special string,
                    # otherwise print only formatted message
                    prints_subst = {
                        'test_id':    'Test run ID   :',
                        'package':    'Package       :',
                        'release':    'Distro:       :',
                        'starttime':  'Test started  :',
                        'arch':       'Architecture  :',
                        'hostname':   'Hostname      :',
                        'endtime':    'Test finished:',
                    }
                    if extra['tag'] in prints_subst:
                        std_format = STD_FORMAT.replace(
                            STD_VARIABLE, ' %s' % prints_subst[extra['tag']])
                    elif extra['tag'] == 'testid':
                        std_format = \
                            STD_FORMAT.replace(STD_VARIABLE, ' Test') + \
                            ' result    : %s' % extra['attrs']['result']
                    else:
                        std_format = STD_FORMAT.replace(STD_VARIABLE, "")
            else:
                # remove level from output
                std_format = STD_FORMAT.replace(STD_VARIABLE, "")
            handlers = copy.copy(self.usm_handlers)
            if 'noxml' in kwargs and kwargs['noxml']:
                del kwargs['noxml']
                # remove xml handler
                for handler in handlers:
                    if isinstance(handler, XmlHandler):
                        self.removeHandler(handler)
            # log to txt outputs with different format - std_format
            self.__txt_format_log(std_format, lvl, msg, *args, **kwargs)
            self.usm_handlers = copy.copy(handlers)
        else:
            logging.Logger.log(self, lvl, msg, *args, **kwargs)


class MRGLog(MRGLogger):
    """ Basic MRG Log class """
    # pylint: disable=R0904
    def __init__(self,
                 testid='',
                 logdir='',
                 debug=False,
                 handlers=None,
                 module=False,
                 output=None,
                 level=logging.INFO,
                 main_logger=None,
                 no_log=False,
                 verbose_lvl=0,
                 ):
        """ initialization
        Key Parameters:
        testid - name of the test or module
        logdir - log directory
        debug - stdout only log level threshold is set to logging.DEBUG
        handlers - list of handlers instances
        module - if it is called by module or by main test
        output - list of which handler should be initialized
               - by default only std is used
               - possible handlers: 'xml', 'std', 'txt'
               - only when handlers are not provided
                 and it is not module instance
               - not used if debug mode
               - e.g. ['xml', 'std', 'txt']A
        level - logging level to be set
        main_logger - top logger, logger where test statistics are counted
        no_log - enable/disable logging
        verbose_lvl - how much is logged by default all is logged
                    - 0: all is logged
                      1: only the most interesting information is logged
                      2: nothing more is logged than the message itself
        """
        # find if it is module or not - module is True or empty testid
        if not testid:
            self.__module = True
        else:
            self.__module = module

        self.__handlers_level = level
        # note: logging.DEBUG is 10
        # logger will not block anything - xml needs debug
        # level of logs will be filtered on handlers
        self.level = logging.DEBUG

        if not self.__module:
            super(MRGLog, self).__init__('main_test')
        else:
            super(MRGLog, self).__init__(testid)

        self.disabled = no_log

        self.__log_lvl = verbose_lvl

        self.__package = 'unknown'

        # logger for counting results
        if main_logger:
            # move down for now
            self.parent = main_logger

        # test results
        self.__test_results = {
            "fails": [],
            "pass": [],
            "waives": [],
            "errors": [],
            "inittime": None,
            }

        # tcms test results and ids
        self.__tcms_tests = OrderedDict()
        self.__act_test = {
            "id": None,
            "desc": '',
            "pass": [],
            "fail": [],
            "waive": [],
            "errors": [],
            "init_time": None,
            }

        if debug or output == ['std']:
            self.__initialize_handlers(
                None, debug=debug, handlers=handlers, output=output)
        else:
            self.__initialize_handlers(
                self.__get_log_dir(logdir, testid),
                debug=False, handlers=handlers, output=output)

        if not self.__module:
            self.__init_log()

    @property
    def log_lvl(self):
        return self.__log_lvl

    @property
    def tcms_tests(self):
        if isinstance(self.parent, MRGLog):
            return self.parent.__tcms_tests
        else:
            return self.__tcms_tests

    @property
    def test_results(self):
        if isinstance(self.parent, MRGLog):
            return self.parent.__test_results
        else:
            return self.__test_results

    @property
    def act_test(self):
        if isinstance(self.parent, MRGLog):
            return self.parent.__act_test
        else:
            return self.__act_test

    def __get_log_dir(self, logdir, testid):
        """ prepare logging directory if needed """
        if not self.__module:
            # try to guess the log directory, or build it
            if len(logdir) > 0:
                # logdir parameter specified, use it
                tmp_logdir = logdir
            else:
                tmp_logdir = os.path.join('logs')
            try:
                os.makedirs(tmp_logdir)
            finally:
                return tmp_logdir
        return None

    def __initialize_handlers(self, logdir, debug, handlers, output):
        """ create handlers instances """
        if handlers:
            # not empty
            self.usm_handlers = copy.copy(handlers)
        elif handlers == [] or self.__module or logdir is None:
            # empty handlers or module or (debug mode or std only)
            if debug:
                # print on std only
                self.__handlers_level = logging.DEBUG
                self.propagate = 0
                self.setStdHandler()
            # use parent handlers or use stdout only
            elif not isinstance(self.parent, MRGLog):
                self.setStdHandler()
        else:
            # initialize handlers
            try:
                if output is not None and 'xml' in output:
                    path = os.path.join(logdir, 'testlog.xml')
                    # try to open and clear the xml journal file
                    xml_file = open(path, 'w')
                    xml_file.close()
                    # add correct handler for log to xml
                    self.setXmlHandler(path)
                if output is not None and 'txt' in output:
                    path = os.path.join(logdir, 'testlog.txt')
                    # try to open and clear the text journal file
                    text_file = open(path, 'w')
                    text_file.close()
                    # add correct handler for log to txt
                    self.setTextHandler(path, self.handlers_level)
                if output is None or 'std' in output:
                    # add correct handler for printing to stdout
                    self.setStdHandler(self.handlers_level)
            except Exception as error:
                raise MRGLoggerException(
                    "Log:: Log init error: %s " % (str(error)))

    def __init_log(self):
        """ log header """
        if self.log_lvl < 1:
            self.log(LOG_LEVEL, str(self.name), extra={'tag': 'test_id'})
        if self.log_lvl < 2:
            self.log(LOG_LEVEL, str(self.__package), extra={'tag': 'package'})
            self.test_results["inittime"] = datetime.now()
            self.log(
                LOG_LEVEL, datetime.strftime(
                    self.test_results["inittime"], TIME_FORMAT_MS),
                extra={'tag': 'starttime'})
            self.log(
                LOG_LEVEL, str(socket.getfqdn()), extra={'tag': 'hostname'})
            if IS_LINUX:
                self.log(
                    LOG_LEVEL, str(os.uname()[-1]), extra={'tag': 'arch'})
                self.log(
                    LOG_LEVEL,
                    str(open("/etc/redhat-release", 'r').read().strip()),
                    extra={'tag': 'release'})
            else:
                self.log(LOG_LEVEL, '', extra={'tag': 'arch'})
                # no error
                self.log(
                    LOG_LEVEL, str(sys.getwindowsversion()),
                    extra={'tag': 'release'})  # pylint: disable=E1101
                # error

            self.log(LOG_LEVEL, '', extra={'tag': 'log', 'starttag': True})
            self.log(LOG_LEVEL, ':' * LINE_LENGTH, noxml=True)

    def close(self):
        """ close instance """
        if self.act_test["id"] != None:
            # close TCMS if running
            self.closeTCMS()
        if not self.__module:
            self.__end_log()

    def __end_log(self):
        """ log ending """
        if self.log_lvl < 1:
            self.log(LOG_LEVEL, ':' * LINE_LENGTH, noxml=True)
            endtime = datetime.now()
            self.log(LOG_LEVEL, '=' * LINE_LENGTH, noxml=True)
            self.log(LOG_LEVEL, '=' * LINE_LENGTH, noxml=True)
            # print all tcms test with results (PASS|FAIL)
            self.log(
                LOG_LEVEL, "Test-case[s] Summary: (%i found)",
                len(self.tcms_tests), noxml=True)
            self.log(LOG_LEVEL, '-' * LINE_LENGTH, noxml=True)
            _tcs_summary = {'PASS': 0, 'FAIL': 0, 'ERROR': 0}
            for testid in self.tcms_tests.keys():
                _tcs_summary[self.tcms_tests[testid]['result']] += 1
                self.log(
                    LOG_LEVEL,
                    ColorFormatter.format_color(
                        '%s %-40s:  #tests:%-4d  #fails:%-4d  desc.:"%s"',
                        COLORS[self.tcms_tests[testid]['result']]),
                    self.tcms_tests[testid]['result'],
                    str(testid),
                    len(self.tcms_tests[testid]['pass']) +
                    len(self.tcms_tests[testid]['fail']) +
                    len(self.tcms_tests[testid]['waived']),
                    len(self.tcms_tests[testid]['fail']),
                    self.tcms_tests[testid]['desc'],
                    noxml=True)
        if self.log_lvl < 2:
            self.log(LOG_LEVEL, '=' * LINE_LENGTH, noxml=True)
            self.log(LOG_LEVEL, 'List of known issues:', noxml=True)
            self.log(LOG_LEVEL, '-' * LINE_LENGTH, noxml=True)
            for issue in USMLog.known_issues:
                self.log(LOG_LEVEL, issue)
            self.log(LOG_LEVEL, '=' * LINE_LENGTH, noxml=True)
            self.log(LOG_LEVEL, '=' * LINE_LENGTH, noxml=True)

        if self.log_lvl < 1:
            if self.test_results["errors"] != 0:
                _result = "ERROR"
            elif self.test_results["fails"] != 0:
                _result = "FAIL"
            else:
                _result = "PASS"
            self.log(
                LOG_LEVEL,
                ColorFormatter.format_bold("Test-Cases Summary") +
                "   #TOTAL: %s #PASSED: %s #FAILED: %s #ERRORS: %s",
                ColorFormatter.format_bold("%-5s" % (len(self.tcms_tests))),
                ColorFormatter.format_color("%-5s" % (
                    _tcs_summary['PASS']), COLORS['PASS']),
                ColorFormatter.format_color("%-5s" % (
                    _tcs_summary['FAIL']), COLORS[_result]),
                ColorFormatter.format_color("%s" % (
                    _tcs_summary['ERROR']), COLORS[_result]),
                noxml=True)
            self.log(
                LOG_LEVEL,
                ColorFormatter.format_bold("Test Summary") +
                " : %s #TOTAl: %s #PASSED: %s #FAILED: %s"
                " #ERRORS: %s #WAIVES: %s",
                ColorFormatter.format_color("%-5s" % _result, COLORS[_result]),
                ColorFormatter.format_bold("%-5s" % (
                    len(self.test_results["fails"]) +
                    len(self.test_results["pass"]) +
                    len(self.test_results["waives"]))),
                ColorFormatter.format_color(
                    "%-5s" % (len(self.test_results["pass"])),
                    COLORS['PASS']),
                ColorFormatter.format_color(
                    "%-5s" % (len(self.test_results["fails"])),
                    COLORS[_result]),
                ColorFormatter.format_color(
                    "%-3s" % (len(self.test_results["errors"])),
                    COLORS[_result]),
                ColorFormatter.format_bold(
                    "%s" % (len(self.test_results["waives"]))),
                noxml=True)
            if IS_LINUX:
                try:
                    self.log(
                        LOG_LEVEL, 'Test name    : %s',
                        os.sep.join(os.getcwd().split(os.sep)[-4:]),
                        noxml=True)
                except Exception:
                    self.log(
                        LOG_LEVEL, 'Test name    : %s',
                        self.name, noxml=True)
            else:
                self.log(LOG_LEVEL, 'Test name    : %s', self.name, noxml=True)
            self.log(
                LOG_LEVEL, 'Duration     : %s',
                str(endtime - self.test_results["inittime"]), noxml=True)
            if IS_LINUX:
                self.log(
                    LOG_LEVEL,
                    'Test on      : %s %s',
                    open("/etc/redhat-release", 'r').read().strip(),
                    str(os.uname()[-1]),
                    noxml=True)
            else:
                self.log(
                    LOG_LEVEL,
                    'Test MRG pkgs : <no-repository> on Windows(%s)',
                    str(sys.getwindowsversion()),  # pylint: disable=E1101
                    noxml=True)
            self.log(LOG_LEVEL, '=' * LINE_LENGTH, noxml=True)
            self.log(LOG_LEVEL, '=' * LINE_LENGTH, noxml=True)
        if self.log_lvl < 1:
            self.log(
                LOG_LEVEL, datetime.strftime(endtime, TIME_FORMAT_MS),
                extra={'tag': 'endtime'})
            self.log(LOG_LEVEL, '', extra={'tag': 'log', 'starttag': False})
            self.__csv_result_file(
                len(self.tcms_tests),
                _tcs_summary['PASS'],
                _tcs_summary['FAIL'],
                _tcs_summary['ERROR'])

    def __csv_result_file(self, _total, _passed, _failed, _errors):
        """
        Create CSV result file for graph in jenkins
        """
        csv_result_file = os.path.join(
            self.__get_log_dir(logdir='', testid=''),
            'testresult.csv')
        with open(csv_result_file, 'w') as csvfile:
            csv_result_writer = csv.writer(csvfile)
            csv_result_writer.writerow(['Total', 'Passed', 'Failed', 'Errors'])
            csv_result_writer.writerow([_total, _passed, _failed, _errors])

    def setXmlHandler(self, xml_file):
        """ prepare xml file logging
        NOTE: this handler has always log level set to DEBUG
        """
        xmlh = XmlHandler(xml_file)
        xmlh.setFormatter(XML_FORMATTER)
        xmlh.setLevel(logging.DEBUG)
        self.addHandler(xmlh)

    def setStdHandler(self, level=logging.INFO):
        """ prepare logging to stdout """
        stdh = logging.StreamHandler(sys.stdout)
        stdh.setFormatter(STD_FORMATTER)
        stdh.setLevel(level)
        self.addHandler(stdh)

    def setTextHandler(self, text_file, level=logging.INFO):
        """ prepare logging to txt file """
        texth = logging.FileHandler(text_file)
        texth.setFormatter(TXT_FORMATTER)
        texth.setLevel(level)
        self.addHandler(texth)

    def getLevel(self):
        """ getter for level """
        return self.__handlers_level

    def setLevel(self, level):
        """ set level
        just for std and text file
        """
        self.__handlers_level = level
        for handler in self.usm_handlers:
            if not isinstance(handler, XmlHandler):
                handler.setLevel(level)

    handlers_level = property(getLevel, setLevel)

    def rlLog(self, message, priority=LOG_LEVEL):
        """ log a message """
        if isinstance(priority, str):
            # no error
            if not priority.strip():  # pylint: disable=E1103
                # error
                severities = {"DEBUG": logging.DEBUG,
                              "INFO": logging.INFO,
                              "WARNING": logging.WARNING,
                              "ERROR": logging.ERROR,
                              "FATAL": logging.CRITICAL,
                              "LOG": LOG_LEVEL}
                level = severities[priority]
        # error
        elif isinstance(priority, int) and priority < 10:
            if priority == 0:
                level = logging.DEBUG
            elif priority == 1:
                level = logging.INFO
            elif priority == 2:
                level = logging.WARNING
            elif priority == 3:
                level = logging.ERROR
            elif priority == 4:
                level = logging.CRITICAL
        elif not priority:
            level = LOG_LEVEL
        else:
            level = priority
        self.log(level, message)

    def rlLogLevel(self, message, level=logging.DEBUG):
        """ log variable level default debug """
        self.rlLog(message, level)

    def rlAddMessage(self, message, severity="LOG"):
        """ log any message default log """
        self.rlLog(message, severity)

    def __increase_counters(self, result=True, message=''):
        """ increase pass or fail counters for logger
        Parameters:
          result: if assert is passed, failed or waived
          message: message to be logged
        """
        if isinstance(self.parent, MRGLog):
            self.parent.__increase_counters(result, message)
            return
        if result == 0:
            self.test_results["pass"].append(message)
            if self.act_test["id"] != None:
                self.act_test["pass"].append(message)
        elif result == 1:
            self.test_results["fails"].append(message)
            if self.act_test["id"] != None:
                self.act_test["fail"].append(message)
        elif result == 3:
            self.test_results["waives"].append(message)
            if self.act_test["id"] != None:
                self.act_test["waive"].append(message)
        elif result == 4:
            self.test_results["errors"].append(message)
            if self.act_test["id"] != None:
                self.act_test["errors"].append(message)

    def passed(self, message, *args, **kwargs):
        """ log pass """
        self.__increase_counters(0, message)
        MRGLogger.passed(self, message, *args, **kwargs)

    def failed(self, message, *args, **kwargs):
        """ log fail """
        self.__increase_counters(1, message)
        MRGLogger.failed(self, message, *args, **kwargs)

    def waived(self, message, *args, **kwargs):
        """ log waive
        there could be special parameter issue with the name of the issue
        """
        self.__increase_counters(3, message)
        if 'issue' in kwargs and kwargs['issue']:
            self.add_issue(kwargs['issue'])
            del(kwargs['issue'])
        MRGLogger.waived(self, message, *args, **kwargs)

    def error(self, message, *args, **kwargs):
        """ log error"""
        self.__increase_counters(4, message)
        MRGLogger.error(self, message, *args, **kwargs)

    def critical(self, message, *args, **kwargs):
        """ log critical"""
        # count "criticals" as errors
        self.__increase_counters(4, message)
        MRGLogger.critical(self, message, *args, **kwargs)
    fatal = critical

    def getTestState(self):
        """ getTestState """
        self.debug(
            'rlGetTestState: %s failed and %s waived assert(s) in test',
            str(self.test_results["fails"]),
            str(self.test_results["waives"]))
        return self.test_results["fails"]

    def addTCMS(self, testid, stat=True, desc=''):
        """ start to count results for the test
        NOTE: Only one can be opened in time
              The test could be part of phase -- testid in phase
        Key Parameters:
        stat - if additional information should be printed
              - by default it is printed (not to xml)
        desc - description of test
        """
        if self.act_test["id"] != None:
            # already running TCMS
            self.closeTCMS()
        if stat:
            if self.log_lvl < 2:
                self.log(LOG_LEVEL, ':' * LINE_LENGTH, noxml=True)
                self.log(LOG_LEVEL, 'Test %s started', str(testid), noxml=True)
        self.act_test["id"] = testid
        self.act_test["desc"] = ''
        if desc:
            self.act_test["desc"] = desc
        self.act_test["fail"] = []
        self.act_test["waive"] = []
        self.act_test["pass"] = []
        self.act_test["errors"] = []
        self.act_test["init_time"] = datetime.now()
    testStart = addTCMS

    def closeTCMS(self, stat=True):
        """ close test
        print PASS, FAIL or ERROR if required
        Key Parameters:
        stat - if additional information should be printed
              - by default it is printed (not to xml)
        """
        if self.act_test["id"] != None:
            if stat:
                if self.log_lvl < 1:
                    self.log(
                        LOG_LEVEL, 'Test %s duration  : %ds',
                        str(self.act_test["id"]),
                        (datetime.now() - self.act_test["init_time"]).seconds,
                        noxml=True)
                    self.log(
                        LOG_LEVEL, 'Test %s assertions: %d good, %d bad',
                        str(self.act_test["id"]),
                        len(self.act_test["pass"]), len(self.act_test["fail"]),
                        noxml=True)

            if len(self.act_test["errors"]) != 0:
                self.addTestId(result='ERROR')
            elif len(self.act_test["fail"]) == 0:
                self.addTestId(result='PASS')
            else:
                self.addTestId(result='FAIL')

            self.tcms_tests[self.act_test["id"]]['pass'] = \
                self.act_test["pass"]
            self.tcms_tests[self.act_test["id"]]['fail'] = \
                self.act_test["fail"]
            self.tcms_tests[self.act_test["id"]]['errors'] = \
                self.act_test["errors"]
            self.tcms_tests[self.act_test["id"]]['desc'] = \
                self.act_test["desc"]

            if stat:
                if self.log_lvl < 1:
                    self.log(LOG_LEVEL, ':' * LINE_LENGTH, noxml=True)

            self.act_test["id"] = None
            self.act_test["desc"] = ''
            self.act_test["fail"] = []
            self.act_test["pass"] = []
            self.act_test["waived"] = []
            self.act_test["errors"] = []
            self.act_test["init_time"] = None
    testEnd = closeTCMS

    def addTestId(self, testid=None, result='FAIL'):
        """ add reult of the test, for tcms parsing """
        if testid is None:
            testid = self.act_test["id"]
        if testid in self.tcms_tests:
            if result == "ERROR":
                self.tcms_tests[testid]['result'] = result
            elif (result == "FAIL" and
                  self.tcms_tests[testid]['result'] != "ERROR"):
                self.tcms_tests[testid]['result'] = result
        else:
            self.tcms_tests[testid] = {
                'result': result, 'pass': [], 'fail': [],
                'waived': [], 'errors': [], 'desc': ''}
        if self.log_lvl < 1:
            self.log(
                LOG_LEVEL, testid,
                extra={
                    'tag': 'testid', 'attrs': {'result': str(result).upper()}})

    @property
    def fails(self):
        """ getter for number of fails """
        return len(self.test_results["fails"])

    @property
    def errors(self):
        """ getter for number of errors"""
        return len(self.test_results["errors"])

    def rlFailsNumber(self):
        """ return number of fails """
        return self.fails

    def add_issue(self, issue):
        """ adds known issue to issue list
        Params:
        * issue: issue string
        """
        self.debug("Add issue: '%s'", issue)
        USMLog.known_issues.add(issue)


class USMLog(object):
    """
    handlers container.
    If any class would use logging, it should use this handlers
    """
    __logger = None
    __module_loggers = {}
    known_issues = set()

    @classmethod
    def get_logger(cls,
                   name='',
                   logdir='',
                   debug=False,
                   handlers=None,
                   module=False,
                   output=None,
                   level=None,
                   verbose_lvl=0,
                   ):
        """ get logger """

        if not level:
            level = logging.DEBUG

        if USMLog.__logger:
            # there is already logger initialized,
            # it is module use logger handlers
            if handlers:
                raise USMLogException("Handlers already initialized,"
                                      " don't use others")
            if not name:
                name = cls.__name__
            if name not in USMLog.__module_loggers:
                USMLog.__module_loggers[name] = MRGLog(
                    testid=name,
                    logdir=logdir,
                    debug=debug,
                    handlers=handlers,
                    module=True,
                    output=output,
                    level=level,
                    main_logger=USMLog.__logger,
                    no_log=USMLog.__logger.disabled,
                    verbose_lvl=verbose_lvl,
                    )
            return USMLog.__module_loggers[name]
        else:
            if module:
                logger = MRGLog(
                    testid=name,
                    logdir=logdir,
                    debug=True,
                    handlers=handlers,
                    module=module,
                    output=output,
                    level=level,
                    verbose_lvl=verbose_lvl,
                    )
                logger.warning('for test there should be some main logger'
                               ' (not module)')
            else:
                logger = MRGLog(
                    testid=name,
                    logdir=logdir,
                    debug=debug,
                    handlers=handlers,
                    module=module,
                    output=output,
                    level=level,
                    verbose_lvl=verbose_lvl,
                    )
            USMLog.__logger = logger
            USMLog.__module_loggers = {}
            return logger

    @classmethod
    def get_module_logger(cls,
                          name='',
                          logdir='',
                          debug=False,
                          handlers=None,
                          output=None,
                          level=logging.INFO,
                          verbose_lvl=0,
                          ):
        """ get logger for module, for api not for the test itself """
        return cls.get_logger(
            name=name,
            logdir=logdir,
            module=True,
            debug=debug,
            handlers=handlers,
            output=output,
            level=level,
            verbose_lvl=verbose_lvl,
            )

    @staticmethod
    def set_logger(in_logger):
        """ set USMLog.__logger """
        USMLog.__logger = in_logger
        USMLog.__module_loggers = {}

    @staticmethod
    def logger():
        """ return USMLog.__logger """
        return USMLog.__logger

    @staticmethod
    def log_off():
        """ switch off logging
        WARNING: it creates simple USMLog.__logger
                 if the logger doesn't exist yet
        """
        if USMLog.__logger:
            USMLog.__logger.disabled = True
        else:
            main_logger = MRGLog('main logger', no_log=True)
            USMLog.set_logger(main_logger)
        for module_logger in USMLog.__module_loggers:
            USMLog.__module_loggers[module_logger].disabled = True

    @staticmethod
    def log_on():
        """ switch on logging """
        if USMLog.__logger:
            USMLog.__logger.disabled = False
        for module_logger in USMLog.__module_loggers:
            USMLog.__module_loggers[module_logger].disabled = False

get_logger = USMLog.get_logger


class USMLogException(Exception):
    """
    Exception for USMLog
    """
    pass

# pylint: enable=C0103

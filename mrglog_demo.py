#!/usr/bin/env python
import mrglog
import importlib


class A(object):
    def __init__(self, level=None):
        if level is None:
            self.logger = mrglog.get_logger(
                'A class logger', module=True)
        else:
            self.logger = mrglog.get_logger(
                'A class logger', module=True, verbose_lvl=level)


class B(object):
    def __init__(self, level=0):
        self.logger = mrglog.USMLog.get_module_logger(
            'B class logger', verbose_lvl=level)


def test_it(logger, a_logger, b_logger):
    print('logger - verbose level {}\nA class logger - verbose level {}\n'
          'B class logger - verbose level {}'.format(logger.log_lvl,
                                                     a_logger.log_lvl,
                                                     b_logger.log_lvl))

    logger.error('nope error')
    logger.waived('ignore it', issue='some well known issue')
    logger.failed('ups fail')
    logger.passed('good again')
    logger.debug('some debug message')

    a_logger.passed('good A1')
    b_logger.failed('bad B1')
    a_logger.info('some info message 1')
    b_logger.fatal('some fatal message 1')

    logger.testStart('test1')

    logger.error('nope another error')
    logger.waived('ignore it again')
    logger.failed('ups fail once more')
    logger.passed('and good again')
    logger.warning('some warning message')

    a_logger.passed('good A2')
    b_logger.failed('bad B2')
    b_logger.passed('good B2')
    b_logger.info('some info message 2')

    logger.testEnd()

    a_logger.testStart('test2')

    logger.waived('ignore 3')
    logger.failed('fail 3')
    logger.passed('good 3')

    a_logger.passed('good A3')
    a_logger.failed('bad A3')
    b_logger.passed('good B3')
    b_logger.debug('some debug message 3')

    a_logger.testEnd()

    b_logger.testStart('test3')

    logger.waived('ignore 4')
    logger.passed('good 4')
    logger.rlLog('some log message', mrglog.LOG_LEVEL)

    a_logger.passed('good A4')
    b_logger.passed('good B4')
    a_logger.warning('warning message 4')

    b_logger.testEnd()

    a_logger.close()
    b_logger.close()
    logger.close()


def reload_mrglog():
  try:
      importlib.reload(mrglog)
  except AttributeError:
      reload(mrglog)

print('----------------------------------------------------------------------')
print('----------------------------------------------------------------------')
print('-------------- verbose not set (prints everything) -------------------')
print('----------------------------------------------------------------------')
print('----------------------------------------------------------------------')

logger = mrglog.USMLog.get_logger('my logger 0')

a = A()
b = B()

test_it(logger, a.logger, b.logger)

print('----------------------------------------------------------------------')
print('----------------------------------------------------------------------')
print('-------- verbose set to 1 (prints only something interesting) --------')
print('----------------------------------------------------------------------')
print('----------------------------------------------------------------------')

reload_mrglog()

logger = mrglog.USMLog.get_logger('my logger 1', verbose_lvl=1)

a = A(1)
b = B(1)

test_it(logger, a.logger, b.logger)

print('----------------------------------------------------------------------')
print('----------------------------------------------------------------------')
print('------------- verbose set to 2 (prints only log messages) ------------')
print('----------------------------------------------------------------------')
print('----------------------------------------------------------------------')

reload_mrglog()

logger = mrglog.USMLog.get_logger('my logger 2', verbose_lvl=2)

a = A(2)
b = B(2)

test_it(logger, a.logger, b.logger)

print('----------------------------------------------------------------------')
print('----------------------------------------------------------------------')
print('--------------------- verbose levels combination ---------------------')
print('----------------------------------------------------------------------')
print('----------------------------------------------------------------------')

reload_mrglog()

logger = mrglog.USMLog.get_logger('my logger 3', verbose_lvl=2)

a = A()
b = B(1)

test_it(logger, a.logger, b.logger)


print('----------------------------------------------------------------------')
print('----------------------------------------------------------------------')
print('--------- xml and txt output test (look for logs directory) ----------')
print('----------------------------------------------------------------------')
print('----------------------------------------------------------------------')

reload_mrglog()

logger = mrglog.USMLog.get_logger('my logger 3', output=['xml', 'txt'])

a = A()
b = B()

test_it(logger, a.logger, b.logger)

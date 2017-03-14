# -*- coding: utf8 -*-
"""
This file contains only very simple unit tests so far.

TODO: create more usefull tests when some mrglog feature is updated.
"""


# import pytest

import mrglog


def test_error_message(capfd):
    msg_text = 'some content'
    # create logger module, we can't move this into fixture because
    # of capfd module
    logger = mrglog.get_logger('test_error_message')
    # log single message
    logger.error(msg_text)
    # get snapshot of the stdout and stderr
    out, err = capfd.readouterr()
    # check expected format: "[12:59:09,804] [ ERROR   ] main_test:: msg_text"
    assert msg_text in out
    assert "ERROR" in out

# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import patch, MagicMock
from datetime import date
import pytest

from wazuh.core.exception import WazuhException


with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        sys.modules['api'] = MagicMock()
        import wazuh.rbac.decorators
        del sys.modules['wazuh.rbac.orm']
        del sys.modules['api']

        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh.stats import *

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'stats')


@pytest.mark.parametrize('date_, data_list', [
    (date(2019, 8, 13), ['15-571-3-2', '15--107--1483--1257--0']),
    (date(2019, 8, 13), ['15-571-3-2']),
    (date(2019, 8, 13), ['15--107--1483--1257--0']),
    (date(2019, 8, 13), ['15'])
])
@patch('wazuh.stats.common.stats_path', new=test_data_path)
def test_totals(date_, data_list):
    """Verify totals() function works returns and correct data

    Checks data type of returned data. Then makes sure that data returned fit
    with the expected.

    Parameters
    ----------
    date_ : str
        Date used to locate file stats.
    data_list : list
        Data to use instead of the original files.
    """
    with patch('wazuh.stats.open', return_value=data_list):
        response = totals(date_)

        assert isinstance(response, WazuhResult), f'The result is not WazuhResult type'

        dict_res = response.to_dict()
        if dict_res['result']['data']:
            for line in data_list:
                data = line.split('-')
                if len(data) == 4:
                    assert int(data[1]) == dict_res['result']['data'][0]['alerts'][0]['sigid'], f'Data do not match'
                    assert int(data[2]) == dict_res['result']['data'][0]['alerts'][0]['level'], f'Data do not match'
                    assert int(data[3]) == dict_res['result']['data'][0]['alerts'][0]['times'], f'Data do not match'
                else:
                    data = line.split('--')
                    if len(data) == 5:
                        assert int(data[0]) == dict_res['result']['data'][0]['hour'], f'Data do not match'
                        assert int(data[1]) == dict_res['result']['data'][0]['totalAlerts'], f'Data do not match'
                        assert int(data[2]) == dict_res['result']['data'][0]['events'], f'Data do not match'
                        assert int(data[3]) == dict_res['result']['data'][0]['syscheck'], f'Data do not match'
                        assert int(data[4]) == dict_res['result']['data'][0]['firewall'], f'Data do not match'


def test_totals_ko_data():
    """Tests totals function exception with data problems works"""
    with patch('wazuh.stats.open', side_effect=IOError):
        with pytest.raises(WazuhException, match=".* 1308 .*"):
            totals(date(1996, 8, 13))

    with patch('wazuh.stats.open', return_value=['15-571-3-2', '15--107--1483']):
        with pytest.raises(WazuhException, match=".* 1309 .*"):
            totals(date(1996, 8, 13))


@pytest.mark.parametrize('effect', [
    None,
    IOError,
])
def test_hourly(effect):
    """Tests hourly() function works and returns correct data

    Parameters
    ----------
    effect : exception
        Exception expected when opening stats file
    """
    with patch('wazuh.stats.open', side_effect=effect):
        response = hourly()
        assert isinstance(response, WazuhResult), f'The result is not WazuhResult type'


@patch('wazuh.common.stats_path', new=test_data_path)
def test_hourly_data():
    """Makes sure that data returned by hourly() fit with the expected."""
    response = hourly()

    assert 24 == response.to_dict()['result']['interactions'], f'Data do not match'
    for hour in range(24):
        assert hour in response.to_dict()['result']['averages'], f'Data do not match'


@pytest.mark.parametrize('effect', [
    None,
    IOError
])
def test_weekly(effect):
    """Tests weekly() function works and returns correct data

    Parameters
    ----------
    effect : exception
        Exception expected when opening stats file
    """
    with patch('wazuh.stats.open', side_effect=effect):
        response = weekly()
        assert isinstance(response, WazuhResult), f'The result is not WazuhResult type'


@patch('wazuh.common.stats_path', new=test_data_path)
def test_weekly_data():
    """Makes sure that data returned by weekly() fit with the expected."""
    response = weekly()

    assert 0 == response.to_dict()['result']['Sun']['interactions'], f'Data do not match'
    for day in DAYS:
        assert day in response.to_dict()['result'].keys(), f'Data do not match'
    for hour in range(24):
        assert hour in response.to_dict()['result']['Sun']['hours'], f'Data do not match'


@patch('wazuh.stats.open')
@patch('wazuh.stats.configparser.RawConfigParser.read_file')
@patch('wazuh.stats.configparser.RawConfigParser.items', return_value={'hour':"'5'"})
def test_get_daemons_stats(mock_items, mock_read, mock_open):
    """Tests get_daemons_stats function works"""
    response = get_daemons_stats('filename')

    assert isinstance(response, dict), f'The result is not dict type'
    mock_open.assert_called_once_with('filename', 'r')


@patch('wazuh.stats.configparser.RawConfigParser.read_file')
def test_get_daemons_stats_ko(mock_readfp):
    """Tests get_daemons_stats function exceptions works"""

    with patch('wazuh.stats.open', side_effect=Exception):
        with pytest.raises(WazuhException, match=".* 1308 .*"):
            get_daemons_stats('filename')

    with patch('wazuh.stats.open'):
        with patch('wazuh.stats.configparser.RawConfigParser.items', return_value={'hour':5}):
            response = get_daemons_stats('filename')

            assert isinstance(response, WazuhException), f'The result is not WazuhResult type'
            assert response.code == 1104, f'Response code is not the same'

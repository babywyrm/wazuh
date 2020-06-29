# coding: utf-8

from __future__ import absolute_import
from datetime import date, datetime  # noqa: F401

from typing import List, Dict  # noqa: F401

from api.models.base_model_ import Model
from api import util


class TokenResponseModel(Model):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    """

    def __init__(self, token: str=None):  # noqa: E501
        """TokenResponseModel - a model defined in Swagger

        :param token: The token of this TokenResponseModel.  # noqa: E501
        :type token: str
        """
        self.swagger_types = {
            'token': str
        }

        self.attribute_map = {
            'token': 'token'
        }

        self._token = token

    @classmethod
    def from_dict(cls, dikt) -> 'TokenResponseModel':
        """Returns the dict as a model

        :param dikt: A dict.
        :type: dict
        :return: The TokenResponse of this TokenResponse.  # noqa: E501
        :rtype: TokenResponseModel
        """
        return util.deserialize_model(dikt, cls)

    @property
    def token(self) -> str:
        """Gets the token of this TokenResponseModel.


        :return: The token of this TokenResponseModel.
        :rtype: str
        """
        return self._token

    @token.setter
    def token(self, token: str):
        """Sets the token of this TokenResponseModel.


        :param token: The token of this TokenResponseModel.
        :type token: str
        """

        self._token = token

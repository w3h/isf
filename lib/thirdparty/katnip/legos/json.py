# Copyright (C) 2016 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
#
# This file is part of Katnip.
#
# Katnip is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# Katnip is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Katnip.  If not, see <http://www.gnu.org/licenses/>.

'''
JSON legos - simplified fuzzing of JSON-based protocols

.. todo:: ``JsonNumber``
'''
from __future__ import absolute_import
import json
import types
from kitty.model import Container
from kitty.model import Group, String, Static, BaseField, SInt32
from kitty.model import ENC_INT_DEC


def _valuename(name):
    return '%s_value' % name


def _keyname(name):
    return '%s_key' % name


class JsonBoolean(Container):
    '''
    JSON boolean field
    '''

    def __init__(self, name, value=None, fuzzable=True):
        '''
        :param name: block name
        :type value: bool
        :param value: value to be used, if None - generate both 'true' and 'false' (default: None)
        :param fuzzable: should we fuzz this field (only if value is not None) (default: True)
        '''
        if value is None:
            field = Group(['true', 'false'], name=_valuename(name))
        else:
            if not isinstance(value, types.BooleanType):
                raise ValueError('value should be bool, not %s' % type(value))
            # fix python and json boolean incompitability
            value = 'true' if value else 'false'
            field = String(value, fuzzable=fuzzable, name=_valuename(name))
        super(JsonBoolean, self).__init__(field, name=name)


class JsonNull(Container):
    '''
    JSON Null field
    '''

    def __init__(self, name, fuzzable=False):
        '''
        :param name: block name
        :param fuzzable: should we fuzz this field (default: False)
        '''
        field = String('null', fuzzable=fuzzable, name=_valuename(name))
        super(JsonNull, self).__init__(field, name=name)


class JsonString(Container):
    '''
    JSON string field
    '''

    def __init__(self, name, value, fuzzable=True):
        '''
        :param name: block name
        :param value: value to be used
        :param fuzzable: should we fuzz this field (default: True)
        '''
        if isinstance(value, BaseField):
            value_field = value
        else:
            value_field = String(value, fuzzable=fuzzable, name=_valuename(name))
        fields = [Static('"'), value_field, Static('"')]
        super(JsonString, self).__init__(fields, name=name)
        self.value = value


class JsonObject(Container):
    '''
    JSON object
    '''

    def __init__(self, name, member_dict, fuzz_keys=False):
        '''
        :param name: block name
        :type member_dict: dictionary (str, :class:`~kitty.model.low_level.fields.BaseField`)
        :param member_dict: members of this object
        :param fuzz_keys: should we fuzz the dictionary keys (default: False)
        '''
        fields = []
        self.members = member_dict
        fields.append(Static('{'))
        items = self.members.items()
        for i, (k, v) in enumerate(items):
            basic_name = name + '_' + k
            fields.append(JsonString(_keyname(basic_name), k, fuzzable=fuzz_keys))
            fields.append(Static(':'))
            fields.append(v)
            if i != (len(items) - 1):
                fields.append(Static(','))
        fields.append(Static('}'))
        super(JsonObject, self).__init__(fields, name=name)


class JsonArray(Container):
    '''
    JSON array field
    '''

    def __init__(self, name, values):
        '''
        :param name: block name
        :type values: list of :class:`~kitty.model.low_level.fields.BaseField`
        :param values: array members
        '''
        self.values = values
        fields = []
        fields.append(Static('['))
        for i, v in enumerate(self.values):
            fields.append(v)
            if i != (len(self.values) - 1):
                fields.append(Static(','))
        fields.append(Static(']'))
        super(JsonArray, self).__init__(fields, name=name)


#
# Internal class, should not be used from the outside
#
class _JsonStringContext:

    def __init__(self):
        self.idx = 0
        self._names = set([])

    def uname(self, name, enforce=True):
        if name in self._names:
            enforce = True
        self._names.add(name)
        if enforce:
            name = '%s_%d' % (name, self.idx)
            self.idx += 1
        return name


def dict_to_JsonObject(the_dict, name=None, ctx=None):
    '''
    Create a JsonObject from a dictionary.
    The context parameter is used for recursive calls,
    no need to pass it from outside.

    :param the_dict: dictionary to base the `JsonObject` on
    :param ctx: context for the parser (default: None)
    :rtype: :class:`~katnip.legos.json.JsonObject`
    :return: JSON object that represents the dictionary
    '''
    if type(the_dict) != dict:
        raise ValueError('expecting dictionary as first argument')
    if ctx is None:
        ctx = _JsonStringContext()
    members = {}
    for (k, v) in the_dict.items():
        if v is None:
            val = JsonNull(name=ctx.uname(k), fuzzable=False)
        elif isinstance(v, types.BooleanType):
            val = JsonBoolean(name=ctx.uname(k), value=v, fuzzable=True)
        elif isinstance(v, types.StringTypes):
            val = JsonString(name=ctx.uname(k), value=v, fuzzable=True)
        elif isinstance(v, types.ListType):
            val = list_to_JsonArray(v, k, ctx)
        elif isinstance(v, types.DictionaryType):
            val = dict_to_JsonObject(v, k, ctx)
        elif isinstance(v, types.IntType):
            val = SInt32(v, encoder=ENC_INT_DEC, name=ctx.uname(k))
        else:
            raise ValueError('type not supported: %s' % type(v))
        members[k] = val
    if name is None:
        name = 'obj'
    return JsonObject(name=ctx.uname(name, False), member_dict=members, fuzz_keys=False)


def list_to_JsonArray(the_list, name=None, ctx=None):
    '''
    Create a JsonArray from a list.
    The context parameter is used for recursive calls,
    no need to pass it from outside.

    :param the_list: list to base the JsonArray on
    :param ctx: context for the parser (default: None)
    :rtype: :class:`~katnip.legos.json.JsonArray`
    :return: JSON object that represents the list
    '''
    if type(the_list) != list:
        raise ValueError('expecting list as first argument')
    if ctx is None:
        ctx = _JsonStringContext()
    elements = []
    for v in the_list:
        if v is None:
            elements.append(JsonNull(ctx.uname('null'), fuzzable=False))
        elif isinstance(v, types.BooleanType):
            elements.append(JsonBoolean(ctx.uname('bool'), value=v, fuzzable=True))
        elif isinstance(v, types.StringTypes):
            elements.append(JsonString(ctx.uname('string'), v, fuzzable=True))
        elif isinstance(v, types.ListType):
            elements.append(list_to_JsonArray(v, None, ctx))
        elif isinstance(v, types.DictionaryType):
            elements.append(dict_to_JsonObject(v, None, ctx))
        elif isinstance(v, types.IntType):
            elements.append(SInt32(v, encoder=ENC_INT_DEC, name=ctx.uname('int')))
        else:
            raise ValueError('type not supported: %s' % type(v))
    if name is None:
        name = 'array'
    return JsonArray(name=ctx.uname(name, False), values=elements)


def str_to_json(json_str, name=None):
    '''
    Create a JSON lego based on a json string.

    :param name: name of the generated container
    :param json_str: json string to base the template on
    :rtype: :class:`~katnip.legos.json.JsonArray` or :class:`~katnip.legos.json.JsonObject`
    :return: JSON object or JSON array.
    '''
    parsed = json.loads(json_str)
    result = None
    if type(parsed) == list:
        result = list_to_JsonArray(parsed, name)
    elif type(parsed) == dict:
        result = dict_to_JsonObject(parsed, name)
    else:
        raise ValueError('parsing json string resulted in unsupported type (%s)' % type(parsed))
    return result

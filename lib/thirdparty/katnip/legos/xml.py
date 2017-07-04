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
XML (tag/type-length-value) legos.
Simplify template creation of XML-based protocol.
'''
from types import StringTypes, ListType, IntType
from kitty.model import Container, Template
from kitty.model import String, Static, SInt32, Clone
from kitty.model import ENC_INT_DEC


def _valuename(name):
    return '%s_value' % name


def _keyname(name):
    return '%s_key' % name


def _check_type(v, ts, name):
    if not isinstance(v, ts):
        raise ValueError('type of %s should be one of %s, but is %s' % (name, ts, type(v)))


class XmlAttribute(Container):
    '''
    XML attribute field, consists of tag and value
    '''

    def __init__(self, name, attribute, value, fuzz_attribute=False, fuzz_value=True):
        '''
        :param name: name of the block
        :param attribute: attribute
        :type value: str/unicode/int
        :param value: value of the attribute
        :param fuzz_attribute: should we fuzz the attribute field (default: False)
        :param fuzz_value: should we fuzz the value field (default: True)
        '''
        _check_type(attribute, StringTypes, 'attribute')
        _check_type(value, StringTypes + (IntType, ), 'value')

        value_name = _valuename(name)
        if isinstance(value, StringTypes):
            value_field = String(value, name=value_name, fuzzable=fuzz_value)
        else:
            value_field = SInt32(value, encoder=ENC_INT_DEC, fuzzable=fuzz_value, name=value_name)
        fields = [
            String(attribute, fuzzable=fuzz_attribute, name='%s_attribute' % name),
            Static('='),
            Static('"'),
            value_field,
            Static('"')
        ]
        super(XmlAttribute, self).__init__(fields, name=name)


class XmlElement(Container):
    '''
    XML element field
    '''

    def __init__(self, name, element_name, attributes=[], content=None, fuzz_name=True, fuzz_content=False, delimiter=''):
        '''
        :param name: name of the field
        :param element_name: element name
        :type attributes: list
        :param attributes: list of attributes of this element (default: [])
        :type content: str/unicode/int/[XmlElement]
        :param content: content of this element (default=None)
        :param fuzz_name: should we fuzz the element name
        :param fuzz_content: should we fuzz the content (n/a for XmlElement)
        '''
        _check_type(element_name, StringTypes, 'element_name')
        _check_type(attributes, ListType, 'attributes')
        if content:
            _check_type(content, StringTypes + (ListType, IntType), 'content')

        value_field = String(element_name, fuzzable=fuzz_name, name='%s_element' % name)

        fields = [
            Static('<'),
            value_field
        ]
        for i, attribute in enumerate(attributes):
            fields.append(Static(' '))
            fields.append(attribute)
        fields.append(Static('>'))
        if content:
            content_name = '%s_content' + name
            if isinstance(content, StringTypes):
                fields.append(String(content, fuzzable=fuzz_content, name=content_name))
            elif isinstance(content, IntType):
                fields.append(SInt32(content, encoder=ENC_INT_DEC, fuzzable=fuzz_content, name=content_name))
            elif isinstance(content, ListType):
                fields.append(Static(delimiter))
                for elem in content:
                    _check_type(elem, XmlElement, 'element inside the content list')
                    fields.append(elem)
        fields.append(Static('</'))
        fields.append(Clone(value_field))
        fields.append(Static('>' + delimiter))
        super(XmlElement, self).__init__(fields, name=name)


if __name__ == '__main__':
    # name, attribute, value, fuzz_attribute=False, fuzz_value=True
    attributes = [
        XmlAttribute(name='attr1', attribute='boom', value='attr1 value'),
        XmlAttribute(name='attr2', attribute='box', value=2),
    ]
    inner_elements = [
        XmlElement(name='inner element', element_name='an_inner_element', content=1, delimiter='\n'),
        XmlElement(name='inner element 2', element_name='an_inner_element', content='brrr', delimiter='\n')
    ]
    element = XmlElement(name='element1', element_name='an_element', attributes=attributes, content=inner_elements, delimiter='\n')
    t = Template(element, name='test')
    print(t.render().tobytes())

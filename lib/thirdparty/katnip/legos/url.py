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
URL legos, based on RFC 1738 and others
this module containes a basic URL lego, as well as the following specific scheme:
HTTP, HTTPS, FTP, FTPS

.. todo:: URL fragments
'''
from urlparse import urlparse
from kitty.model import Container, OneOf
from kitty.model import BaseField, String, Delimiter, BitField, Group
from kitty.model import ENC_STR_DEFAULT, ENC_INT_DEC
from kitty.core import KittyException


# ------------------ Helper classes and methods ------------------

def _to_string_field(name, field, fuzzable=True, encoder=ENC_STR_DEFAULT):
    if isinstance(field, BaseField):
        return field
    return String(name=name, value=field, fuzzable=fuzzable, encoder=encoder)


def _merge(*parts):
    return parts[-1]


class Url(Container):
    '''
    Base container for fuzzing URLs.

    ::

        genericurl = scheme ":" schemepart
    '''
    def __init__(self, scheme, parts, fuzz_scheme=True, fuzz_parts=True, fuzz_delim=True, fuzzable=True, name=None):
        '''
        :type scheme: str or instance of :class:`~kitty.model.low_level.field.BaseField`
        :param scheme: url scheme
        :type parts: str or instance of :class:`~kitty.model.low_level.field.BaseField`
        :param parts: url parts (i.e. content)
        :param fuzz_scheme: should fuzz scheme (default: True)
        :param fuzz_parts: should fuzz parts (default: True)
        :param fuzz_delim: should fuzz delimiters (default: True)
        :param fuzzable: should fuzz the container (default: True)
        :param name: name of container (default: None)
        '''
        scheme = _to_string_field(_merge(name, 'scheme'), scheme, fuzzable=fuzz_scheme)
        delim = Delimiter(name=_merge(name, 'delimiter'), value=':', fuzzable=fuzz_delim)
        parts = _to_string_field(_merge(name, 'scheme parts'), parts, fuzzable=fuzz_parts)
        super(Url, self).__init__(name=name, fields=[scheme, delim, parts], fuzzable=fuzzable)


class IpUrl(Url):
    '''
    IP-based URL

    ::

        ip-schemepart  = "//" login [ "/" urlpath ]
        login -> see Login class
        alphadigit     = alpha | digit
        hostnumber     = digits "." digits "." digits "." digits
        user           = *[ uchar | ";" | "?" | "&" | "=" ]
        password       = *[ uchar | ";" | "?" | "&" | "=" ]
        urlpath        = *xchar    ; depends on protocol see section 3.1
    '''
    def __init__(self, scheme, login, url_path=None, fuzz_scheme=True, fuzz_login=True, fuzz_delims=True, fuzzable=True, name=None):
        '''
        :type scheme: str or instance of :class:`~kitty.model.low_level.field.BaseField`
        :param scheme: url scheme
        :type login:

            str or instance of :class:`~kitty.model.low_level.field.BaseField`
            recommend using :class:`~katnip.legos.url.Login`

        :param login: the login information
        :type path:

            instance of :class:`~kitty.model.low_level.field.BaseField`
            recommend using :class:`~katnip.legos.url.Path`

        :param url_path: the url path (default: None)
        :param fuzz_scheme: should fuzz scheme (default: True)
        :param fuzz_login: should fuzz login (default: True)
        :param fuzz_delims: should fuzz delimiters (default: True)
        :param fuzzable: should fuzz the container (default: True)
        :param name: name of container (default: None)
        '''
        parts_fields = [
            Delimiter(name=_merge(name, 'forward slashs'), value='//', fuzzable=fuzz_delims),
            _to_string_field(_merge(name, 'login'), login, fuzzable=fuzz_login)
        ]
        if url_path is not None:
            parts_fields.append(Delimiter(name=_merge(name, 'url path delim'), value='/', fuzzable=fuzz_delims))
            parts_fields.append(url_path)
        parts = Container(name=_merge(name, 'parts'), fields=parts_fields)
        super(IpUrl, self).__init__(name=name, scheme=scheme, parts=parts, fuzz_scheme=fuzz_scheme, fuzz_delim=fuzz_delims, fuzzable=fuzzable)


class Login(Container):
    '''
    Container to fuzz the login part of the URL

    ::

        login          = [ user [ ":" password ] "@" ]
    '''

    def __init__(self, username=None, password=None, fuzz_username=True, fuzz_password=True, fuzz_delims=True, fuzzable=True, name=None):
        '''
        :param username: user name (default: None)
        :param password: password (default: None)
        :param fuzz_username: should fuzz username (default: True)
        :param fuzz_password: should fuzz password (default: True)
        :param fuzz_delims: should fuzz delimiters (default: True)
        :param fuzzable: should fuzz the container (default: True)
        :param name: name of container (default: None)
        '''
        fields = []
        if username is not None:
            fields.append(_to_string_field(_merge('name', 'username'), username, fuzzable=fuzz_username))
            if password is not None:
                fields.append(Delimiter(name=_merge(name, 'username password delim'), value=':', fuzzable=fuzz_delims))
                fields.append(_to_string_field(_merge('name', 'password'), password, fuzzable=fuzz_password))
            fields.append(Delimiter(name=_merge(name, 'username hostport delim'), value='@', fuzzable=fuzz_delims))
        elif password is not None:
            raise KittyException('Login cannot have password without username')

        super(Login, self).__init__(name=name, fields=fields, fuzzable=fuzzable)


class DecimalNumber(OneOf):
    '''
    Decimal number fuzzing.
    It's main strategy is to fuzz both
    values (integer vulnerabilities)
    and format (string vulnerabilities).
    '''

    def __init__(self, value, num_bits=64, signed=False, fuzzable=True, name=None):
        '''
        :param value: default integer value
        :param num_bits: number of bit in the integer (default: 64)
        :param signed: can the value be negative (default: False)
        :param fuzzable: should fuzz the container (default: True)
        :param name: name of container (default: None)
        '''
        fields = [
            BitField(name=_merge(name, 'int mutations'), value=value, length=num_bits, signed=signed, encoder=ENC_INT_DEC),
            String(name='string mutations', value='%s' % value)
        ]
        super(DecimalNumber, self).__init__(name=name, fields=fields, fuzzable=fuzzable)


class HostPort(Container):
    '''
    Container for fuzzing the host/port of the URL.

    ::

        hostport       = host [ ":" port ]
        port           = digits
    '''
    def __init__(self, host, port=None, fuzz_host=True, fuzz_port=True, fuzz_delim=True, fuzzable=True, name=None):
        '''
        :type host:

            str or instance of :class:`~kitty.model.low_level.field.BaseField`
            recommend using :class:`~katnip.legos.url.HostName`

        :param host: hostname
        :param port: port number (default: None)
        :param fuzz_host: should fuzz the hostname (default: True)
        :param fuzz_port: should fuzz the port (default: True)
        :param fuzz_delim: should fuzz the delimiter (default: True)
        :param fuzzable: should fuzz the container (default: True)
        :param name: name of container (default: None)
        '''
        fields = []
        fields.append(HostName(host=host, fuzz_delims=fuzz_delim, name=_merge(name, 'host'), fuzzable=fuzz_host))
        if port is not None:
            fields.append(Delimiter(name=_merge(name, 'host port delimiter'), value=':', fuzzable=fuzz_delim))
            fields.append(DecimalNumber(name=_merge(name, 'port'), value=port, num_bits=32, fuzzable=fuzz_port))
        super(HostPort, self).__init__(name=name, fields=fields, fuzzable=fuzzable)


class HostName(Container):
    '''
    Container to fuzz the hostname

    ::

        host           = hostname | hostnumber
        hostname       = *[ domainlabel "." ] toplabel
    '''
    def __init__(self, host='', fuzz_delims=False, fuzzable=True, name=None):
        '''
        :type host: str
        :param host: hostname (default: '')
        :param fuzz_delims: should fuzz the delimiters (default: False)
        :param fuzzable: should fuzz the container (default: True)
        :param name: name of container (default: None)
        '''
        fields = []
        domain_labels = host.split('.')
        if len(domain_labels):
            for i, domain_label in enumerate(domain_labels[:-1]):
                fields.append(String(name='domain label %d' % i, value=domain_label))
                fields.append(Delimiter(name='domain label delimiter %d' % i, value='.', fuzzable=fuzz_delims))
            fields.append(String(name='top most domain label', value=domain_labels[-1]))
        super(HostName, self).__init__(name=name, fields=fields, fuzzable=fuzzable)


class Search(Container):
    '''
    Container to fuzz the search part of the URL

    .. todo:: real implementation (parse search string etc.)
    '''
    def __init__(self, search='', fuzz_delims=False, fuzzable=True, name=None):
        '''
        :param search: search string (default: '')
        :param fuzz_delims: should fuzz the delimiters (default: False)
        :param name: name of container (default: None)
        :param fuzzable: should fuzz the container (default: True)
        '''
        fields = [
            Delimiter(name='search main delim', value='?', fuzzable=fuzz_delims),
            String(name='search data', value=search),
        ]
        super(Search, self).__init__(name=name, fields=fields, fuzzable=fuzzable)


class Path(Container):
    '''
    Container to fuzz the path of the URL
    '''
    def __init__(self, path=None, path_delim='/', fuzz_delims=True, fuzzable=True, name=None):
        '''
        :type path: str
        :param path: path string
        :param path_delim: delimiter in the path str
        :param fuzz_delims: should fuzz the delimiters (default: False)
        :param name: name of container (default: None)
        :param fuzzable: should fuzz the container (default: True)
        '''
        fields = []
        if path is not None:
            fields.append(Delimiter(name='main delim', value='/', fuzzable=fuzz_delims))
            path_parts = path.split(path_delim)
            for i in range(len(path_parts) - 1):
                fields.append(String(name='path part %d' % i, value=path_parts[i]))
                fields.append(Delimiter(name='path delim %d' % i, value=path_delim, fuzzable=fuzz_delims))
            fields.append(String(name='path last part', value=path_parts[-1]))
        super(Path, self).__init__(name=name, fields=fields, fuzzable=fuzzable)


# ------------------ Complete URL Legos ------------------

class HttpUrl(Url):
    '''
    Container to fuzz Http(s) URL

    ::

        httpurl        = "http://" hostport [ "/" hpath [ "?" search ]]
        hpath          = hsegment *[ "/" hsegment ]
        hsegment       = *[ uchar | ";" | ":" | "@" | "&" | "=" ]
        search         = *[ uchar | ";" | ":" | "@" | "&" | "=" ]
    '''
    def __init__(self, scheme='http', login=None, hostport=None, path=None, search=None,
                 fuzz_scheme=True, fuzz_delims=True, fuzzable=True, name=None):
        '''
        :param scheme: URL scheme name (default: 'http')
        :type login:

            instance of :class:`~kitty.model.low_level.field.BaseField`
            recommend using :class:`~katnip.legos.url.Login`

        :param login: the login information (default: None)
        :param hostport: :class:`katnip.legos.url.HostPort` object, must be set (default: None)
        :param path: Path object (default: None)
        :param search: Search object (default: None)
        :param fuzz_scheme: should fuzz the URL scheme (default: True)
        :param fuzz_delims: should fuzz the delimiters (default: True)
        :param fuzzable: is the container fuzzable (default: True)
        :param name: name of the container (default: None)
        '''
        if hostport is None:
            raise KittyException('hostport is mandatory in HttpUrl')
        parts_fields = []
        parts_fields.append(Delimiter(name=_merge(name, 'forward slashs'), value='//', fuzzable=fuzz_delims))
        if login:
            parts_fields.append(login)
        parts_fields.append(hostport)
        if path:
            parts_fields.append(path)
            if search is not None:
                parts_fields.append(search)
        parts = Container(name=_merge(name, 'parts'), fields=parts_fields)
        super(HttpUrl, self).__init__(name=name, scheme=scheme, parts=parts, fuzz_scheme=fuzz_scheme, fuzz_delim=fuzz_delims, fuzzable=fuzzable)

    @classmethod
    def from_string(cls, the_url, fuzz_delims=True, fuzzable=True, name=None):
        '''
        Create an HttpUrl Lego from string

        :param the_url: the url string
        :param fuzz_delims: should fuzz delimiters (default: True)
        :param fuzzable: is the container fuzzable (default: True)
        :param name: name of the container (default: None)
        '''
        parsed = urlparse(the_url)
        hostport = None
        path = None
        search = None
        login = None
        if parsed.username:
            login = Login(username=parsed.username, password=parsed.password, name='login', fuzz_delims=fuzz_delims)
        if parsed.port:
            port = int(parsed.port)
        else:
            port = None
        hostport = HostPort(host=parsed.hostname, port=port, fuzz_delim=fuzz_delims, fuzzable=fuzzable, name='hostport')
        if parsed.path:
            path = Path(path=parsed.path[1:], fuzz_delims=fuzz_delims, fuzzable=fuzzable, name='path')
        if parsed.query:
            search = Search(search=parsed.query, fuzz_delims=fuzz_delims, fuzzable=fuzzable, name='search')
        return HttpUrl(scheme=parsed.scheme, login=login, hostport=hostport, path=path, search=search, fuzzable=fuzzable)


class FType(Container):
    '''
    Container to fuzz the FTP Type of FTP URL

    ::

        ftptype        = "A" | "I" | "D" | "a" | "i" | "d"
    '''

    def __init__(self, the_type, fuzz_delims=True, fuzzable=True, name=None):
        '''
        :type the_type: str
        :param the_type: the FTP type
        :param fuzz_delims: should fuzz delimiters (default: True)
        :param fuzzable: is the container fuzzable (default: True)
        :param name: name of the container (default: None)
        '''
        super(FType, self).__init__(name=name, fuzzable=fuzzable, fields=[
            Delimiter(name='delim from path', value=';', fuzzable=fuzz_delims),
            String(name='key', value='ftype'),
            Delimiter(name='delim from value', value='=', fuzzable=fuzz_delims),
            OneOf(name='file type', fields=[
                Group(name='possible valid values', values=['A', 'I', 'D', 'a', 'i', 'd']),
                String(name='mutations', value=the_type),
            ])
        ])


class FtpUrl(Url):
    '''
    Container to fuzz FTP URLs

    ::

        ftpurl         = "ftp://" login [ "/" fpath [ ";type=" ftptype ]]
        fpath          = fsegment *[ "/" fsegment ]
        fsegment       = *[ uchar | "?" | ":" | "@" | "&" | "=" ]
        ftptype        -> see FType
    '''

    def __init__(self, scheme='ftp', login=None, hostport=None, path=None, ftype=None,
                 fuzz_scheme=True, fuzz_delims=True, fuzzable=True, name=None):
        '''
        :param scheme: URL scheme name (default: 'ftp')
        :type login:

            instance of :class:`~kitty.model.low_level.field.BaseField`
            recommend using :class:`~katnip.legos.url.Login`

        :param login: the login information (default: None)
        :type hostport: :class:`katnip.legos.url.HostPort` object (default: None)
        :param hostport: FTP host and port
        :type path: :class:`katnip.legos.url.Path` object (default: None)
        :param path: file path
        :type ftype: :class:`katnip.legos.url.FType` object (default: None)
        :param ftype: FTP type
        :param fuzz_scheme: should fuzz the URL scheme (default: True)
        :param fuzz_delims: should fuzz the delimiters (default: True)
        :param fuzzable: is the container fuzzable (default: True)
        :param name: name of the container (default: None)
        '''
        fields = []
        fields.append(Delimiter(name=_merge(name, 'forward slashs'), value='//', fuzzable=fuzz_delims))
        if login is not None:
            fields.append(login)
        fields.append(hostport)
        if path:
            fields.append(path)
            if ftype is not None:
                fields.append(ftype)
        parts = Container(name='parts', fields=fields, fuzzable=fuzzable)
        super(FtpUrl, self).__init__(name=name, scheme=scheme, parts=parts, fuzz_scheme=fuzz_scheme, fuzz_delim=fuzz_delims, fuzzable=fuzzable)

    @classmethod
    def from_string(cls, the_url, fuzz_delims=True, fuzzable=True, name=None):
        '''
        Create an FtpUrl Lego from string

        :param the_url: the url string
        :param fuzz_delims: should fuzz delimiters (default: True)
        :param fuzzable: is the container fuzzable (default: True)
        :param name: name of the container (default: None)

        .. todo: better parameter parsing
        '''
        parsed = urlparse(the_url)
        login = None
        path = None
        ftype = None
        if parsed.username:
            login = Login(username=parsed.username, password=parsed.password, name='login', fuzz_delims=fuzz_delims)
        if parsed.port:
            port = int(parsed.port)
        else:
            port = None
        hostport = HostPort(host=parsed.hostname, port=port, fuzz_delim=fuzz_delims, fuzzable=fuzzable, name='hostport')
        if parsed.path:
            path = Path(path=parsed.path[1:], fuzz_delims=fuzz_delims, name='path')
        if parsed.params:
            params = parsed.params
            if params.startswith('type='):
                ftype = FType(the_type=params[-1], fuzz_delims=fuzz_delims, name='ftype')
        return FtpUrl(scheme=parsed.scheme, login=login, hostport=hostport, path=path, ftype=ftype, fuzzable=fuzzable, fuzz_delims=fuzz_delims, name=name)


class EmailAddress(Container):
    '''
    Container to fuzz email address
    '''

    def __init__(self, username, hostname, fuzz_delim=True, fuzzable=True, name=None):
        '''
        :param username: email username
        :param hostname: email hostname
        :param fuzz_delim: should fuzz the delimiter (default: True)
        :param fuzzable: is the container fuzzable (default: True)
        :param name: name of the container (default: None)
        '''
        fields = [
            _to_string_field(_merge(name, 'username'), username, fuzzable=True),
            Delimiter('@', fuzzable=fuzz_delim),
            _to_string_field(_merge(name, 'hostname'), hostname, fuzzable=True),
        ]
        super(EmailAddress, self).__init__(fields=fields, fuzzable=fuzzable, name=name)

    @classmethod
    def from_string(cls, the_str, fuzz_delims=True, fuzzable=True, name=None):
        email = the_str
        if email.count('@') != 1:
            raise KittyException('invalid email address: %s' % email)
        username = email.split('@')[0]
        host = email.split('@')[1]
        hostname = HostPort(host)
        return EmailAddress(username=username, hostname=hostname, fuzz_delim=fuzz_delims, fuzzable=fuzzable, name=name)


class EmailUrl(Url):

    def __init__(self, email, scheme='mailto', fuzz_scheme=True, fuzz_user=True, fuzz_host=True, fuzz_delim=True, fuzzable=True, name=None):
        '''
        :type email: :class:`~katnip.legos.url.EmailAddress`
        :param email: the email address
        :param scheme: URL scheme (default: 'mailto')
        :param fuzz_scheme: should fuzz the URL scheme (default: True)
        :param fuzz_user: should fuzz the username (default: True)
        :param fuzz_host: should fuzz the host (default: True)
        :param fuzz_delim: should fuzz the delimiter (default: True)
        :param fuzzable: is the container fuzzable (default: True)
        :param name: name of the container (default: None)
        '''
        super(EmailUrl, self).__init__(name=name, scheme=scheme, parts=email, fuzz_scheme=fuzz_scheme, fuzz_delim=fuzz_delim, fuzzable=fuzzable)

    @classmethod
    def from_string(cls, the_url, fuzz_delims=True, fuzzable=True, name=None):
        parsed = urlparse(the_url)
        email_address = EmailAddress.from_string(parsed.path, fuzz_delims, fuzzable, name)
        return EmailUrl(email_address, scheme=parsed.scheme, fuzz_delim=fuzz_delims, fuzzable=fuzzable, name=name)


def url_from_string(url, fuzz_delims=True, fuzzable=True, name=None):
    '''
    Create a URL from string,
    only URLs with supported schemes will result in a lego.
    In the rest of the cases, an exception will be raised.

    :param url: the URL string
    :param fuzz_delims: should fuzz delimiters (default: True)
    :param fuzzable: should the resulted container be fuzzable (default: True)
    :param name: name of the resulted container (default: None)
    '''
    generators = {
        'http': HttpUrl.from_string,
        'https': HttpUrl.from_string,
        'ftp': FtpUrl.from_string,
        'ftps': FtpUrl.from_string,
        'mailto': EmailUrl.from_string,
    }
    parsed = urlparse(url)
    scheme = parsed.scheme
    if not scheme:
        raise KittyException('URL is invalid (no scheme)')
    if scheme in generators:
        generator = generators[scheme]
        return generator(the_url=url, fuzz_delims=fuzz_delims, fuzzable=fuzzable, name=name)
    else:
        raise KittyException('Unknown URL scheme (%s)' % scheme)

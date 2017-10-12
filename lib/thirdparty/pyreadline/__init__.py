# -*- coding: utf-8 -*-
#*****************************************************************************
#       Copyright (C) 2003-2006 Gary Bishop.
#       Copyright (C) 2006  Jorgen Stenarson. <jorgen.stenarson@bostream.nu>
#
#  Distributed under the terms of the BSD License.  The full license is in
#  the file COPYING, distributed as part of this software.
#*****************************************************************************
from __future__ import print_function, unicode_literals, absolute_import
from platform import system

_S = system()
if 'windows' != _S.lower():
    raise RuntimeError('pyreadline is for Windows only, not {}.'.format(_S))
del system, _S

from . import unicode_helper
from . import logger, clipboard, lineeditor, modes, console
from . rlmain import *

from . import rlmain

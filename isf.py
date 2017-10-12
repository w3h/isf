#!/usr/bin/env python
# -*- coding:utf-8 -*-

import code
import os,sys
from core import env
from core import util
from core.edfplugin import EDFPlugin
from core.fuzzbunch import Fuzzbunch
from core.pluginfinder import addplugins
from core import exception
from core.daveplugin import DAVEPlugin
from core.deployablemanager import DeployableManager

"""
Set up core paths
"""
(ISF_FILE, ISF_DIR, EDFLIB_DIR) = env.setup_core_paths( os.path.realpath(__file__))


"""
Plugin directories
"""
PAYLOAD_DIR = os.path.join(ISF_DIR, "module/payloads")
EXPLOIT_DIR = os.path.join(ISF_DIR, "module/exploits")
TOUCH_DIR = os.path.join(ISF_DIR, "module/touches")
SPECIAL_DIR = os.path.join(ISF_DIR, "module/specials")

"""
ISF directories
"""
LOG_DIR    = os.path.join(ISF_DIR, "logs")
ISF_CONFIG = os.path.join(ISF_DIR, "isf.xml")


def make_env_path():
    p = util.get_sitepackages_path()
    f = open(os.path.join(p, "isf.pth"), "wb+")
    info = ISF_DIR + "\n"
    info += ISF_DIR + "/lib/protocols" + "\n"
    info += ISF_DIR + "/lib/thirdparty" + "\n"
    f.write(info)
    f.close()

def do_interactive(isf):
    gvars = globals()
    gvars['quit'] = (lambda *x: isf.io.print_error("Press Ctrl-D to quit"))
    gvars['exit'] = gvars['quit']
    isf.io.print_warning("Dropping to Interactive Python Interpreter")
    isf.io.print_warning("Press Ctrl-D to exit")
    code.interact(local=gvars, banner="")

def main(isf):
    isf.printbanner()
    while 1:
        try:
            isf.cmdloop()
        except exception.Interpreter:
            do_interactive(isf)
        else:
            break

def load_plugins(isf):
    isf.io.pre_input(None)
    isf.io.print_msg("Loading Plugins")
    isf.io.post_input()

    addplugins(isf, "Exploit", EXPLOIT_DIR, EDFPlugin)
    addplugins(isf, "Payload", PAYLOAD_DIR, EDFPlugin)
    addplugins(isf, "Touch", TOUCH_DIR, EDFPlugin)
    addplugins(isf, "Special", SPECIAL_DIR, DAVEPlugin, DeployableManager)
    return

@exception.exceptionwrapped
def setup_and_run(config, fbdir, logdir):
    make_env_path()

    global isf
    isf = Fuzzbunch(config, fbdir, logdir)
    load_plugins(isf)
    main(isf)


if __name__ == "__main__":
    setup_and_run(ISF_CONFIG, ISF_DIR, LOG_DIR)

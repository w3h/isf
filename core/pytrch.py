from ctypes import *
from xml.etree import ElementTree
import xml.dom.minidom
import util
import xml.parsers.expat as expat
import exception
import re

def getText(node, recursive = False):
  L = ['']
  for n in node.childNodes:
    if n.nodeType in (xml.dom.Node.TEXT_NODE, xml.dom.Node.CDATA_SECTION_NODE):
      L.append(n.data)
    else:
      if not recursive:
        return None

      L.append( getText(n) )

  return ''.join(L)

def get_elements(xmlDoc, tag):
    try:
        elements = xmlDoc.getElementsByTagName(tag)
        if len(elements) == 0:
            elements = xmlDoc.getElementsByTagName("t:"+tag)
        return elements
    except:
        return []

def get_root_elements(xmlDoc, tag):
  dom = []
  try:
    for rt in xmlDoc.childNodes:
      if rt.nodeName == tag or rt.nodeName == "t:"+tag:
        dom.append(rt)
  except:
    pass

  return dom

def get_root_elements_by_name(xmlDoc, tag, name):
  try:
    for rt in xmlDoc.childNodes:
      if rt.nodeName == tag or rt.nodeName == "t:"+tag:
        if rt.getAttribute('name') == name:
          return rt
  except:
    pass

  return None

class TrchError(Exception):
  pass

def Exc_Trch(*args):
  print("[!] Exc_Trch")
  pass

def Parameter_Boolean_getValue(*args):
  ret = str(args[0].getAttribute('value'))
  if ret.lower() in ("false", "f", "0", "off"):
    return False
  elif ret.lower() in ("true", "t", "1", "on"):
    return True

  ret = str(args[0].getAttribute('default'))
  if ret.lower() in ("false", "f", "0", "off"):
    return False
  elif ret.lower() in ("true", "t", "1", "on"):
    return True

  return False

def Parameter_IPv4_getValue(*args):
  ret = args[0].getAttribute('value')
  if ret: return ret
  ret = args[0].getAttribute('default')
  return ret

def Parameter_IPv6_getValue(*args):
  ret = args[0].getAttribute('value')
  if ret: return ret
  ret = args[0].getAttribute('default')
  return ret

def Parameter_LocalFile_getValue(*args):
  print("[!] Parameter_LocalFile_getValue")
  pass

def Parameter_Port_getValue(*args):
  ret = args[0].getAttribute('value')
  if ret: return ret
  ret = args[0].getAttribute('default')
  return ret

def Parameter_S8_getValue(*args):
  ret = args[0].getAttribute('value')
  if ret: return ret
  ret = args[0].getAttribute('default')
  return ret

def Parameter_S16_getValue(*args):
  ret = args[0].getAttribute('value')
  if ret: return ret
  ret = args[0].getAttribute('default')
  return ret

def Parameter_S32_getValue(*args):
  ret = args[0].getAttribute('value')
  if ret: return ret
  ret = args[0].getAttribute('default')
  return ret

def Parameter_S64_getValue(*args):
  ret = args[0].getAttribute('value')
  if ret: return ret
  ret = args[0].getAttribute('default')
  return ret

def Parameter_U8_getValue(*args):
  ret = args[0].getAttribute('value')
  if ret: return ret
  ret = args[0].getAttribute('default')
  return ret

def Parameter_U16_getValue(*args):
  ret = args[0].getAttribute('value')
  if ret: return ret
  ret = args[0].getAttribute('default')
  return ret

def Parameter_U32_getValue(*args):
  ret = args[0].getAttribute('value')
  if ret: return ret
  ret = args[0].getAttribute('default')
  return ret

def Parameter_U64_getValue(*args):
  ret = args[0].getAttribute('value')
  if ret: return ret
  ret = args[0].getAttribute('default')
  return ret

def Parameter_Socket_getValue(*args):
  ret = args[0].getAttribute('value')
  if ret: return ret
  ret = args[0].getAttribute('default')
  return ret

def Parameter_String_getValue(*args):
  ret = args[0].getAttribute('value')
  if ret: return ret
  ret = args[0].getAttribute('default')
  return ret

def Parameter_UString_getValue(*args):
  ret = args[0].getAttribute('value')
  if ret: return ret
  ret = args[0].getAttribute('default')
  return ret

def Parameter_Buffer_getValue(*args):
  ret = args[0].getAttribute('value')
  if ret: return ret
  ret = args[0].getAttribute('default')
  return ret

def Paramchoice_getValue(*args):
  ret = args[0].getAttribute('value')
  if ret: return ret
  ret = args[0].getAttribute('default')
  return ret

def Config_create(*args):
  print("[!] Config_create")
  pass

def Config_delete(*args):
  print("[!] Config_delete")
  pass

def Config_duplicate(*args):
  print("[!] Config_duplicate")
  pass

def Config_getConfigVersion(*args):
  s = args[0].getAttribute('configversion')
  return s

def Config_getConstants(*args):
  print("[!] Config_getConstants")
  pass

def Config_getID(*args):
  s = args[0].getAttribute('id')
  return s.decode('utf-8')

def Config_getInputParams(*args):
  try:
    return get_elements(args[0], "inputparameters")[0]
  except:
    return []

def Config_getName(*args):
  s = args[0].getAttribute('name')
  return s.decode('utf-8')

def Config_getNamespaceUri(*args):
  s = args[0].getAttribute('id')
  return s.decode('utf-8')

def Config_getOutputParams(*args):
  try:
    return get_elements(args[0], "outputparameters")[0]
  except:
    return []

def Config_getSchemaVersion(*args):
  s = args[0].getAttribute('version')
  return s

def Config_getVersion(*args):
  s = args[0].getAttribute('version')
  return s

def Config_getAuthor(*args):
  s = args[0].getAttribute('author')
  return s

def Config_marshal(*args):
  info = []
  dom = args[0]
  info.append(dom.getAttribute('xmlns:t'))
  info.append(dom.getAttribute('id'))
  info.append(dom.getAttribute('configversion'))
  info.append(dom.getAttribute('name'))
  info.append(dom.getAttribute('version'))
  ret = '''<t:config xmlns:t = "{}" id = "{}" configversion = "{}" name = "{}" version = "{}" > \r\n'''.format(*info)

  input = get_elements(dom, "inputparameters")
  if input and input[0]:
    ret += "<t:inputparameters>\r\n"
    inputpara = get_elements(input[0], "parameter")
    for d in inputpara:
      info = []
      info.append(d.getAttribute('name'))
      info.append(d.getAttribute('description'))
      info.append(d.getAttribute('type'))
      ret += '''<t:parameter name = "{}" description = "{}" type = "{}" '''.format(*info)

      tmp = d.getAttribute('format')
      if tmp:
        ret += 'format = "' + str(tmp) + '" '

      tmp = d.getAttribute('default')
      if tmp:
        ret += 'default = "' + str(tmp) + '" '

      tmp = d.getAttribute('valid')
      if tmp:
        ret += 'valid = "' + str(tmp) + '" '

      tmp = d.getAttribute('value')
      if tmp:
        ret += 'value = "' + str(tmp) + '" '

      ret += "> </t:parameter>\r\n"
    ret += "</t:inputparameters>\r\n"

  output = get_elements(dom, "outputparameters")
  if output and output[0]:
    ret += "<t:outputparameters>\r\n"
    inputpara = get_elements(input[0], "parameter")
    for d in inputpara:
      info = []
      info.append(d.getAttribute('name'))
      info.append(d.getAttribute('description'))
      info.append(d.getAttribute('type'))
      ret += '''<t:parameter name = "{}" description = "{}" type = "{}" '''.format(*info)

      tmp = d.getAttribute('format')
      if tmp:
        ret += 'format = "' + str(tmp) + '" '

      tmp = d.getAttribute('default')
      if tmp:
        ret += 'default = "' + str(tmp) + '" '

      tmp = d.getAttribute('valid')
      if tmp:
        ret += 'valid = "' + str(tmp) + '" '

      tmp = d.getAttribute('value')
      if tmp:
        ret += 'value = "' + str(tmp) + '" '

      ret += "> </t:parameter>\r\n"
    ret += "</t:outputparameters>\r\n"

  ret += '</t:config>'
  return ret

def Config_printUsage(*args):
  print("[!] Config_printUsage")
  pass

def Config_setConstants(*args):
  print("[!] Config_setConstants")
  pass

def Config_setInputParams(*args):
  print("[!] Config_setInputParams")
  pass

def Config_setOutputParams(*args):
  print("[!] Config_setOutputParams")
  pass

def Config_unmarshal(*args):
  dom = xml.dom.minidom.parseString(*args)
  return get_elements(dom, "config")[0]

def FinalizeXMLUnmarshal():
  print("[!] FinalizeXMLUnmarshal")
  pass

def InitializeXMLUnmarshal():
  print("[!] InitializeXMLUnmarshal")
  pass

def Params_addParamchoice(*args):
  print("[!] Params_addParamchoice")
  pass

def Params_addParameter(*args):
  print("[!] Params_addParameter")
  pass

def Params_create(*args):
  print("[!] Params_create")
  pass

def Params_delete(*args):
  print("[!] Params_delete")
  pass

def Params_duplicate(*args):
  print("[!] Params_duplicate")
  pass

def Params_findParamchoice(*args):
  xmlDoc = args[0]
  name = args[1]
  tag = 'paramchoice'
  try:
    for rt in xmlDoc.childNodes:
      if rt.nodeName == tag or rt.nodeName == "t:" + tag:
        if rt.getAttribute('name') == name:
          return rt
  except:
    pass

  return None

def Params_findParameter(*args):
  dom = get_elements(args[0], 'parameter')
  for rt in dom:
    if rt.getAttribute('name') == args[1]:
      return rt

  return None

def Params_getName(*args):
  return  args[0].getAttribute('name')

def Params_getNumParamchoices(*args):
  return len(get_root_elements(args[0], 'paramchoice'))

def Params_getNumParameters(*args):
  return len(get_root_elements(args[0], 'parameter'))

def Params_getParamchoice(*args):
  dom = get_root_elements(args[0], 'paramchoice')
  return dom[args[1]]

def Params_getParameter(*args):
  dom = get_root_elements(args[0], 'parameter')
  return dom[args[1]]

def Params_isValid(*args):
  r = args[0].getAttribute('valid')
  if r == 'false':
    return False
  return True


def Params_parseCommandLine(*args):
  print("[!] Params_parseCommandLine")
  pass

def Params_printInvalid(*args):
  print("[!] Params_printInvalid")
  pass

def Params_removeParameter(*args):
  print("[!] Params_removeParameter")
  pass

def Params_getCallbackIPv4Values(*args):
  print("[!] Params_getCallbackIPv4Values")
  pass

def Params_getCallbackIPv6Values(*args):
  print("[!] Params_getCallbackIPv6Values")
  pass

def Params_getCallbackPortValues(*args):
  print("[!] Params_getCallbackPortValues")
  pass

def Params_validateCallbackPorts(*args):
  print("[!] Params_validateCallbackPorts")
  pass

def Paramchoice_addParamgroup(*args):
  print("[!] Paramchoice_addParamgroup")
  pass

def Paramchoice_create(*args):
  print("[!] Paramchoice_create")
  pass

def Paramchoice_delete(*args):
  print("[!] Paramchoice_delete")
  pass

def Paramchoice_getDefaultValue(*args):
  return args[0].getAttribute('default')

def Paramchoice_getDescription(*args):
  return args[0].getAttribute('description')

def Paramchoice_getName(*args):
  return args[0].getAttribute('name')

def Paramchoice_getNumParamgroups(*args):
  dom = get_root_elements(args[0], "paramgroup")
  return len(dom)

def Paramchoice_getParamgroup(*args):
  dom = get_root_elements(args[0], "paramgroup")
  return dom[args[1]]

def Paramchoice_hasValidValue(*args):
  if args[0].getAttribute('value'):
    return True
  else:
    return False

def Paramchoice_hasValue(*args):
  return args[0].getAttribute('value')

def Paramchoice_isValid(*args):
  r = args[0].getAttribute('valid')
  if r == 'false':
    return False
  return True

def Paramchoice_matchName(*args):
  print("[!] Paramchoice_matchName")
  pass

def Paramchoice_setValue(*args):
  args[0].setAttribute('value', args[1])

def Parameter_delete(*args):
  print("[!] Parameter_delete")
  pass

def Parameter_getDescription(*args):
  return args[0].getAttribute('description')

def Parameter_getFormat(*args):
  return args[0].getAttribute("format")

def Parameter_getInvalidReason(*args):
  print("[!] Parameter_getInvalidReason")
  pass

def Parameter_getMarshalledDefault(*args):
  print("[!] Parameter_getMarshalledDefault")
  pass

def Parameter_getMarshalledValue(*args):
  print("[!] Parameter_getMarshalledValue")
  pass

def Parameter_getName(*args):
  return args[0].getAttribute('name')

def Parameter_getType(*args):
  return args[0].getAttribute('type')

def Parameter_hasValue(*args):
  r = args[0].getAttribute('value')
  if r: return True
  r = args[0].getAttribute('default')
  if r: return True
  return False

def Parameter_hasValidValue(*args):
  v = args[0].getAttribute('value')
  if not v:
    return False

  t  = args[0].getAttribute('type').upper()
  if t == 'S8':
    if int(v) > pow(2,8) or int(v) < -pow(2,8):
      return False
  elif t == 'S16':
    if int(v) > pow(2,16) or int(v) < -pow(2,16):
      return False
  elif t == 'S32':
    if int(v) > pow(2,32) or int(v) < -pow(2,32):
      return False
  elif t == 'S64':
    if int(v) > pow(2,64) or int(v) < -pow(2,64):
      return False
  elif t == 'U8':
    if int(v) > pow(2, 8) or int(v) < 0:
      return False
  elif t == 'U16':
    if int(v) > pow(2, 16) or int(v) < 0:
      return False
  elif t == 'U32':
    if int(v) > pow(2, 32) or int(v) < 0:
      return False
  elif t == 'U64':
    if int(v) > pow(2, 64) or int(v) < 0:
      return False
  elif t == 'IPV4':
    if not re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', v):
      return False
  elif t == 'IPV6':
    if not re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', v):
      return False
  elif t == 'TCPPORT':
    if int(v) > 65535 or int(v) < 0:
      return False
  elif t == 'USTRING' or t == 'STRING':
    pass
  elif t == 'BOOLEAN' or t == 'BOOL':
    if not str(v).lower() in ("false", "f", "0", "off", "true", "t", "1", "on"):
      return False
  elif t == 'BUFFER':
    pass
  else:
    print "++++++++++++++++++++++++++ Invalid Type ++++++++++++++++++++++++++ ->",t

  return True

def Parameter_hide(*args):
  return args[0].getAttribute('hidden')

def Parameter_isHidden(*args):
  if "true" == args[0].getAttribute('hidden'):
    return True
  else:
    return False

def Parameter_isRequired(*args):
  if "true" == args[0].getAttribute('required'):
    return True
  else:
    return False

def Parameter_isValid(*args):
  r = args[0].getAttribute('valid')
  if r == 'false':
    return False
  return True

def Parameter_markInvalid(*args):
  print("[!] Parameter_markInvalid")
  pass

def Parameter_markInvalidWithReason(*args):
  print("[!] Parameter_markInvalidWithReason")
  pass

def Parameter_matchFormat(*args):
  print("[!] Parameter_matchFormat")
  pass

def Parameter_matchFormatAndType(*args):
  print("[!] Parameter_matchFormatAndType")
  pass

def Parameter_matchName(*args):
  print("[!] Parameter_matchName")
  pass

def Parameter_matchType(*args):
  print("[!] Parameter_matchType")
  pass

def Parameter_resetValue(*args):
  print("[!] Parameter_resetValue")
  pass

def Parameter_setMarshalledValue(*args):
  print("[!] Parameter_setMarshalledValue")
  pass

def Parameter_Boolean_create(*args):
  print("[!] Parameter_Boolean_create")
  pass

def Parameter_Boolean_setValue(*args):
  if args[1]:
    args[0].setAttribute('value', "True")
  else:
    args[0].setAttribute('value', "False")

def Parameter_Boolean_List_create(*args):
  print("[!] Parameter_Boolean_List_create")
  pass

def Parameter_Boolean_List_getSize(*args):
  print("[!] Parameter_Boolean_List_getSize")
  pass

def Parameter_Boolean_List_getValue(*args):
  print("[!] Parameter_Boolean_List_getValue")
  pass

def Parameter_Boolean_List_setValue(*args):
  print("[!] Parameter_Boolean_List_setValue")
  pass

def Parameter_Buffer_create(*args):
  print("[!] Parameter_Buffer_create")
  pass

def Parameter_Buffer_setValue(*args):
  args[0].setAttribute('value', args[1])

def Parameter_Buffer_List_create(*args):
  print("[!] Parameter_Buffer_List_create")
  pass

def Parameter_Buffer_List_getSize(*args):
  print("[!] Parameter_Buffer_List_getSize")
  pass

def Parameter_Buffer_List_getValue(*args):
  print("[!] Parameter_Buffer_List_getValue")
  pass

def Parameter_Buffer_List_setValue(*args):
  print("[!] Parameter_Buffer_List_setValue")
  pass

def Parameter_IPv4_create(*args):
  print("[!] Parameter_IPv4_create")
  pass

def Parameter_IPv4_setValue(*args):
  args[0].setAttribute('value', args[1])

def Parameter_IPv4_List_create(*args):
  print("[!] Parameter_IPv4_List_create")
  pass

def Parameter_IPv4_List_getSize(*args):
  print("[!] Parameter_IPv4_List_getSize")
  pass

def Parameter_IPv4_List_getValue(*args):
  print("[!] Parameter_IPv4_List_getValue")
  pass

def Parameter_IPv4_List_setValue(*args):
  print("[!] Parameter_IPv4_List_setValue")
  pass

def Parameter_IPv6_create(*args):
  print("[!] Parameter_IPv6_create")
  pass

def Parameter_IPv6_setValue(*args):
  print("[!] Parameter_IPv6_setValue")
  pass

def Parameter_IPv6_List_create(*args):
  print("[!] Parameter_IPv6_List_create")
  pass

def Parameter_IPv6_List_getSize(*args):
  print("[!] Parameter_IPv6_List_getSize")
  pass

def Parameter_IPv6_List_getValue(*args):
  print("[!] Parameter_IPv6_List_getValue")
  pass

def Parameter_IPv6_List_setValue(*args):
  print("[!] Parameter_IPv6_List_setValue")
  pass

def Parameter_LocalFile_create(*args):
  print("[!] Parameter_LocalFile_create")
  pass

def Parameter_LocalFile_setValue(*args):
  print("[!] Parameter_LocalFile_setValue")
  pass

def Parameter_LocalFile_List_create(*args):
  print("[!] Parameter_LocalFile_List_create")
  pass

def Parameter_LocalFile_List_getSize(*args):
  print("[!] Parameter_LocalFile_List_getSize")
  pass

def Parameter_LocalFile_List_getValue(*args):
  print("[!] Parameter_LocalFile_List_getValue")
  pass

def Parameter_LocalFile_List_setValue(*args):
  print("[!] Parameter_LocalFile_List_setValue")
  pass

def Parameter_Port_setValue(*args):
  args[0].setAttribute('value', args[1])


def Parameter_Port_List_getSize(*args):
  print("[!] Parameter_Port_List_getSize")
  pass

def Parameter_Port_List_getValue(*args):
  print("[!] Parameter_Port_List_getValue")
  pass

def Parameter_Port_List_setValue(*args):
  print("[!] Parameter_Port_List_setValue")
  pass

def Parameter_S8_create(*args):
  print("[!] Parameter_S8_create")
  pass

def Parameter_S8_setValue(*args):
  args[0].setAttribute('value', args[1])

def Parameter_S8_List_create(*args):
  print("[!] Parameter_S8_List_create")
  pass

def Parameter_S8_List_getSize(*args):
  print("[!] Parameter_S8_List_getSize")
  pass

def Parameter_S8_List_getValue(*args):
  print("[!] Parameter_S8_List_getValue")
  pass

def Parameter_S8_List_setValue(*args):
  print("[!] Parameter_S8_List_setValue")
  pass

def Parameter_S16_create(*args):
  print("[!] Parameter_S16_create")
  pass

def Parameter_S16_setValue(*args):
  args[0].setAttribute('value', args[1])

def Parameter_S16_List_create(*args):
  print("[!] Parameter_S16_List_create")
  pass

def Parameter_S16_List_getSize(*args):
  print("[!] Parameter_S16_List_getSize")
  pass

def Parameter_S16_List_getValue(*args):
  print("[!] Parameter_S16_List_getValue")
  pass

def Parameter_S16_List_setValue(*args):
  print("[!] Parameter_S16_List_setValue")
  pass

def Parameter_S32_create(*args):
  print("[!] Parameter_S32_create")
  pass

def Parameter_S32_setValue(*args):
  args[0].setAttribute('value', args[1])

def Parameter_S32_List_create(*args):
  print("[!] Parameter_S32_List_create")
  pass

def Parameter_S32_List_getSize(*args):
  print("[!] Parameter_S32_List_getSize")
  pass

def Parameter_S32_List_getValue(*args):
  print("[!] Parameter_S32_List_getValue")
  pass

def Parameter_S32_List_setValue(*args):
  print("[!] Parameter_S32_List_setValue")
  pass

def Parameter_S64_create(*args):
  print("[!] Parameter_S64_create")
  pass

def Parameter_S64_setValue(*args):
  args[0].setAttribute('value', args[1])

def Parameter_S64_List_create(*args):
  print("[!] Parameter_S64_List_create")
  pass

def Parameter_S64_List_getSize(*args):
  print("[!] Parameter_S64_List_getSize")
  pass

def Parameter_S64_List_getValue(*args):
  print("[!] Parameter_S64_List_getValue")
  pass

def Parameter_S64_List_setValue(*args):
  print("[!] Parameter_S64_List_setValue")
  pass

def Parameter_Socket_create(*args):
  print("[!] Parameter_Socket_create")
  pass

def Parameter_Socket_setValue(*args):
  args[0].setAttribute('value', args[1])

def Parameter_Socket_List_create(*args):
  print("[!] Parameter_Socket_List_create")
  pass

def Parameter_Socket_List_getSize(*args):
  print("[!] Parameter_Socket_List_getSize")
  pass

def Parameter_Socket_List_getValue(*args):
  print("[!] Parameter_Socket_List_getValue")
  pass

def Parameter_Socket_List_setValue(*args):
  print("[!] Parameter_Socket_List_setValue")
  pass

def Parameter_String_create(*args):
  print("[!] Parameter_String_create")
  pass

def Parameter_String_setValue(*args):
  args[0].setAttribute('value', args[1])

def Parameter_String_List_create(*args):
  print("[!] Parameter_String_List_create")
  pass

def Parameter_String_List_getSize(*args):
  print("[!] Parameter_String_List_getSize")
  pass

def Parameter_String_List_getValue(*args):
  print("[!] Parameter_String_List_getValue")
  pass

def Parameter_String_List_setValue(*args):
  print("[!] Parameter_String_List_setValue")
  pass

def Parameter_TcpPort_create(*args):
  print("[!] Parameter_TcpPort_create")
  pass

def Parameter_TcpPort_List_create(*args):
  print("[!] Parameter_TcpPort_List_create")
  pass

def Parameter_U8_create(*args):
  print("[!] Parameter_U8_create")
  pass

def Parameter_U8_setValue(*args):
  args[0].setAttribute('value', args[1])

def Parameter_U8_List_create(*args):
  print("[!] Parameter_U8_List_create")
  pass

def Parameter_U8_List_getSize(*args):
  print("[!] Parameter_U8_List_getSize")
  pass

def Parameter_U8_List_getValue(*args):
  print("[!] Parameter_U8_List_getValue")
  pass

def Parameter_U8_List_setValue(*args):
  print("[!] Parameter_U8_List_setValue")
  pass

def Parameter_U16_create(*args):
  print("[!] Parameter_U16_create")
  pass

def Parameter_U16_setValue(*args):
  args[0].setAttribute('value', args[1])

def Parameter_U16_List_create(*args):
  print("[!] Parameter_U16_List_create")
  pass

def Parameter_U16_List_getSize(*args):
  print("[!] Parameter_U16_List_getSize")
  pass

def Parameter_U16_List_getValue(*args):
  print("[!] Parameter_U16_List_getValue")
  pass

def Parameter_U16_List_setValue(*args):
  print("[!] Parameter_U16_List_setValue")
  pass

def Parameter_U32_create(*args):
  print("[!] Parameter_U32_create")
  pass

def Parameter_U32_setValue(*args):
  args[0].setAttribute('value', args[1])

def Parameter_U32_List_create(*args):
  print("[!] Parameter_U32_List_create")
  pass

def Parameter_U32_List_getSize(*args):
  print("[!] Parameter_U32_List_getSize")
  pass

def Parameter_U32_List_getValue(*args):
  print("[!] Parameter_U32_List_getValue")
  pass

def Parameter_U32_List_setValue(*args):
  print("[!] Parameter_U32_List_setValue")
  pass

def Parameter_U64_create(*args):
  print("[!] Parameter_U64_create")
  pass

def Parameter_U64_setValue(*args):
  print("[!] Parameter_U64_setValue")
  pass

def Parameter_U64_List_create(*args):
  print("[!] Parameter_U64_List_create")
  pass

def Parameter_U64_List_getSize(*args):
  print("[!] Parameter_U64_List_getSize")
  pass

def Parameter_U64_List_getValue(*args):
  print("[!] Parameter_U64_List_getValue")
  pass

def Parameter_U64_List_setValue(*args):
  print("[!] Parameter_U64_List_setValue")
  pass

def Parameter_UdpPort_create(*args):
  print("[!] Parameter_UdpPort_create")
  pass

def Parameter_UdpPort_List_create(*args):
  print("[!] Parameter_UdpPort_List_create")
  pass

def Parameter_UString_create(*args):
  print("[!] Parameter_UString_create")
  pass

def Parameter_UString_setValue(*args):
  print("[!] Parameter_UString_setValue")
  pass

def Parameter_UString_List_create(*args):
  print("[!] Parameter_UString_List_create")
  pass

def Parameter_UString_List_getSize(*args):
  print("[!] Parameter_UString_List_getSize")
  pass

def Parameter_UString_List_getValue(*args):
  print("[!] Parameter_UString_List_getValue")
  pass

def Parameter_UString_List_setValue(*args):
  print("[!] Parameter_UString_List_setValue")
  pass

def Paramgroup_addParamchoice(*args):
  print("[!] Paramgroup_addParamchoice")
  pass

def Paramgroup_addParameter(*args):
  print("[!] Paramgroup_addParameter")
  pass

def Paramgroup_create(*args):
  print("[!] Paramgroup_create")
  pass

def Paramgroup_delete(*args):
  print("[!] Paramgroup_delete")
  pass

def Paramgroup_getDescription(*args):
  return args[0].getAttribute('description')

def Paramgroup_getName(*args):
  return args[0].getAttribute('name')

def Paramgroup_getNumParamchoices(*args):
  num = 0
  try:
    for rt in args[0].childNodes:
      if rt.nodeName == 'paramchoice':
        num = num + 1
  except:
    pass

  return num

def Paramgroup_getNumParameters(*args):
  num = 0
  try:
    for rt in args[0].childNodes:
      if rt.nodeName == 'parameter' or rt.nodeName == 't:parameter':
        num = num + 1
  except:
    pass

  return num

def Paramgroup_getParamchoice(*args):
  dom = []
  try:
    for rt in args[0].childNodes:
      if rt.nodeName == 'paramchoice' or rt.nodeName == 't:paramchoice':
        dom.append(rt)
  except:
    pass

  return dom[args[1]]

def Paramgroup_getParameter(*args):
  dom = []
  try:
    for rt in args[0].childNodes:
      if rt.nodeName == 'parameter' or rt.nodeName == 't:parameter':
        dom.append(rt)
  except:
    pass

  return dom[args[1]]


def Paramgroup_isValid(*args):
  r = args[0].getAttribute('valid')
  if r == 'false':
    return False
  return True
  '''
  if args[0].getAttribute('value'):
    return True
  else:
    return False
  '''

def Paramgroup_matchName(*args):
  print("[!] Paramgroup_matchName")
  pass

def Paramgroup_removeParameter(*args):
  print("[!] Paramgroup_removeParameter")
  pass

def List_format():
  print("[!] List_format")
  pass

def Scalar_format():
  print("[!] Scalar_format")
  pass

def Boolean_type():
  print("[!] Boolean_type")
  pass

def Buffer_type():
  print("[!] Buffer_type")
  pass

def IPv4_type():
  print("[!] IPv4_type")
  pass

def IPv6_type():
  print("[!] IPv6_type")
  pass

def LocalFile_type():
  print("[!] LocalFile_type")
  pass

def S8_type():
  print("[!] S8_type")
  pass

def S16_type():
  print("[!] S16_type")
  pass

def S32_type():
  print("[!] S32_type")
  pass

def S64_type():
  print("[!] S64_type")
  pass

def Socket_type():
  print("[!] Socket_type")
  pass

def String_type():
  print("[!] String_type")
  pass

def TcpPort_type():
  print("[!] TcpPort_type")
  pass

def U8_type():
  print("[!] U8_type")
  pass

def U16_type():
  print("[!] U16_type")
  pass

def U32_type():
  print("[!] U32_type")
  pass

def U64_type():
  print("[!] U64_type")
  pass

def UdpPort_type():
  print("[!] UdpPort_type")
  pass

def UString_type():
  print("[!] UString_type")
  pass

def Boolean_marshal(*args):
  print("[!] Boolean_marshal")
  pass

def Boolean_List_marshal(*args):
  print("[!] Boolean_List_marshal")
  pass

def Buffer_marshal(*args):
  print("[!] Buffer_marshal")
  pass

def Buffer_List_marshal(*args):
  print("[!] Buffer_List_marshal")
  pass

def IPv4_marshal(*args):
  print("[!] IPv4_marshal")
  pass

def IPv4_List_marshal(*args):
  print("[!] IPv4_List_marshal")
  pass

def IPv6_marshal(*args):
  print("[!] IPv6_marshal")
  pass

def IPv6_List_marshal(*args):
  print("[!] IPv6_List_marshal")
  pass

def LocalFile_marshal(*args):
  print("[!] LocalFile_marshal")
  pass

def LocalFile_List_marshal(*args):
  print("[!] LocalFile_List_marshal")
  pass

def Port_marshal(*args):
  print("[!] Port_marshal")
  pass

def Port_List_marshal(*args):
  print("[!] Port_List_marshal")
  pass

def S8_marshal(*args):
  print("[!] S8_marshal")
  pass

def S8_List_marshal(*args):
  print("[!] S8_List_marshal")
  pass

def S16_marshal(*args):
  print("[!] S16_marshal")
  pass

def S16_List_marshal(*args):
  print("[!] S16_List_marshal")
  pass

def S32_marshal(*args):
  print("[!] S32_marshal")
  pass

def S32_List_marshal(*args):
  print("[!] S32_List_marshal")
  pass

def S64_marshal(*args):
  print("[!] S64_marshal")
  pass

def S64_List_marshal(*args):
  print("[!] S64_List_marshal")
  pass

def Socket_marshal(*args):
  print("[!] Socket_marshal")
  pass

def Socket_List_marshal(*args):
  print("[!] Socket_List_marshal")
  pass

def String_marshal(*args):
  print("[!] String_marshal")
  pass

def String_List_marshal(*args):
  print("[!] String_List_marshal")
  pass

def U8_marshal(*args):
  print("[!] U8_marshal")
  pass

def U8_List_marshal(*args):
  print("[!] U8_List_marshal")
  pass

def U16_marshal(*args):
  print("[!] U16_marshal")
  pass

def U16_List_marshal(*args):
  print("[!] U16_List_marshal")
  pass

def U32_marshal(*args):
  print("[!] U32_marshal")
  pass

def U32_List_marshal(*args):
  print("[!] U32_List_marshal")
  pass

def U64_marshal(*args):
  print("[!] U64_marshal")
  pass

def U64_List_marshal(*args):
  print("[!] U64_List_marshal")
  pass

def UString_marshal(*args):
  print("[!] UString_marshal")
  pass

def UString_List_marshal(*args):
  print("[!] UString_List_marshal")
  pass



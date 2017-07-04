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
USB Protocol tempaltes.
The templates here are based on the USB 2.0 spec.
All page / section references are for the USB 2.0 spec document
The USB 2.0 may be downloaded from:
http://www.usb.org/developers/docs/usb20_docs/usb_20_042814.zip
'''

from kitty.model import *
from katnip.legos.dynamic import DynamicInt
from katnip.legos.usb_hid import GenerateHidReport


class _StandardRequestCodes:
    '''
    Standard request codes [Section 9.4, table 9.4]
    '''
    GET_STATUS = 0x0
    CLEAR_FEATURE = 0x1
    RESERVED_2 = 0x2
    SET_FEATURE = 0x3
    RESERVED_4 = 0x4
    SET_ADDRESS = 0x5
    GET_DESCRIPTOR = 0x6
    SET_DESCRIPTOR = 0x7
    GET_CONFIGURATION = 0x8
    SET_CONFIGURATION = 0x9
    GET_INTERFACE = 0xa
    SET_INTERFACE = 0xb
    SYNCH_FRAME = 0xc


class _DescriptorTypes:

    '''Descriptor types [Section 9.4, table 9.5]'''

    DEVICE = 0x1
    CONFIGURATION = 0x2
    STRING = 0x3
    INTERFACE = 0x4
    ENDPOINT = 0x5
    DEVICE_QUALIFIER = 0x6
    OTHER_SPEED_CONFIGURATION = 0x7
    INTERFACE_POWER = 0x8
    HID = 0x21
    HID_REPORT = 0x22
    CS_INTERFACE = 0x24  # usbcdc11.pdf table 24
    CS_ENDPOINT = 0x25  # usbcdc11.pdf table 24
    HUB = 0x29


class _StandardFeatureSelector:
    '''Standard feature selectors [Section 9.4, table 9.6]'''
    ENDPOINT_HALT = 0
    DEVICE_REMOTE_WAKEUP = 1
    TEST_MODE = 2


class Descriptor(Template):
    '''
    USB descriptor template.
    '''

    def __init__(self, name, descriptor_type, fields, fuzz_type=True):
        if isinstance(fields, BaseField):
            fields = [fields]
        fields.insert(0, SizeInBytes(name='bLength', sized_field=self, length=8, fuzzable=True))
        fields.insert(1, UInt8(name='bDescriptorType', value=descriptor_type, fuzzable=fuzz_type))
        super(Descriptor, self).__init__(name=name, fields=fields)


class SubDescriptor(Container):
    def __init__(self, name, descriptor_type, fields, fuzz_type=True):
        if isinstance(fields, BaseField):
            fields = [fields]
        fields.insert(0, SizeInBytes(name='bLength', sized_field=self, length=8, fuzzable=True))
        fields.insert(1, UInt8(name='bDescriptorType', value=descriptor_type, fuzzable=fuzz_type))
        super(SubDescriptor, self).__init__(name=name, fields=fields)


class SizedPt(Container):
    '''
    Sized part of a descriptor.
    It receives all fields excepts of the size field and adds it.
    '''
    def __init__(self, name, fields):
        '''
        :param name: name of the Container
        :param fields: list of fields in the container
        '''
        if isinstance(fields, BaseField):
            fields = [fields]
        fields.insert(0, SizeInBytes(name='%s size' % name, sized_field=self, length=8, fuzzable=True))
        super(SizedPt, self).__init__(name=name, fields=fields)


# ################### #
# Generic descriptors #
# ################### #

# Device descriptor
# Section 9.6.1, page 261
device_descriptor = Descriptor(
    name='device_descriptor',
    descriptor_type=_DescriptorTypes.DEVICE,
    fields=[
        LE16(name='bcdUSB', value=0x0100),  # USB 2.0 is reported as 0x0200, USB 1.1 as 0x0110 and USB 1.0 as 0x0100
        UInt8(name='bDeviceClass', value=0),
        UInt8(name='bDeviceSubClass', value=0),
        UInt8(name='bDeviceProtocol', value=0),
        UInt8(name='bMaxPacketSize', value=64),  # valid sizes: 8,16,32,64
        LE16(name='idVendor', value=0),
        LE16(name='idProduct', value=0),
        LE16(name='bcdDevice', value=0),
        UInt8(name='iManufacturer', value=0),
        UInt8(name='iProduct', value=0),
        UInt8(name='iSerialNumber', value=0),
        UInt8(name='bNumConfigurations', value=0)
    ])

# Device qualifier descriptor
# Section 9.6.2, page 264
device_qualifier_descriptor = Descriptor(
    name='device_qualifier_descriptor',
    descriptor_type=_DescriptorTypes.DEVICE_QUALIFIER,
    fields=[
        LE16(name='bcdUSB', value=0x0100),  # USB 2.0 is reported as 0x0200, USB 1.1 as 0x0110 and USB 1.0 as 0x0100
        UInt8(name='bDeviceClass', value=0),
        UInt8(name='bDeviceSubClass', value=0),
        UInt8(name='bDeviceProtocol', value=0),
        UInt8(name='bMaxPacketSize', value=0),  # valid sizes: 8,16,32,64
        UInt8(name='bNumConfigurations', value=0),
        UInt8(name='bReserved', value=0)
    ])

# Configuration descriptor
# Section 9.6.3, page 265
configuration_descriptor = Template(
    name='configuration_descriptor',
    fields=[
        UInt8(name='bLength', value=9),
        UInt8(name='bDescriptorType', value=_DescriptorTypes.CONFIGURATION),
        LE16(name='wTotalLength', value=9),
        ElementCount(name='bNumInterfaces', depends_on='interfaces', length=8),
        UInt8(name='bConfigurationValue', value=1),
        UInt8(name='iConfiguration', value=0),
        BitField(name='bmAttributes', value=0, length=8),
        UInt8(name='bMaxPower', value=1),
        List(name='interfaces', fields=[
            Container(name='iface and eps', fields=[
                SubDescriptor(
                    name='interface_descriptor',
                    descriptor_type=_DescriptorTypes.INTERFACE,
                    fields=[
                        UInt8(name='bInterfaceNumber', value=0),
                        UInt8(name='bAlternateSetting', value=0),
                        ElementCount(name='bNumEndpoints', depends_on='endpoints', length=8),
                        UInt8(name='bInterfaceClass', value=0x08),
                        UInt8(name='bInterfaceSubClass', value=0x06),
                        UInt8(name='bInterfaceProtocol', value=0x50),
                        UInt8(name='iInterface', value=0),
                        List(name='endpoints', fields=[
                            SubDescriptor(
                                name='endpoint_descriptor',
                                descriptor_type=_DescriptorTypes.ENDPOINT,
                                fields=[
                                    UInt8(name='bEndpointAddress', value=0),
                                    BitField(name='bmAttributes', value=0, length=8),
                                    LE16(name='wMaxPacketSize', value=65535),
                                    UInt8(name='bInterval', value=0)
                                ])
                        ]),
                    ])
            ]),
        ]),
    ])


# Other_Speed_Configuration descriptor
# Section 9.6.4, page 267
other_speed_configuration_descriptor = Descriptor(
    name='other_speed_configuration_descriptor',
    descriptor_type=_DescriptorTypes.OTHER_SPEED_CONFIGURATION,
    fields=[
        LE16(name='wTotalLength', value=0xffff),  # TODO: real default size
        UInt8(name='bNumInterfaces', value=0xff),  # TODO: real default size
        UInt8(name='bConfigurationValue', value=0xff),  # TODO: real default size
        UInt8(name='iConfiguration', value=0xff),
        BitField(name='bmAttributes', value=0, length=8),
        UInt8(name='bMaxPower', value=0xff)
    ])


# Endpoint descriptor
# Section 9.6.6, page 269
endpoint_descriptor = Descriptor(
    name='endpoint_descriptor',
    descriptor_type=_DescriptorTypes.ENDPOINT,
    fields=[
        UInt8(name='bEndpointAddress', value=0),
        BitField(name='bmAttributes', value=0, length=8),
        LE16(name='wMaxPacketSize', value=65535),
        UInt8(name='bInterval', value=0)
    ])


# String descriptor (regular and zero)
# Section 9.6.7, page 273
string_descriptor = Descriptor(
    name='string_descriptor',
    descriptor_type=_DescriptorTypes.STRING,
    fields=[
        String(name='bString', value='hello_kitty', encoder=StrEncodeEncoder('utf_16_le'), max_size=254/2)
    ])


string_descriptor_zero = Descriptor(
    name='string_descriptor_zero',
    descriptor_type=_DescriptorTypes.STRING,
    fields=[
        RandomBytes(name='lang_id', min_length=0, max_length=253, step=3, value='\x04\x09')
    ])

hub_descriptor = Descriptor(
    name='hub_descriptor',
    descriptor_type=_DescriptorTypes.HUB,
    fields=[
        UInt8(name='bNbrPorts', value=4),
        BitField(name='wHubCharacteristics', value=0xe000, length=16),
        UInt8(name='bPwrOn2PwrGood', value=0x32),
        UInt8(name='bHubContrCurrent', value=0x64),
        UInt8(name='DeviceRemovable', value=0),
        UInt8(name='PortPwrCtrlMask', value=0xff)
    ])


# TODO: usbcsendpoint_descriptor
# TODO: usbcsinterface_descriptor

###################################################
#              Mass Storage Templates             #
###################################################

# TODO: scsi_test_unit_ready_response (nothing to fuzz! no data returned, besides the csw)
# TODO: scsi_send_diagnostic_response
# TODO: scsi_prevent_allow_medium_removal_response
# TODO: scsi_write_10_response (nothing to fuzz! no data returned, besides the csw)
# TODO: scsi_write_6_response
# TODO: scsi_read_6_response
# TODO: scsi_verify_10_response


# USBMassStorageClass
reset_request = Template(
    name='reset_request',
    fields=String(name='reset response', value=''))


# USBMassStorageClass
msc_get_max_lun_response = Template(
    name='msc_get_max_lun_response',
    fields=UInt8(name='Max_LUN', value=0x00))


# Request Sense - FuzzableUSBMassStorageInterface
scsi_request_sense_response = Template(
    name='scsi_request_sense_response',
    fields=[
        UInt8(name='ResponseCode', value=0x70),
        UInt8(name='VALID', value=0x00),
        UInt8(name='Obsolete', value=0x00),
        UInt8(name='SenseKey', value=0x00),
        UInt8(name='Resv', value=0x00),
        UInt8(name='ILI', value=0x00),
        UInt8(name='EOM', value=0x00),
        UInt8(name='FILEMARK', value=0x00),
        BE32(name='Information', value=0x00),
        SizedPt(
            name='Additional_Sense_data',
            fields=[
                BE32(name='CmdSpecificInfo', value=0x00),
                UInt8(name='ASC', value=0x00),
                UInt8(name='ASCQ', value=0x00),
                UInt8(name='FRUC', value=0x00),
                UInt8(name='SenseKeySpecific_0', value=0x00),
                UInt8(name='SenseKeySpecific_1', value=0x00),
                UInt8(name='SenseKeySpecific_2', value=0x00),
            ])
    ])


# Inquiry - FuzzableUSBMassStorageInterface
scsi_inquiry_response = Template(
    name='scsi_inquiry_response',
    fields=[
        UInt8(name='Peripheral', value=0x00),
        UInt8(name='Removable', value=0x80),
        UInt8(name='Version', value=0x04),
        UInt8(name='Response_Data_Format', value=0x02),
        SizeInBytes(
            name='Additional Length',
            sized_field='Additional Inquiry Data',
            length=8
        ),
        SizedPt(name='Additional Inquiry Data',
                fields=[
                    UInt8(name='Sccstp', value=0x00),
                    UInt8(name='Bqueetc', value=0x00),
                    UInt8(name='CmdQue', value=0x00),
                    Pad(8 * 8, fields=String(name='VendorID', value='Paul', max_size=8)),
                    Pad(16 * 8, fields=String(name='ProductID', value='Atreides', max_size=16)),
                    Pad(4 * 8, fields=String(name='productRev', value='1718', max_size=4)),
                ])
    ])


# Mode Sense - FuzzableUSBMassStorageInterface
scsi_mode_sense_6_response = Template(
    name='scsi_mode_sense_6_response',
    fields=[
        SizeInBytes(name='bLength', sized_field='scsi_mode_sense_6_response', length=8, fuzzable=True),
        UInt8(name='MediumType', value=0x00),
        UInt8(name='Device_Specific_Param', value=0x00),
        SizedPt(name='Mode_Parameter_Container', fields=RandomBytes(name='Mode_Parameter', min_length=0, max_length=4, value='\x1c'))
    ])


# Mode Sense - FuzzableUSBMassStorageInterface
scsi_mode_sense_10_response = Template(
    name='scsi_mode_sense_10_response',
    fields=[
        SizeInBytes(name='bLength', sized_field='scsi_mode_sense_10_response', length=8, fuzzable=True),
        UInt8(name='MediumType', value=0x00),
        UInt8(name='Device_Specific_Param', value=0x00),
        SizedPt(name='Mode_Parameter_Container', fields=RandomBytes(name='Mode_Parameter', min_length=0, max_length=4, value='\x1c'))
    ])


# Read Format Capacity - FuzzableUSBMassStorageInterface
scsi_read_format_capacities = Template(
    name='scsi_read_format_capacities',
    fields=[
        BE32(name='capacity_list_length', value=0x8),
        BE32(name='num_of_blocks', value=0x1000),
        BE16(name='descriptor_code', value=0x1000),
        BE16(name='block_length', value=0x0200)
    ])


# Read Capacity - FuzzableUSBMassStorageInterface
scsi_read_capacity_10_response = Template(
    name='scsi_read_capacity_10_response',
    fields=[
        BE32(name='NumBlocks', value=0x4fff),
        BE32(name='BlockLen', value=0x200)
    ])


##############################
# Smart Card Class Templates #
##############################

# TODO: smartcard_Secure_response
# TODO: smartcard_Mechanical_response
# TODO: smartcard_Abort_response
# TODO: smartcard_SetDataRateAndClock_Frequency_response
# TODO: smartcard_scd_icc_descriptor


class R2PParameters(Template):

    def __init__(self, name, status, error, proto, ab_data, fuzzable=True):
        fields = [
            U8(name='bMessageType', value=0x82),
            SizeInBytes(name='dwLength', sized_field=ab_data, length=32, fuzzable=True, encoder=ENC_INT_LE),
            DynamicInt(name='bSlot', key='bSlot', bitfield=U8(name='bSlotInt', value=0)),
            DynamicInt(name='bSeq', key='bSeq', bitfield=U8(name='bSeqInt', value=0)),
            U8(name='bStatus', value=status),
            U8(name='bError', value=error),
            U8(name='bProtocolNum', value=proto),
            Container(name='abData', fields=ab_data),
        ]
        super(R2PParameters, self).__init__(name=name, fields=fields, fuzzable=fuzzable)


smartcard_GetParameters_response = R2PParameters(
    name='smartcard_GetParameters_response',
    status=0x00,
    error=0x80,
    proto=0,
    ab_data=RandomBytes(name='data', value='\x11\x00\x00\x0a\x00', min_length=0, max_length=150),
)


smartcard_ResetParameters_response = R2PParameters(
    name='smartcard_ResetParameters_response',
    status=0x00,
    error=0x80,
    proto=0,
    ab_data=RandomBytes(name='data', value='\x11\x00\x00\x0a\x00', min_length=0, max_length=150),
)

smartcard_SetParameters_response = R2PParameters(
    name='smartcard_SetParameters_response',
    status=0x00,
    error=0x80,
    proto=0,
    ab_data=RandomBytes(name='data', value='\x11\x00\x00\x0a\x00', min_length=0, max_length=150),
)


class R2PDataBlock(Template):

    def __init__(self, name, status, error, chain_param, ab_data, fuzzable=True):
        fields = [
            U8(name='bMessageType', value=0x80),
            SizeInBytes(name='dwLength', sized_field=ab_data, length=32, fuzzable=True, encoder=ENC_INT_LE),
            DynamicInt(name='bSlot', key='bSlot', bitfield=U8(name='bSlotInt', value=0)),
            DynamicInt(name='bSeq', key='bSeq', bitfield=U8(name='bSeqInt', value=0)),
            U8(name='bStatus', value=status),
            U8(name='bError', value=error),
            U8(name='bChainParameter', value=chain_param),
            Container(name='abData', fields=ab_data),
        ]
        super(R2PDataBlock, self).__init__(name=name, fields=fields, fuzzable=fuzzable)

smartcard_IccPowerOn_response = R2PDataBlock(
    name='smartcard_IccPowerOn_response',
    status=0x00,
    error=0x80,
    chain_param=0x00,
    ab_data=RandomBytes(name='data', value='\x3b\x6e\x00\x00\x80\x31\x80\x66\xb0\x84\x12\x01\x6e\x01\x83\x00\x90\x00', min_length=0, max_length=150),
)

smartcard_XfrBlock_response = R2PDataBlock(
    name='smartcard_XfrBlock_response',
    status=0x00,
    error=0x80,
    chain_param=0x00,
    ab_data=RandomBytes(name='data', value='\x6a\x82', min_length=0, max_length=150),
)


class R2PSlotStatus(Template):
    def __init__(self, name, status, error, clock_status, fuzzable=True):
        fields = [
            U8(name='bMessageType', value=0x80),
            LE32(name='dwLength', value=0x00),
            DynamicInt(name='bSlot', key='bSlot', bitfield=U8(name='bSlotInt', value=0)),
            DynamicInt(name='bSeq', key='bSeq', bitfield=U8(name='bSeqInt', value=0)),
            U8(name='bStatus', value=status),
            U8(name='bError', value=error),
            U8(name='bClockStatus', value=clock_status),
        ]
        super(R2PSlotStatus, self).__init__(name=name, fields=fields, fuzzable=fuzzable)


smartcard_IccPowerOff_response = R2PSlotStatus('smartcard_IccPowerOff_response', 0x00, 0x80, 0)
smartcard_GetSlotStatus_response = R2PSlotStatus('smartcard_GetSlotStatus_response', 0x00, 0x80, 0)
smartcard_IccClock_response = R2PSlotStatus('smartcard_IccClock_response', 0x00, 0x80, 0)
smartcard_T0APDU_response = R2PSlotStatus('smartcard_T0APDU_response', 0x00, 0x80, 0)


class R2PEscape(Template):

    def __init__(self, name, status, error, ab_data, fuzzable=True):
        fields = [
            U8(name='bMessageType', value=0x83),
            SizeInBytes(name='dwLength', sized_field='abData', length=32, fuzzable=True, encoder=ENC_INT_LE),
            DynamicInt(name='bSlot', key='bSlot', bitfield=U8(name='bSlotInt', value=0)),
            DynamicInt(name='bSeq', key='bSeq', bitfield=U8(name='bSeqInt', value=0)),
            U8(name='bStatus', value=status),
            U8(name='bError', value=error),
            U8(name='bRFU', value=0),
            Container(name='abData', fields=ab_data),
        ]
        super(R2PEscape, self).__init__(name=name, fields=fields, fuzzable=fuzzable)

smartcard_Escape_response = R2PEscape('smartcard_Escape_response', 0x00, 0x00, RandomBytes(name='data', value='', min_length=0, max_length=150))


class R2PDataRateAndClockFrequency(Template):

    def __init__(self, name, status, error, freq, rate, fuzzable=True):
        fields = [
            U8(name='bMessageType', value=0x84),
            SizeInBytes(name='dwLength', sized_field=ab_data, length=32, fuzzable=True, encoder=ENC_INT_LE),
            DynamicInt(name='bSlot', key='bSlot', bitfield=U8(name='bSlotInt', value=0)),
            DynamicInt(name='bSeq', key='bSeq', bitfield=U8(name='bSeqInt', value=0)),
            U8(name='bStatus', value=status),
            U8(name='bError', value=error),
            U8(name='bRFU', value=0),
            Container(name='abData', fields=[
                LE32(name='dwClockFrequency', value=freq),
                LE32(name='dwDataRate', value=rate),
            ]),
        ]
        super(R2PDataRateAndClockFrequency, self).__init__(name=name, fields=fields, fuzzable=fuzzable)


###################################################
#              CDC Class Templates                #
###################################################
class _CDC_DescriptorSubTypes:  # CDC Functional Descriptors

    '''Descriptor sub types [usbcdc11.pdf table 25]'''

    HEADER_FUNCTIONAL = 0
    CALL_MANAGMENT = 1
    ABSTRACT_CONTROL_MANAGEMENT = 2
    DIRECT_LINE_MANAGEMENT = 3
    TELEPHONE_RINGER = 4
    TELEPHONE_CALL = 5
    UNION_FUNCTIONAL = 6
    COUNTRY_SELECTION = 7
    TELEPHONE_OPERATIONAL_MODES = 8
    USB_TERMINAL = 9
    NETWORK_CHANNEL_TERMINAL = 0xa
    PROTOCOL_UNIT = 0xb
    EXTENSION_UNIT = 0xc
    MULTI_CHANNEL_MANAGEMENT = 0xd
    CAPI_CONTROL_MANAGEMENT = 0xe
    ETHERNET_NETWORKING = 0xf
    ATM_NETWORKING = 0x10
    # 0x11-0xff reserved


cdc_header_functional_descriptor = Descriptor(
    name='cdc_header_functional_descriptor',
    descriptor_type=_DescriptorTypes.CS_INTERFACE,
    fields=[
        UInt8(name='bDesciptorSubType', value=_CDC_DescriptorSubTypes.HEADER_FUNCTIONAL),
        LE16(name='bcdCDC', value=0xffff)
    ])


cdc_call_management_functional_descriptor = Descriptor(
    name='cdc_call_management_functional_descriptor',
    descriptor_type=_DescriptorTypes.CS_INTERFACE,
    fields=[
        UInt8(name='bDesciptorSubType', value=_CDC_DescriptorSubTypes.CALL_MANAGMENT),
        BitField(name='bmCapabilities', value=0, length=8),
        UInt8(name='bDataInterface', value=0)
    ])


# TODO: Missing descriptors for subtypes 3,4,5

cdc_abstract_control_management_functional_descriptor = Descriptor(
    name='cdc_abstract_control_management_functional_descriptor',
    descriptor_type=_DescriptorTypes.CS_INTERFACE,
    fields=[
        UInt8(name='bDesciptorSubType', value=_CDC_DescriptorSubTypes.ABSTRACT_CONTROL_MANAGEMENT),
        BitField(name='bmCapabilities', value=0, length=8)
    ])


cdc_union_functional_descriptor = Descriptor(
    name='cdc_union_functional_descriptor',
    descriptor_type=_DescriptorTypes.CS_INTERFACE,
    fields=[
        UInt8(name='bDesciptorSubType', value=_CDC_DescriptorSubTypes.UNION_FUNCTIONAL),
        UInt8(name='bMasterInterface', value=0),
        Repeat(UInt8(name='bSlaveInterfaceX', value=0), 0, 251)
    ])


# TODO: Missing descriptors 7,8,9,10,11,12,13,14

cdc_ethernet_networking_functional_descriptor = Descriptor(
    name='cdc_ethernet_networking_functional_descriptor',
    descriptor_type=_DescriptorTypes.CS_INTERFACE,
    fields=[
        UInt8(name='bDesciptorSubType', value=_CDC_DescriptorSubTypes.ETHERNET_NETWORKING),
        UInt8(name='iMACAddress', value=0),
        BitField(name='bmEthernetStatistics', value=0xffffffff, length=32),
        LE16(name='wMaxSegmentSize', value=1514),
        LE16(name='wNumberMCFilters', value=0),
        UInt8(name='bNumberPowerFilters', value=0)
    ])


###################################################
#              Audio Class Templates              #
###################################################
class _AC_DescriptorSubTypes:  # AC Interface Descriptor Subtype

    '''Descriptor sub types [audio10.pdf table A-5]'''

    AC_DESCRIPTOR_UNDEFINED = 0x00
    HEADER = 0x01
    INPUT_TERMINAL = 0x02
    OUTPUT_TERMINAL = 0x03
    MIXER_UNIT = 0x04
    SELECTOR_UNIT = 0x05
    FEATURE_UNIT = 0x06
    PROCESSING_UNIT = 0x07
    EXTENSION_UNIT = 0x08


class _AS_DescriptorSubTypes:  # AS Interface Descriptor Subtype

    '''Descriptor sub types [audio10.pdf table A-6]'''

    AS_DESCRIPTOR_UNDEFINED = 0x00
    AS_GENERAL = 0x01
    FORMAT_TYPE = 0x02
    FORMAT_SPECIFIC = 0x03


# TODO: audio_ep2_buffer_available

# TODO: remove?
audio_header_descriptor = Descriptor(
    name='audio_header_descriptor',
    descriptor_type=_DescriptorTypes.CS_INTERFACE,
    fields=[
        UInt8(name='bDesciptorSubType', value=_AC_DescriptorSubTypes.HEADER),
        LE16(name='bcdADC', value=0x0100),
        LE16(name='wTotalLength', value=0x1e),
        UInt8(name='bInCollection', value=0x1),
        Repeat(UInt8(name='baInterfaceNrX', value=1), 0, 247)
    ])

# TODO: remove?
audio_input_terminal_descriptor = Descriptor(
    descriptor_type=_DescriptorTypes.CS_INTERFACE,
    name='audio_input_terminal_descriptor',
    fields=[
        UInt8(name='bDesciptorSubType', value=_AC_DescriptorSubTypes.INPUT_TERMINAL),
        UInt8(name='bTerminalID', value=0x00),
        LE16(name='wTerminalType', value=0x0206),  # termt10.pdf table 2-2
        UInt8(name='bAssocTerminal', value=0x00),
        UInt8(name='bNrChannels', value=0x01),
        LE16(name='wChannelConfig', value=0x0101),
        UInt8(name='iChannelNames', value=0x00),
        UInt8(name='iTerminal', value=0x00)
    ])

# TODO: remove?
audio_output_terminal_descriptor = Descriptor(
    name='audio_output_terminal_descriptor',
    descriptor_type=_DescriptorTypes.CS_INTERFACE,
    fields=[
        UInt8(name='bDesciptorSubType', value=_AC_DescriptorSubTypes.OUTPUT_TERMINAL),
        UInt8(name='bTerminalID', value=0x00),
        LE16(name='wTerminalType', value=0x0307),  # termt10.pdf table 2-3
        UInt8(name='bAssocTerminal', value=0x00),
        UInt8(name='bSourceID', value=0x01),
        UInt8(name='iTerminal', value=0x00)
    ])

# Table 4-7
# TODO: remove?
audio_feature_unit_descriptor = Descriptor(
    name='audio_feature_unit_descriptor',
    descriptor_type=_DescriptorTypes.CS_INTERFACE,
    fields=[
        UInt8(name='bDesciptorSubType', value=_AC_DescriptorSubTypes.FEATURE_UNIT),
        UInt8(name='bUnitID', value=0x00),
        UInt8(name='bSourceID', value=0x00),
        SizedPt(name='bmaControls',
                fields=RandomBytes(name='bmaControlsX', value='\x00', min_length=0, step=17, max_length=249)),
        UInt8(name='iFeature', value=0x00)
    ])


# Table 4-19
# TODO: remove?
audio_as_interface_descriptor = Descriptor(
    name='audio_as_interface_descriptor',
    descriptor_type=_DescriptorTypes.CS_INTERFACE,
    fields=[
        UInt8(name='bDesciptorSubType', value=_AS_DescriptorSubTypes.AS_GENERAL),
        UInt8(name='bTerminalLink', value=0x00),
        UInt8(name='bDelay', value=0x00),
        LE16(name='wFormatTag', value=0x0001)
    ])


# TODO: remove?
audio_as_format_type_descriptor = Descriptor(
    name='audio_as_format_type_descriptor',
    descriptor_type=_DescriptorTypes.CS_INTERFACE,
    fields=[
        UInt8(name='bDesciptorSubType', value=_AS_DescriptorSubTypes.FORMAT_TYPE),
        UInt8(name='bFormatType', value=0x01),
        UInt8(name='bNrChannels', value=0x01),
        UInt8(name='bSubFrameSize', value=0x02),
        UInt8(name='bBitResolution', value=0x10),
        UInt8(name='bSamFreqType', value=0x01),
        BitField(name='tSamFreq', length=24, value=0x01F40)
    ])


audio_hid_descriptor = Descriptor(
    name='audio_hid_descriptor',
    descriptor_type=_DescriptorTypes.HID,
    fields=[
        DynamicInt('bcdHID', LE16(value=0x1001)),
        DynamicInt('bCountryCode', UInt8(value=0x00)),
        DynamicInt('bNumDescriptors', UInt8(value=0x01)),
        DynamicInt('bDescriptorType2', UInt8(value=_DescriptorTypes.HID_REPORT)),
        DynamicInt('wDescriptorLength', LE16(value=0x2b)),
    ]
)

# this descriptor is based on umap
# https://github.com/nccgroup/umap
# commit 3ad812135f8c34dcde0e055d1fefe30500196c0f
audio_report_descriptor = Template(
    name='audio_report_descriptor',
    fields=GenerateHidReport(
        '050C0901A1011500250109E909EA75019502810209E209008106050B092095018142050C09009503810226FF000900750895038102090095049102C0'.decode('hex')
    )
)

###################################################
#              HID Class Templates                #
###################################################

hid_descriptor = Descriptor(
    name='hid_descriptor',
    descriptor_type=_DescriptorTypes.HID,
    fields=[
        DynamicInt('bcdHID', LE16(value=0x0110)),
        DynamicInt('bCountryCode', UInt8(value=0x00)),
        DynamicInt('bNumDescriptors', UInt8(value=0x01)),
        DynamicInt('bDescriptorType2', UInt8(value=_DescriptorTypes.HID_REPORT)),
        DynamicInt('wDescriptorLength', LE16(value=0x27)),
    ])


# this descriptor is based on umap
# https://github.com/nccgroup/umap
# commit 3ad812135f8c34dcde0e055d1fefe30500196c0f
hid_report_descriptor = Template(
    name='hid_report_descriptor',
    fields=GenerateHidReport(
        '05010906A101050719E029E7150025017501950881029501750881011900296515002565750895018100C0'.decode('hex')
    )
)

# Crashing windows
# s_initialize('interface_descriptor')
# s_sizer(name='bLength', block_name='descriptor_block', length=1, fuzzable=False, inclusive=True)  # 9 Bytes
# if s_block_start('descriptor_block'):
#     UInt8(name='bDescriptorType', value=_DescriptorTypes.INTERFACE, fuzzable=True),
#     s_byte(name='bInterfaceNumber', value=0, fuzzable=False)
#     s_byte(name='bAlternateSetting', value=0, fuzzable=False)
#     s_byte(name='bNumEndpoints', value=0, fuzzable=False)
#     s_byte(name='bInterfaceClass', value=0x08, fuzzable=False)
#     s_byte(name='bInterfaceSubClass', value=0x06, fuzzable=False)
#     s_byte(name='bInterfaceProtocol', value=0x50, fuzzable=False)
#     s_byte(name='iInterface', value=0, fuzzable=True)
# s_block_end('descriptor_block')

from kitty.model import *

def CString(name, value):
    return Container(
        name=name,
        fields=[
            String(name=name, value=value),
            Static(name=name + '_term', value='\x00')
        ]
    )

def DomainString(name, value):
    parts = value.split('.')
    for i in range(len(parts)):
        part = String(name='part%d' % i, value=parts[i])
        lpart = SizeInBytes(name='part%d_len' % i, sized_field=part, length=8)


standard_query_response = Template(
    name='standard_query_response',
    fields=[
        Dynamic(name='transaction_id', key='transaction_id', default_value='12'),
        BE16(name='flags', value=0x8180),
        BE16(name='questions', value=1),  # should be length of some sort?
        BE16(name='answer_rrs', value=1),  # should be length of some sort?
        BE16(name='authority_rrs', value=1),  # should be length of some sort?
        BE16(name='additional_rrs', value=1),  # should be length of some sort?
        Container(
            name='queries',
            fields=[
                CString(name='name', value='checkip.dyndns.org'),
                LE16(name='type', value=0x1),
                LE16(name='class', value=0x1),
            ]
        ),
        Container(
            name='answers',
            fields=[
                BE16(name='name', value=0xc00c),
                BE16(name='type', value=0x5),  # CNAME
                BE16(name='class', value=0x1),  # IN
                BE32(name='ttl', value=0x115),
                SizeInBytes(name='data_length', sized_field='primary_name', length=16),
                CString(name='primary_name', value='checkip.dyndns.com')
            ]
        ),
        Container(
            name='authoritatives_nameservers',
            fields=[
                BE16(name='name', value=0xc038),
                BE16(name='type', value=0x2),  # NS
                BE16(name='class', value=0x1),  # IN
                BE32(name='ttl', value=0x56f0),
                # SizeInBytes(name='data_length', sized_field='nameserver', length=16),



            ]
        ),
        Container(
            name='addtional_records',
            fields=[
            ]
        )
    ]
)

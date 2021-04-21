# Functions to encode DMR and MMDVM
from dmr_utils3 import bptc, decode
from bitarray import bitarray
from binascii import b2a_hex as ahex
from bitarray.util import hex2ba as hex2bits
import random
from dmr_utils3.utils import bytes_3, int_id, get_alias, bytes_2, bytes_4
import re
import libscrc
from pathlib import Path

def create_crc16(fragment_input):
    crc16 = libscrc.gsm16(bytearray.fromhex(fragment_input))
    return fragment_input + re.sub('x', '0', str(hex(crc16 ^ 0xcccc))[-4:])

def create_crc32(fragment_input):
    # Create and append CRC32 to data 
    # Create list of hex
    word_list = []
    count_index = 0
    while count_index < len(fragment_input):
        word_list.append((fragment_input[count_index:count_index + 2]))
        count_index = count_index + 2
    # Create string of rearranged word_list to match ETSI 102 361-1 pg 141
    lst_index = 0
    crc_string = ''
    for i in (word_list):
        #print(lst_index)
        if lst_index % 2 == 0:
            crc_string =  crc_string + word_list[lst_index + 1]
            #print(crc_string)
        if lst_index % 2 == 1:
            crc_string = crc_string + word_list[lst_index - 1]
            #print(crc_string)
        lst_index = lst_index + 1
    # Create bytearray of word_list_string
   # print(crc_string)
    word_array = libscrc.posix(bytearray.fromhex(crc_string))
    # XOR to get almost final CRC
    pre_crc = str(hex(word_array ^ 0xffffffff))[2:]
    # Rearrange pre_crc for transmission
    crc = ''
    c = 8
    while c > 0:
        crc = crc + pre_crc[c-2:c]
        c = c - 2
    crc = crc.ljust(8, '0')
    print(crc)
    # Return original data and append CRC32
    print('Output: ' + fragment_input + crc)
    #print(len(crc.zfill(9)))
    return fragment_input + crc
def create_crc16_csbk(fragment_input):
    crc16_csbk = libscrc.gsm16(bytearray.fromhex(fragment_input))
    return fragment_input + re.sub('x', '0', str(hex(crc16_csbk ^ 0xa5a5))[-4:])
def csbk_gen(to_id, from_id):
    csbk_lst = ['BD00801a', 'BD008019', 'BD008018', 'BD008017', 'BD008016']

    send_seq_list = ''
    for block in csbk_lst:
        block = block + to_id + from_id
        block  = create_crc16_csbk(block)
        print(block)
        send_seq_list = send_seq_list + block
        print(send_seq_list)
    return send_seq_list
def mmdvm_encapsulate(dst_id, src_id, peer_id, _seq, _slot, _call_type, _dtype_vseq, _stream_id, _dmr_data):
    signature = 'DMRD'
    # needs to be in bytes
    frame_type = 0x10 #bytes_2(int(10))
    #print((frame_type))
    dest_id = bytes_3(int(dst_id, 16))
#    print((dest_id))

    #print(ahex(dest_id))
    source_id = bytes_3(int(src_id, 16))
    via_id = bytes_4(int(peer_id, 16))
   # print((source_id))
    #print(ahex(via_id))
    seq = int(_seq).to_bytes(1, 'big')
    #print(ahex(seq))
    # Binary, 0 for 1, 1 for 2
    slot = bitarray(str(_slot))
    #print(slot)
    # binary, 0 for group, 1 for unit, bin(1)
   # print(_call_type)
    call_type = bitarray(str(_call_type))
    #print(call_type)
    #0x00 for voice, 0x01 for voice sync, 0x10 for data 
    #frame_type = int(16).to_bytes(1, 'big')
    frame_type = bitarray('10')
    #print(frame_type)
    # Observed to be always 7, int. Will be 6 for header
    #dtype_vseq = hex(int(_dtype_vseq)).encode()
    if _dtype_vseq == 6:
        dtype_vseq = bitarray('0110')
    if _dtype_vseq == 7:
        dtype_vseq = bitarray('0111')
    if _dtype_vseq == 3:
        dtype_vseq = bitarray('0011')
    # 9 digit integer in hex
    stream_id = bytes_4(_stream_id)
    #print(ahex(stream_id))

    middle_guts = slot + call_type + frame_type + dtype_vseq
    #print(middle_guts)
    dmr_data = str(_dmr_data)[2:-1] #str(re.sub("b'|'", '', str(_dmr_data)))
    complete_packet = signature.encode() + seq + dest_id + source_id + via_id + middle_guts.tobytes() + stream_id + bytes.fromhex((dmr_data)) + bitarray('0000000000101111').tobytes()#bytes.fromhex(dmr_data)
    #print('Complete: ' + type(ahex(complete_packet)))
##    #print(hex2bits(ahex(complete_packet))[119:120])
    #print(bitarray.frombytes(ahex(complete_packet)))
    return complete_packet


### Sequence MMDVM packets from encoded DMR
##def seq_mmdvm(dmr_list):
##    cap_in = 0
##    mmdvm_send_seq = []
##    for i in dmr_list:
##        if cap_in < 8:
##            
##        if cap_in == 8:
##            #print('header')
##            the_mmdvm_pkt = mmdvm_encapsulate(3153597, 3153591, 9099, cap_in, 1, 1, 6, rand_seq, i) #(bytes.fromhex(re.sub("b'|'", '', str(orig_cap[cap_in][20:-4])))))
##        else:
##            #print('block')
##            the_mmdvm_pkt = mmdvm_encapsulate(3153597, 3153591, 9099, cap_in, 1, 1, 7, rand_seq, i)#(bytes.fromhex(re.sub("b'|'", '', str(orig_cap[cap_in][20:-4])))))
##        new_send_seq.append(ahex(the_mmdvm_pkt))
##        cap_in = cap_in + 1

# Break long string into block sequence
def block_sequence(input_string):
    seq_blocks = len(input_string)/24
    n = 0
    block_seq = []
    while n < seq_blocks:
        if n == 0:
            block_seq.append(bytes.fromhex(input_string[:24].ljust(24,'0')))
            n = n + 1
        else:
            block_seq.append(bytes.fromhex(input_string[n*24:n*24+24].ljust(24,'0')))
            n = n + 1
    return block_seq

# Takes list of DMR packets, 12 bytes, then encodes them
def dmr_encode(packet_list, _slot):
    send_seq = []
    for i in packet_list:
        stitched_pkt = bptc.interleave_19696(bptc.encode_19696(i))
        l_slot = bitarray('0111011100')
        #MS
        #sync_data = bitarray('110101011101011111110111011111111101011101010111')
        if _slot == 0:
            # TS1 - F7FDD5DDFD55
            sync_data = bitarray('111101111111110111010101110111011111110101010101')
        if _slot == 1:
            #TS2 - D7557F5FF7F5
            sync_data = bitarray('110101110101010101111111010111111111011111110101')
        # TS1
        #sync_data = bitarray('111101111111110111010101110111011111110101010101')
        #TS2
        #sync_data = bitarray('110101110101010101111111010111111111011111110101')
        r_slot = bitarray('1101110001')
        # Data sync? 110101011101011111110111011111111101011101010111 - D5D7F77FD757
        new_pkt = ahex(stitched_pkt[:98] + l_slot + sync_data + r_slot + stitched_pkt[98:])
        send_seq.append(new_pkt)
    return send_seq


def create_sms_seq(dst_id, src_id, peer_id, _slot, _call_type, dmr_string):
    rand_seq = random.randint(1, 999999)
    block_seq = block_sequence(dmr_string)
    dmr_list = dmr_encode(block_seq, _slot)
    cap_in = 0
    mmdvm_send_seq = []
    for i in dmr_list:
        #print(i)
        if use_csbk == True:
            if cap_in < 5:
                the_mmdvm_pkt = mmdvm_encapsulate(dst_id, src_id, peer_id, cap_in, _slot, _call_type, 3, rand_seq, i)
                #print(block_seq[cap_in])
                #print(3)
            if cap_in == 5:
                #print(block_seq[cap_in])
                #print(6)
                the_mmdvm_pkt = mmdvm_encapsulate(dst_id, src_id, peer_id, cap_in, _slot, _call_type, 6, rand_seq, i) #(bytes.fromhex(re.sub("b'|'", '', str(orig_cap[cap_in][20:-4])))))
            if cap_in > 5:
                #print(block_seq[cap_in])
                #print(7)
                the_mmdvm_pkt = mmdvm_encapsulate(dst_id, src_id, peer_id, cap_in, _slot, _call_type, 7, rand_seq, i)#(bytes.fromhex(re.sub("b'|'", '', str(orig_cap[cap_in][20:-4])))))
            mmdvm_send_seq.append(ahex(the_mmdvm_pkt))
            cap_in = cap_in + 1
        if use_csbk == False:
            if cap_in == 0:
                the_mmdvm_pkt = mmdvm_encapsulate(dst_id, src_id, peer_id, cap_in, _slot, _call_type, 6, rand_seq, i) #(bytes.fromhex(re.sub("b'|'", '', str(orig_cap[cap_in][20:-4])))))
            else:
                the_mmdvm_pkt = mmdvm_encapsulate(dst_id, src_id, peer_id, cap_in, _slot, _call_type, 7, rand_seq, i)#(bytes.fromhex(re.sub("b'|'", '', str(orig_cap[cap_in][20:-4])))))
            mmdvm_send_seq.append(ahex(the_mmdvm_pkt))
            cap_in = cap_in + 1
    with open('/tmp/.hblink_data_que/' + str(random.randint(1000, 9999)) + '.mmdvm_seq', "w") as packet_write_file:
                packet_write_file.write(str(mmdvm_send_seq))

    return mmdvm_send_seq
try:
    Path('/tmp/.hblink_data_que/').mkdir(parents=True, exist_ok=True)
except:
    pass

# Built for max length msg
def sms_headers(to_id, from_id):
##    #ETSI 102 361-2 uncompressed ipv4
##    # UDP header, src and dest ports are 4007, 0fa7
##    udp_ports = '0fa70fa7'
##    # Length, of what?
##    udp_length = '00da'
##    # Checksum
##    udp_checksum = '4b37'
##
##    # IPV4
##    #IPV4 version and header length, always 45
##    ipv4_v_l = '45'
##    #Type of service, always 00
##    ipv4_svc = '00'
##    #length, always 00ee
##    ipv4_len = '00ee'
##    #ID always 000d
##    ipv4_id = '000d'
##    #Flags and offset always0
##    ipv4_flag_off = '0000'
##    #TTL and Protocol always 4011, no matter what
##    ipv4_ttl_proto = '4011'
    #ipv4 = '450000ee000d0000401100000c' + from_id + '0c' + to_id
    #ipv4 = '450000ee00000000401100000c' + from_id + '0c' + to_id
    ipv4 = '450000ee00000000401100000c' + from_id + '0c' + to_id
    print(from_id)
    print(to_id)
    count_index = 0
    hdr_lst = []
    while count_index < len(ipv4):
        hdr_lst.append((ipv4[count_index:count_index + 4]))
        count_index = count_index + 4
    sum = 0
    for i in hdr_lst:
        sum = sum + int(i, 16)
    flipped = ''
    for i in str(bin(sum))[2:]:
        if i == '1':
            flipped = flipped + '0'
        if i == '0':
            flipped = flipped + '1'
    ipv4_chk_sum = str(hex(int(flipped, 2)))[2:]
    print(ipv4_chk_sum)
    header = ipv4[:20] + ipv4_chk_sum + ipv4[24:] +  '0fa70fa700da583100d0a00081040d000a'
    return header

def format_sms(msg, to_id, from_id):
    msg_bytes = str.encode(msg)
    encoded = "".join([str('00' + x) for x in re.findall('..',bytes.hex(msg_bytes))] )
    final = encoded
    while len(final) < 400:
        final = final + '002e'
    final = final + '0000000000000000000000'
    headers = sms_headers(to_id, from_id)
    return headers + final

def gen_header(to_id, from_id, call_type):
    #print(call_type)
    if call_type == 1:
        seq_header = '024A' + to_id + from_id + '9550'
    if call_type == 0:
        seq_header = '824A' + to_id + from_id + '9550'
    return seq_header

def send_sms(csbk, to_id, from_id, peer_id, call_type, slot, msg):
    global use_csbk
    #to_id = str(hex(to_id))[2:].zfill(6)
    #from_id = str(hex(from_id))[2:].zfill(6)
    to_id = str(hex(to_id))[2:].zfill(6)
    from_id = str(hex(from_id))[2:].zfill(6)
    peer_id = str(hex(peer_id))[2:].zfill(8)
    # Weird fix for redio not decoding, will fix later
    if len(str(int(from_id, 16))) >= 4 and len(str(int(from_id, 16))) <= 6:
        from_id = str('000000')
    if call_type == 'unit':
        new_call_type = 1
    if call_type == 'group':
        new_call_type = 0
    if csbk == 'yes':
        use_csbk = True
        create_sms_seq(to_id, from_id, peer_id, int(slot), new_call_type, csbk_gen(to_id, from_id) + create_crc16(gen_header(to_id, from_id, new_call_type)) + create_crc32(format_sms(msg, to_id, from_id)))
    else:
        use_csbk = False
        create_sms_seq(to_id, from_id, peer_id, int(slot), new_call_type, create_crc16(gen_header(to_id, from_id, new_call_type)) + create_crc32(format_sms(msg, to_id, from_id)))
    print('Call type: ' + call_type)
    print('Destination: ' + str(to_id))
    print('Source: ' + str(from_id))
    print('Message: ' + msg)
    print('Use CSBK: ' + str(use_csbk))
    print('Slot: ' + str(int(slot)))

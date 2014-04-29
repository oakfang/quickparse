import struct
import re
from StringIO import StringIO
from operator import add
from collections import defaultdict


STRUCT_CONSTS = {'big endian': '>',
                 'little endian': '<',
                 'network': '!',
                 'char': 'c',
                 'byte': 'b',
                 'unsigned byte': 'B',
                 'bool': '?',
                 'short': 'h',
                 'unsigned short': 'H',
                 'int': 'i',
                 'unsigned int': 'I',
                 'long': 'q',
                 'unsigned long': 'Q',
                 'int8': 'b',
                 'uint8': 'B',
                 'int16': 'h',
                 'uint16': 'H',
                 'int32': 'i',
                 'uint32': 'I',
                 'int64': 'q',
                 'uint64': 'Q',
                 'float': 'f',
                 'double': 'd',
                 'string *\( *(\d+) *\)': '\\1s',
                 'string *\( *([a-zA-Z_][a-zA-Z0-9_]+) *\)': '#{\\1}s'}


class Parser(object):
    BRANCHES = ()
    NAMESPACE = ''
    EXTENDED_PROPERTIES = []
    ENDIANITY = STRUCT_CONSTS['network']
    DEFINITION = ''

    def __init__(self):
        self._def_list = self._define_block(self.DEFINITION)
        self._fields = [d[0] for d in self._def_list]
        self._struct_def = self.ENDIANITY + reduce(add, [d[1] for d in self._def_list])

    def __repr__(self):
        return "<Parser of {}>".format(self.NAMESPACE)

    def _line_to_def_tuple(self, line):
        sline = line.split()
        stype, field = ' '.join(sline[:-1]), sline[-1]
        for const, val in STRUCT_CONSTS.iteritems():
            if not re.match(const, stype, re.IGNORECASE):
                continue
            stype = re.sub('^'+const+'$', val, stype.lower())
        return field, stype

    def _define_block(self, definition):
        lines = filter(bool, map(lambda s: s.strip(), definition.split(';')))
        return map(self._line_to_def_tuple, lines)

    @classmethod
    def branch(cls, bcls):
        bcls.NAMESPACE = cls.NAMESPACE
        cls.BRANCHES += (bcls,)
        return bcls

    def validate(self, packet):
        return True

    def _parse_partial(self, struct_info, data, field_offset):
        try:
            return {self._fields[field_offset:][i]: value for i, value
                    in enumerate(struct.unpack(struct_info,
                                               data))}
        except:
            raise RuntimeError("{} {}".format(struct_info, data))

    def _parse_segment(self, packet, layer):
        raw = StringIO(packet.data)
        struct_info = self._struct_def
        var_index = struct_info.find('#{')
        end_var_index = struct_info.find('}')
        parsed_data = {}

        while var_index != -1:
            to_parse = raw.read(struct.calcsize(struct_info[:var_index]))
            parsed_data.update(self._parse_partial(struct_info[:var_index],
                                                   to_parse, len(parsed_data)))
            var = struct_info[var_index + 2:end_var_index]
            var_value = parsed_data[var] if isinstance(parsed_data[var],
                                                       (int, long)) else len(parsed_data[var])
            struct_info = str(var_value) + struct_info[end_var_index + 1:]
            var_index = struct_info.find('#{')
            end_var_index = struct_info.find('}')

        to_parse = raw.read(struct.calcsize(struct_info))
        parsed_data.update(self._parse_partial(struct_info, to_parse, len(parsed_data)))
        packet.data = raw.read()
        return parsed_data

    def parse(self, packet):
        if not self.validate(packet):
            return False
        if not hasattr(packet, self.NAMESPACE):
            setattr(packet, self.NAMESPACE, type(self.NAMESPACE, (object,), {}))
        layer = getattr(packet, self.NAMESPACE)
        for f, v in self._parse_segment(packet, layer).iteritems():
            setattr(layer, f, v)
        for prop in self.EXTENDED_PROPERTIES:
            method = getattr(self, prop)
            setattr(layer, method.im_func.func_name, method(layer))
        for branch in self.BRANCHES:
            ibranch = branch()
            ibranch.parse(packet)
        return True


class PacketContainer(object):
    def __init__(self, raw):
        self.data = raw


class ParsingChain(object):
    def __init__(self):
        self.chain = defaultdict(list)

    def add(self, parser, follower):
        self.chain[parser].append(follower)

    def __getitem__(self, namespace):
        if namespace is None:
            return self.chain[None]
        parser = filter(lambda p: p.NAMESPACE == namespace, self.chain)
        return self.chain[parser]

    def parse(self, packet):
        parsers = self[None]
        while parsers:
            for parser in parsers:
                iparser = parser()
                if iparser.parse(packet):
                    parsers = self.chain.get(parser)
                    break
            else:
                parsers = []


class StreamReader(object):
    def __init__(self, data):
        self.data = StringIO(data)

    def next(self):
        return PacketContainer(self.data.read(20))

    def __getitem__(self, index):
        orig_pos = self.data.tell()
        self.restart()
        for _ in xrange(index + 1):
            packet = self.next()
        self.data.seek(orig_pos)
        return packet

    def restart(self):
        self.data.seek(0)


class PcapHeader(Parser):
    NAMESPACE = 'header'
    DEFINITION = """
                 uint32 magic;
                 uint16 major_version;
                 uint16 minor_version;
                 int32 thiszone;
                 uint32 sigfigs;
                 uint32 snaplen;
                 uint32 network;
                 """
    ENDIANITY = STRUCT_CONSTS['little endian']


class PcapPacket(Parser):
    NAMESPACE = 'pcap'
    DEFINITION = """
                 unsigned long timestamp;
                 uint32 bizzare;
                 uint32 packet_length;
                 """
    ENDIANITY = STRUCT_CONSTS['little endian']


class PcapStreamReader(StreamReader):
    def __init__(self, cap, chain):
        self.data = open(cap, 'rb')
        self.chain = chain
        header_packet = PacketContainer(self.data.read(24))
        PcapHeader().parse(header_packet)
        self.header = header_packet.header
        self.base = PcapPacket()

    def restart(self):
        self.data.seek(24)

    def next(self):
        temp = PacketContainer(self.data.read(16))
        self.base.parse(temp)
        packet = PacketContainer(self.data.read(temp.pcap.packet_length))
        self.chain.parse(packet)
        return packet


################################### TESTING
import socket


class Ethernet(Parser):
    NAMESPACE = 'ether'
    DEFINITION = """
                 string(6) dst_mac_raw;
                 string(6) src_mac_raw;
                 uint8 next_protocol;
                 """
    EXTENDED_PROPERTIES = ['src_mac', 'dst_mac']

    def src_mac(self, layer):
        src_mac_hex = layer.src_mac_raw.encode('hex')
        return ':'.join([src_mac_hex[i]+src_mac_hex[i+1] for i in xrange(0, 11, 2)])

    def dst_mac(self, layer):
        src_mac_hex = layer.dst_mac_raw.encode('hex')
        return ':'.join([src_mac_hex[i]+src_mac_hex[i+1] for i in xrange(0, 11, 2)])


class IP(Parser):
    NAMESPACE = 'ip'
    DEFINITION = """
                 uint8 version_header_length;
                 uint8 diff;
                 uint16 length;
                 uint16 id;
                 uint8 flags;
                 uint16 fragmant;
                 uint8 ttl;
                 uint8 protocol;
                 uint16 checksum;
                 string(4) src_ip_raw;
                 string(4) dst_ip_raw;
                 """
    EXTENDED_PROPERTIES = ['src_ip', 'dst_ip']

    def validate(self, packet):
        return packet.ether.next_protocol == 8

    def src_ip(self, layer):
        return socket.inet_ntoa(layer.src_ip_raw)

    def dst_ip(self, layer):
        return socket.inet_ntoa(layer.dst_ip_raw)


class UDP(Parser):
    NAMESPACE = 'udp'
    DEFINITION = ("uint16 src_port;"
                  "uint16 dst_port;"
                  "uint16 length;"
                  "uint16 checksum;")

    def validate(self, packet):
        return packet.ip.protocol == 17


if __name__ == "__main__":
    binds = ParsingChain()
    binds.add(None, Ethernet)
    binds.add(Ethernet, IP)
    binds.add(IP, UDP)

    cap = PcapStreamReader("cap.pcap", binds)
    p = cap[0]
    print p.udp.dst_port

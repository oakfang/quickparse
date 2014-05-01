import re
import os
import tokenize as tok
from StringIO import StringIO
from importlib import import_module
from functools import partial
from cPickle import dump as pickle_dump, load as pickle_load, HIGHEST_PROTOCOL
from qparse import Parser, STRUCT_CONSTS


UNSIGNED = 'unsigned'
STRING = 'string'
CHAR = 'char'
INT = 'int'
FLOAT = 'float'
CHAR = 'char'
LONG = 'long'
UINT16 = 'uint16'
BOOL = 'bool'
UINT32 = 'uint32'
INT32 = 'int32'
INT16 = 'int16'
UINT8 = 'uint8'
BYTE = 'byte'
INT8 = 'int8'
UINT64 = 'uint64'
SHORT = 'short'
DOUBLE = 'double'
INT64 = 'int64'
VARS = (UNSIGNED, STRING, CHAR, INT, FLOAT, CHAR, LONG, UINT16, BOOL, UINT32, INT32, INT16, UINT8,
        BYTE, INT8, UINT64, SHORT, DOUBLE, INT64)


VALIDATE = 'validate'
BRANCH = 'branch'
AS = 'as'
PROPERTY = 'property'
RESERVED_NAMES = (VALIDATE, BRANCH, AS, PROPERTY)


PROTOCOL = 'protocol'
IMPORT = 'import'
COMMENT = '#'


SBLOCK = '{'
EBLOCK = '}'


COMPILED_SIGNATURE = 'QuickParseY'


def syntax(condition, msg=''):
    if not condition:
        raise SyntaxError(msg)


class Scope(object):
    def __init__(self, **kwargs):
        self.inner_scopes = []
        for k, v in kwargs.iteritems():
            setattr(self, k, v)


class GlobalScope(Scope):
    def __init__(self):
        super(GlobalScope, self).__init__(imports={})
        self._moduls = None

    def add_import(self, module, monicre=None):
        monicre = monicre or module
        self.imports[monicre] = module

    def make(self):
        self._moduls = {monicre: import_module(module)
                        for monicre, module in self.imports.iteritems()}

    def get_modules(self):
        if self._moduls is None:
            self.make()
        return self._moduls.copy()

    def __str__(self):
        sio = StringIO()
        sio.write('from qparse import Parser, STRUCT_CONSTS\n')
        for monicre, mod in self.imports.iteritems():
            sio.write('import {} as {}\n'.format(mod, monicre))
        sio.write('\n\n')
        for proto in self.inner_scopes:
            sio.write(proto)
        sio.seek(0)
        return sio.read().replace('\t', ' ' * 4)


class ProtocolScope(Scope):
    def __init__(self, name, global_scope):
        super(ProtocolScope, self).__init__(name=name, fields=[], sources={}, endianity="network")
        self._global = global_scope

    def add_branch(self, branch):
        self.inner_scopes.append(branch)

    def make(self):
        validate = {'validate': lambda s, p: True}
        properties = {}
        if 'validate' in self.sources:
            exec self.sources['validate'] in self._global.get_modules(), validate
        for prop in filter(lambda s: s != 'validate', self.sources):
            exec self.sources[prop] in self._global.get_modules(), properties
        protocol_dict = {'NAMESPACE': self.name,
                         'ENDIANITY': STRUCT_CONSTS[self.endianity],
                         'DEFINITION': ';'.join(self.fields),
                         'validate': validate['validate'],
                         'EXTENDED_PROPERTIES': properties.keys()}
        protocol_dict.update(properties)
        protocol = type(self.name,
                        (Parser,),
                        protocol_dict)
        for branch in self.inner_scopes:
            protocol.branch(branch.make())
        return protocol

    def __str__(self):
        sio = StringIO()
        sio.write('class {}(Parser):\n'.format(self.name))
        sio.write('\tNAMESPACE = "{}"\n'.format(self.name))
        sio.write('\tENDIANITY = STRUCT_CONSTS["{}"]\n'.format(self.endianity))
        sio.write('\tDEFINITION = "{}"\n'.format(';'.join(self.fields)))
        sio.write('\tEXTENDED_PROPERTIES = {}\n'.format(filter(lambda s: s != 'validate',
                                                               self.sources)))
        sio.write('\n')
        for source in self.sources.itervalues():
            source = source.replace('\r', '\n')
            for line in source.split('\n'):
                if line:
                    sio.write('\t{}\n'.format(line))
            sio.write('\n')
        sio.write('\n')
        for branch in self.inner_scopes:
            sio.write('@{}.branch\n'.format(self.name))
            sio.write(branch)
        sio.seek(0)
        return sio.read()


class QPTokenizer(object):
    def __init__(self):
        self._gen = None
        self.globals = None
        self.guide = {COMMENT: self.handle_comment,
                      PROTOCOL: partial(self.handle_branch, main=True),
                      BRANCH: self.handle_branch,
                      IMPORT: self.handle_import}

    def factory(self, token, scope=None):
        if scope is None:
            syntax(token in (PROTOCOL, IMPORT),
                   'Expected "protocol" or "import" at global scope, not ' + token)
            return self.guide[token]()
        return self.guide[token](scope)

    def _init_token_gen(self, src):
        self._gen = tok.generate_tokens(src.readline)
        self.globals = GlobalScope()
        self.imports = {}

    def gtok(self):
        tk, val, _, _, _ = self._gen.next()
        return tk, val

    def gtok_line(self):
        tk, val, _, _, line = self._gen.next()
        return tk, val, line

    def gtok_skipnl(self, pline=False):
        tk, val, line = self.gtok_line()
        while tk in (tok.NL, tok.NEWLINE):
            tk, val, line = self.gtok_line()
        return (tk, val, line) if pline else (tk, val)

    def assert_new_line(self):
        syntax(self.gtok()[0] in (tok.NL, tok.NEWLINE), 'There shoulb be a new line here.')

    def get_name(self):
        tk, val = self.gtok()
        syntax(tk == tok.NAME, 'There should be a name token here.')
        return val

    def handle_import(self):
        mod = self.get_name()
        monicre = mod
        tk, val = self.gtok()
        syntax(tk in (tok.NL, tok.NEWLINE) or val == AS)
        if tk not in (tok.NL, tok.NEWLINE):
            monicre = self.get_name()
        self.globals.add_import(mod, monicre)
        return self.gtok_skipnl()[1]

    def handle_branch(self, scope=None, main=False):
        proto = ProtocolScope(self.get_name(), self.globals)
        if main:
            self.globals.inner_scopes.append(proto)
        else:
            scope.add_branch(proto)
        self.handle_protocol_block(proto)

    def handle_comment(self):
        tk, _ = self.gtok()
        while not tk in (tok.NL, tok.NEWLINE):
            tk, _ = self.gtok()

    def handle_endianity(self, scope):
        bufr = []
        tk, val = self.gtok()
        while not tk in (tok.NL, tok.NEWLINE):
            bufr.append(val)
            tk, val = self.gtok()
        scope.endianity = ' '.join(bufr)

    def handle_protocol_block(self, scope):
        tk, val = self.gtok_skipnl()
        syntax(tk == tok.OP and val == SBLOCK, 'There should be a block starter here.')
        self.assert_new_line()
        tk, val = self.gtok_skipnl()
        while not (tk == tok.OP and val == EBLOCK):
            syntax(tk in (tok.NAME, tok.COMMENT), '{}: {}'.format(tk, repr(val)))
            if tk == tok.NAME:
                if val not in RESERVED_NAMES:
                    self.handle_var(scope, val)
                elif val == BRANCH:
                    self.handle_branch(scope)
                elif val == VALIDATE:
                    self.handle_validate(scope)
                elif val == AS:
                    self.handle_endianity(scope)
                elif val == PROPERTY:
                    self.handle_property(scope)
            elif tk == tok.COMMENT:
                self.handle_comment()
            tk, val = self.gtok_skipnl()

    def handle_var(self, scope, first_token):
        syntax(first_token in VARS, "Unexpected name token: " + first_token)
        bfr = [first_token]
        tk, val = self.gtok()
        while tk not in (tok.NL, tok.NEWLINE):
            bfr.append(val)
            tk, val = self.gtok()
        scope.fields.append(' '.join(bfr))

    def handle_function_block(self, scope, func_name, params):
        native_string = 'def {}({}):\n'.format(func_name, ', '.join(params))
        tk, val = self.gtok_skipnl()
        syntax(tk == tok.OP and val == SBLOCK, 'There should be a block starter here.')
        lines = []
        insertion_flag = False
        braces_level = 0
        tk, val, line = self.gtok_skipnl(True)
        while not(tk == tok.OP and val == EBLOCK) and not braces_level:
            if not insertion_flag:
                lines.append(line)
                insertion_flag = True
            if val == SBLOCK:
                braces_level += 1
            elif val == EBLOCK:
                braces_level -= 1
            elif tk in (tok.NL, tok.NEWLINE):
                insertion_flag = False
            tk, val, line = self.gtok_line()
        offset = len(min([re.match('(\s*)\w', line).groups(1)[0] for line in lines]))
        for line in lines:
            native_string += (' ' * 4) + line[offset:].replace('\t', ' ' * 4)
        scope.sources[func_name] = native_string

    def handle_validate(self, scope):
        param = self.get_name()
        self.handle_function_block(scope, 'validate', ('self', param))

    def handle_property(self, scope):
        func_name = self.get_name()
        param = self.get_name()
        self.handle_function_block(scope, func_name, ('self', param))

    def compile_source(self, src):
        self._init_token_gen(src)
        cmd = self.get_name()
        try:
            while cmd is not None:
                cmd = self.factory(cmd)
        except StopIteration:
            pass

    def parse_source(self, src):
        self.compile_source(src)
        return {proto.name: proto.make() for proto in self.globals.inner_scopes}

    def parse_file(self, path):
        with open(path, 'rb') as qp:
            return self.parse_source(qp)

    def parse_string(self, string):
        return self.parse_source(StringIO(string))


def compile_file(path, to_python=False):
    qpt = QPTokenizer()
    with open(path, 'rb') as qp:
        qpt.compile_source(qp)
    base_dir, parser = os.path.split(path)
    if not to_python:
        cparser = parser + 'y'
        cfile = open(os.path.join(base_dir, cparser), 'wb')
        cfile.write(COMPILED_SIGNATURE)
        pickle_dump(qpt.globals, cfile, HIGHEST_PROTOCOL)
    else:
        cparser = parser.split('.')[0] + '.py'
        cfile = open(os.path.join(base_dir, cparser), 'wb')
        cfile.write(str(qpt.globals))


def import_parser(path, auto=True, from_raw=True):
    qpt = QPTokenizer()
    if (auto and path.endswith('qpy')) or (not auto and not from_raw):
        cfile = open(path, 'rb')
        assert cfile.read(len(COMPILED_SIGNATURE)) == COMPILED_SIGNATURE, "Wrong file format"
        dump = pickle_load(cfile)
        return {proto.name: proto.make() for proto in dump.inner_scopes}
    elif (auto and path.endswith('qp')) or (not auto and from_raw):
        return qpt.parse_file(path)
    else:
        raise ValueError("auto parser path should end with .qp for raw parsers, "
                         "or .qpy for compiled ones.")


if __name__ == "__main__":
    from qparse import Ethernet, IP, ParsingChain, PacketContainer
    from operator import add
    compile_file('jambo.qp', True)
    JamboParser = import_parser('jambo.qpy')['jambo']
    binds = ParsingChain()
    binds.add(None, Ethernet)
    binds.add(Ethernet, IP)
    binds.add(IP, JamboParser)
    data = add(add('00000011111100000022222208'.decode('hex'),
                   '\x00'*13),
               add('010101010000000011111111111100000000010004'.decode('hex'),
                   'hell'))
    packet = PacketContainer(data)
    binds.parse(packet)
    print packet.jambo.dst_ip
    print packet.jambo.name

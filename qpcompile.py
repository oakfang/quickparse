import re
import os
import tokenize as tok
from StringIO import StringIO
from importlib import import_module
from types import ModuleType
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


SBLOCK = '{'
EBLOCK = '}'


def syntax(condition, msg=''):
    if not condition:
        raise SyntaxError(msg)


class QPTokenizer(object):
    def __init__(self, save_sources=False):
        self._save_sources = save_sources
        self._gen = None
        self.globals = None
        self.imports = {}

    def _init_token_gen(self, src):
        self._gen = tok.generate_tokens(src.readline)
        self.globals = None
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

    def handle_branch(self, lcl=None, main=False):
        pglb = {"name": self.get_name(), "fields": [], "validate": lambda s, p: True,
                "branches": [], "endianity": 'network', "properties": {}, "sources": {}}
        if main:
            self.globals = pglb
        else:
            lcl["branches"].append(pglb)
        self.handle_block(pglb)

    def handle_comment(self):
        tk, _ = self.gtok()
        while not tk in (tok.NL, tok.NEWLINE):
            tk, _ = self.gtok()

    def handle_endianity(self, lcl):
        bufr = []
        tk, val = self.gtok()
        while not tk in (tok.NL, tok.NEWLINE):
            bufr.append(val)
            tk, val = self.gtok()
        lcl['endianity'] = ' '.join(bufr)

    def handle_block(self, lcl):
        tk, val = self.gtok_skipnl()
        syntax(tk == tok.OP and val == SBLOCK, 'There should be a block starter here.')
        self.assert_new_line()
        tk, val = self.gtok_skipnl()
        while not (tk == tok.OP and val == EBLOCK):
            syntax(tk in (tok.NAME, tok.COMMENT), '{}: {}'.format(tk, repr(val)))
            if tk == tok.NAME:
                if val not in RESERVED_NAMES:
                    self.handle_var(lcl, val)
                elif val == BRANCH:
                    self.handle_branch(lcl)
                elif val == VALIDATE:
                    self.handle_validate(lcl)
                elif val == AS:
                    self.handle_endianity(lcl)
                elif val == PROPERTY:
                    self.handle_property(lcl)
            elif tk == tok.COMMENT:
                self.handle_comment()
            tk, val = self.gtok_skipnl()

    def handle_var(self, lcl, first_token):
        syntax(first_token in VARS, "Unexpected name token: " + first_token)
        bfr = [first_token]
        tk, val = self.gtok()
        while tk not in (tok.NL, tok.NEWLINE):
            bfr.append(val)
            tk, val = self.gtok()
        lcl['fields'].append(' '.join(bfr))

    def handle_function_block(self, lcl, func_name, params, context=None):
        context = context or {}
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
        exec native_string in self.imports, context
        return context[func_name], native_string

    def handle_validate(self, lcl):
        param = self.get_name()
        _, source = self.handle_function_block(lcl, 'validate', ('self', param), lcl)
        if self._save_sources:
            lcl['sources']['validate'] = source

    def handle_property(self, lcl):
        func_name = self.get_name()
        param = self.get_name()
        lcl['properties'][func_name], source = self.handle_function_block(lcl, func_name,
                                                                          ('self', param))
        if self._save_sources:
            lcl['sources'][func_name] = source

    def _get_protocol(self, lcl):
        protocol_dict = {'NAMESPACE': lcl['name'],
                         'ENDIANITY': STRUCT_CONSTS[lcl['endianity']],
                         'DEFINITION': ';'.join(lcl['fields']),
                         'validate': lcl['validate'],
                         'EXTENDED_PROPERTIES': lcl['properties'].keys()}
        protocol_dict.update(lcl['properties'])
        protocol = type(lcl['name'],
                        (Parser,),
                        protocol_dict)
        for branch in lcl['branches']:
            protocol.branch(self._get_protocol(branch))
        return protocol

    def compile_source(self, src):
        self._init_token_gen(src)
        cmd = self.get_name()
        while cmd == IMPORT:
            mod = self.get_name()
            monicre = mod
            tk, val = self.gtok()
            syntax(tk in (tok.NL, tok.NEWLINE) or val == AS)
            if tk not in (tok.NL, tok.NEWLINE):
                monicre = self.get_name()
            self.imports[monicre] = import_module(mod)
            cmd = self.gtok_skipnl()[1]
        syntax(cmd == PROTOCOL, 'Expected "protocol" at file start, not ' + cmd)
        self.handle_branch(main=True)
        return self.globals, self.imports

    def parse_source(self, src):
        compiled, _ = self.compile_source(src)
        return self._get_protocol(compiled)

    def parse_file(self, path):
        with open(path, 'rb') as qp:
            return self.parse_source(qp)

    def parse_string(self, string):
        return self.parse_source(StringIO(string))


def _clean_compiled(cdict):
    del cdict['validate']
    del cdict['properties']
    for branch in cdict['branches']:
        _clean_compiled(branch)


def compile_file(path):
    qpt = QPTokenizer(True)
    with open(path, 'rb') as qp:
        compiled, imports = qpt.compile_source(qp)
    imported = {name: mod.__name__ for name, mod in imports.iteritems() if isinstance(mod,
                                                                                      ModuleType)}
    _clean_compiled(compiled)
    dump = {'tree': compiled, 'imports': imported}
    base_dir, parser = os.path.split(path)
    cparser = parser + 'y'
    pickle_dump(dump, open(os.path.join(base_dir, cparser), 'wb'), HIGHEST_PROTOCOL)


def _dynamic_compile_tree(tree, imports):
    tree['validate'] = lambda s, p: True
    tree['properties'] = {}
    if 'validate' in tree['sources']:
        exec tree['sources']['validate'] in imports, tree
        del tree['sources']['validate']
    for func in tree['sources']:
        exec tree['sources'][func] in imports, tree['properties']
    for branch in tree['branches']:
        _dynamic_compile_tree(branch, imports)


def import_parser(path):
    qpt = QPTokenizer()
    if path.endswith('qpy'):
        dump = pickle_load(open(path, 'rb'))
        imports = {name: import_module(modname) for name, modname in dump['imports'].iteritems()}
        compiled = dump['tree']
        _dynamic_compile_tree(compiled, imports)
        return qpt._get_protocol(compiled)
    elif path.endswith('qp'):
        return qpt.parse_file(path)
    else:
        raise ValueError("parser path should end with .qp for raw parsers, "
                         "or .qpy for compiled ones.")


if __name__ == "__main__":
    from qparse import Ethernet, IP, ParsingChain, PacketContainer
    from operator import add
    compile_file('jambo.qp')
    JamboParser = import_parser('jambo.qpy')
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

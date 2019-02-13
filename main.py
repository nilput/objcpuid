# author: nilput <github.com/nilput>
# to install dependencies:
#   pip install capstone
#   pip install pyelftools

from capstone import *
from elftools.elf.elffile import ELFFile
from types import SimpleNamespace as Namespace
import argparse
import functools

opts = Namespace(**{
        'print_disassembly' : False, 
        'debug' : False, 
        'summary' : False,
        'print_section_names' : False,
        'watchlist' : [],
        })


#stores the section number in the elf, the symbol name, its start and size
class Symbol_Loc:
    def __init__(self, section_num, name, start, size):
        assert(isinstance(section_num, int))
        assert(isinstance(name, str))
        assert(isinstance(start, int))
        assert(isinstance(size, int))
        self.section_num = section_num
        self.name = name
        self.start = start
        self.size = size
    #returns -1, 0, 1 (left - right)
    @staticmethod
    def cmp(left, right):
        assert(left.section_num == right.section_num) #only syms of the same section are meant to be compared
        if left.start != right.start:
            return 1 if left.start > right.start else -1
        return 0
    #used to sort a list of these by address so that we can binary search
    @staticmethod
    def cmpkey():
        return functools.cmp_to_key(Symbol_Loc.cmp)

def binary_search1(val_list, val, left, right, cmp_func):
    lend = right
    while True:
        mid = (left + right + 1) // 2
        cmp_result = cmp_func(val_list[mid], val) 
        if cmp_result > 0: #middle is larger
            right = mid - 1
        elif cmp_result < 0: #middle is smaller
            left  = mid + 1
        else:
            return (mid, mid)
        if left > right:
            break
    return (-1, mid)

def binary_search(val_list, val, cmp_func):
    idx, mid = binary_search1(val_list, val, 0, len(val_list) - 1, cmp_func)
    return idx

#if it doesnt find the key, then it returns the index of the minimum key before it
#if there's nothing before it, it returns -1
def binary_search_min(val_list, val, cmp_func):
    llen = len(val_list) 
    idx, mid = binary_search1(val_list, val, 0, llen - 1, cmp_func)
    if idx == -1 and mid >= 0:
        while mid > 0 and cmp_func(val_list[mid], val) > 0:
            mid -= 1
        if cmp_func(val_list[mid], val) < 0: #smaller than val
            idx = mid
    return idx


#stores a bunch of symbols in their respective sections
class Sym_Registry:
    def __init__(self):
        self.sects = {}
    def get_address(self, section_num, address):
        #binary search
        if section_num not in self.sects:
            return None
        def cmp(left, right_address):
            assert(isinstance(left, Symbol_Loc))
            return left.start - right_address
        idx = binary_search_min(self.sects[section_num], address, cmp)
        if idx == -1:
            return None
        return self.sects[section_num][idx]
    def add_symbol(self, sym):
        assert(isinstance(sym, Symbol_Loc))
        if sym.section_num not in self.sects:
            self.sects[sym.section_num] = []
        self.sects[sym.section_num].append(sym)
        self.sects[sym.section_num].sort(key = Symbol_Loc.cmpkey())

def process_text_section(elffile, section_num, registry):
    arch = elffile.get_machine_arch()
    if arch != 'x64':
        print("error, only 'X86_64' supported, found: {}".format(arch))
        return
    section = elffile.get_section(section_num)
    code = section.data()
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    last_name = ''
    name_changed = False
    insn_group_map = {}
    for i in md.disasm(code, 0x0000):
        if i.id == 0:
            if opts.debug:
                print(':skipped an instruction at {}'.format(i.address)) 
            continue
        address = i.address
        symloc = registry.get_address(section_num, address)
        if symloc.name != last_name:
            last_name = symloc.name
            name_changed = True
        for grp in i.groups:
            grp_name = i.group_name(grp)
            if grp_name not in insn_group_map:
                insn_group_map[grp_name] = 0
            if grp_name in opts.watchlist:
                print('{} instruction at function {}:'.format(grp_name, last_name))
                print("0x{:x}:\t{}\t{}\n".format(i.address, i.mnemonic, i.op_str))
            insn_group_map[grp_name] = insn_group_map[grp_name] + 1
        if opts.print_disassembly:
            if name_changed:
                print('{}:'.format(symloc.name)) #print function names
                name_changed = False
            print("\t\t0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    if opts.summary:
        if not len(insn_group_map):
            print('no instructions found')
        sorted_list = list(insn_group_map.items())
        sorted_list.sort(key = lambda x: x[1])
        for group_name, count in sorted_list:
            print('{}:\t{}'.format(group_name,count))


def process_symtab(elffile, section_num, registry):
    section = elffile.get_section(section_num)
    for symbol in section.iter_symbols():
        if not isinstance(symbol.entry['st_shndx'], int):
            if opts.debug:
                print('skipped entry: {} because of its st_shndx: {}'.format(symbol.name, symbol.entry['st_shndx']))
            continue
        if opts.debug:
            print('symbol: "{}" located at idx:{} start: 0x{:x}, size: 0x{:x}'.format(
                                                                                symbol.name,
                                                                                symbol.entry['st_shndx'],
                                                                                symbol.entry['st_value'],
                                                                                symbol.entry['st_size']))
        symloc = Symbol_Loc(symbol.entry['st_shndx'], #section index
                            symbol.name, 
                            symbol.entry['st_value'], #start address
                            symbol.entry['st_size']) #size
        registry.add_symbol(symloc)
    
def process_file(filename):
    print('file: ', filename)
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)
        symreg = Sym_Registry()
        text_sections_nums = []
        for i,section in enumerate(elffile.iter_sections()):
            if opts.print_section_names:
                print('  ' + section.name)
            if section.name == '.text':
                text_sections_nums.append(i)
            if section.name == '.symtab':
                process_symtab(elffile, i, symreg)
        for section_num in text_sections_nums:
            process_text_section(elffile, section_num, symreg)

def main():
    parser = argparse.ArgumentParser(description='cpu feature detector')
    parser.add_argument('input_files', nargs=argparse.REMAINDER, help='input files to be processed')
    parser.add_argument('--disassemble', action='store_true',  help='print disassembled text section')
    parser.add_argument('--watch', action='append',  help='print the address and function name whenever an instructions group is specified')
    parser.add_argument('--summary', action='store_true',  help='print a summary of used instruction groups at the end of each file')
    parser.add_argument('--debug', action='store_true',  help='print useless debug info')
    parser.add_argument('--section-names', action='store_true',  help='print section names')
    args = parser.parse_args()
    opts.print_disassembly = args.disassemble
    opts.debug = args.debug
    opts.summary = args.summary
    opts.print_section_names = args.section_names
    if args.watch:
        opts.watchlist.extend(args.watch)
    if not args.input_files or len(args.input_files) == 0:
        print('error, no input files')
    for infile in args.input_files:
        process_file(infile)

if __name__ == '__main__':
    main()

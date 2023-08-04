#!/usr/bin/env python3
##
## This file is part of the sigrok-util project.
##
## Copyright (C) 2013 Marcus Comstedt <marcus@mc.pp.se>
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 3 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, see <http://www.gnu.org/licenses/>.
##

import struct

class elf:

    def read_struct(self, struct_fmt, struct_fields):
        fmt = self.elf_endianprefix + str.translate(struct_fmt, self.elf_format);
        fields = struct.unpack(fmt, self.file.read(struct.calcsize(fmt)))
        return dict(zip(struct_fields, fields))

    def read_ehdr(self):
        return self.read_struct(
            '16sHHWNNNWHHHHHH',
            (
                'e_ident',
                'e_type',
                'e_machine',
                'e_version',
                'e_entry',
                'e_phoff',
                'e_shoff',
                'e_flags',
                'e_ehsize',
                'e_phentsize',
                'e_phnum',
                'e_shentsize',
                'e_shnum',
                'e_shstrndx',
            ),
        )

    def read_shdr(self):
        return self.read_struct(
            'WWNNNNWWNN',
            (
                'sh_name',
                'sh_type',
                'sh_flags',
                'sh_addr',
                'sh_offset',
                'sh_size',
                'sh_link',
                'sh_info',
                'sh_addralign',
                'sh_entsize',
            ),
        )

    def read_section(self, shdr):
        self.file.seek(shdr['sh_offset'])
        return self.file.read(shdr['sh_size'])

    def get_name(self, name, strtab=None):
        strtab = strtab or self.strtab
        nul = strtab.find(b'\0', name)
        if nul < 0:
            return bytes.decode(strtab[name:])
        else:
            return bytes.decode(strtab[name:nul])

    def find_section(self, name):
        for section in self.shdrs:
            if self.get_name(section['sh_name']) == name:
                return section
        raise KeyError(name)

    def parse_symbol(self):
        if self.elf_wordsize == 64:
            return self.read_struct(
                'WBBHNX',
                (
                    'st_name',
                    'st_info',
                    'st_other',
                    'st_shndx',
                    'st_value',
                    'st_size',
                ),
            )
        else:
            return self.read_struct(
                'WNWBBH',
                (
                    'st_name',
                    'st_value',
                    'st_size',
                    'st_info',
                    'st_other',
                    'st_shndx',
                ),
            )

    def parse_rela(self):
        return self.read_struct('NNn', ('r_offset', 'r_info', 'r_addend'))

    def parse_rel(self):
        return self.read_struct('NN', ('r_offset', 'r_info'))

    def fixup_reloc(self, reloc):
        if 'r_addend' not in reloc:
            reloc['r_addend'] = 0
        if self.elf_wordsize == 64:
            reloc['r_sym'] = reloc['r_info'] >> 32
            reloc['r_type'] = reloc['r_info'] & 0xffffffff
        else:
            reloc['r_sym'] = reloc['r_info'] >> 8
            reloc['r_type'] = reloc['r_info'] & 0xff
        return reloc

    def parse_symbols(self, symsecname, strsecname):
        try:
            symsechdr = self.find_section(symsecname)
            strsechdr = self.find_section(strsecname)
        except KeyError:
            return {}
        strsec = self.read_section(strsechdr)
        self.file.seek(symsechdr['sh_offset'])
        syms = [
            dict(self.parse_symbol(), number=i)
            for i in range(0, symsechdr['sh_size'] // symsechdr['sh_entsize'])
        ]
        return {self.get_name(sym['st_name'], strsec): sym for sym in syms}

    def parse_relocs(self, section):
        self.file.seek(section['sh_offset'])
        return (
            [
                self.fixup_reloc(self.parse_rela())
                for _ in range(0, section['sh_size'] // section['sh_entsize'])
            ]
            if section['sh_type'] == 4
            else [
                self.fixup_reloc(self.parse_rel())
                for _ in range(0, section['sh_size'] // section['sh_entsize'])
            ]
        )

    def address_to_offset(self, addr):
        for section in self.shdrs:
            if (section['sh_addr'] <= addr and
                section['sh_addr']+section['sh_size'] > addr):
                return section['sh_offset']+(addr-section['sh_addr'])
        raise IndexError('address out of range')

    def load_symbol(self, sym):
        self.file.seek(self.address_to_offset(sym['st_value']))
        return self.file.read(sym['st_size'])

    def __init__(self, filename):
        self.file = open(filename, 'rb')
        magic = self.file.read(16)

        if magic[:4] != b'\x7fELF':
            raise Exception("ELF signature not found")

        if magic[4] == 1:
            self.elf_wordsize = 32
            nativeint = 'Ii'
        elif magic[4] == 2:
            self.elf_wordsize = 64
            nativeint = 'Qq'
        else:
            raise Exception("Invalid ELF file class")

        if magic[5] == 1:
            self.elf_endianprefix = '<'
        elif magic[5] == 2:
            self.elf_endianprefix = '>'
        else:
            raise Exception("Invalid ELF data encoding")

        self.elf_format = str.maketrans('HWwXxNn', f'HIiQq{nativeint}')

        self.file.seek(0)
        self.ehdr = self.read_ehdr()
        self.file.seek(self.ehdr['e_shoff'])
        self.shdrs = [this.read_shdr() for _ in range(this.ehdr['e_shnum'])]

        self.strtab = self.read_section(self.shdrs[self.ehdr['e_shstrndx']])

        self.symtab = self.parse_symbols('.symtab', '.strtab')
        self.dynsym = self.parse_symbols('.dynsym', '.dynstr')

        self.relocs = {}
        for section in self.shdrs:
            if section['sh_type'] in [4, 9]:
                rels = {}
                symsec = self.shdrs[section['sh_link']]
                if self.get_name(symsec['sh_name']) == '.symtab':
                    rels['symbols'] = self.symtab
                elif self.get_name(symsec['sh_name']) == '.dynsym':
                    rels['symbols'] = self.dynsym
                rels['relocs'] = self.parse_relocs(section)
                self.relocs[self.get_name(section['sh_name'])] = rels

    def __del__(self):
        try:
            self.file.close()
        except AttributeError:
            pass

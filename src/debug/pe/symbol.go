// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pe

import (
	"encoding/binary"
	"fmt"
	"io"
)

const COFFSmallSymbolSize = 18
const COFFBigSymbolSize = 20

// COFFSymbol represents single COFF symbol table record.
type COFFSymbol interface {
	GetName() [8]uint8
	GetValue() uint32
	GetSectionNumber() int
	GetType() uint16
	GetStorageClass() uint8
	GetNumberOfAuxSymbols() uint8
}

type COFFSmallSymbol struct {
	Name               [8]uint8
	Value              uint32
	SectionNumber      int16
	Type               uint16
	StorageClass       uint8
	NumberOfAuxSymbols uint8
}

type COFFBigSymbol struct {
	Name               [8]uint8
	Value              uint32
	SectionNumber      int32
	Type               uint16
	StorageClass       uint8
	NumberOfAuxSymbols uint8
}


func readCOFFSymbols(fh FileHeader, r io.ReadSeeker) ([]COFFSymbol, error) {
	if fh.GetPointerToSymbolTable() == 0 {
		return nil, nil
	}
	if fh.GetNumberOfSymbols() <= 0 {
		return nil, nil
	}
	_, err := r.Seek(int64(fh.GetPointerToSymbolTable()), seekStart)
	if err != nil {
		return nil, fmt.Errorf("fail to seek to symbol table: %v", err)
	}

	syms := make([]COFFSymbol, fh.GetNumberOfSymbols())

	switch fh.GetSymbolSize() {
	case COFFSmallSymbolSize:
		ss := make([]COFFSmallSymbol, len(syms))
		err = binary.Read(r, binary.LittleEndian, ss)
		if err == nil {
			for i := range ss {
				syms[i] = &ss[i]
			}
		}
	case COFFBigSymbolSize:
		sb := make([]COFFBigSymbol, len(syms))
		err = binary.Read(r, binary.LittleEndian, sb)
		if err == nil {
			for i := range sb {
				syms[i] = &sb[i]
			}
		}
	default:
		err = fmt.Errorf("unknown symbol size: %v", fh.GetSymbolSize())
	}

	if err != nil {
		return nil, fmt.Errorf("fail to read symbol table: %v", err)
	}
	return syms, nil
}

// isSymNameOffset checks symbol name if it is encoded as offset into string table.
func isSymNameOffset(name [8]byte) (bool, uint32) {
	if name[0] == 0 && name[1] == 0 && name[2] == 0 && name[3] == 0 {
		return true, binary.LittleEndian.Uint32(name[4:])
	}
	return false, 0
}

// FullName finds real name of symbol sym. Normally name is stored
// in sym.Name, but if it is longer then 8 characters, it is stored
// in COFF string table st instead.
func FullName(sym COFFSymbol, st StringTable) (string, error) {
	name := sym.GetName()
	if ok, offset := isSymNameOffset(name); ok {
		return st.String(offset)
	}
	return cstring(name[:]), nil
}

func removeAuxSymbols(allsyms []COFFSymbol, st StringTable) ([]*Symbol, error) {
	if len(allsyms) == 0 {
		return nil, nil
	}
	syms := make([]*Symbol, 0)
	aux := uint8(0)
	for _, sym := range allsyms {
		if aux > 0 {
			aux--
			continue
		}
		name, err := FullName(sym, st)
		if err != nil {
			return nil, err
		}
		aux = sym.GetNumberOfAuxSymbols()
		s := &Symbol{
			Name:          name,
			Value:         sym.GetValue(),
			SectionNumber: sym.GetSectionNumber(),
			Type:          sym.GetType(),
			StorageClass:  sym.GetStorageClass(),
		}
		syms = append(syms, s)
	}
	return syms, nil
}

// Symbol is similar to COFFSymbol with Name field replaced
// by Go string. Symbol also does not have NumberOfAuxSymbols.
type Symbol struct {
	Name          string
	Value         uint32
	SectionNumber int
	Type          uint16
	StorageClass  uint8
}


func (s *COFFSmallSymbol) GetName() [8]uint8 {
	return s.Name
}

func (s *COFFSmallSymbol) GetValue() uint32 {
	return s.Value
}

func (s *COFFSmallSymbol) GetSectionNumber() int {
	return int(s.SectionNumber)
}

func (s *COFFSmallSymbol) GetType() uint16 {
	return s.Type
}

func (s *COFFSmallSymbol) GetStorageClass() uint8 {
	return s.StorageClass
}

func (s *COFFSmallSymbol) GetNumberOfAuxSymbols() uint8 {
	return s.NumberOfAuxSymbols
}


func (s *COFFBigSymbol) GetName() [8]uint8 {
	return s.Name
}

func (s *COFFBigSymbol) GetValue() uint32 {
	return s.Value
}

func (s *COFFBigSymbol) GetSectionNumber() int {
	return int(s.SectionNumber)
}

func (s *COFFBigSymbol) GetType() uint16 {
	return s.Type
}

func (s *COFFBigSymbol) GetStorageClass() uint8 {
	return s.StorageClass
}

func (s *COFFBigSymbol) GetNumberOfAuxSymbols() uint8 {
	return s.NumberOfAuxSymbols
}

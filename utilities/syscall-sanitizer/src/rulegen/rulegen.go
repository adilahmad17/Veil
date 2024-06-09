package main

// #cgo CFLAGS: -I ${SRCDIR}/../../include
// #include "scsan.h"
import "C"

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

// TODO: Support syscall dispatching, e.g., ioctl.

type SCSANTypeID int

type SCSANTypeBase struct {
	ID   SCSANTypeID
	Name string
	Type string // for debugging
}

func (b *SCSANTypeBase) GetID() SCSANTypeID   { return b.ID }
func (b *SCSANTypeBase) SetID(ID SCSANTypeID) { b.ID = ID }
func (b *SCSANTypeBase) GetName() string      { return b.Name }
func (b *SCSANTypeBase) GetTypeName() string  { return b.Type }

type SCSANType interface {
	GetID() SCSANTypeID
	SetID(SCSANTypeID)
	GetName() string
	GetTypeName() string
}

type SCSANScalarType struct {
	SCSANType
	Len int `json:"len"`
}

type SCSANPointerType struct {
	SCSANType
	Pointee SCSANTypeID `json:"pointee"`
	Dir     prog.Dir    `json:"dir"`
}

type SCSANArrayType struct {
	SCSANType
	IsVarLen      bool          `json:"is_var_len"`
	StaticLen     int           `json:"static_len"`
	DynLenArg     SCSANTypeID   `json:"dyn_len_arg"`
	DynLenArgPath []SCSANTypeID `json:"dyn_len_arg_path"`
	Elem          SCSANTypeID   `json:"elem"`
}

type SCSANBufferType struct {
	SCSANType
	IsVarLen      bool          `json:"is_var_len"`
	StaticLen     int           `json:"static_len"`
	DynLenArg     SCSANTypeID   `json:"dyn_len_arg"`
	DynLenArgPath []SCSANTypeID `json:"dyn_len_arg_path"`
}

type SCSANStructField struct {
	Name    string      `json:"name"`   // for debugging
	Offset  int         `json:"offset"` // in bytes
	FieldID SCSANTypeID `json:"field_id"`
}

// TODO: support dynamic length for struct field, which needs to consider alignment.
// 	Example: rnd_entpropy struct.
type SCSANStructType struct {
	SCSANType
	StaticLen     int                `json:"static_len"`
	Fields        []SCSANStructField `json:"elem"`
	IsVarLen      bool               `json:"is_var_len"`
	DynLenArg     SCSANTypeID        `json:"dyn_len_arg"`
	DynLenArgPath []SCSANTypeID      `json:"dyn_len_arg_path"`
}

type SCSANUnionType struct {
	SCSANType
	StaticLen     int                `json:"static_len"`
	DynLenArg     SCSANTypeID        `json:"dyn_len_arg"`
	DynLenArgPath []SCSANTypeID      `json:"dyn_len_arg_path"`
	Fields        []SCSANStructField `json:"elem"`
}

type SCSANLenType struct {
	SCSANType
	Len      int  `json:"len"`
	OfScalar bool `json:"of_scalar"`
	BitSize  int  `json:"bit_size"`
	path     []string
}

type SyscallArg struct {
	TypeID SCSANTypeID `json:"type_id"`
	Name   string      `json:"name"`
}

type SyscallInfo struct {
	NR            int          `json:"nr"`
	Name          string       `json:"name"`
	Args          []SyscallArg `json:"args"`
	BranchArg     int          `json:"branch_arg"`
	BranchArgVals []uint64     `json:"branch_arg_vals"`
}

func (s *SyscallInfo) DebugString() string {
	b, err := json.MarshalIndent(s, "", "\t")
	if err != nil {
		log.Fatalf("cannot marshal spec: %v", err)
	}
	return string(b)
}

type Spec struct {
	Call    []*SyscallInfo `json:"call"`
	Types   []SCSANType    `json:"types"`
	typeMap map[string]SCSANType
}

func (s *Spec) CCallSpec() string {
	buf := bytes.NewBuffer(nil)
	// TODO: not hardcode this part.
	maxSysNo := 1024
	fmt.Fprintf(buf, "%v %v\n", maxSysNo, len(s.Call))
	for _, c := range s.Call {
		fmt.Fprintf(buf, "%v\n%v\n", c.NR, len(c.Args))
		for _, a := range c.Args {
			fmt.Fprintf(buf, "%v ", a.TypeID)
		}
		fmt.Fprintf(buf, "\n")
		fmt.Fprintf(buf, "%v %v\n", c.BranchArg, len(c.BranchArgVals))
		for _, v := range c.BranchArgVals {
			fmt.Fprintf(buf, "%v ", v)
		}
		fmt.Fprintf(buf, "\n")
	}
	return buf.String()
}

func (s *Spec) CArgSpec() string {
	buf := bytes.NewBuffer(nil)
	// TODO: not hardcode this part.
	fmt.Fprintf(buf, "%v\n", len(s.Types))
	for _, t := range s.Types {
		fmt.Fprintf(buf, "%v ", t.GetID())
		switch tt := t.(type) {
		case *SCSANScalarType:
			fmt.Fprintf(buf, "%v\n", int(C.SCALAR_TYPE))
			fmt.Fprintf(buf, "%v\n", tt.Len)
		case *SCSANArrayType:
			fmt.Fprintf(buf, "%v\n", int(C.ARRAY_TYPE))
			IsVarLenInt := 0
			if tt.IsVarLen {
				IsVarLenInt = 1
			}
			fmt.Fprintf(buf, "%v %v %v %v\n", IsVarLenInt, tt.StaticLen, tt.DynLenArg, tt.Elem)
			fmt.Fprintf(buf, "%v\n", len(tt.DynLenArgPath))
			if len(tt.DynLenArgPath) != 0 {
				for _, p := range tt.DynLenArgPath {
					fmt.Fprintf(buf, "%v ", p)
				}
				fmt.Fprintf(buf, "\n")
			}
		case *SCSANBufferType:
			fmt.Fprintf(buf, "%v\n", int(C.BUFFER_TYPE))
			IsVarLenInt := 0
			if tt.IsVarLen {
				IsVarLenInt = 1
			}
			fmt.Fprintf(buf, "%v %v %v\n", IsVarLenInt, tt.StaticLen, tt.DynLenArg)
			fmt.Fprintf(buf, "%v\n", len(tt.DynLenArgPath))
			if len(tt.DynLenArgPath) != 0 {
				for _, p := range tt.DynLenArgPath {
					fmt.Fprintf(buf, "%v ", p)
				}
				fmt.Fprintf(buf, "\n")
			}
		case *SCSANStructType:
			fmt.Fprintf(buf, "%v\n", int(C.STRUCT_TYPE))
			IsVarLenInt := 0
			if tt.IsVarLen {
				IsVarLenInt = 1
			}
			fmt.Fprintf(buf, "%v %v %v %v\n", len(tt.Fields), IsVarLenInt, tt.StaticLen, tt.DynLenArg)
			for _, f := range tt.Fields {
				fmt.Fprintf(buf, "%v %v\n", f.FieldID, f.Offset)
			}
			fmt.Fprintf(buf, "%v\n", len(tt.DynLenArgPath))
			if len(tt.DynLenArgPath) != 0 {
				for _, p := range tt.DynLenArgPath {
					fmt.Fprintf(buf, "%v ", p)
				}
				fmt.Fprintf(buf, "\n")
			}
		case *SCSANPointerType:
			fmt.Fprintf(buf, "%v\n", int(C.POINTER_TYPE))
			dir := 0
			switch tt.Dir {
			case prog.DirIn:
				dir = C.IN_DIR
			case prog.DirInOut:
				dir = C.INOUT_DIR
			case prog.DirOut:
				dir = C.OUT_DIR
			default:
				log.Fatalf("unsupported dir")
			}
			fmt.Fprintf(buf, "%v %v\n", tt.Pointee, dir)
			fmt.Fprintf(buf, "\n")
		case *SCSANLenType:
			fmt.Fprintf(buf, "%v\n", int(C.LEN_TYPE))
			fmt.Fprintf(buf, "%v %v\n", tt.Len, tt.BitSize)
		case *SCSANUnionType:
			// Take union type as buffer for now.
			fmt.Fprintf(buf, "%v\n", int(C.BUFFER_TYPE))
			IsVarLenInt := 0
			if tt.DynLenArg != -1 {
				IsVarLenInt = 1
			}
			fmt.Fprintf(buf, "%v %v %v\n", IsVarLenInt, tt.StaticLen, tt.DynLenArg)
			fmt.Fprintf(buf, "%v\n", len(tt.DynLenArgPath))
			if len(tt.DynLenArgPath) != 0 {
				for _, p := range tt.DynLenArgPath {
					fmt.Fprintf(buf, "%v ", p)
				}
				fmt.Fprintf(buf, "\n")
			}
		default:
			log.Fatalf("unsupported type %v", t.GetTypeName())

		}
	}
	return buf.String()
}

func (s *Spec) DebugString() string {
	b, err := json.MarshalIndent(s, "", "\t")
	if err != nil {
		log.Fatalf("cannot marshal spec: %v", err)
	}
	return string(b)
}

func (s *Spec) HumanStringFieldTypeName(t SCSANType) string {
	switch tt := t.(type) {
	case *SCSANPointerType:
		return "*" + s.HumanStringFieldTypeName(s.Types[tt.Pointee])
	case *SCSANArrayType:
		if tt.Elem == -1 {
			return "[ommited]"
		} else {
			return "[" + s.HumanStringFieldTypeName(s.Types[tt.Elem]) + "]"
		}
	}
	return t.GetName()
}

func (s *Spec) HumanString() string {
	buf := bytes.NewBuffer(nil)
	for _, t := range s.Types {
		switch tt := t.(type) {
		case *SCSANStructType:
			fmt.Fprintf(buf, "struct %v [size = %v] {\n", t.GetName(), tt.StaticLen)
			for _, f := range tt.Fields {
				ft := s.Types[f.FieldID]
				fmt.Fprintf(buf, "\t%v %15v", f.Name, s.HumanStringFieldTypeName(ft))
				fmt.Fprintf(buf, " [")
				switch tft := ft.(type) {
				case *SCSANArrayType:
					if tft.IsVarLen {
						fmt.Fprintf(buf, "len id = %v, ", tft.DynLenArg)
					} else {
						fmt.Fprintf(buf, "len = %v, ", tft.StaticLen)
					}

				case *SCSANBufferType:
					if tft.IsVarLen {
						fmt.Fprintf(buf, "len id = %v, ", tft.DynLenArg)
					} else {
						fmt.Fprintf(buf, "len = %v, ", tft.StaticLen)
					}
				}
				fmt.Fprintf(buf, "id = %v, offset = %v]\n", ft.GetID(), f.Offset)
			}
			fmt.Fprintf(buf, "}\n")
			// case *SCSANUnionType:
			// 	fmt.Fprintf(buf, "union %v [size = %v] {\n", t.GetName(), tt.StaticLen)
			// 	for _, f := range tt.Fields {
			// 		fmt.Fprintf(buf, "%v %15v\n", f.Name, s.Types[f.FieldID].GetName())
			// 	}
			// 	fmt.Fprintf(buf, "}\n")
		}
	}
	return buf.String()
}

func (s *Spec) NewSCSANType(t SCSANType) {
	name := t.GetName()
	id := SCSANTypeID(len(s.Types))
	t.SetID(id)
	s.Types = append(s.Types, t)
	switch t.(type) {
	case *SCSANUnionType, *SCSANStructType:
		s.typeMap[name] = t
	}
}

// When error occurs, we will not rollback the spec. So there
// can be some useless types in spec. But we ensure they are all
// valid and should never affect others in bad ways.
func (s *Spec) analyzeType(t prog.Type) (SCSANType, error) {
	name := t.String()

	log.Printf("now analyze %v", name)

	// Name is unique for these types, not sure about others.
	switch t.(type) {
	case *prog.UnionType, *prog.StructType:
		if st, ok := s.typeMap[name]; ok {
			return st, nil
		}
	}

	if t.IsBitfield() {
		return nil, fmt.Errorf("%v is bitfield", name)
	}

	switch tt := t.(type) {
	case *prog.ArrayType:
		return s.analyzeArrayType(tt)
	case *prog.BufferType:
		return s.analyzeBufferType(tt)
	case *prog.LenType:
		return s.analyzeLenType(tt)
	case *prog.PtrType:
		return s.analyzePtrType(tt)
	case *prog.StructType:
		return s.analyzeStructType(tt)
	case *prog.ConstType, *prog.CsumType, *prog.ProcType, *prog.FlagsType, *prog.IntType, *prog.ResourceType, *prog.VmaType:
		return s.analyzeScalarType(tt)
	case *prog.UnionType:
		return s.AnalyzeUnionType(tt)
	default:
		return nil, fmt.Errorf("should not reach here")
	}

}

func (s *Spec) AnalyzeUnionType(pt *prog.UnionType) (*SCSANUnionType, error) {
	name := pt.Name()
	// NOTE: For sock_storage, var len is false...why?
	// if pt.Varlen() {
	// 	return nil, fmt.Errorf("union %v is var len", name)
	// }
	nt := &SCSANUnionType{
		SCSANType: &SCSANTypeBase{
			Name: name,
			Type: "union",
		},
		StaticLen: int(pt.Size()),
		DynLenArg: -1,
	}
	for _, f := range pt.Fields {
		t, err := s.analyzeType(f.Type)
		if err != nil {
			return nil, fmt.Errorf("cannot analyze union %v field %v: %w", name, f.Name, err)
		}
		nt.Fields = append(nt.Fields, SCSANStructField{Name: f.Name, Offset: 0, FieldID: t.GetID()})

	}
	s.NewSCSANType(nt)
	return nt, nil
}

func (s *Spec) analyzeScalarType(pt prog.Type) (*SCSANScalarType, error) {
	name := pt.String()
	if pt.Varlen() {
		return nil, fmt.Errorf("scalar type %v is not fixed length", name)
	}
	st := &SCSANScalarType{
		SCSANType: &SCSANTypeBase{
			Name: name,
			Type: "scalar",
		},
		// Assume the length is in bytes.
		Len: int(pt.Size()),
	}
	s.NewSCSANType(st)
	return st, nil
}

func (s *Spec) analyzeBufferType(pt *prog.BufferType) (*SCSANBufferType, error) {
	name := pt.String()
	st := &SCSANBufferType{
		SCSANType: &SCSANTypeBase{
			Name: name,
			Type: "buffer",
		},
		DynLenArg: -1,
	}
	switch pt.Kind {
	case prog.BufferFilename, prog.BufferGlob, prog.BufferString, prog.BufferText:
		// String buffer. Length can be determined using strlen().
		st.DynLenArg = -2
	}
	st.IsVarLen = pt.Varlen()
	// Leave dyn_len at this stage.
	if st.IsVarLen {
		st.StaticLen = 0
	} else {
		st.StaticLen = int(pt.Size())
	}
	s.NewSCSANType(st)
	return st, nil
}

func (s *Spec) analyzeArrayType(pt *prog.ArrayType) (*SCSANArrayType, error) {
	name := pt.String()
	st := &SCSANArrayType{
		SCSANType: &SCSANTypeBase{
			Name: name,
			Type: "array",
		},
		DynLenArg: -1,
	}
	st.IsVarLen = pt.Varlen()
	// Leave dyn_len at this stage.
	if st.IsVarLen {
		st.StaticLen = 0
	} else {
		st.StaticLen = int(pt.Size())
	}
	elem, err := s.analyzeType(pt.Elem)
	if err != nil {
		return nil, fmt.Errorf("array %v: %w", name, err)
	}
	st.Elem = elem.GetID()
	s.NewSCSANType(st)
	return st, nil
}

func (s *Spec) analyzeLenType(pt *prog.LenType) (*SCSANLenType, error) {
	name := pt.String()
	st := &SCSANLenType{
		SCSANType: &SCSANTypeBase{
			Name: name,
			Type: "len",
		},
	}
	if pt.Varlen() {
		return nil, fmt.Errorf("len type %v is var length", name)
	}
	st.Len = int(pt.Size())
	st.path = pt.Path
	st.BitSize = int(pt.BitSize)
	s.NewSCSANType(st)
	return st, nil
}

func (s *Spec) analyzePtrType(pt *prog.PtrType) (*SCSANPointerType, error) {
	name := pt.String()
	st := &SCSANPointerType{
		SCSANType: &SCSANTypeBase{
			Name: name,
			Type: "pointer",
		},
	}
	st.Dir = pt.ElemDir
	pointeeTy, err := s.analyzeType(pt.Elem)
	if err != nil {
		return nil, fmt.Errorf("pointer %v: %w", name, err)
	}
	st.Pointee = pointeeTy.GetID()
	s.NewSCSANType(st)
	return st, nil
}

func (s *Spec) analyzeStructType(pt *prog.StructType) (*SCSANStructType, error) {
	name := pt.String()
	st := &SCSANStructType{
		SCSANType: &SCSANTypeBase{
			Name: name,
			Type: "struct",
		},
		DynLenArg: -1,
	}
	if pt.IsVarlen {
		st.IsVarLen = true
		// return nil, fmt.Errorf("struct %v has var length", name)
	} else {
		st.StaticLen = int(pt.Size())
	}
	offset := 0
	for i, f := range pt.Fields {
		if pt.IsVarlen && i == len(pt.Fields)-1 {
			// Skip the last field since it is useless and tricky to handle
			break
		}
		ft, err := s.analyzeType(f.Type)
		if err != nil {
			return nil, fmt.Errorf("struct %v, field %v: %w", name, f.Name, err)
		}
		align := int(f.Alignment())
		if align != 0 {
			offset = ((offset + align - 1) / align) * align
		}
		st.Fields = append(st.Fields, SCSANStructField{
			Name:    f.Name,
			FieldID: ft.GetID(),
			Offset:  offset,
		})
		if i < len(pt.Fields)-1 {
			offset += int(f.Size())
		}
	}
	s.NewSCSANType(st)
	return st, nil
}

func (s *Spec) analyzeCall(call *prog.Syscall) (*SyscallInfo, error) {
	name := call.Name
	// if strings.Contains(name, "$") {
	// 	return nil, fmt.Errorf("call %v needs dispatching support", name)
	// }
	si := &SyscallInfo{
		NR:   int(call.NR),
		Name: call.Name,
	}
	for _, a := range call.Args {
		t, err := s.analyzeType(a.Type)
		if err != nil {
			return nil, fmt.Errorf("cannot analyze call %v on arg %v: %w", name, a.Name, err)
		}
		si.Args = append(si.Args, SyscallArg{TypeID: t.GetID(), Name: a.Name})
	}
	return si, nil
}

func (s *Spec) CheckUnionInCall(call *SyscallInfo) error {
	for _, a := range call.Args {
		err := s.CheckUnionInType(s.Types[a.TypeID])
		if err != nil {
			return fmt.Errorf("in call %v: %w", call.Name, err)
		}
	}
	return nil
}

func (s *Spec) CheckUnionInType(t SCSANType) error {
	switch tt := t.(type) {
	case *SCSANUnionType:
		has, reason := s.CheckTypeHasPointerOrLen(t, t.GetName())
		if has {
			return fmt.Errorf("union %v has pointers or lens: %v", t.GetName(), reason)
		}
	case *SCSANStructType:
		for _, f := range tt.Fields {
			err := s.CheckUnionInType(s.Types[f.FieldID])
			if err != nil {
				return fmt.Errorf("in struct %v, field %v: %w", t.GetName(), f.Name, err)
			}
		}
	case *SCSANPointerType:
		return s.CheckUnionInType(s.Types[tt.Pointee])
	case *SCSANArrayType:
		return s.CheckUnionInType(s.Types[tt.Elem])
	}
	return nil
}

func (s *Spec) CheckTypeHasPointerOrLen(t SCSANType, reasonPrefix string) (bool, string) {
	switch tt := t.(type) {
	case *SCSANStructType:
		for _, f := range tt.Fields {
			next := s.Types[f.FieldID]
			has, reason := s.CheckTypeHasPointerOrLen(next, reasonPrefix+":"+f.Name)
			if has {
				return true, reason
			}
		}
	case *SCSANUnionType:
		for _, f := range tt.Fields {
			next := s.Types[f.FieldID]
			has, reason := s.CheckTypeHasPointerOrLen(next, reasonPrefix+":"+f.Name)
			if has {
				return true, reason
			}
		}
	case *SCSANArrayType:
		return s.CheckTypeHasPointerOrLen(s.Types[tt.Elem], reasonPrefix+":"+t.GetName())
	case *SCSANLenType:
		if tt.OfScalar {
			return false, ""
		} else {
			return true, fmt.Sprintf("%v:%v is len", reasonPrefix, tt.GetName())
		}
	case *SCSANPointerType:
		return true, fmt.Sprintf("%v:%v is pointer", reasonPrefix, tt.GetName())
	// case *SCSANBufferType:
	// 	return true, fmt.Sprintf("%v:%v is buffer", reasonPrefix, tt.GetName())

	default:
		return false, ""
	}
	return false, ""
}

func (s *Spec) ResolveLenInCall(call *SyscallInfo) error {
	for _, a := range call.Args {
		t := s.Types[a.TypeID]
		err := s.ResolveLenInType(t, true, nil, nil, call)
		if err != nil {
			return fmt.Errorf("cannot resolve length for call %v: %w", call.Name, err)
		}
	}
	return nil
}

func (s *Spec) ResolveLenInType(t SCSANType, atCall bool, parentStructOrUnion, nowStructOrUnion SCSANType, call *SyscallInfo) error {
	switch tt := t.(type) {
	case *SCSANLenType:
		return s.ResolveOneLen(tt, atCall, parentStructOrUnion, nowStructOrUnion, call)
	case *SCSANUnionType:
		for _, f := range tt.Fields {
			err := s.ResolveLenInType(s.Types[f.FieldID], false, nowStructOrUnion, tt, call)
			if err != nil {
				return fmt.Errorf("cannot resolve len in union %v field %v: %w", tt.GetName(), f.Name, err)
			}
		}
	case *SCSANStructType:
		for _, f := range tt.Fields {
			err := s.ResolveLenInType(s.Types[f.FieldID], false, nowStructOrUnion, tt, call)
			if err != nil {
				return fmt.Errorf("cannot resolve len in union %v field %v: %w", tt.GetName(), f.Name, err)
			}
		}
	case *SCSANPointerType:
		return s.ResolveLenInType(s.Types[tt.Pointee], atCall, parentStructOrUnion, nowStructOrUnion, call)
	case *SCSANArrayType:
		return s.ResolveLenInType(s.Types[tt.Elem], false, parentStructOrUnion, nowStructOrUnion, call)

	default:
	}
	return nil
}

func (s *Spec) ResolveOneLen(t *SCSANLenType, atCall bool, parentStructOrUnion, nowStructOrUnion SCSANType, call *SyscallInfo) error {
	if t.path[0] == prog.ParentRef {
		return s.resolveOneLenTypeRec(t, false, nowStructOrUnion, call, t.path[1:], []SCSANTypeID{t.GetID()})
	} else if t.path[0] == prog.SyscallRef {
		return s.resolveOneLenTypeRec(t, true, nil, call, t.path[1:], []SCSANTypeID{t.GetID()})
	} else {
		return s.resolveOneLenTypeRec(t, atCall, nowStructOrUnion, call, t.path, []SCSANTypeID{t.GetID()})
	}
}

func reversePath(p []SCSANTypeID) []SCSANTypeID {
	r := []SCSANTypeID{}
	for i := len(p) - 1; i >= 0; i-- {
		r = append(r, p[i])
	}
	return r
}

func (s *Spec) resolveOneLenTypeRec(t *SCSANLenType, atCall bool, now SCSANType, call *SyscallInfo, path []string, revPath []SCSANTypeID) error {
	if len(path) == 0 {
		// NOTE: assume this only happens when user specifies 'len[parent]'
		// Maybe we could assume this to be more generic.
		switch tnow := now.(type) {
		case *SCSANStructType:
			tnow.DynLenArg = t.GetID()
			tnow.DynLenArgPath = reversePath(revPath)
			return nil
		default:
			return fmt.Errorf("unhandled resolve to parent %v", now.GetName())
		}
	}
	var next SCSANType
	find := false
	if atCall {
		log.Printf("at call")
		for _, a := range call.Args {
			if a.Name == path[0] {
				next = s.Types[a.TypeID]
				find = true
				revPath = append(revPath, -2)
				break
			}
		}
	} else {
		log.Printf("not at call path = %v nn = %v", path, now.GetName())
		switch nn := now.(type) {
		case *SCSANStructType:
			for _, f := range nn.Fields {
				log.Printf("field name = %v", f.Name)
				if f.Name == path[0] {
					next = s.Types[f.FieldID]
					revPath = append(revPath, -1)
					find = true
				}
			}
		case *SCSANUnionType:
			for _, f := range nn.Fields {
				if f.Name == path[0] {
					next = s.Types[f.FieldID]
					revPath = append(revPath, -1)
					find = true
				}
			}
		default:
			log.Fatalf("invalid now type")
		}
	}
	if !find {
		log.Fatalf("cannot resolve len")
	}

	// Unwrap pointer for 1 level.
	switch ttt := next.(type) {
	case *SCSANPointerType:
		next = s.Types[ttt.Pointee]
		revPath = append(revPath, -1)
	}

	switch ttt := next.(type) {
	case *SCSANPointerType:
		return fmt.Errorf("nested pointer type not supported at this time")
	case *SCSANStructType:
		if len(path) < 2 {
			log.Printf("len %v resolving ends at struct %v", t.GetName(), ttt.GetName())
			ttt.DynLenArg = t.GetID()
			ttt.DynLenArgPath = reversePath(revPath)
			return nil
		}
		return s.resolveOneLenTypeRec(t, false, ttt, call, path[1:], revPath)
	case *SCSANUnionType:
		if len(path) < 2 {
			// In C, union length is fixed. But in Syzlang, union can also used
			// to describe buffer backed by different data structures (see `sock_storage` in `cmsghdr`).
			// Thus its length is not fixed.
			// When a len resolves to union, we assume the latter case.
			log.Printf("len %v resolving ends at union %v", t.GetName(), ttt.GetName())
			ttt.DynLenArg = t.GetID()
			ttt.DynLenArgPath = reversePath(revPath)
			return nil
		}
		return fmt.Errorf("len %v resolving wants to go deeper into union %v", t.GetName(), ttt.GetName())
	case *SCSANBufferType:
		if len(path) != 1 {
			log.Fatalf("len resolving wants to go deeper into buffer")
		}
		if ttt.IsVarLen {
			ttt.DynLenArg = t.GetID()
			ttt.DynLenArgPath = reversePath(revPath)
		}
		return nil
	case *SCSANArrayType:
		if len(path) != 1 {
			log.Fatalf("len resolving wants to go deeper into array")
		}
		if ttt.IsVarLen {
			ttt.DynLenArg = t.GetID()
			ttt.DynLenArgPath = reversePath(revPath)
		}
		return nil
	case *SCSANScalarType:
		t.OfScalar = true
		return nil

	default:
		log.Fatalf("incorrect argument type")
	}
	log.Fatalf("should not reach here")
	return nil
}

func (s *Spec) CheckCallUnresolvedLen(si *SyscallInfo) (bool, string) {
	for _, a := range si.Args {
		if unres, reason := s.CheckTypeUnresolvedLen(s.Types[a.TypeID], fmt.Sprintf("call %v:", si.Name)); unres {
			return true, reason
		}
	}
	return false, ""
}

func (s *Spec) CheckTypeUnresolvedLen(t SCSANType, reasonPrefix string) (bool, string) {
	switch tt := t.(type) {
	case *SCSANArrayType:
		if tt.IsVarLen && tt.DynLenArg == -1 {
			return true, fmt.Sprintf("%v array %v is dynamic but no len is found", reasonPrefix, t.GetName())
		}
		return s.CheckTypeUnresolvedLen(s.Types[tt.Elem], fmt.Sprintf("%v array %v:", reasonPrefix, tt.GetName()))
	case *SCSANBufferType:
		// Buffer is taken as a pointer.
		if tt.IsVarLen && tt.DynLenArg == -1 {
			return true, fmt.Sprintf("%v buffer %v is dynamic but no len is found", reasonPrefix, t.GetName())
		}
	case *SCSANStructType:
		for _, f := range tt.Fields {
			if unres, reason := s.CheckTypeUnresolvedLen(s.Types[f.FieldID], fmt.Sprintf("%v struct %v, field %v:", reasonPrefix, t.GetName(), f.Name)); unres {
				return true, reason
			}
		}
	case *SCSANUnionType:
		for _, f := range tt.Fields {
			if unres, reason := s.CheckTypeUnresolvedLen(s.Types[f.FieldID], fmt.Sprintf("%v union %v, field %v:", t.GetName(), reasonPrefix, f.Name)); unres {
				return true, reason
			}
		}
	case *SCSANPointerType:
		return s.CheckTypeUnresolvedLen(s.Types[tt.Pointee], fmt.Sprintf("%v pointer %v:", reasonPrefix, t.GetName()))
	}
	return false, ""
}

func (s *Spec) CopyTypeWithTruncation(ns *Spec, t SCSANType, newID map[SCSANTypeID]SCSANTypeID, mustCopy bool) (SCSANType, bool) {
	switch tt := t.(type) {
	case *SCSANLenType:
		if mustCopy || !tt.OfScalar {
			// TODO: do this deep copy for all types
			nLen := &SCSANLenType{
				SCSANType: &SCSANTypeBase{
					Name: tt.GetName(),
					Type: tt.GetTypeName(),
				},
				Len:      tt.Len,
				OfScalar: tt.OfScalar,
				BitSize:  tt.BitSize,
				path:     tt.path,
			}
			ns.NewSCSANType(nLen)
			log.Printf("set %v -> %v", tt.GetID(), nLen.GetID())
			newID[tt.GetID()] = nLen.GetID()
			return nLen, false
		} else {
			log.Printf("tt id = %v name = %v is of scalar", tt.GetID(), tt.GetName())
			return nil, true
		}
	case *SCSANArrayType:
		nElemID := SCSANTypeID(-1)
		nElem, drop := s.CopyTypeWithTruncation(ns, s.Types[tt.Elem], newID, mustCopy)
		if drop {
			return nil, true
		}
		nElemID = nElem.GetID()
		nArr := &SCSANArrayType{
			SCSANType: &SCSANTypeBase{
				Name: tt.GetName(),
				Type: tt.GetTypeName(),
			},
			IsVarLen:      tt.IsVarLen,
			StaticLen:     tt.StaticLen,
			DynLenArg:     tt.DynLenArg,
			DynLenArgPath: tt.DynLenArgPath,
			Elem:          tt.Elem,
		}
		nArr.Elem = nElemID
		// if tt.DynLenArg >= 0 {
		// 	nLen, _ := s.CopyTypeWithTruncation(ns, s.Types[tt.DynLenArg], newID, false)
		// 	nArr.DynLenArg = nLen.GetID()
		// }
		ns.NewSCSANType(nArr)
		newID[tt.GetID()] = nArr.GetID()
		return nArr, false
	case *SCSANBufferType:
		nBuf := &SCSANBufferType{
			SCSANType: &SCSANTypeBase{
				Name: tt.GetName(),
				Type: tt.GetTypeName(),
			},
			IsVarLen:      tt.IsVarLen,
			StaticLen:     tt.StaticLen,
			DynLenArg:     tt.DynLenArg,
			DynLenArgPath: tt.DynLenArgPath,
		}
		// if tt.DynLenArg >= 0 {
		// 	nLen, _ := s.CopyTypeWithTruncation(ns, s.Types[tt.DynLenArg], newID, false)
		// 	nBuf.DynLenArg = nLen.GetID()
		// }
		ns.NewSCSANType(nBuf)
		newID[tt.GetID()] = nBuf.GetID()
		return nBuf, false
	case *SCSANPointerType:
		nPtr := &SCSANPointerType{
			SCSANType: &SCSANTypeBase{
				Name: tt.GetName(),
				Type: tt.GetTypeName(),
			},
			Pointee: tt.Pointee,
			Dir:     tt.Dir,
		}
		*nPtr = *tt
		nPointee, _ := s.CopyTypeWithTruncation(ns, s.Types[tt.Pointee], newID, true)
		nPtr.Pointee = nPointee.GetID()
		ns.NewSCSANType(nPtr)
		newID[tt.GetID()] = nPtr.GetID()
		return nPtr, false
	case *SCSANStructType:
		nStruct := &SCSANStructType{
			SCSANType: &SCSANTypeBase{
				Name: tt.GetName(),
				Type: tt.GetTypeName(),
			},
			IsVarLen:      tt.IsVarLen,
			StaticLen:     tt.StaticLen,
			DynLenArg:     tt.DynLenArg,
			DynLenArgPath: tt.DynLenArgPath,
		}
		nStruct.Fields = []SCSANStructField{}
		for _, f := range tt.Fields {
			nf, drop := s.CopyTypeWithTruncation(ns, s.Types[f.FieldID], newID, false)
			if !drop {
				nField := SCSANStructField{}
				nField = f
				nField.FieldID = nf.GetID()
				nStruct.Fields = append(nStruct.Fields, nField)
			}
		}
		// if tt.DynLenArg >= 0 {
		// 	nLen, _ := s.CopyTypeWithTruncation(ns, s.Types[tt.DynLenArg], newID, false)
		// 	nStruct.DynLenArg = nLen.GetID()
		// }
		if len(nStruct.Fields) == 0 && !mustCopy {
			return nil, true
		} else {
			ns.NewSCSANType(nStruct)
			newID[tt.GetID()] = nStruct.GetID()
			return nStruct, false
		}
	case *SCSANUnionType:
		// At this stage, we have already checked that all unions are static length and do not contain len or pointer type.
		// So we only copy the union type if it is required by the caller.
		if mustCopy {
			nUnion := &SCSANUnionType{
				SCSANType: &SCSANTypeBase{
					Name: tt.GetName(),
					Type: tt.GetTypeName(),
				},
				StaticLen:     tt.StaticLen,
				DynLenArg:     tt.DynLenArg,
				DynLenArgPath: tt.DynLenArgPath,
			}
			// We can clear the fields since they are not needed
			nUnion.Fields = []SCSANStructField{}
			ns.NewSCSANType(nUnion)
			newID[tt.GetID()] = nUnion.GetID()
			return nUnion, false
		} else {
			return nil, true
		}
	case *SCSANScalarType:
		if mustCopy {
			nScalar := &SCSANScalarType{
				SCSANType: &SCSANTypeBase{
					Name: tt.GetName(),
					Type: tt.GetTypeName(),
				},
				Len: tt.Len,
			}
			ns.NewSCSANType(nScalar)
			newID[tt.GetID()] = nScalar.GetID()
			return nScalar, false
		} else {
			return nil, true
		}
	default:
		log.Fatalf("unhandled type for copy with truncation")
		return nil, true
	}
}

func (s *Spec) CopySyscallInfoWithTruncation(si *SyscallInfo, ns *Spec, newID map[SCSANTypeID]SCSANTypeID) *SyscallInfo {
	nsi := &SyscallInfo{
		NR:            si.NR,
		Name:          si.Name,
		BranchArg:     si.BranchArg,
		BranchArgVals: si.BranchArgVals,
	}
	nsi.Args = []SyscallArg{}
	l := len(ns.Types)
	for _, a := range si.Args {
		na := SyscallArg{}
		na = a
		nt, _ := s.CopyTypeWithTruncation(ns, s.Types[a.TypeID], newID, true)
		na.TypeID = nt.GetID()
		nsi.Args = append(nsi.Args, na)
	}
	// TODO: So much duplicate code here. Simplify it by using an embeded interface.
	for _, na := range ns.Types[l:] {
		switch t := na.(type) {
		case *SCSANArrayType:
			if t.DynLenArg >= 0 {
				t.DynLenArg = newID[t.DynLenArg]
			}
			for i := 0; i < len(t.DynLenArgPath); i++ {
				if t.DynLenArgPath[i] >= 0 {
					t.DynLenArgPath[i] = newID[t.DynLenArgPath[i]]
				}
			}
		case *SCSANBufferType:
			if t.DynLenArg >= 0 {
				t.DynLenArg = newID[t.DynLenArg]
			}
			for i := 0; i < len(t.DynLenArgPath); i++ {
				if t.DynLenArgPath[i] >= 0 {
					t.DynLenArgPath[i] = newID[t.DynLenArgPath[i]]
				}
			}
		case *SCSANStructType:
			if t.DynLenArg >= 0 {
				t.DynLenArg = newID[t.DynLenArg]
			}
			for i := 0; i < len(t.DynLenArgPath); i++ {
				if t.DynLenArgPath[i] >= 0 {
					t.DynLenArgPath[i] = newID[t.DynLenArgPath[i]]
				}
			}
		case *SCSANUnionType:
			if t.DynLenArg >= 0 {
				t.DynLenArg = newID[t.DynLenArg]
			}
			for i := 0; i < len(t.DynLenArgPath); i++ {
				if t.DynLenArgPath[i] >= 0 {
					t.DynLenArgPath[i] = newID[t.DynLenArgPath[i]]
				}
			}
		}

	}
	return nsi
}

func (s *Spec) CheckCallBranchArg(call *prog.Syscall, branchArg int) ([]uint64, error) {
	if len(call.Args) <= branchArg {
		return nil, fmt.Errorf("call %v only has %v args, but branch arg is at %v", call.CallName, len(call.Args), branchArg)
	}
	switch t := call.Args[branchArg].Type.(type) {
	case *prog.ConstType:
		return []uint64{t.Val}, nil
	case *prog.FlagsType:
		return t.Vals, nil
	}
	return nil, fmt.Errorf("call %v %v arg is not const type", call.Name, branchArg)
}

func main() {

	// Syzlang type note:

	// Phase I:
	// Initialized all types by traversing top-down from syscalls.
	// Indirect pointer types:
	// 	PointerType:
	// 		A pointer to typed memory (e.g., struct, array, ...).
	//		Length refers to the underlying type.
	//		If array, length = array.length * array.elem.length
	// 		If struct, length = struct.length
	// 	BufferType:
	// 		A pointer to untyped memory.
	// LenType
	//	Only keep the LenType that points to the indirect pointer types.
	// 	Others are used to better generate fuzzing program, e.g., a network header
	// 	must contains the length of message, which is not useful for us.
	// ArrayType
	// 	static: length = x
	// 	dyn: length = lenVar.evaluate()
	// StructType
	//
	// UnionType:
	// 	Include only when it has fixed length.
	// VMAType:
	// 	Used in `mmap` to do memory operations. Take it as scalar, do not allocate memory.
	// Rest of types:
	// 	Take them as scalar types.
	//
	// For now, we ignore dispatched syscalls, i.e., those whose call name contains '$'.
	//
	// Phase II:
	// Resove length:
	// 	For all len, find its related variables.
	// 	If the related variable is not dynamic length, then mark it, so we can ignore it in future.
	// 	Else, save the len var ID in the related variable.
	// Check Union:
	// 	Find if there is union that contains pointer or valid len types. If so, mark the call as unsupported.
	//
	// We don't remove unreferenced types.

}

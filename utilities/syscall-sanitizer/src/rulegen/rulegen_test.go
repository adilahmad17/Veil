package main

import (
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func Test(t *testing.T) {
	target, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		log.Fatalf("cannot get program target: %v", err)
	}
	spec := &Spec{
		typeMap: make(map[string]SCSANType),
	}
	ns := &Spec{
		typeMap: make(map[string]SCSANType),
	}
	syscallListPath := os.Getenv("SCSAN_SYSCALL_LIST")
	if len(syscallListPath) == 0 {
		log.Fatalf("SCSAN_SYSCALL_LIST not specified")
	}
	b, err := ioutil.ReadFile(syscallListPath)
	if err != nil {
		log.Fatalf("cannot read syscall list: %v", err)
	}
	supportedCalls := strings.Split(string(b), "\n")
	for _, callName := range supportedCalls {
		branchArg := -1
		if callName[0] == '!' {
			continue
		}
		if strings.Contains(callName, ":") {
			sp := strings.Split(callName, ":")
			if len(sp) != 2 {
				t.Fatalf("incorrect call dispatching format for %s", callName)
			}
			branchArg, err = strconv.Atoi(strings.TrimSpace(sp[1]))
			if err != nil {
				t.Fatalf("%s does not contain dispatching number", callName)
			}
			if branchArg < 0 || branchArg >= 6 {
				t.Fatalf("branch argument must be between 0 and 5, now is %v", branchArg)
			}
			callName = sp[0]
		}
		log.Printf("Analyzing call %v...", callName)
		call, ok := target.SyscallMap[callName]
		if !ok {
			t.Fatalf("call %v is not in grammar", call)
		}
		branchArgVals := []uint64{}
		if branchArg != -1 {
			branchArgVals, err = spec.CheckCallBranchArg(call, branchArg)
			if err != nil {
				t.Fatalf("%v", err)
			}
		}
		si, err := spec.analyzeCall(call)
		if err != nil {
			t.Logf("%v", err)
		}
		si.BranchArg = branchArg
		si.BranchArgVals = branchArgVals
		err = spec.ResolveLenInCall(si)
		if err != nil {
			t.Logf("%v", err)
		}
		err = spec.CheckUnionInCall(si)
		if err != nil {
			t.Logf("%v", err)
		}
		if unres, reason := spec.CheckCallUnresolvedLen(si); unres {
			t.Fatalf("has unresolved len: %v", reason)
		}
		spec.Call = append(spec.Call, si)
		nsi := spec.CopySyscallInfoWithTruncation(si, ns, map[SCSANTypeID]SCSANTypeID{})
		ns.Call = append(ns.Call, nsi)
	}

	t.Logf("--------------------------- after truncation ---------------------------")
	t.Logf("%v", ns.DebugString())
	t.Logf("%v", ns.HumanString())
	t.Logf("%v", ns.CArgSpec())
	t.Logf("%v", ns.CCallSpec())
	err = ioutil.WriteFile("../../spec/call_spec.gen", []byte(ns.CCallSpec()), 0666)
	if err != nil {
		t.Fatalf("cannot write call spec: %v", err)
	}
	err = ioutil.WriteFile("../../spec/arg_spec.gen", []byte(ns.CArgSpec()), 0666)
	if err != nil {
		t.Fatalf("cannot write arg spec: %v", err)
	}
	err = ioutil.WriteFile("../../spec/spec.dbg", []byte(ns.HumanString()), 0666)
	if err != nil {
		t.Fatalf("cannot write debug spec: %v", err)
	}

}

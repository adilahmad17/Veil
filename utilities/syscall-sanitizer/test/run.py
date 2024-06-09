#!/usr/bin/python3

import subprocess, os


test_dir = os.path.dirname(os.path.abspath(__file__))
proj_dir = os.path.dirname(test_dir)
call_spec = os.path.join(proj_dir, 'spec', 'call_spec.gen')
arg_spec = os.path.join(proj_dir, 'spec', 'arg_spec.gen')
trace = os.path.join(test_dir, 'strace.txt')

env = {
        'SCSAN_CALL_SPEC': call_spec,
        'SCSAN_ARG_SPEC': arg_spec,
}

s = subprocess.check_output(['strace', '-v', './test'], env=env, stderr=subprocess.STDOUT).decode('utf-8')

with open(trace, "r") as f:
        for i, l in enumerate(f.readlines()):
                if l.strip() in s:
                        print("PASS test", i)
                else:
                        print("--------------------------------------")
                        print("FAIL test", i)
                        print("expect:", l.strip())
                        print("cannot find it in:")
                        print(s)
                        exit(-1)
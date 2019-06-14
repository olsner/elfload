#!/bin/bash

###############################################################################
# Actual tests

test_stackalign() {
    compile_asm stackalign.S
    testenv+=( foo=bar )
    check "$runelf" "$out"
    check "$runelf" "$out" arg1
    check "$runelf" "$out" arg1longersdf
    testenv+=( foo=bar bar=baz )
    check "$runelf" "$out" arg1 longersdf
    check "$runelf" "$out" arg1
    check "$runelf" "$out"
}
test_true() {
    compile_asm true.S
    check "$runelf" "$out"
}

###############################################################################
# Internal functions

# runtest TESTFUN
runtest() {
    local testenv=( )
    local testfun="$1"
    local out="tmp/$testfun"
    local failed_checks=0
    if "$@" && (( failed_checks == 0 )); then
        echo "$testfun: OK"
        let pass=pass+1
    else
        echo "$testfun: $failed_checks checks failed"
        let fail=fail+1
    fi
    return 0
}
compile_asm() {
    gcc  -nostdlib -static -o "$out" "$@"
}
check() {
    local cmd=( "$@" )
    if (( strace )); then
        cmd=( strace "$@" )
    fi
    if env -i "${testenv[@]}" "${cmd[@]}"; then
        if (( v )); then
            echo "PASS: in $testfun: \"$@\" (with ${testenv[@]}) exited with status=$?"
        fi
    else
        echo "FAIL: in $testfun: \"$@\" (with ${testenv[@]}) failed with status=$?"
        (( failed_checks++ ))
        return 1
    fi
}

###############################################################################
# Entry point and test runner

mkdir -p tmp
runelf=../out/runelf-pie
pass=0
fail=0

if [ $# -eq 0 ]; then
    funs=( $(declare -F | cut -d\  -f3 | grep ^test_ ) )
else
    funs=( "$@" )
fi
for f in "${funs[@]}"; do
    runtest "$f"
done

echo
echo "PASS: $pass"
echo "FAIL: $fail"
exit $fail

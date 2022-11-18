#!/bin/bash

###############################################################################
# Actual tests

test_stackalign() {
    compile stackalign.S
    testenv+=( foo=bar )
    check "$runelf" "$out"
    check "$runelf" "$out" arg1
    check "$runelf" "$out" arg1longersdf
    check "$runelf" "$out" arg1 longersdf
    testenv+=( bar=baz )
    check "$runelf" "$out" arg1 longersdf
    check "$runelf" "$out" arg1
    check "$runelf" "$out"
}
test_true() {
    compile true.S
    check "$runelf" "$out"
}
test_proc_cmdline() {
    compile cat.c
    check_output "$out\0/proc/self/cmdline\0" "$out" /proc/self/cmdline
    check_output "$out\0/proc/self/cmdline\0" "$runelf" "$out" /proc/self/cmdline
}
test_proc_environ() {
    compile cat.c
    check_output "" "$out" /proc/self/environ
    check_output "" "$runelf" "$out" /proc/self/environ
    testenv+=( foo=bar )
    check_output "foo=bar\0" "$out" /proc/self/environ
    check_output "foo=bar\0" "$runelf" "$out" /proc/self/environ
    testenv+=( bar=baz )
    check_output "foo=bar\0bar=baz\0" "$out" /proc/self/environ
    check_output "foo=bar\0bar=baz\0" "$runelf" "$out" /proc/self/environ
}
test_proc_comm() {
    compile cat.c
    check_output "test_proc_comm\n" "$out" /proc/self/comm
    # TODO Check /proc/$pid/task/$pid/comm, which is what PR_SET_NAME affects.
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
compile() {
    gcc -g -nostdlib -static -ffreestanding -c -o "${out}.o" "$@"
    gcc -g -nostdlib -static -ffreestanding -o "$out" "${out}.o"
}
check() {
    local cmd=( "$@" )
    if (( strace )); then
        cmd=( strace -i "$@" )
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
check_output() {
    local refout=$1
    shift
    local cmd=( "$@" )
    if (( strace )); then
        cmd=( strace -i "$@" )
    fi
    local outf="tmp/${testfun}.out"
    local errf="tmp/${testfun}.err"
    local reff="tmp/${testfun}.ref"
    echo -ne "$refout" >"$reff"

    # Run the command
    if (( v )); then
        echo Running: env -i "${testenv[@]}" "${cmd[@]}" ">$outf" "2>$errf"
    fi
    env -i "${testenv[@]}" "${cmd[@]}" >"$outf" 2>"$errf"

    # Check status and compare output
    local res=$?
    if (( res )); then
        echo "FAIL: in $testfun: \"$@\" (with ${testenv[@]}) failed with status=$res"
        (( failed_checks++ ))
        return 1
    fi
    if cmp -s "$outf" "$reff"; then
        if (( v )); then
            echo "PASS: in $testfun: \"$@\" (with ${testenv[@]}) succeeded and produced correct output"
        fi
    else
        echo "FAIL: in $testfun: \"$@\" (with ${testenv[@]}): wrong output"
        printf "Expected output: %q\n" "$(cat "$reff")"
        printf "Actual output: %q\n" "$(cat "$outf")"
        (( failed_checks++ ))
        return 1
    fi
}

###############################################################################
# Entry point and test runner

mkdir -p tmp
runelfs=( ../out/runelf-pie ../out/runelf-static ../out/runelf )
pass=0
fail=0

if [ $# -eq 0 ]; then
    funs=( $(declare -F | cut -d\  -f3 | grep ^test_ ) )
else
    funs=( "$@" )
fi
for runelf in "${runelfs[@]}"; do
    echo "Testing $runelf"
    for f in "${funs[@]}"; do
        runtest "$f"
    done
    echo
done

echo "PASS: $pass"
echo "FAIL: $fail"
exit $fail

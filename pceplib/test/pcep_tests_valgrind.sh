#
# Common function definition for PCEPlib valgrind tests
#

function valgrind_test()
{
    local test_suite=$1
    [[ -z ${test_suite} ]]     && { echo "${FUNCNAME}(): test_suite not specified."; exit 1; }
    [[ ! -x "${test_suite}" ]] && { echo "${test_suite} is not an executable file."; exit 1; }

    G_SLICE=always-malloc
    G_DEBUG=gc-friendly
    VALGRIND="valgrind -v --tool=memcheck --leak-check=full --num-callers=40 --error-exitcode=1"
    ${VALGRIND} --log-file=${test_suite}.val.log ./${test_suite} || ({ echo "Valgrind memory check error"; exit 1; })
}

#!/usr/bin/env bash
# Compile reference modules against this configured, patched FRR source tree.
set -euo pipefail
source_dir=$(cd "$(dirname "$0")/../.." && pwd)
module_dir="$source_dir/tools/nsr-experimental"
output_dir=$(realpath -m "${1:?provide a NEW output directory}")
[ -f "$source_dir/config.h" ] || { echo 'Configure FRR first' >&2; exit 2; }
[ ! -e "$output_dir" ] || { echo 'Output directory already exists' >&2; exit 2; }
mkdir -p "$output_dir"
make -C "$source_dir" -j"${JOBS:-2}" bgpd/bgpd bfdd/bfdd
cd "$module_dir"
for name in bgpd_native_journal bgpd_native_follow bfdd_native_journal bfdd_native_follow; do
    extra=()
    if [ "$name" = bgpd_native_journal ]; then extra=(tcp_snapshot.c); fi
    "${CC:-cc}" -std=gnu11 -fms-extensions -O2 -Wall -Wextra -Werror \
        -Wno-unused-parameter -Wno-missing-field-initializers \
        -shared -fPIC -DHAVE_CONFIG_H -I"$source_dir" -I"$source_dir/lib" \
        "$name.c" "${extra[@]}" -o "$output_dir/$name.so"
done
for name in tcp_stage_node tcp_stage_batch; do
    extra=()
    if [ "$name" = tcp_stage_batch ]; then extra=(-ljson-c); fi
    "${CC:-cc}" -std=gnu11 -O2 -Wall -Wextra -Werror "$name.c" tcp_snapshot.c \
        "${extra[@]}" -o "$output_dir/$name"
done
for name in tcp_output_gate tcp_output_gate_multi; do
    "${CC:-cc}" -std=gnu11 -O2 -Wall -Wextra -Werror "$name.c" \
        -lnetfilter_queue -ljson-c -o "$output_dir/$name"
done
sha256sum "$output_dir"/*.so "$output_dir"/tcp_* > "$output_dir/artifacts.sha256"

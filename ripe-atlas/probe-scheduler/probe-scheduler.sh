#!/usr/bin/env bash

ipv4_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
batch_size=10
log_file="probe-scheduler.log"
test_target=""

if [ "$#" -ne 1 ]; then
    >&2 echo "Usage: $0 PROBES_CSV"
    exit 1
fi
probes_csv="$1"

if [ -z "$test_target" ]; then
    >&2 echo "Variable 'test_target' must be initialized."
    exit 2
fi

function log() {
    printf "`date -Iseconds`: $@\n" | tee -a "$log_file"
}

function run_traceroute() {
    probe_id="$1"
    probe_addr="$2"
    output_file="${probe_id}-traceroute.txt"
    ip_version="6"

    # By default, we assume that we're dealing with an IPv6 address.
    # Check if we're dealing with an IPv4 address instead.
    if [[ $probe_addr =~ $ipv4_regex ]]; then
        ip_version="4"
    fi

    log "Running traceroute to ${probe_addr} (ID=${probe_id})."
    echo "probe_id=${probe_id},probe_addr=${probe_addr}." > "$output_file"
    traceroute \
        "-$ip_version" \
        --icmp \
        -n \
        "$probe_addr" >> "$output_file" 2>&1 &
}

function run_atlas_measurement() {
    probe_batch="$1"
    log "Probe batch: $probe_batch"

    # Run TCP traceroute.
    ripe-atlas measure traceroute \
        --protocol TCP \
        --measurement-tags "geo-latency-measurements" \
        --from-probes "$probe_batch" \
        --no-report \
        --dry-run \
        "$test_target"

    # Run ICMP tranceroute.
    ripe-atlas measure traceroute \
        --protocol ICMP \
        --measurement-tags "geo-latency-measurements" \
        --from-probes "$probe_batch" \
        --no-report \
        --dry-run \
        "$test_target"

    # Run TLS traceroute.
    ripe-atlas measure sslcert \
        --measurement-tags "geo-latency-measurements" \
        --from-probes "$probe_batch" \
        --no-report \
        --dry-run \
        "$test_target"
}

# Read our CSV-formatted probe file in chunks.
while mapfile -t -n "$batch_size" ary && ((${#ary[@]})); do
    probe_ids=""

    # Run a traceroute for each probe in the current batch.
    for i in ${!ary[@]}; do
        probe_id=$(echo "${ary[$i]}" | cut -d "," -f 1)
        probe_addr=$(echo "${ary[$i]}" | cut -d "," -f 2)
        if [ -z "$probe_ids" ]; then
            probe_ids="$probe_id"
        else
            probe_ids="${probe_ids},${probe_id}"
        fi
        run_traceroute "$probe_id" "$probe_addr"
        sleep 0.1
    done

    # Run the RIPE Atlas measurement for the current batch.
    run_atlas_measurement "$probe_ids"

    # Wait for a few seconds to disperse load on our measurement machine.
    log "---"
    sleep 3
done < "$probes_csv"
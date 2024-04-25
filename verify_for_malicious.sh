#!/bin/bash

syntactic_analysis() {
    file="$1"
    num_lines=$(wc -l < "$file")
    num_words=$(wc -w < "$file")
    num_chars=$(wc -c < "$file")

    if grep -qE 'corrupted|dangerous|risk|attack|malware|malicious' "$file"; then
        exit 1
    fi

    if LC_ALL=C grep -q '[^[:print:]]' "$file"; then
        exit 1
    fi

    exit 0
}

main() {
    if [ "$#" -ne 1 ]; then
        echo "Usage: $0 file_to_check"
        exit 1
    fi

    syntactic_analysis "$1"
}

main "$@"

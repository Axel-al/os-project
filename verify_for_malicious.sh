#!/bin/bash

file="$1"

check_dangerous() {
    if [[ $(grep -P "[^\x00-\x7F]" "$file") ]]; then
        echo "$file"
        return 1
    fi

    if grep -qE 'corrupted|dangerous|risk|attack|malware|malicious' "$file"; then
        echo "$file"
        return 1
    fi

    return 0
}

main() {
    if [[ ! -e "$file" ]]; then
        echo "File does not exist."
        exit 1
    fi

    if [[ $(wc -l < "$file") -lt 3 ]]; then
        if [[ $(wc -w < "$file") -gt 1000 && $(wc -c < "$file") -gt 2000 ]]; then
            check_dangerous
            if [[ $? -eq 0 ]]; then
                echo "SAFE"
            fi
        fi
    fi
}

main

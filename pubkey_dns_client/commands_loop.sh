#!/bin/bash

commands="" # Commands to be executed
seconds=5   # Default execution every 5 seconds
total=0     # Total number of executions, default always runing

show_help()
{
    echo -e "Options:\n"\
        "  -c '\"<cmd>\"'\tCommands to execute, content needs to\n"\
        "\t\tbe enclosed in quotation marks: (\\\") or ('\").\n"\
        "  -s <num>\tSeconds between each execution.\n"\
        "  -t <num>\tVariable number of loops.\n"\
        "  --help\tDisplay this information."
}

parse_input_loop()
{
    for ((i = 0; i < $#; i++))
    do
        arg=${args[$i]}

        if [ "$arg" == "-s" ]; then
            ((i++))
            seconds=${args[$i]} && continue
        fi
        if [ "$arg" == "-t" ]; then
            ((i++))
            total=${args[$i]} && continue
        fi
        if [ "$arg" == "-c" ]; then
            ((i++))
            arg=${args[$i]}

            if ! echo $arg | grep -Eq "^\""; then
                echo "Invalid commands. Try: $0 --help"
                exit 1
            fi
            commands+=$arg

            while ! echo $arg | grep -Eq "\"$" && ((i < $#))
            do
                ((i++))
                arg=${args[$i]}
                commands+=" "$arg
            done
            continue
        fi
        if [ "$arg" == "--help"  ] || [ "$arg" == "-h"  ]; then
            show_help
            exit 0
        fi
        echo Invalid input \"$arg\". Try \"$0 --help\" && exit 0
    done
}

parse_input()
{
    if [ $# -lt 1 ]; then
        echo "Missing args. Try: $0 --help" && exit 1
    fi

    for arg in $@
    do
        args[$arg_idx]=$arg
        ((arg_idx++))
    done

    parse_input_loop $@

    # Remove quotation marks
    intercept_len=$(( ${#commands} - 2 ))
    commands=${commands: 1:$intercept_len}
    echo -e "\n\tCommands: $commands"

    # I'm too lazy to do more checks, the user is responsible for it
    result=`echo $total | grep "[^0-9]"`

    if [ ! -z $result ]; then
        echo "Invalid total number '$total'."
        exit 1
    fi
    if [ $total -gt 0 ]; then
        echo -e "\tTotal number of executions: $total"
    fi
    result=`echo $seconds | grep "[^0-9]"`

    if [[ ! -z $result ]] || [[ $seconds -lt 1 ]]; then
        echo "Invalid seconds '$seconds'."
        exit 1
    fi
    echo -e "\tSleep seconds: $seconds\n"
}

doing_work()
{
    if [ $total -gt 0 ]
    then
        for ((i = 0; i < $total; i++))
        do
            $commands &
            sleep $seconds
        done
        return
    fi

    while true
    do
        # echo run: $commands
        $commands &
        sleep $seconds
    done
}

main()
{
    parse_input $@
    doing_work
}

main $@


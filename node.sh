#!/bin/bash

# Check if at least one argument is provided
if [ $# -lt 1 ]; then
    echo "Usage: $0 my_port [peer_port]"
    exit 1
fi

# Assign arguments to variables
my_port=$1
peer_port=$2

# Build the command based on the arguments
if [ -z "$peer_port" ]; then
    cmd="./netclocksync -b 127.0.0.1 -p $my_port"
else
    cmd="./netclocksync -b 127.0.0.1 -p $my_port -a 127.0.0.1 -r $peer_port"
fi

# Display the command
echo "Executing: $cmd"

# Trap SIGINT (Ctrl+C) and forward it to the child process
trap 'kill $child_pid 2>/dev/null' SIGINT

# Execute the command and forward stdout and stderr
$cmd &
child_pid=$!
wait $child_pid
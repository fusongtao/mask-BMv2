#!/bin/bash

# s1 controller
./run_controller.py -a 127.0.0.1:50051 -n s1 -d 0

# s2 controller
./run_controller.py -a 127.0.0.1:50052 -n s2 -d 1

# s3 controller
./run_controller.py -a 127.0.0.1:50053 -n s3 -d 2

# s4 controller
./run_controller.py -a 127.0.0.1:50054 -n s4 -d 3

# s5 controller
./run_controller.py -a 127.0.0.1:50055 -n s5 -d 4

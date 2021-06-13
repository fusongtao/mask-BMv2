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

# s6 controller
./run_controller.py -a 127.0.0.1:50056 -n s6 -d 5

# s7 controller
./run_controller.py -a 127.0.0.1:50057 -n s7 -d 6

# s8 controller
./run_controller.py -a 127.0.0.1:50058 -n s8 -d 7

# s9 controller
./run_controller.py -a 127.0.0.1:50059 -n s9 -d 8

# s10 controller
./run_controller.py -a 127.0.0.1:50060 -n s10 -d 9

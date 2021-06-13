# 


1.copy the directory into the BMv2 enviroment, recommends the directory of "~/P4/tutorials/exercises".
### Compiling and running P4 code
2.Open a new terminal in directory "~/P4/tutorials/exercises/mask/P4", compile the P4 code using "make" in this terminal.And run three terminal with the command "xterm h1 h2 h1"
3.Open five new terminal in directory "~/P4/tutorials/exercises/mask/P4/switch" and run the follow command line as:
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

4.4.If you want to increase the path length, you could change the two ".json"  in directory "~/P4/tutorials/exercises/mask/P4/assets". 

### Usage
5.Open "h2" and run the command "./receive.py", and "h1" with the command "./localization.py".
6.Open "h1" and run the command "./send.py 0", the "h1" will send a certain number(as the "def new_policy(epoch)" in the "headerNew.py" calculates with the"policy" and the "epoch") of packets toward "h2", "h2" will verify and display the outcome. Each end of an epoch, it would send an ACK toward "h1", the ternimal with the command "./localization.py" would recieve and display it.

The inspiration to utilize the sip_hash is from https://github.com/SPINE-P4/spine-code

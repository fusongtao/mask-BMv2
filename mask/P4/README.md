
### Prepare
1.copy the directory into the BMv2 enviroment, recommends the directory of "/P4/tutorials/exercises".
### Compiling and running P4 code
2.Open a new terminal in directory "/P4/tutorials/exercises/mask/P4", compile the P4 code using "make" in this terminal.And run two terminal with the command "xterm h1 h2"
3.Open five new terminal in directory "/P4/tutorials/exercises/mask/P4/switch" and run the follow command line as:
## s1 controller
./run_controller.py -a 127.0.0.1:50051 -n s1 -d 0
## s2 controller
./run_controller.py -a 127.0.0.1:50052 -n s2 -d 1
## s3 controller
./run_controller.py -a 127.0.0.1:50053 -n s3 -d 2
## s4 controller
./run_controller.py -a 127.0.0.1:50054 -n s4 -d 3
## s5 controller
./run_controller.py -a 127.0.0.1:50055 -n s5 -d 4

### Usage
4.Open "xterm h2" and run the command "./receive.py".

5.Open "xterm h1" and run the command "./send.py 0", the "h1" will send 5 packets toward "h2", "h2" will verify and display the outcome. Each command sends 5 packets, and the outcome accumulated in "h2".

6.If you want to test the negotiating processing, Open second "xterm h1" in the first terminal, and run the command "./resend.py". In the first "h1" run the command "./send.py 1", and "h2" will send an ack toward "h1", trigger the second "h1" run the "./resend.py", it will send  50 packets towards "h2", and then send a "check point packet".

7.All the switch terminal will display the processing in the relative terminal.

8.You could also change the path length with the modification of the two .json document in the directory "./P4/assets"(decreasd the length directly, if you want to increase the path length, you should alter the document "switch_controller.py" in the directory "./p4/switch" to increase the relative switch). You could also alter the policy in the python document to change the data packet number in each epoch.


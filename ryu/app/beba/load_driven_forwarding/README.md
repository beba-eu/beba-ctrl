# Load-driven Forwarding

### Requirements:
	iperf3	
### Description
	
The code below implements a load-driven forwarding application based on flowlets in the Beba switch environment.

![alt tag](https://raw.githubusercontent.com/angelotulumello/beba-ctrl/tree/beba_advanced/ryu/app/beba/load_driven_forwarding/ldf-topo.png)

The topology is composed of three leaves and two spines in which all leaves are connected to both spines, so having two possible paths to reach the same destination. 
It is possible to change the RTT in the topology described in leafSpineTopo.py by changing the delays, as well as the constant RTT defined in the controller code in *ldf-flowlets.py*. To evaluate the probe mechanism (MPLS packets) and the forwarding behaviour of the flowlets, start some flows and a tcpdump capture on the interfaces between leaves and spines. For this purpose, the iperf3 tool was used to make tests, and it is required for the application to work properly.

### Setup:

To start the application open two ssh terminals. 
In the first shell type:
	
	ryu-manager ldf-flowlets.py

to start the controller.
Then in the second shell type: 

	sudo python leafSpineTopo.py 

to start the topology.
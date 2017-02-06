#!/usr/bin/python

"""
This example shows how to create an empty Mininet object
(without a topology object) and add nodes to it manually.
"""

from mininet.net import Mininet
from mininet.node import UserSwitch,RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from mininet.topo import Topo

def myNet():

	"Create an empty network and add nodes to it."

	net = Mininet( controller=RemoteController, switch=UserSwitch, link=TCLink, autoStaticArp=True )

	info( '*** Adding controller\n' )
	net.addController( 'c0' )

	net.addHost( 'h1' , mac="00:00:00:00:00:01" )
	net.addHost( 'h2' , mac="00:00:00:00:00:02" )
	net.addHost( 'h3' , mac="00:00:00:00:00:03" )
	#leaves
	net.addSwitch('s1')
	net.addSwitch('s2')
	net.addSwitch('s3')
	#spines
	net.addSwitch('s4')
	net.addSwitch('s5')

	info( '*** Creating links\n' )
	net.addLink( 's1', 's4' , bw=3 )
	net.addLink( 's1', 's5' , bw=3 ) 
	net.addLink( 's2', 's4' , bw=3 )
	net.addLink( 's2', 's5' , bw=3 )
	net.addLink( 's3', 's4' , bw=3 )
	net.addLink( 's3', 's5' , bw=3 )

	net.addLink( 'h1', 's1' , bw=6 )
	net.addLink( 'h2', 's2' , bw=6 )
	net.addLink( 'h3', 's3' , bw=6 )

	info( '*** Starting network\n')
	net.start()

	info( '*** Disabling tcp-segmentation overload on hosts\' interfaces\n')
	info( '    ofsoftswitch13 supports segments of length <= 1514 only\n')
	net.get('h1').cmd("ethtool -K h1-eth0 tso off")
	net.get('h2').cmd("ethtool -K h2-eth0 tso off")
	net.get('h3').cmd("ethtool -K h3-eth0 tso off")

	info( '*** Starting tcpdump on node\'s interfaces\n')
	net.get('h1').cmd("tcpdump -ni h1-eth0 -w ~/h1-eth0.pcap &")
	net.get('h2').cmd("tcpdump -ni h2-eth0 -w ~/h2-eth0.pcap &")
	net.get('s1').cmd("tcpdump -ni s1-eth1 -w ~/s1-eth1.pcap &")
	net.get('s1').cmd("tcpdump -ni s1-eth2 -w ~/s1-eth2.pcap &")
	net.get('s2').cmd("tcpdump -ni s2-eth1 -w ~/s2-eth1.pcap &")
	net.get('s2').cmd("tcpdump -ni s2-eth2 -w ~/s2-eth2.pcap &")

	info('*** Opening udp port 5001 on h2\n')
	net.get('h2').cmd("nc -u -lp 5001 &")

	info('*** Opening tcp port 4001 on h1\n')
	net.get('h1').cmd("nc -lp 4001 &")

	info('\n*** Opening iperf3 servers on hosts (10.0.0.1-3), on ports 6666 and 6667\n')

	net.get('h1').cmd("iperf3 -s -D -p 6666 && iperf3 -s -D -p 6667 && iperf3 -s -D -p 6668")
	net.get('h2').cmd("iperf3 -s -D -p 6666 && iperf3 -s -D -p 6667 && iperf3 -s -D -p 6668")
	net.get('h3').cmd("iperf3 -s -D -p 6666 && iperf3 -s -D -p 6667 && iperf3 -s -D -p 6668")

	net.get('h1').cmd("iperf3 -s -D -p 10000 && iperf3 -s -D -p 10001")
	net.get('h2').cmd("iperf3 -s -D -p 10000 && iperf3 -s -D -p 10001")
	net.get('h3').cmd("iperf3 -s -D -p 10000 && iperf3 -s -D -p 10001")

	net.get('h1').cmd("iperf3 -c 10.0.0.2 -p 10000 -l 1 -b 1b -t 1000 > outs/out1 &")
	net.get('h1').cmd("iperf3 -c 10.0.0.2 -p 10001 -l 1 -b 1b -t 1000 > outs/out2 &")
	net.get('h2').cmd("iperf3 -c 10.0.0.3 -p 10000 -l 1 -b 1b -t 1000 > outs/out3 &")
	net.get('h2').cmd("iperf3 -c 10.0.0.3 -p 10001 -l 1 -b 1b -t 1000 > outs/out4 &")
	net.get('h3').cmd("iperf3 -c 10.0.0.1 -p 10000 -l 1 -b 1b -t 1000 > outs/out5 &")
	net.get('h3').cmd("iperf3 -c 10.0.0.1 -p 10001 -l 1 -b 1b -t 1000 > outs/out6 &")

	info( '*** Running CLI\n' )
	CLI( net )

	info( '*** Stopping network' )
	net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNet()
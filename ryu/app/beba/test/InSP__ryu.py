import logging
import os,subprocess,time
from mininet.net import Mininet
from mininet.topo import SingleSwitchTopo
from mininet.node import UserSwitch,RemoteController
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
import ryu.ofproto.ofproto_v1_3 as ofproto
import ryu.ofproto.ofproto_v1_3_parser as ofparser
import ryu.ofproto.beba_v1_0 as bebaproto
import ryu.ofproto.beba_v1_0_parser as bebaparser
from ryu.lib import hub
from scapy.all import Ether, ARP
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from beba import BebaSwitchDbg,BebaHost

LOG = logging.getLogger('app.beba.pkttmp')

class BebaInSP(app_manager.RyuApp):

	def __init__(self, *args, **kwargs):
		super(BebaInSP, self).__init__(*args, **kwargs)
		if os.geteuid() != 0:
		    exit("You need to have root privileges to run this script")
		# Kill Mininet
		os.system("sudo mn -c 2> /dev/null")
		print 'Starting Mininet'
		self.net = Mininet(topo=SingleSwitchTopo(2),switch=BebaSwitchDbg,host=BebaHost,controller=RemoteController,cleanup=True,autoSetMacs=True,listenPort=6634,autoStaticArp=False)
		self.net.start()
		self.test_id = 0

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		self.monitor_thread = hub.spawn(getattr(self, '_monitor%s' % self.test_id),datapath)
		self.test_id += 1

	def add_flow(self, datapath, table_id, priority, match, actions):
		if len(actions) > 0:
			inst = [ofparser.OFPInstructionActions(
					ofproto.OFPIT_APPLY_ACTIONS, actions)]
		else:
			inst = []
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table_id,
								priority=priority, match=match, instructions=inst)
		datapath.send_msg(mod)
		
	def add_pktgen_flow(self, datapath, table_id, priority, match, pkttmp_id, actions):
		if len(actions) > 0:
			inst = [bebaparser.OFPInstructionInSwitchPktGen(pkttmp_id, actions)]
		else:
			inst = []
		mod = ofparser.OFPFlowMod(datapath=datapath, table_id=table_id,
								priority=priority, match=match, instructions=inst)
		datapath.send_msg(mod)

	def ping_and_sniff(self,test_num):
		print '\n\nStart Tcpdump on H1-eth0 interface'
		self.net['h1'].cmd('(tcpdump -n -l &> /tmp/tcpdumplog.h1) &')
		t = 0
		while t<3:
			print 'Waiting %d sec for tcpdump startup...' % (3-t)
			t += 1
			time.sleep(1)
		print '\n\nPing from h1 to h2'
		self.net['h1'].cmd('ping -c1 10.0.0.2')

		# Processes are shared: kill command from h1 kills also tcpdump in h1!
		self.net['h1'].cmd("kill -SIGINT $(pidof tcpdump)")

		with open("/tmp/tcpdumplog.h1","r") as myfile:
			h1data=myfile.read()

		if 'ARP, Request who-has 10.0.0.2 tell 10.0.0.1' in h1data and 'ARP, Reply 172.16.0.2 is-at 00:01:02:03:04:05' in h1data:
			print 'Test %d: \x1b[32mSUCCESS!\x1b[0m' % test_num
		else:
			print 'Test %d: \x1b[31mFAIL\x1b[0m' % test_num
			self.stop_test_and_exit()

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):
		msg = ev.msg
		datapath = msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocols(ethernet.ethernet)[0]
		
		if eth.ethertype != ether_types.ETH_TYPE_ARP:
			# ignore not arp packet
			LOG.info("unexpected packet...")
			return
		
		data = str(Ether(src='00:01:02:03:04:05', dst='46:9c:96:30:ff:d5') / ARP(
						hwsrc='00:01:02:03:04:05', hwdst='46:9c:96:30:ff:d5', psrc="172.16.0.2", pdst='172.16.0.1', op=2))

		actions = [parser.OFPActionOutput(1)]
		out = parser.OFPPacketOut(
			datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER,
			actions=actions, data=data)
		datapath.send_msg(out)


	def test0(self,datapath):
		pkt_data = str(Ether(src='00:01:02:03:04:05', dst='46:9c:96:30:ff:d5')/ARP(
						hwsrc='00:01:02:03:04:05',hwdst='46:9c:96:30:ff:d5',psrc="172.16.0.2",pdst='172.16.0.1',op=2))

		LOG.info("Configuring switch %d..." % datapath.id)

		LOG.info("Creating PKTTMP entries...")
		""" Create PKTTMP entries """
		req = bebaparser.OFPExpMsgAddPktTmp(datapath=datapath, pkttmp_id=0, pkt_data=pkt_data)
 		datapath.send_msg(req)
		
		LOG.info("Creating PKTTMP triggers...")
		""" Create PKTTMP trigger (install flow entry) """
		match = ofparser.OFPMatch(in_port=1)
		actions = [ofparser.OFPActionOutput(1)]
		self.add_pktgen_flow(datapath=datapath, table_id=0, priority=0,
							 match=match, pkttmp_id=0, actions=actions)

	def test1(self,datapath):
		LOG.info("Configuring switch %d..." % datapath.id)
		
		LOG.info("Creating ARP triggers...")
		match = ofparser.OFPMatch(in_port=1)
		actions = [ofparser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
										ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath=datapath, table_id=0, priority=0,
							 match=match, actions=actions)

	def _monitor0(self,datapath):
		print("Network is ready")
		# [TEST 0]
		# mininet> h1 ping -c1 h2
		# The switch should send back to H1 an ARP reply "172.16.0.2 is-at 00:01:02:03:04:05"
		self.test0(datapath)
		self.ping_and_sniff(test_num=0)
		self.restart_mininet()

	def _monitor1(self,datapath):
		print("Network is ready")
		# [TEST 1]
		# mininet> h1 ping -c1 h2
		# The controller should send a packetOUT command to the switch to send an ARP reply to h1 "172.16.0.2 is-at 00:01:02:03:04:05"
		self.test1(datapath)
		self.ping_and_sniff(test_num=1)
		#self.restart_mininet()
		self.stop_test_and_gracefully_exit()

	def restart_mininet(self):
		print 'Restarting Mininet\n'
		os.system("sudo mn -c 2> /dev/null")
		self.net = Mininet(topo=SingleSwitchTopo(2),switch=UserSwitch,controller=RemoteController,cleanup=True,autoSetMacs=True,listenPort=6634,autoStaticArp=False)
		self.net.start()

	def stop_test_and_gracefully_exit(self):
		# Kill Mininet and/or Ryu
		self.net.stop()
		os.system("sudo mn -c 2> /dev/null")
		# Send SIGTERM instead of SIGKILL
		os.system("kill -7 $(pidof -x ryu-manager) 2> /dev/null")

	def stop_test_and_exit(self):
		# Kill Mininet and/or Ryu
		self.net.stop()
		os.system("sudo mn -c 2> /dev/null")
		os.system("kill -9 $(pidof -x ryu-manager) 2> /dev/null")
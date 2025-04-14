from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_4
from os_ken.lib.packet import packet
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import in_proto
from os_ken.lib.packet import arp
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import tcp
from os_ken.lib.packet.tcp import TCP_SYN
from os_ken.lib.packet.tcp import TCP_FIN
from os_ken.lib.packet.tcp import TCP_RST
from os_ken.lib.packet.tcp import TCP_ACK
from os_ken.lib.packet.ether_types import ETH_TYPE_IP, ETH_TYPE_ARP
import time

class Nat(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Nat, self).__init__(*args, **kwargs)
        self.lmac = '00:00:00:00:00:10'  # MAC addr for our private network
        self.emac = '00:00:00:00:00:20'  # MAC addr for our public network
        self.hostmacs = {
                '10.0.1.100': '00:00:00:00:00:01',  # h1
                '10.0.2.100': '00:00:00:00:00:02',  # h2
                '10.0.2.101': '00:00:00:00:00:03',  # h3
                }
        
        # format for the NAT table is {(priv_ip, priv_port, pub_ip, pub_port): (nat_port, timestamp)}
        self.nat_table = {}
        
        self.MAX_PORTS = 65000 # as per requirement 4
        self.available_ports = set( range(1, self.MAX_PORTS + 1) )
        
        self.NAT_PUBLIC_IP = '10.0.1.2'
        self.NAT_PRIVATE_IP = '10.0.2.1'
        self.NAT_TIMEOUT = 10

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        return out

    def _send_rst_packet(self, datapath, in_port, orig_pkt):
        # we use this func to send an RST packet to our client when the NAT table is full
        eth = orig_pkt.get_protocols(ethernet.ethernet)[0]
        ip_header = orig_pkt.get_protocol(ipv4.ipv4)
        tcp_header = orig_pkt.get_protocol(tcp.tcp)
        
        print("NAT table full! Sending RST packet to client.")
        
        pkt = packet.Packet()
        
        # add an ethernet header
        pkt.add_protocol(ethernet.ethernet( 
            dst=eth.src, # swap!
            src=self.lmac, # swap!
            ethertype=ETH_TYPE_IP
        ))
        
        # add an IP header
        pkt.add_protocol(ipv4.ipv4(
            dst=ip_header.src, # swap!
            src=ip_header.dst, # swap!
            proto=ip_header.proto
        ))
        
        # add a TCP header with the RST flag
        pkt.add_protocol(tcp.tcp(
            src_port=tcp_header.dst_port, # swap!
            dst_port=tcp_header.src_port, # swap!
            seq=tcp_header.ack if tcp_header.ack else 0,
            ack=tcp_header.seq + 1 if tcp_header.seq else 0,
            bits=TCP_RST | TCP_ACK # and then add an RST flag as per requirement 3 of this assigngment
        ))
        
        # send our packet
        out = self._send_packet(datapath, in_port, pkt)
        datapath.send_msg(out)

    def _clear_one_expired_entry(self) -> bool:
        # we use this func to clear an expired NAT table entry
        
        current_time = time.time()
        
        # find one singular expired entry
        for key, (nat_port, timestamp) in self.nat_table.items():
            if current_time - timestamp > self.NAT_TIMEOUT: 
                # since we found one, remove it and return success
                del self.nat_table[key]
                self.available_ports.add(nat_port)
                print(f"Cleared expired entry: {key[0]}:{key[1]} -> {self.NAT_PUBLIC_IP}:{nat_port}")
                print(f"Available ports after cleanup: {self.available_ports}")
                return True # yay! 
    
        return False  # no expired entries could be found 

    def _get_available_port(self):
        # we use this func to try and get an available port for NAT
        if not self.available_ports:
            # then we should try to find & clear an expired entry
            self._clear_one_expired_entry()
        
        if self.available_ports:
            return self.available_ports.pop()
        return None

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev): # this gets called whenever our switch connects to the controller
        dp = ev.msg.datapath
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        acts = [psr.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, psr.OFPMatch(), acts)

    def add_flow(self, dp, prio, match, acts, buffer_id=None, delete=False): # note to self: features_handler calls this 
        # we use this func to add or rm flow rules within the switch 
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        
        bufferfish = buffer_id if buffer_id is not None else ofp.OFP_NO_BUFFER # I really wanted to call it bufferfish

        if delete:
            modification = psr.OFPFlowMod(datapath=dp, command=dp.ofproto.OFPFC_DELETE, out_port=dp.ofproto.OFPP_ANY, out_group=dp.ofproto.OFPG_ANY, match=match)
        else: # otherwise we wanna add a new rule to the switch
            instructions = [ psr.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, acts) ]
            modification = psr.OFPFlowMod(datapath=dp, buffer_id=bufferfish, priority=prio, match=match, instructions=instructions)

        dp.send_msg(modification)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        in_port, pkt = ( msg.match['in_port'], packet.Packet(msg.data) )
        dp = msg.datapath
        ofp, psr, _ = (dp.ofproto, dp.ofproto_parser, format(dp.id, '016d')) # I wanted to make dp.id a zero-padded int of width 16
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # handle ARPs
        if eth.ethertype == ETH_TYPE_ARP:
            arp_header = pkt.get_protocols(arp.arp)[0]
            if arp_header.opcode == arp.ARP_REQUEST: # we only care about requests
                print('ARP', pkt)
                arp_reply = packet.Packet()
                arp_reply.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, dst=eth.src, src=self.emac if in_port == 1 else self.lmac))
                arp_reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=self.emac if in_port == 1 else self.lmac, dst_mac=arp_header.src_mac, src_ip=arp_header.dst_ip, dst_ip=arp_header.src_ip))
                out = self._send_packet(dp, in_port, arp_reply)
                print('ARP Rep', arp_reply)
                dp.send_msg(out)
            return

        # handle IP packets
        if eth.ethertype == ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4) # grab ipv4 header
            
            # we only wanna handle TCP packets
            if ip_pkt and ip_pkt.proto == in_proto.IPPROTO_TCP:
                tcp_pkt = pkt.get_protocol(tcp.tcp) # grab TCP header if so
                
                # handle packets from private -> public
                if in_port != 1 and ip_pkt.dst.startswith('10.0.1'):
                    private_ip = ip_pkt.src
                    private_port = tcp_pkt.src_port
                    public_ip = ip_pkt.dst
                    public_port = tcp_pkt.dst_port
                    
                    nat_key = (private_ip, private_port, public_ip, public_port) # let's make a 4-tuple for easy NAT table lookups
                    
                    # we gotta make sure this connection doesn't already exist ':D 
                    if nat_key in self.nat_table:
                        # connection already exists so let's just update the timestamp and return immediately
                        nat_port = self.nat_table[nat_key][0]
                        self.nat_table[nat_key] = (nat_port, time.time())
                        return
                    
                    # connection didn't already exist, lets proceed 
                    nat_port = self._get_available_port() 
                    
                    if nat_port is None: 
                        # unfortunately the NAT table is completely full!
                        # we couldn't even make space by kicking out an expired entry.
                        # let's just send an RST packet and return, as per requirement 3.
                        self._send_rst_packet(dp, in_port, pkt)
                        return

                    # okay yay there was space, let's create our new NAT entry with the current timestamp
                    self.nat_table[nat_key] = ( nat_port, time.time() )
                    
                    print(f"Created NAT entry: {private_ip}:{private_port} -> {self.NAT_PUBLIC_IP}:{nat_port}")
                    print(f"Available ports: {self.available_ports}")
                    print(f"Table entries occupied: {len(self.nat_table)}")
                    
                    # HERE WE INSTALL FLOW RULES FOR BOTH POSSIBLE DIRECTIONS...
                    
                    # priv —> pub (SNAT)
                    match_ptop = psr.OFPMatch(
                        in_port = in_port,
                        eth_type = ETH_TYPE_IP,
                        ipv4_src = private_ip,
                        ipv4_dst = public_ip,
                        ip_proto = in_proto.IPPROTO_TCP,
                        tcp_src = private_port,
                        tcp_dst = public_port
                    )
                    
                    actions_ptop = [
                        psr.OFPActionSetField(eth_src=self.emac),
                        psr.OFPActionSetField(eth_dst=self.hostmacs[public_ip]),
                        psr.OFPActionSetField(ipv4_src=self.NAT_PUBLIC_IP),
                        psr.OFPActionSetField(tcp_src=nat_port),
                        psr.OFPActionOutput(port=1)
                    ]
                    
                    self.add_flow(dp, 100, match_ptop, actions_ptop, msg.buffer_id)
                    
                    # pub —> priv (DNAT)
                    match_ptop = psr.OFPMatch(
                        in_port=1,
                        eth_type=ETH_TYPE_IP,
                        ipv4_src=public_ip,
                        ipv4_dst=self.NAT_PUBLIC_IP,
                        ip_proto=in_proto.IPPROTO_TCP,
                        tcp_src=public_port,
                        tcp_dst=nat_port
                    )
                    
                    actions_ptop = [
                        psr.OFPActionSetField(eth_src=self.lmac),
                        psr.OFPActionSetField(eth_dst=self.hostmacs[private_ip]),
                        psr.OFPActionSetField(ipv4_dst=private_ip),
                        psr.OFPActionSetField(tcp_dst=private_port),
                        psr.OFPActionOutput(port=in_port)
                    ]
                    
                    self.add_flow(dp, 100, match_ptop, actions_ptop)
                    
                    # if we used the buffer_id in the flow_mod, then we can stop here! no need to send a packet
                    if msg.buffer_id != ofp.OFP_NO_BUFFER:
                        return
                    
                    # forward the first packet in the new connection
                    actions = [
                        psr.OFPActionSetField(eth_src = self.emac),
                        psr.OFPActionSetField(eth_dst = self.hostmacs[public_ip]),
                        psr.OFPActionSetField(ipv4_src = self.NAT_PUBLIC_IP),
                        psr.OFPActionSetField(tcp_src = nat_port),
                        psr.OFPActionOutput(port = 1)
                    ]
                    
                    data = None
                    if msg.buffer_id == ofp.OFP_NO_BUFFER:
                        data = msg.data
                    else:
                        data = None
                    
                    out = psr.OFPPacketOut( datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=data )

                    dp.send_msg(out)
                    return
        
        # drop non-TCP non-IPv4 packets 
        actions = []
        out = psr.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=None if msg.buffer_id != ofp.OFP_NO_BUFFER else msg.data)
        # ^ create packet (out) with an empty action list
        dp.send_msg(out) # and send to switch

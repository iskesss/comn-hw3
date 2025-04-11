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
import datetime

class Nat(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Nat, self).__init__(*args, **kwargs)
        self.lmac = '00:00:00:00:00:10'
        self.emac = '00:00:00:00:00:20'
        self.hostmacs = {
                '10.0.1.100': '00:00:00:00:00:01',
                '10.0.2.100': '00:00:00:00:00:02',
                '10.0.2.101': '00:00:00:00:00:03',
                }
        
        # NAT configuration
        self.private_net = '10.0.2.0/24'
        self.public_net = '10.0.1.0/24'
        self.nat_ip = '10.0.1.2'
        self.local_ip = '10.0.2.1'
        
        # NAT table: {(nat_port): (client_ip, client_port, server_ip, server_port, timestamp)}
        self.nat_table = {}
        
        # Track allocated ports per server
        # {(server_ip, server_port): set of nat_ports}
        self.server_port_map = {}
        
        # Next available NAT port (start from 1 as shown in the example)
        self.next_port = 1
        
        # Maximum NAT table entries per server address/port
        self.max_entries_per_server = 65000
        
        # Timeout (in seconds) for NAT entries (10 seconds as specified, which is much shorter than what the RFC suggests, but whatever)
        self.timeout = 10 

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

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        dp = ev.msg.datapath
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        acts = [psr.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, psr.OFPMatch(), acts)

    def add_flow(self, dp, prio, match, acts, buffer_id=None, delete=False):
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        bid = buffer_id if buffer_id is not None else ofp.OFP_NO_BUFFER
        if delete:
            mod = psr.OFPFlowMod(datapath=dp, command=dp.ofproto.OFPFC_DELETE,
                    out_port=dp.ofproto.OFPP_ANY, out_group=dp.ofproto.OFPG_ANY,
                    match=match)
        else:
            ins = [psr.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, acts)]
            mod = psr.OFPFlowMod(datapath=dp, buffer_id=bid, priority=prio,
                                match=match, instructions=ins)
        dp.send_msg(mod)
    
    def _is_private_ip(self, ip):
        """Check if IP is in the private network."""
        return ip.startswith('10.0.2.')
    
    def _allocate_nat_port(self, server_ip, server_port):
        """Allocate a NAT port for a new connection to server_ip:server_port."""
        # Get or create set of ports already used for this server
        server_key = (server_ip, server_port)
        if server_key not in self.server_port_map:
            self.server_port_map[server_key] = set()
        
        used_ports = self.server_port_map[server_key]
        
        # Check if we've reached maximum entries for this server
        if len(used_ports) >= self.max_entries_per_server:
            # Try to find an expired entry to reuse
            current_time = datetime.datetime.now()
            expired_port = None
            
            for nat_port in list(self.nat_table.keys()):
                client_ip, client_port, s_ip, s_port, timestamp = self.nat_table[nat_port]
                if (s_ip, s_port) == server_key and (current_time - timestamp).total_seconds() > self.timeout:
                    expired_port = nat_port
                    # Delete the expired entry
                    del self.nat_table[nat_port]
                    used_ports.remove(nat_port)
                    break
            
            if expired_port is None:
                # No expired entries, cannot allocate a new port
                return None
            else:
                return expired_port
        
        # Find an available port (start from next_port and wrap around)
        start_port = self.next_port
        while True:
            if self.next_port not in used_ports and self.next_port not in self.nat_table:
                # Found an available port
                used_ports.add(self.next_port)
                allocated_port = self.next_port
                # Increment next_port for next time
                self.next_port = (self.next_port % 65535) + 1
                return allocated_port
            
            # Try next port
            self.next_port = (self.next_port % 65535) + 1
            
            # If we've tried all ports, give up
            if self.next_port == start_port:
                return None
    
    def _add_nat_entry(self, client_ip, client_port, server_ip, server_port, nat_port):
        """Add a new entry to the NAT table."""
        self.nat_table[nat_port] = (client_ip, client_port, server_ip, server_port, datetime.datetime.now())
        print(f"NAT entry added: {client_ip}:{client_port} -> {self.nat_ip}:{nat_port} -> {server_ip}:{server_port}")
    
    def _get_nat_entry_by_nat_port(self, nat_port):
        """Get NAT entry by NAT port."""
        if nat_port in self.nat_table:
            # Update timestamp to refresh the entry
            entry = list(self.nat_table[nat_port])
            entry[4] = datetime.datetime.now()
            self.nat_table[nat_port] = tuple(entry)
            return self.nat_table[nat_port]
        return None
    
    def _get_nat_entry_by_client(self, client_ip, client_port, server_ip, server_port):
        """Get NAT entry by client info."""
        for nat_port, entry in self.nat_table.items():
            if (entry[0] == client_ip and entry[1] == client_port and 
                entry[2] == server_ip and entry[3] == server_port):
                # Update timestamp to refresh the entry
                entry_list = list(entry)
                entry_list[4] = datetime.datetime.now()
                self.nat_table[nat_port] = tuple(entry_list)
                return nat_port, entry
        return None, None
    
    def _send_tcp_rst(self, datapath, pkt, in_port):
        """Send a TCP RST packet to the client."""
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        
        # Create a new packet with RST flag
        rst_pkt = packet.Packet()
        
        # Add ethernet header (swap src and dst)
        rst_pkt.add_protocol(ethernet.ethernet(
            ethertype=eth_pkt.ethertype,
            dst=eth_pkt.src,
            src=eth_pkt.dst))
        
        # Add IP header (swap src and dst)
        rst_pkt.add_protocol(ipv4.ipv4(
            version=ip_pkt.version,
            header_length=ip_pkt.header_length,
            tos=ip_pkt.tos,
            total_length=0,  # Will be filled by the OS
            identification=ip_pkt.identification,
            flags=ip_pkt.flags,
            offset=ip_pkt.offset,
            ttl=ip_pkt.ttl,
            proto=ip_pkt.proto,
            csum=0,  # Will be filled by the OS
            src=ip_pkt.dst,
            dst=ip_pkt.src))
        
        # Add TCP header with RST flag
        rst_pkt.add_protocol(tcp.tcp(
            src_port=tcp_pkt.dst_port,
            dst_port=tcp_pkt.src_port,
            seq=tcp_pkt.ack,
            ack=0,
            offset=5,
            bits=TCP_RST,
            window_size=0,
            csum=0,  # Will be filled by the OS
            urgent=0,
            option=None))
        
        # Send RST packet
        ofp = datapath.ofproto
        out = self._send_packet(datapath, in_port, rst_pkt)
        datapath.send_msg(out)
        print(f"TCP RST sent to {ip_pkt.src}:{tcp_pkt.src_port}")
    
    def _install_nat_flows(self, datapath, client_ip, client_port, server_ip, server_port, nat_port, in_port, buffer_id=None):
        """Install NAT flow rules."""
        ofp, psr = (datapath.ofproto, datapath.ofproto_parser)
        
        # Create flow for outgoing direction (private -> public)
        match_outgoing = psr.OFPMatch(
            in_port=2 if in_port == 2 else 3,  # From private network
            eth_type=ETH_TYPE_IP,
            ipv4_src=client_ip,
            ipv4_dst=server_ip,
            ip_proto=in_proto.IPPROTO_TCP,
            tcp_src=client_port,
            tcp_dst=server_port
        )
        
        actions_outgoing = [
            psr.OFPActionSetField(eth_src=self.emac),
            psr.OFPActionSetField(eth_dst=self.hostmacs.get(server_ip, 'ff:ff:ff:ff:ff:ff')),
            psr.OFPActionSetField(ipv4_src=self.nat_ip),
            psr.OFPActionSetField(tcp_src=nat_port),
            psr.OFPActionOutput(port=1)  # To public network
        ]
        
        # Create flow for incoming direction (public -> private)
        match_incoming = psr.OFPMatch(
            in_port=1,  # From public network
            eth_type=ETH_TYPE_IP,
            ipv4_src=server_ip,
            ipv4_dst=self.nat_ip,
            ip_proto=in_proto.IPPROTO_TCP,
            tcp_src=server_port,
            tcp_dst=nat_port
        )
        
        actions_incoming = [
            psr.OFPActionSetField(eth_src=self.lmac),
            psr.OFPActionSetField(eth_dst=self.hostmacs.get(client_ip, 'ff:ff:ff:ff:ff:ff')),
            psr.OFPActionSetField(ipv4_dst=client_ip),
            psr.OFPActionSetField(tcp_dst=client_port),
            psr.OFPActionOutput(port=2 if in_port == 2 else 3)  # Back to private network
        ]
        
        # Install flows
        self.add_flow(datapath, 10, match_outgoing, actions_outgoing)
        self.add_flow(datapath, 10, match_incoming, actions_incoming)
        
        print(f"NAT flows installed for {client_ip}:{client_port} <-> {self.nat_ip}:{nat_port} <-> {server_ip}:{server_port}")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev): # invoked every time the controller receives a packet
        msg = ev.msg
        in_port, pkt = (msg.match['in_port'], packet.Packet(msg.data))
        
        # Debug print to show when controller receives packets (just to verify that every data packet is not redirected to the controller -- delete later)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt and eth_pkt.ethertype == ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt and ip_pkt.proto == in_proto.IPPROTO_TCP:
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                if tcp_pkt:
                    print(f"CONTROLLER RECEIVED PACKET: {ip_pkt.src}:{tcp_pkt.src_port} -> {ip_pkt.dst}:{tcp_pkt.dst_port} (TCP Flags: {tcp_pkt.bits})")
        
        dp = msg.datapath
        ofp, psr, did = (dp.ofproto, dp.ofproto_parser, format(dp.id, '016d'))
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Handle ARP requests
        if eth.ethertype == ETH_TYPE_ARP:
            ah = pkt.get_protocols(arp.arp)[0]
            if ah.opcode == arp.ARP_REQUEST:
                print('ARP', pkt)
                ar = packet.Packet()
                ar.add_protocol(ethernet.ethernet(ethertype=eth.ethertype,
                    dst=eth.src,
                    src=self.emac if in_port == 1 else self.lmac))
                ar.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                    src_mac=self.emac if in_port == 1 else self.lmac,
                    dst_mac=ah.src_mac, src_ip=ah.dst_ip, dst_ip=ah.src_ip))
                out = self._send_packet(dp, in_port, ar)
                print('ARP Rep', ar)
                dp.send_msg(out)
            return

        # Handle IPv4 packets
        if eth.ethertype == ETH_TYPE_IP:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            
            # Handle only TCP packets
            if ip_pkt and ip_pkt.proto == in_proto.IPPROTO_TCP:
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                
                if tcp_pkt:
                    # Packet from private network (needs NAT)
                    if in_port != 1:  # From port 2 or 3 (private network)
                        client_ip = ip_pkt.src
                        client_port = tcp_pkt.src_port
                        server_ip = ip_pkt.dst
                        server_port = tcp_pkt.dst_port
                        
                        # Check if we already have a NAT entry for this connection
                        nat_port, entry = self._get_nat_entry_by_client(client_ip, client_port, server_ip, server_port)
                        
                        if nat_port is None:
                            # Need to create a new NAT entry
                            nat_port = self._allocate_nat_port(server_ip, server_port)
                            
                            if nat_port is None:
                                # NAT table is full, send RST to client
                                self._send_tcp_rst(dp, pkt, in_port)
                                return
                            
                            # Create new NAT entry
                            self._add_nat_entry(client_ip, client_port, server_ip, server_port, nat_port)
                            
                        # Install NAT flows
                        self._install_nat_flows(dp, client_ip, client_port, server_ip, server_port, nat_port, in_port)
                        
                        # Forward the current packet
                        actions = [
                            psr.OFPActionSetField(eth_src=self.emac),
                            psr.OFPActionSetField(eth_dst=self.hostmacs.get(server_ip, 'ff:ff:ff:ff:ff:ff')),
                            psr.OFPActionSetField(ipv4_src=self.nat_ip),
                            psr.OFPActionSetField(tcp_src=nat_port),
                            psr.OFPActionOutput(port=1)  # To public network
                        ]
                    
                    # Packet from public network (needs reverse NAT)
                    else:  # From port 1 (public network)
                        if ip_pkt.dst == self.nat_ip:
                            nat_port = tcp_pkt.dst_port
                            
                            # Look up NAT entry
                            entry = self._get_nat_entry_by_nat_port(nat_port)
                            
                            if entry:
                                client_ip, client_port, server_ip, server_port, _ = entry
                                
                                # Check if this packet is from the correct server
                                if ip_pkt.src != server_ip or tcp_pkt.src_port != server_port:
                                    # Doesn't match our NAT entry, drop it
                                    return
                                
                                # Forward the current packet
                                actions = [
                                    psr.OFPActionSetField(eth_src=self.lmac),
                                    psr.OFPActionSetField(eth_dst=self.hostmacs.get(client_ip, 'ff:ff:ff:ff:ff:ff')),
                                    psr.OFPActionSetField(ipv4_dst=client_ip),
                                    psr.OFPActionSetField(tcp_dst=client_port),
                                    psr.OFPActionOutput(port=2 if client_ip == '10.0.2.100' else 3)  # Back to private network
                                ]
                            else:
                                # No NAT entry found for this port, drop the packet
                                return
                        else:
                            # Not destined for NAT IP, drop it
                            return
                else:
                    # Not a TCP packet, drop it
                    return
            else:
                # Not an IPv4 or not TCP, drop it
                return
        else:
            # Not an IPv4 packet, drop it
            return
        
        # Send the packet
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = psr.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                              in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)
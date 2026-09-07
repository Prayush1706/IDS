import time
import queue
import logging
import threading
import warnings

warnings.filterwarnings("ignore",category=UserWarning)

try:
    from scapy.all import sniff,IP,IPv6,TCP,UDP,ICMP,DNS,conf
    SCAPY_AVAILABLE=True
except ImportError:
    SCAPY_AVAILABLE=False

logger=logging.getLogger("live_sniffer")
logging.basicConfig(level=logging.INFO,format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

class FlowRecord:
    def __init__(self,client_ip,server_ip,client_port,server_port,protocol):
        self.src_ip=client_ip
        self.dst_ip=server_ip
        self.src_port=client_port
        self.dst_port=server_port
        self.protocol=protocol
        self.start_time=time.time()
        self.last_time=self.start_time
        self.last_in_time=self.start_time
        self.last_out_time=self.start_time
        self.last_emitted_time=self.start_time
        self.in_bytes=0
        self.out_bytes=0
        self.in_pkts=0
        self.out_pkts=0
        self.shortest_pkt=65535
        self.longest_pkt=0
        self.min_ip_pkt_len=65535
        self.pkts_up_to_128=0
        self.pkts_128_to_256=0
        self.pkts_256_to_512=0
        self.pkts_512_to_1024=0
        self.tcp_flags=0
        self.server_tcp_flags=0
        self.tcp_win_in=0
        self.tcp_win_out=0
        self.min_ttl=255
        self.retransmitted_in_bytes=0
        self.retransmitted_out_bytes=0
        self.retransmitted_in_pkts=0
        self.dns_query_id=0
        self.dns_query_type=0
        self.dns_ttl_answer=0
        self.icmp_type=0
        self.ftp_ret_code=0
        self.l7_proto=self._infer_l7_proto(client_port,server_port)

    def _infer_l7_proto(self,p1,p2):
        ports={p1,p2}
        if 443 in ports or 8443 in ports:return 91
        if 80 in ports or 8080 in ports:return 7
        if 53 in ports:return 5
        if 22 in ports:return 131
        if 21 in ports or 20 in ports:return 1
        if 3306 in ports or 5432 in ports:return 178
        if 3389 in ports:return 45
        if 445 in ports or 139 in ports:return 118
        return 0

    def add_packet(self,pkt,is_from_client=True):
        self.last_time=time.time()
        pkt_len=len(pkt)
        if pkt_len<self.shortest_pkt:self.shortest_pkt=pkt_len
        if pkt_len>self.longest_pkt:self.longest_pkt=pkt_len
        if pkt_len<=128:self.pkts_up_to_128+=1
        elif pkt_len<=256:self.pkts_128_to_256+=1
        elif pkt_len<=512:self.pkts_256_to_512+=1
        elif pkt_len<=1024:self.pkts_512_to_1024+=1
        if IP in pkt:
            ttl=pkt[IP].ttl
            if ttl<self.min_ttl:self.min_ttl=ttl
            ip_len=pkt[IP].len
            if ip_len<self.min_ip_pkt_len:self.min_ip_pkt_len=ip_len
        elif IPv6 in pkt:
            hlim=pkt[IPv6].hlim
            if hlim<self.min_ttl:self.min_ttl=hlim
            self.min_ip_pkt_len=min(self.min_ip_pkt_len,pkt_len)
        if is_from_client:
            self.in_bytes+=pkt_len
            self.in_pkts+=1
            self.last_in_time=self.last_time
            if TCP in pkt:
                self.tcp_flags|=int(pkt[TCP].flags)
                self.tcp_win_in=max(self.tcp_win_in,pkt[TCP].window)
        else:
            self.out_bytes+=pkt_len
            self.out_pkts+=1
            self.last_out_time=self.last_time
            if TCP in pkt:
                self.server_tcp_flags|=int(pkt[TCP].flags)
                self.tcp_win_out=max(self.tcp_win_out,pkt[TCP].window)
        if DNS in pkt:
            dns_layer=pkt[DNS]
            self.dns_query_id=dns_layer.id
            if dns_layer.qd:
                self.dns_query_type=dns_layer.qd.qtype
            if dns_layer.an and hasattr(dns_layer.an,'ttl'):
                self.dns_ttl_answer=dns_layer.an.ttl
        if ICMP in pkt:
            self.icmp_type=pkt[ICMP].type

    def to_feature_dict(self):
        duration_sec=self.last_time-self.start_time
        duration_ms=duration_sec*1000.0 if duration_sec>=0.5 else 0.0
        dur_in=max(0.0,self.last_in_time-self.start_time) if duration_sec>=0.5 else 0.0
        dur_out=max(0.0,self.last_out_time-self.start_time) if (duration_sec>=0.5 and self.out_pkts>0) else 0.0
        throughput_in=(self.in_bytes*8.0)/duration_sec if duration_sec>=1.0 else 0.0
        throughput_out=(self.out_bytes*8.0)/duration_sec if (duration_sec>=1.0 and self.out_pkts>0) else 0.0
        shortest=self.shortest_pkt if self.shortest_pkt!=65535 else 40
        min_ip_len=self.min_ip_pkt_len if self.min_ip_pkt_len!=65535 else 40
        min_ttl_val=self.min_ttl if self.min_ttl!=255 else 64
        raw_dict={
            "PROTOCOL":float(self.protocol),
            "L7_PROTO":float(self.l7_proto),
            "IN_BYTES":float(self.in_bytes),
            "OUT_BYTES":float(self.out_bytes),
            "TCP_FLAGS":float(self.tcp_flags if self.tcp_flags>0 else 24),
            "SERVER_TCP_FLAGS":float(self.server_tcp_flags if self.server_tcp_flags>0 else 24),
            "FLOW_DURATION_MILLISECONDS":float(duration_ms),
            "DURATION_IN":float(dur_in),
            "DURATION_OUT":float(dur_out),
            "MIN_TTL":float(min_ttl_val),
            "LONGEST_FLOW_PKT":float(self.longest_pkt),
            "SHORTEST_FLOW_PKT":float(shortest),
            "MIN_IP_PKT_LEN":float(min_ip_len),
            "SRC_TO_DST_SECOND_BYTES":float(self.in_bytes),
            "DST_TO_SRC_SECOND_BYTES":float(self.out_bytes),
            "RETRANSMITTED_IN_BYTES":float(self.retransmitted_in_bytes),
            "RETRANSMITTED_IN_PKTS":float(self.retransmitted_in_pkts),
            "RETRANSMITTED_OUT_BYTES":float(self.retransmitted_out_bytes),
            "SRC_TO_DST_AVG_THROUGHPUT":float(throughput_in),
            "DST_TO_SRC_AVG_THROUGHPUT":float(throughput_out),
            "NUM_PKTS_UP_TO_128_BYTES":float(self.pkts_up_to_128),
            "NUM_PKTS_128_TO_256_BYTES":float(self.pkts_128_to_256),
            "NUM_PKTS_256_TO_512_BYTES":float(self.pkts_256_to_512),
            "NUM_PKTS_512_TO_1024_BYTES":float(self.pkts_512_to_1024),
            "TCP_WIN_MAX_IN":float(0.0 if duration_ms==0.0 else min(self.tcp_win_in,65535)),
            "TCP_WIN_MAX_OUT":float(0.0 if duration_ms==0.0 else min(self.tcp_win_out,65535)),
            "ICMP_TYPE":float(self.icmp_type),
            "DNS_QUERY_ID":float(self.dns_query_id),
            "DNS_QUERY_TYPE":float(self.dns_query_type),
            "DNS_TTL_ANSWER":float(self.dns_ttl_answer),
            "FTP_COMMAND_RET_CODE":float(self.ftp_ret_code),
        }
        proto_str="TCP" if self.protocol==6 else ("UDP" if self.protocol==17 else ("ICMP" if self.protocol==1 else "OTHER"))
        return {
            "timestamp":self.last_time,
            "src_ip":self.src_ip,
            "dst_ip":self.dst_ip,
            "src_port":self.src_port,
            "dst_port":self.dst_port,
            "protocol":proto_str,
            "l7_proto":self.l7_proto,
            "in_bytes":self.in_bytes,
            "out_bytes":self.out_bytes,
            "in_pkts":self.in_pkts,
            "out_pkts":self.out_pkts,
            "flow_duration_ms":duration_ms,
            "tcp_flags":self.tcp_flags,
            "raw_features":raw_dict,
            "is_live_capture":True
        }

class LivePacketSniffer:
    def __init__(self,max_queue_size=500):
        self.flow_queue=queue.Queue(maxsize=max_queue_size)
        self.active_flows={}
        self.lock=threading.Lock()
        self.is_running=False
        self.sniff_thread=None
        self.flush_thread=None
        self.flow_timeout=2.0
        self.snapshot_interval=1.2

    def start(self):
        if not SCAPY_AVAILABLE:
            logger.error("Scapy is not available. Cannot start live sniffer.")
            return False
        if self.is_running:
            return True
        self.is_running=True
        self.sniff_thread=threading.Thread(target=self._sniff_worker,daemon=True)
        self.flush_thread=threading.Thread(target=self._flush_worker,daemon=True)
        self.sniff_thread.start()
        self.flush_thread.start()
        logger.info("Live PC packet sniffer started.")
        return True

    def stop(self):
        self.is_running=False
        logger.info("Live packet sniffer stopped.")

    def _determine_client_server(self,ip1,ip2,port1,port2):
        well_known_server_ports={80,443,8080,8443,53,22,21,25,110,143,993,995,3306,5432,27017,3389,445,139}
        if port2 in well_known_server_ports:
            return True
        if port1 in well_known_server_ports:
            return False
        return port1>=port2

    def _packet_callback(self,pkt):
        if not self.is_running:
            return
        if IP in pkt:
            src_ip=pkt[IP].src
            dst_ip=pkt[IP].dst
            proto=pkt[IP].proto
        elif IPv6 in pkt:
            src_ip=pkt[IPv6].src
            dst_ip=pkt[IPv6].dst
            proto=pkt[IPv6].nh
        else:
            return
        src_port=0
        dst_port=0
        if TCP in pkt:
            src_port=pkt[TCP].sport
            dst_port=pkt[TCP].dport
        elif UDP in pkt:
            src_port=pkt[UDP].sport
            dst_port=pkt[UDP].dport
        if src_port==8000 or dst_port==8000:
            return
        if src_ip in ["127.0.0.1","::1"] and dst_ip in ["127.0.0.1","::1"]:
            return
        is_p1_client=self._determine_client_server(src_ip,dst_ip,src_port,dst_port)
        if is_p1_client:
            client_ip,server_ip=src_ip,dst_ip
            client_port,server_port=src_port,dst_port
            is_from_client=True
        else:
            client_ip,server_ip=dst_ip,src_ip
            client_port,server_port=dst_port,src_port
            is_from_client=False
        flow_key=(client_ip,server_ip,client_port,server_port,proto)
        now=time.time()
        with self.lock:
            if flow_key in self.active_flows:
                flow=self.active_flows[flow_key]
                flow.add_packet(pkt,is_from_client=is_from_client)
            else:
                flow=FlowRecord(client_ip,server_ip,client_port,server_port,proto)
                flow.add_packet(pkt,is_from_client=is_from_client)
                self.active_flows[flow_key]=flow
            is_fin_rst=(TCP in pkt and (pkt[TCP].flags&0x05!=0))
            if is_fin_rst or (now-flow.last_emitted_time)>=self.snapshot_interval:
                flow.last_emitted_time=now
                try:
                    self.flow_queue.put_nowait(flow.to_feature_dict())
                except queue.Full:
                    pass

    def _sniff_worker(self):
        while self.is_running:
            try:
                sniff(prn=self._packet_callback,store=0,timeout=1.0)
            except Exception as e:
                logger.warning(f"Sniff iteration warning: {e}")
                time.sleep(0.5)

    def _flush_worker(self):
        while self.is_running:
            time.sleep(0.5)
            now=time.time()
            to_remove=[]
            with self.lock:
                for key,flow in list(self.active_flows.items()):
                    if (now-flow.last_time)>self.flow_timeout:
                        to_remove.append(key)
                        try:
                            self.flow_queue.put_nowait(flow.to_feature_dict())
                        except queue.Full:
                            pass
                for key in to_remove:
                    if key in self.active_flows:
                        del self.active_flows[key]

    def get_next_flow(self,timeout=0.02):
        try:
            return self.flow_queue.get(timeout=timeout)
        except queue.Empty:
            return None

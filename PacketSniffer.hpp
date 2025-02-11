#pragma once
#include <pcap.h>
#include <arpa/inet.h> 
#include <string>
#include <map>
#include <iostream>
#include <fstream>
#include <vector>


class PacketSniffer
{
private:
#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

	using tcp_seq = u_int;

	struct sniff_ethernet
	{
		u_char ether_dhost[ETHER_ADDR_LEN];
		u_char ether_shost[ETHER_ADDR_LEN];
		u_short ether_type;
	};


	struct sniff_ip
	{
		u_char ip_vhl;
		u_char ip_tos;
		u_short ip_len;
		u_short ip_id;
		u_short ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
		u_char ip_ttl;
		u_char ip_p;
		u_short ip_sum;
		struct in_addr ip_src, ip_dst;
	};


	struct sniff_tcp
	{
		u_short th_sport;
		u_short th_dport;
		tcp_seq th_seq;
		tcp_seq th_ack;
		u_char th_offx2;
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;
		u_short th_sum;
		u_short th_urp;
	};


	struct StreamStats
	{
		uint32_t packet_count = 0;
		uint32_t byte_count = 0;
	};


	pcap_if_t* alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = nullptr;
	char filter_exp[3] = "ip";
	struct bpf_program fp;
	std::map<std::string, StreamStats> stream_map;

	static std::string create_stream_key(const sniff_ip* ip, uint16_t src_port, uint16_t dst_port);
	static void get_packet(u_char* args, const pcap_pkthdr* header, const u_char* packet, PacketSniffer* sniffer);
	const char* get_name_by_id(int interface_number);



public:
	bool get_interfaces();
	void show_interfaces() const;
	int init_live_handler(int interface_number);
	int init_file_handler(std::string file_name);
	void write_to_csv() const;
};

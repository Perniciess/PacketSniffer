#include "PacketSniffer.hpp"



std::string PacketSniffer::create_stream_key(const sniff_ip* ip, uint16_t src_port, uint16_t dst_port)
{
	char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &ip->ip_src, src_ip_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip->ip_dst, dst_ip_str, INET_ADDRSTRLEN);
	return std::string(src_ip_str) + ":" + std::string(dst_ip_str) + ":" + std::to_string(src_port) + ":" +
		std::to_string(dst_port);
}

void PacketSniffer::get_packet(u_char* args,const pcap_pkthdr* header, const u_char* packet, PacketSniffer* sniffer)
{	(void) args;
	(void) header;
	const sniff_ip* ip = (sniff_ip*)(packet + SIZE_ETHERNET);
	int size_ip = IP_HL(ip) * 4;
	if (size_ip < 20) return;
	std::string proto;
	switch (ip->ip_p)
	{
	case IPPROTO_TCP: proto = "TCP";
		break;
	case IPPROTO_UDP: proto = "UDP";
		break;
	default: return;
	}

	const sniff_tcp* tcp = (sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	int size_tcp = TH_OFF(tcp) * 4;
	if (size_tcp < 20 and size_tcp != 8) return;
	int size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	if (size_payload == 0) return;
	uint16_t src_port = ntohs(tcp->th_sport);
	uint16_t dst_port = ntohs(tcp->th_dport);
	std::string key = create_stream_key(ip, src_port, dst_port);
	if (sniffer)
	{
		sniffer->stream_map[key].packet_count++;
		sniffer->stream_map[key].byte_count += size_payload;
	}
	char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &ip->ip_src, src_ip_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip->ip_dst, dst_ip_str, INET_ADDRSTRLEN);
}

const char* PacketSniffer::get_name_by_id(const int interface_number)
{
	int count = 0;
	for (pcap_if_t* d = alldevs; d != nullptr; d = d->next)
	{
		if (count == interface_number)
		{
			const char* interface_name = d->name;
			std::cout << "You have selected a device: " << d->description << "\n";
			return interface_name;
		}
		count++;
	}
	return nullptr;
}


bool PacketSniffer::get_interfaces()
{
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		return false;
	}
	return true;
}

void PacketSniffer::show_interfaces() const
{
	if (!alldevs)
	{
		std::cout << "No interfaces available\n";
		return;
	}
	int count = 0;
	std::cout << "Available interfaces:\n";
	for (pcap_if_t* d = alldevs; d != nullptr; d = d->next)
	{
		std::cout << count++ << ": "
			<< (d->description ? d->description : d->name)
			<< "\n";
	}
	return; 
}

int PacketSniffer::init_live_handler(const int interface_number)
{
	const char* interface_name = get_name_by_id(interface_number);
	handle = pcap_open_live(interface_name, SNAP_LEN, 1, 1000, errbuf);
	if (handle == nullptr)
	{
		std::cout << "Couldn't open device\n";
		return 1;
	}
	if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1 || pcap_setfilter(handle, &fp) == -1)
	{
		std::cout << "Error with parse filter or install filter " << filter_exp << "\n";
		return 1;
	}

	pcap_loop(handle, 100, [](u_char* args, const pcap_pkthdr* header, const u_char* packet)
	{
		get_packet(args, header, packet, reinterpret_cast<PacketSniffer*>(args));
	}, reinterpret_cast<u_char*>(this));
	pcap_freecode(&fp);
	pcap_close(handle);
	return 0;
}


int PacketSniffer::init_file_handler(std::string file_name)
{
	handle = pcap_open_offline(file_name.c_str(), errbuf);
	if (handle == nullptr)
	{
		std::cout << "Couldn't open file: " << file_name << "\n";
		return 1;
	}
	if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1 || pcap_setfilter(handle, &fp) == -1)
	{
		std::cout << "Error with parse filter or install filter " << filter_exp << "\n";
		return 1;
	}
	pcap_loop(handle, 100, [](u_char* args, const pcap_pkthdr* header, const u_char* packet)
	{
		get_packet(args, header, packet, reinterpret_cast<PacketSniffer*>(args));
	}, reinterpret_cast<u_char*>(this));
	pcap_freecode(&fp);
	pcap_close(handle);
	return 0;
}
void PacketSniffer::write_to_csv() const
{
	std::ofstream file("stream_stats.csv");
	if (!file.is_open())
	{
		std::cout << "Failed to create CSV file\n";
		return;
	}
	file << "Source IP,Destination IP, Source Port,Destination Port,Packets,Bytes\n";
	for (const auto& entry : stream_map)
	{
		const std::string& key = entry.first;
		const StreamStats& stats = entry.second;
		std::vector<std::string> parts;
		size_t pos = 0;
		for (int i = 0; i < 4; ++i)
		{
			size_t new_pos = key.find_first_of(":-", pos);
			if (new_pos == std::string::npos) break;
			parts.push_back(key.substr(pos, new_pos - pos));
			pos = new_pos + 1;
		}
		parts.push_back(key.substr(pos));
		if (parts.size() != 4) continue;
		file << parts[0] << ","
			<< parts[1] << ","
			<< parts[2] << ","
			<< parts[3] << ","
			<< stats.packet_count << ","
			<< stats.byte_count << "\n";
	}
	file.close();
}

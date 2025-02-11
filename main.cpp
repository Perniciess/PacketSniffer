#include "PacketSniffer.hpp"


int main(int argc, char** argv)
{	
	(void) argc;
	(void) argv;
	PacketSniffer sniffer;

	int analyze_choice;

	std::string file_name;

	std::cout << "Enter 1 to read packets from the network interface, and 2 to read from the pcap-file: ";

	std::cin >> analyze_choice;

	if (analyze_choice != 1 && analyze_choice != 2)

	{

		std::cout << "Input error\n";

		return 1;

	}

	if (analyze_choice == 1)

	{

		if (!sniffer.get_interfaces())

		{

			std::cout << "No available network devices\n";

			return 1;

		}

		sniffer.show_interfaces();

		std::cout << "Choose interface by id: ";

		int interface_number;

		std::cin >> interface_number;

		sniffer.init_live_handler(interface_number);

	}

	else if (analyze_choice == 2)

	{

		std::cout << "Enter the path to the pcap-file (example: test.pcap): ";

		std::cin >> file_name;

		sniffer.init_file_handler(file_name);

	}

	sniffer.write_to_csv();

	return 0;

}

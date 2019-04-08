/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"
#include <iostream>
#include "undecided.hpp"
#include "bitset"


// #define ACK 0b010000;
// #define SYN 0b000010;
// #define FIN 0b000001;
// #define RST 0b000100;

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{
	this->portAndIpTofd.clear();
	this->fdToSock.clear();
	this->allPort.clear();
}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	int sockfd ;
	int retval;
	int * addrlen;
	uint16_t port;
	uint32_t addr;
	struct sockaddr* client_addr;
	struct sockaddr* server_addr;

	switch(param.syscallNumber)
	{
	case SOCKET:
	{
		//this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);

		sockfd = createFileDescriptor(pid);
		assert(sockfd >-1);
		retval = -1;

		Sock * newsock = new Sock(param.param1_int,param.param2_int,param.param3_int,sockfd);
		newsock->pid = pid;
		struct sockey * pidfd = new sockey();
		pidfd->pid = pid;
		pidfd->fd = sockfd;

		fdToSock.insert(std::pair<struct sockey,Sock* >(*pidfd,newsock));
		retval = sockfd;
		returnSystemCall(syscallUUID, retval); // guess this = SystemCallInterface

		break;
	}
	case CLOSE:
	{
	// std::cout << "[CLOSE] START!!"<< std::endl;
		retval = 0;
		sockfd = param.param1_int;
		struct sockey * pidfd = new sockey();
		pidfd->pid = pid;
		pidfd->fd = sockfd;

		if(this->fdToSock.find(*pidfd) == this->fdToSock.end()) {
			retval = -1;
			returnSystemCall(syscallUUID, retval);
			break;
		}

		Sock * sock = this->fdToSock[*pidfd];

		// remove fd
		this->fdToSock.erase(*pidfd);
		removeFileDescriptor(pid, sockfd);

		if(sock->binded == 0) {
			returnSystemCall(syscallUUID, retval);
			break;
		}
		port = ((struct sockaddr_in *)sock->get_sockaddr())->sin_port;
    addr = ((struct sockaddr_in *)sock->get_sockaddr())->sin_addr.s_addr;

		struct key * k = (struct key *)malloc(sizeof(key));
		k->port = port;
		k->ip = addr;

		if(this->allPort.find(port) == this->allPort.end()){
			// port not binded

		}
		else {
			if(this->allPort[port] == 1) this->allPort.erase(port);
			else this->allPort[port]--;
			this->portAndIpTofd.erase(*k);
		}
		retval = 0;
		sock->~Sock();
		returnSystemCall(syscallUUID, retval);

		//this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	}
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
	{

		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		// param.param1_int = sockfd;
		// param.param2_ptr = (void*)addr;
		// param.param3_int = addrlen;
    // client 쪽에서만 실행함.

    sockfd = param.param1_int;
		struct sockey * pidfd = new sockey();
		pidfd->pid = pid;
		pidfd->fd = sockfd;
		struct sockaddr_in * server_addr_in = (struct sockaddr_in *)param.param2_ptr;
		int addrlen = param.param3_int;
		server_addr_in->sin_addr.s_addr = ntohl(server_addr_in->sin_addr.s_addr);
		server_addr_in->sin_port = ntohs(server_addr_in->sin_port);
		client_addr = new sockaddr();
		Sock * sock = fdToSock[*pidfd];

					// assert(0);
		if(sock->binded > 0){
			/* Already binded */
			client_addr = sock->get_sockaddr();
		}
		else{

			// new connection. assign client ip/port.
			uint8_t ip_buffer[4];

			ip_buffer[0] = server_addr_in->sin_addr.s_addr >> 24;
			ip_buffer[1] = server_addr_in->sin_addr.s_addr >> 16;
			ip_buffer[2] = server_addr_in->sin_addr.s_addr >> 8;
			ip_buffer[3] = server_addr_in->sin_addr.s_addr;

			int interface_index = RoutingInfo().getRoutingTable(ip_buffer);
			RoutingInfo().getIPAddr(ip_buffer, interface_index);
			// assert(RoutingInfo().getIPAddr(ip_buffer, interface_index));
			// std::cout << "[CONNECT] server_addr : "<<server_addr_in->sin_addr.s_addr << std::endl;
			// std::cout << "[CONNECT] server_addr : "<<std::bitset<8>(ip_buffer[0])<< std::endl;
			// std::cout << "[CONNECT] server_addr : "<<std::bitset<8>(ip_buffer[1])<< std::endl;
			// std::cout << "[CONNECT] server_addr : "<<std::bitset<8>(ip_buffer[2])<< std::endl;
			// std::cout << "[CONNECT] server_addr : "<<(u_long)(ip_buffer)<< std::endl;

			((struct sockaddr_in *)client_addr)->sin_addr.s_addr = *ip_buffer;

			/* Assign Random Port (which is not a duplicate) */

			uint16_t port_buffer;
			struct key * key_buf = (struct key *)malloc(sizeof(key));

			// std::cout << "[CONNECT] ip_buffer : "<<((struct sockaddr_in *)client_addr)->sin_addr.s_addr<< std::endl;

			// random port setting.
			do{
				port_buffer = rand() % 10000;
				key_buf->port = port_buffer;
				key_buf->ip = ((struct sockaddr_in *)client_addr)->sin_addr.s_addr;
			}
			while(this->portAndIpTofd.find(*key_buf) != this->portAndIpTofd.end());
			((struct sockaddr_in *)client_addr)->sin_port = port_buffer;

			// client socket address setting.
			sock->set_sockaddr(client_addr, sizeof(client_addr));
			if(!(this->allPort.insert(std::pair<uint16_t,int>(port,1)).second)){
				++this->allPort[port];
			}
			this->portAndIpTofd.insert(std::pair<struct key,struct sockey>(*key_buf,*pidfd));

		}

		/* STATE does not changed until now.
		   CREATE elements to write in new syn packet */

		struct sockaddr_in * client_addr_in = (struct sockaddr_in *)client_addr;
		// struct sockaddr_in * server_addr_in = (struct sockaddr_in *)server_addr;

		uint32_t src_ip = htonl(client_addr_in->sin_addr.s_addr);
		uint32_t dest_ip = htonl(server_addr_in->sin_addr.s_addr);
		uint16_t src_port = htons(client_addr_in->sin_port);
		uint16_t dest_port = htons(server_addr_in->sin_port);

		//
		// std::cout << "[CONNECT]" << src_ip << std::endl;
		// std::cout << "[CONNECT]" << dest_ip<< std::endl;
		// std::cout << "[CONNECT]" << src_port << std::endl;
		// std::cout << "[CONNECT]" << dest_port << std::endl;

		uint8_t flagfield = 0b000010;

		uint32_t seq_no = rand() % 10000; // sequence number field
		// uint32_t seq_no = 0xfffff4e1;
		uint32_t ack_no = 0; // acknowledgment number field
		uint16_t window_size = htons(0xc800);


		/* Update sent socket to sent socket list */

		// struct sent_socket* new_sent_socket;
		// new_sent_socket = new sent_socket();
		// new_sent_socket->fd = sockfd;
		// sock->client_addr = client_addr;
	  sock->syscallblock = syscallUUID;
		sock->binded = 1;

		struct client_TCP * new_client_TCP;
		new_client_TCP = new client_TCP();
		new_client_TCP->state = SYN_SENT;
		new_client_TCP->server_addr = (struct sockaddr *)server_addr_in;
		new_client_TCP->client_sn = seq_no;
		sock->sock_is_client->pending_info = *new_client_TCP;
		uint8_t header_length = 0x50;
		syn_sent_sock.push_back(*sock);
		seq_no = htonl(seq_no);


		/* WRITE SYN Packet and Send */
		/************************************************
		* 14+0 : ipv4                                   *
		* 14+1 : DSCP,ECN                               *
		* 14+2 : packet->getSize() - ip_start (2bytes)  *
		* 14+4 : cur_id (2bytes)                        *
		* 14+9 : protocol                               *
		* 14+10: checksum (2bytes)                      *
		*************************************************/
		Packet * SYN_packet = this->allocatePacket(54);
		SYN_packet->writeData(14+12, &src_ip, 4);
		SYN_packet->writeData(14+16, &dest_ip, 4);
		SYN_packet->writeData(14+20, &src_port, 2);
		SYN_packet->writeData(14+22, &dest_port, 2);
		SYN_packet->writeData(14+24, &seq_no, 4);
		SYN_packet->writeData(14+28, &ack_no, 4);
		SYN_packet->writeData(14+32, &header_length, 1);
		SYN_packet->writeData(14+32+1, &flagfield, 1);
		SYN_packet->writeData(14+32+1+1, &window_size, 2);

		uint8_t tcp_header_buffer[20];
		SYN_packet->readData(14+20, tcp_header_buffer,20 );
		// uint16_t checksum = NetworkUtil::one_sum(tcp_header_buffer,20);
		uint16_t checksum = NetworkUtil::tcp_sum(src_ip,dest_ip,tcp_header_buffer,20);
		checksum = ~checksum;
		if(checksum == 0xFFFF) checksum = 0;
		checksum = htons(checksum);
		SYN_packet->writeData(14+ 32+1+1+2, (uint8_t*)&checksum, 2);


		this->sendPacket("IPv4", SYN_packet);

		struct connection_TCP * new_bct;
		new_bct = new connection_TCP();
		new_bct->client_addr_in = client_addr_in;
		new_bct->server_addr_in = server_addr_in;
		this->before_connection_list.push_back(*new_bct);

		// std::cout << "[CONNECT] sent SYN Packet "<< std::endl;
		break;
	}
	case LISTEN:
	{
	// std::cout << "[LISTEN] START!!"<< std::endl;
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		retval = 0;
		Sock * sock;
		sockfd = param.param1_int;
		int backlog = param.param2_int;
		struct sockey * pidfd = new sockey();
		pidfd->pid = pid;
		pidfd->fd = sockfd;

		if(!fdToSock[*pidfd]) {
			retval = -1;
			returnSystemCall(syscallUUID, retval);
		}
		sock = fdToSock[*pidfd];
		sock->sock_is_server->backlog = backlog;
		sock->sock_is_server->state = SYN_LISTEN;
		listening_sock.push_back(*sock);

		returnSystemCall(syscallUUID, retval);

		break;
	}
	case ACCEPT:
	{
	std::cout << "[ACCEPT] START!!"<< std::endl;
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		sockfd =  param.param1_int;
		struct sockey * pidfd = new sockey();
		pidfd->pid = pid;
		pidfd->fd = sockfd;

		struct sockaddr_in * client_addr_in = (struct sockaddr_in *)param.param2_ptr;
		client_addr_in->sin_family = AF_INET;

		std::cout << "[ACCEPT] sin_family AF_INET : "<<AF_INET << std::endl;


		bool is_there_listen = false;

		std::vector<Sock>::iterator listen_to_accept;

		// if(fdToSock[sockfd]->sock_is_server->pid >0){
		// 		// std::cout << "[ACCEPT] other host is accepting"<< pid<< std::endl;
		// }

		for( listen_to_accept = listening_sock.begin(); listen_to_accept!= listening_sock.end(); listen_to_accept++)
		{
			if(sockfd == listen_to_accept->sockfd){
				is_there_listen = true;
				break;
			}
		}
		if(!is_there_listen) returnSystemCall(syscallUUID, -1);
		bool returned = accept_now(fdToSock[*pidfd], syscallUUID);
		if(!returned){
					std::cout << "[ACCEPT] accept called early!!"<< std::endl;
					accept_waiting_list.push_back(syscallUUID);
		}

		break;
	}
	case BIND:
	{
		retval = 0;
		sockfd = param.param1_int;
		struct sockey * pidfd = new sockey();
		pidfd->pid = pid;
		pidfd->fd = sockfd;

				std::cout << "[BIND] START!! "<< sockfd<< std::endl;
		server_addr = (struct sockaddr *)param.param2_ptr;

		struct sockaddr_in * server_addr_in = new sockaddr_in();
		server_addr_in->sin_port = ntohs(((struct sockaddr_in *)server_addr)->sin_port);
		server_addr_in->sin_addr.s_addr = ntohl(((struct sockaddr_in *)server_addr)->sin_addr.s_addr);
		server_addr_in->sin_family = ((struct sockaddr_in *)server_addr)->sin_family;
		addrlen = (int *)&param.param3_int;

		std::cout << "[BIND] server_ip: "<<server_addr_in->sin_addr.s_addr<< std::endl;
		std::cout << "[BIND] server_port: "<<server_addr_in->sin_port<< std::endl;

		port = server_addr_in->sin_port;
		addr = server_addr_in->sin_addr.s_addr;

		Sock * sock = fdToSock[*pidfd];

		struct key * k = (struct key *)malloc(sizeof(key));
		k->port = port;
		k->ip = addr;

		struct key * buf = (struct key *)malloc(sizeof(key));
		memset(buf, 0, sizeof(key));
		memcpy(buf, &port, sizeof(port));
		// buf[sizeof(u_short)] = htonl(INADDR_ANY);
		buf->ip = INADDR_ANY;

		if( (sock->binded > 0 && ((struct sockaddr_in *)sock->get_sockaddr())->sin_port != port) || // 이미 binded 되었거나
			 	this->fdToSock.find(*pidfd) == this->fdToSock.end()|| // sock 의 fd 가 this->fdToSock 에 없거나
				this->portAndIpTofd.find(*k) != this->portAndIpTofd.end() || // bind 하려는 ip:port 에 연결된 fd(=>sock) 이 있거나
				this->portAndIpTofd.find(*buf) != this->portAndIpTofd.end() || // bind 하려는 :port 가 0.0.0.0/0:port 에 binded 되어있거나
				(this->allPort.find(port) != this->allPort.end() && addr == INADDR_ANY)){ //port 가 사용중이고, bind 하려는 ip 가 0.0.0.0/0 이거나

									std::cout << "[BIND] here!!! :"<< this->allPort[port] << std::endl;
									std::cout << "[BIND] 0:"<< (sock->binded > 0 && ((struct sockaddr_in *)sock->get_sockaddr())->sin_port != port)<< std::endl;
									std::cout << "[BIND] 1:"<< (this->fdToSock.find(*pidfd) == this->fdToSock.end())<< std::endl;
									std::cout << "[BIND] 2:"<< (this->portAndIpTofd.find(*k) != this->portAndIpTofd.end() )<< std::endl;
									std::cout << "[BIND] 3:"<< (this->portAndIpTofd.find(*buf) != this->portAndIpTofd.end() )<< std::endl;
									std::cout << "[BIND] 4:"<< (this->allPort.find(port) != this->allPort.end() && addr == htonl(INADDR_ANY))<< std::endl;
			retval = -1;
					// std::cout << syscallUUID << std::endl;
			returnSystemCall(syscallUUID, retval);
			break;
		}

		sock->set_sockaddr((struct sockaddr *)server_addr_in,*addrlen);

		// port 사용중인 ip 갯수.
		if(!(this->allPort.insert(std::pair<uint16_t,int>(port,1)).second)){
			++this->allPort[port];
		}

		// this->allPort.insert((port));
		this->portAndIpTofd.insert(std::pair<struct key,struct sockey>(*k,*pidfd));

		// std::cout << "[BIND] key_ip : "<< k->ip<<" key_port: "<<k->port << std::endl;
		// std::cout << "[BIND] sock_addr : "<< &sock << std::endl;
		// std::cout << "[BIND] sock_fd : "<< sockfd << std::endl;


		// free(sockaddr);
		sock->binded = 1;
		returnSystemCall(syscallUUID, retval);
		//this->syscall_bind(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		(socklen_t) param.param3_int);
		break;
	}
	case GETSOCKNAME:
	{
	// std::cout << "[GETSOCKNAME] START!!"<< std::endl;
		//this->syscall_getsockname(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		retval = 0;
		sockfd = param.param1_int;
		addrlen = (int *)param.param3_ptr;
		struct sockey * pidfd = new sockey();
		pidfd->pid = pid;
		pidfd->fd = sockfd;

		struct sockaddr_in * addr_in = new sockaddr_in();
		memcpy(addr_in, fdToSock[*pidfd]->get_sockaddr(), sizeof(struct sockaddr_in));
   std::cout << "[GETSOCKNAME] addr : "<<addr_in->sin_addr.s_addr<<" port: "<<addr_in->sin_port<< std::endl;
		addr_in->sin_addr.s_addr = htonl(addr_in->sin_addr.s_addr);
		addr_in->sin_port = htons(addr_in->sin_port);

		if(*addrlen < 8) {
			retval = -1;
			returnSystemCall(syscallUUID, retval);
			break;
		}
		socklen_t copy_size = std::min(16, *addrlen);
		memcpy(param.param2_ptr, addr_in, copy_size);

		returnSystemCall(syscallUUID, retval);

		break;
	}
	case GETPEERNAME:
	{
	// std::cout << "[GETPEERNAME] START!!"<< std::endl;
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));

		retval = 0;
		sockfd = param.param1_int;
		struct sockey * pidfd = new sockey();
		pidfd->pid = pid;
		pidfd->fd = sockfd;

		struct sockaddr_in * tmp_addr = (struct sockaddr_in *)param.param2_ptr;
		addrlen = (int *)param.param3_ptr;
		Sock * sock = fdToSock[*pidfd];
		struct sockaddr_in * addr_in = (struct sockaddr_in *) sock->sock_is_client->pending_info.server_addr;

    // std::cout << "[GETPEERNAME] ADDR : "<< addr_in->sin_addr.s_addr<< std::endl;
		// std::cout << "[GETPEERNAME] PORT : "<< addr_in->sin_port<< std::endl;
		// std::cout << "[GETPEERNAME] FAMI : "<< addr_in->sin_family<< std::endl;
		if(*addrlen < 8) {
			retval = -1;
			returnSystemCall(syscallUUID, retval);
			break;
		}
		// socklen_t copy_size = std::min(16, *addrlen);
		// memcpy(param.param2_ptr, addr_in, copy_size);
		tmp_addr->sin_addr.s_addr = addr_in->sin_addr.s_addr;
		tmp_addr->sin_port = addr_in->sin_port;
		tmp_addr->sin_family = addr_in->sin_family;
		returnSystemCall(syscallUUID, retval);
		break;
	}
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

	// std::cout << "[packetArrived] START!!" << std::endl;
	/* PARSING PACKET DATA */


	uint32_t src_ip;
	uint32_t dest_ip;
	uint16_t src_port;
	uint16_t dest_port;

	uint8_t flagfield;

	uint32_t seq_no; // sequence number field
	uint32_t ack_no; // acknowledgment number field

	Sock * sock;
	// int sockfd;
	struct sockey * pidfd;


	struct sockaddr_in * client_addr_in = new sockaddr_in();
	struct sockaddr_in * server_addr_in = new sockaddr_in();
	/* Parsing TCP header data */
	packet->readData(14+12, &src_ip, 4);
	packet->readData(14+16, &dest_ip, 4);
	packet->readData(14+20, &src_port, 2);
	packet->readData(14+22, &dest_port, 2);

					// std::cout<<std::hex<<"0x"<<src_port<<"\n";

	packet->readData(14+20+13, &flagfield, 1);

	packet->readData(14+20+4, &seq_no, 4);
	packet->readData(14+20+8, &ack_no, 4);

	uint8_t ACK, SYN, FIN, RST; // flag bits
	ACK = flagfield & 0b010000;
	SYN = flagfield & 0b000010;
	FIN = flagfield & 0b000001;
	RST = flagfield & 0b000100;

  /* CHECK checksum */
	// TO-DO
	// IF CHECKSUM WRONG JUST DROP Packet

	src_ip = ntohl(src_ip);
	dest_ip = ntohl(dest_ip);
	src_port = ntohs(src_port);
	dest_port = ntohs(dest_port);
	seq_no = ntohl(seq_no);
	ack_no = ntohl(ack_no);

	struct key * key_for_client = (struct key *)malloc(sizeof(key));
	key_for_client->port = dest_port;
	key_for_client->ip = dest_ip;

	struct key * key_for_server = (struct key *)malloc(sizeof(key));
	key_for_server->port = dest_port;
	key_for_server->ip = src_ip;

	struct key * key_for_server2 = (struct key *)malloc(sizeof(key));
	key_for_server2->port = dest_port;
	key_for_server2->ip = 0;

	int is_connected = 0; // not connected : 0 , before_connected : 1, connected : 2
	is_connected = get_connection_no(src_ip,dest_ip,src_port,dest_port);

	if(is_connected == 2){
		// already connected.

// std::cout << "[packetArrived] already connected"<< std::endl;
	}

	else if (is_connected == 1 || is_connected == 0){
		// before connected
		if(portAndIpTofd.find(*key_for_server) != portAndIpTofd.end()) {
			pidfd = &portAndIpTofd[*key_for_server];
			sock = fdToSock[*pidfd];
					// std::cout << "[packetArrived] server sock 1" << std::endl;
		}
		else if(portAndIpTofd.find(*key_for_server2) != portAndIpTofd.end()){
			pidfd = &portAndIpTofd[*key_for_server2];
			sock = fdToSock[*pidfd];
					// std::cout << "[packetArrived] server sock 2" << std::endl;
		}
		else if(portAndIpTofd.find(*key_for_client) != portAndIpTofd.end()){
			pidfd = &portAndIpTofd[*key_for_client];
			sock = fdToSock[*pidfd];
					// std::cout << "[packetArrived] SYNACK synack here 2" << std::endl;
		}
		else {
			// std::cout << "[packetArrived] <DANGEROUS> no key for server !! " << std::endl;
		}
		if(SYN && ACK){
				std::cout << "[packetArrived] SYNACK" << std::endl;
		 		/* CLIENT
				 	 SYNACK_PACKET FROM SERVER and TIME TO SEND ACK_PACKET TO SERVER*/

				server_addr_in->sin_family = AF_INET;
				server_addr_in->sin_addr.s_addr = src_ip;
				server_addr_in->sin_port = src_port;


				uint8_t flagfield = 0b010000;
				uint32_t ack_seq_no = ack_no; // sequence number field
				uint32_t ack_ack_no = seq_no + 1; // acknowledgment number field
				uint16_t window_size = htons(0xc800);

							// std::cout << "[packetArrived] SYNACK here 0" << std::endl;

				struct client_TCP * new_client_TCP;
				new_client_TCP = new client_TCP();
				new_client_TCP->state = ESTABLISHED;
				new_client_TCP->server_addr = (struct sockaddr *)server_addr_in;
				new_client_TCP->server_sn = seq_no;
				new_client_TCP->client_sn = ack_no;
				sock->sock_is_client->pending_info = *new_client_TCP;
				uint8_t header_length = 0x50;

							// std::cout << "[packetArrived] SYNACK here 1" << std::endl;

				dest_ip = htonl(dest_ip);
				src_ip = htonl(src_ip);
				dest_port = htons(dest_port);
				src_port = htons(src_port);
				ack_seq_no = htonl(ack_seq_no);
				ack_ack_no = htonl(ack_ack_no);

				Packet * ACK_packet = this->allocatePacket(54);
				ACK_packet->writeData(14+12, &dest_ip, 4);
				ACK_packet->writeData(14+16, &src_ip, 4);
				ACK_packet->writeData(14+20, &dest_port, 2);
				ACK_packet->writeData(14+22, &src_port, 2);
				ACK_packet->writeData(14+24, &ack_seq_no, 4);
				ACK_packet->writeData(14+28, &ack_ack_no, 4);
				ACK_packet->writeData(14+32, &header_length, 1);
				ACK_packet->writeData(14+32+1, &flagfield, 1);
				ACK_packet->writeData(14+32+1+1, &window_size, 2);

				uint8_t tcp_header_buffer[20];
				ACK_packet->readData(14+20, tcp_header_buffer,20 );
				uint16_t checksum = NetworkUtil::tcp_sum(dest_ip,src_ip,tcp_header_buffer,20);
				// uint16_t checksum = NetworkUtil::one_sum(tcp_header_buffer,20);
				checksum = ~checksum;
				if(checksum == 0xFFFF) checksum = 0;
				checksum = htons(checksum);
				ACK_packet->writeData(14+ 32+1+1+2, (uint8_t*)&checksum, 2);


				this->sendPacket("IPv4", ACK_packet);
				this->freePacket(packet);
				// std::cout << "[packetArrived] sent ACK Packet "<< std::endl;
				returnSystemCall(sock->syscallblock, 0);

		}

		else if(SYN || ACK){
					std::cout << "[packetArrived] SYN || ACK" << std::endl;

					bool is_in_pending = false;
					bool is_in_accepted = false;


					std::vector<server_TCP>::iterator check_pending;
					std::vector<server_TCP>::iterator check_accept;

					for( check_pending = sock->sock_is_server->pending_list.begin(); check_pending!= sock->sock_is_server->pending_list.end(); check_pending++)
					{
						client_addr_in = (struct sockaddr_in *)check_pending->client_addr;
						if(client_addr_in->sin_addr.s_addr == src_ip && client_addr_in->sin_port == src_port){
							is_in_pending = true;
							break;
						}
					}

					for( check_accept = sock->sock_is_server->accepted_list.begin(); check_accept!= sock->sock_is_server->accepted_list.end(); check_accept++)
					{
						client_addr_in = (struct sockaddr_in *)check_accept->client_addr;
						if(client_addr_in->sin_addr.s_addr == src_ip && client_addr_in->sin_port == src_port){
							is_in_accepted = true;
							break;
						}
					}

																					std::cout << "[packetArrived] SA 2 " << std::endl;

					/* SYN_PACKET FROM CLIENT and TIME TO SEND SYNACK_PACKET TO CLIENT*/
					if( !is_in_pending && !is_in_accepted && SYN){

						if(sock->sock_is_server->backlog <= (int)sock->sock_is_server->pending_list.size()){
							// drop the packet
						}
						else{

																std::cout << "[packetArrived] SYN " << std::endl;
							struct server_TCP * new_pending;
							client_addr_in = new sockaddr_in();

							new_pending = new server_TCP();
							new_pending->state = SYN_RCVD;

							int new_sockfd = createFileDescriptor(sock->pid);
							Sock * new_sock = new Sock(AF_INET,SOCK_STREAM,IPPROTO_TCP,new_sockfd);
							pidfd = new sockey();
							pidfd->pid = sock->pid;
							pidfd->fd = new_sockfd;

							fdToSock.insert(std::pair<struct sockey,Sock* >(*pidfd,new_sock));

							new_sock->sock_is_server->state = SYN_RCVD;
							new_sock->set_sockaddr((struct sockaddr *)sock->get_sockaddr(), sizeof(struct sockaddr));
							// struct sockaddr_in * server_addr_in = (struct sockaddr_in *)new_sock->get_sockaddr();
							// std::cout << "[packetArrived] SYN 3 new sock addr : " <<server_addr_in->sin_addr.s_addr<<" port : "<<server_addr_in->sin_port << std::endl;
							client_addr_in->sin_family = AF_INET;
							client_addr_in->sin_addr.s_addr = src_ip;
							client_addr_in->sin_port = src_port;

							uint32_t synack_seq_no = rand() % 10000;
							uint32_t synack_ack_no = seq_no + 1;

							new_pending->client_addr = (struct sockaddr *)client_addr_in;
							new_pending->server_sn = synack_seq_no;
							new_pending->client_sn = seq_no;
							new_pending->sockfd = new_sockfd;
																													// std::cout << "[packetArrived] SYN 4" << std::endl;
							sock->sock_is_server->pending_list.push_back(*new_pending);
							/* Send Reply to Client */




							Packet* SYNACK_packet = this->allocatePacket(54);
							/*
							std::cout<<std::hex<<"0x"<<dest_ip<<"\n";
							std::cout<<std::hex<<"0x"<<src_ip<<"\n";
							std::cout<<std::hex<<"0x"<<dest_port<<"\n";
							std::cout<<std::hex<<"0x"<<src_port<<"\n";
							std::cout<<std::hex<<"0x"<<send_seq<<"\n";
							std::cout<<std::hex<<"0x"<<send_ack<<"\n";
							*/
							uint8_t flagfield = 0b010010;
							uint8_t header_length = 0x50;
							uint16_t window_size = htons(0xc800);

							dest_ip = htonl(dest_ip);
							src_ip = htonl(src_ip);
							dest_port = htons(dest_port);
							src_port = htons(src_port);
							synack_seq_no = htonl(synack_seq_no);
							synack_ack_no = htonl(synack_ack_no);

							SYNACK_packet->writeData(14+12, (uint8_t*)&dest_ip, 4);
							SYNACK_packet->writeData(14+16, (uint8_t*)&src_ip, 4);
							SYNACK_packet->writeData(14+20, (uint8_t*)&dest_port, 2);
							SYNACK_packet->writeData(14+22, (uint8_t*)&src_port, 2);
							SYNACK_packet->writeData(14+24, (uint8_t*)&synack_seq_no, 4);
							SYNACK_packet->writeData(14+28, (uint8_t*)&synack_ack_no, 4);
							SYNACK_packet->writeData(14+28+4, (uint8_t*)&header_length, 1);
							SYNACK_packet->writeData(14+28+4+1, &flagfield, 1);
							SYNACK_packet->writeData(14+33+1, &window_size, 2);



							// std::cout<<std::hex<<"0x"<<dest_ip<<"\n";
							// std::cout<<std::hex<<"0x"<<src_ip<<"\n";
							// std::cout<<std::hex<<"0x"<<dest_port<<"\n";
							// std::cout<<std::hex<<"0x"<<src_port<<"\n";
							// std::cout<<std::hex<<"0x"<<synack_seq_no<<"\n";
							// std::cout<<std::hex<<"0x"<<synack_ack_no<<"\n";
							/*
							std::cout<<sendflag<<"\n";


							std::cout<<std::hex<<"0x"<<unsigned(sendflag)<<"\n";
							*/



							uint8_t tcp_header_buffer[20];
							SYNACK_packet->readData(14+20, tcp_header_buffer,20 );
							uint16_t checksum = NetworkUtil::tcp_sum(dest_ip,src_ip,tcp_header_buffer,20);
							// uint16_t checksum = NetworkUtil::one_sum(tcp_header_buffer,20);
							checksum = ~checksum;
							if(checksum == 0xFFFF) checksum = 0;
							checksum = htons(checksum);
							SYNACK_packet->writeData(14+ 32+1+1+2, (uint8_t*)&checksum, 2);

							this->sendPacket("IPv4", SYNACK_packet);
							std::cout << "[packetArrived] sent SYNACK Packet" << std::endl;
						}
						this->freePacket(packet);
					}

					else if( is_in_pending && !is_in_accepted && ACK){
						/* Third Handshake (ACK segment from client) */
						//std::cout << "In here THird handshake\n";

						if(ack_no == check_pending->server_sn + 1){

							/* Update Server TCP state */
							check_pending->state = ESTABLISHED;
							sock->sock_is_server->accepted_list.push_back(*check_pending);
							sock->sock_is_server->pending_list.erase(check_pending);

							this->freePacket(packet);

							std::vector<UUID>::iterator syscallblock;
							for (syscallblock=accept_waiting_list.begin();syscallblock!=accept_waiting_list.end();syscallblock++){
								accept_now(sock,*syscallblock);
								accept_waiting_list.erase(syscallblock);
								break;
							}

						}
					}



		}
	}
}

void TCPAssignment::timerCallback(void* payload)
{
	// Sock * sock = (Sock *)payload;
	// uint32_t src_ip = ((struct sockaddr_in *)sock->get_sockaddr())->sin_addr.s_addr;
	// uint16_t src_port = ((struct sockaddr_in *)sock->get_sockaddr())->sin_port;
	// uint32_t dest_ip;
	// uint16_t dest_port;
	//
  // std::vector<server_TCP>::iterator check_tcp;
	// check_tcp = sock->sock_is_server->accepted_list.begin();
	// dest_ip = ((struct sockaddr_in *)check_tcp->client_addr)->sin_addr.s_addr;
	// dest_port = ((struct sockaddr_in *)check_tcp->client_addr)->sin_port;
	//
	// if(get_connection_no(src_ip,dest_ip,src_port,dest_port) == 1){
	// 	struct connection_TCP connection = find_connection(src_ip,dest_ip,src_port,dest_port);
	// 	int fd = connection.sockfd;
	// 	sock->sock_is_server->accepted_list.erase(check_tcp);
	// 	// before_connection_list.pop_front();
	// 	connection_list.push_back(connection);
	// 	returnSystemCall(check_tcp->syscallblock, fd);
	// }
	// else{
	// 	// this->addTimer(payload, 1);
	// }
	//
	//

	// payload <= socket
	// connection exist => returnSystemCall
	// connection not exist sleep again.


}

int TCPAssignment::get_connection_no(uint32_t src_ip, uint32_t dest_ip, uint16_t src_port, uint16_t dest_port){
	std::vector<connection_TCP>::iterator connection;
	// std::cout << "[is_there_connectiond] here"<< std::endl;
	for( connection = connection_list.begin(); connection!= connection_list.end(); connection++)
	{
		struct sockaddr_in * addr_in_1 = connection->client_addr_in;
		struct sockaddr_in * addr_in_2 = connection->server_addr_in;

		if(addr_in_1->sin_port == src_port && addr_in_1->sin_addr.s_addr == src_ip &&
				addr_in_2->sin_port == dest_port && addr_in_2->sin_addr.s_addr == dest_ip){
					return 2;
		}

		else if(addr_in_1->sin_port == dest_port && addr_in_1->sin_addr.s_addr == dest_ip &&
				addr_in_2->sin_port == src_port && addr_in_2->sin_addr.s_addr == src_ip){
					return 2;
		}
	}

	for( connection = before_connection_list.begin(); connection!= before_connection_list.end(); connection++)
	{
		struct sockaddr_in * addr_in_1 = connection->client_addr_in;
		struct sockaddr_in * addr_in_2 = connection->server_addr_in;

		if(addr_in_1->sin_port == src_port && addr_in_1->sin_addr.s_addr == src_ip &&
				addr_in_2->sin_port == dest_port && addr_in_2->sin_addr.s_addr == dest_ip){
					return 1;
		}

		else if(addr_in_1->sin_port == dest_port && addr_in_1->sin_addr.s_addr == dest_ip &&
				addr_in_2->sin_port == src_port && addr_in_2->sin_addr.s_addr == src_ip){
					return 1;
		}
	}
	return 0;
}


struct connection_TCP TCPAssignment::find_connection(uint32_t src_ip, uint32_t dest_ip, uint16_t src_port, uint16_t dest_port){
	std::vector<connection_TCP>::iterator connection;
	// std::cout << "[find_connection] here"<< std::endl;
	for( connection = before_connection_list.begin(); connection!= before_connection_list.end(); connection++)
	{
		struct sockaddr_in * addr_in_1 = connection->client_addr_in;
		struct sockaddr_in * addr_in_2 = connection->server_addr_in;

		if(addr_in_1->sin_port == src_port && addr_in_1->sin_addr.s_addr == src_ip &&
				addr_in_2->sin_port == dest_port && addr_in_2->sin_addr.s_addr == dest_ip){
					return *connection;
		}

		else if(addr_in_1->sin_port == dest_port && addr_in_1->sin_addr.s_addr == dest_ip &&
				addr_in_2->sin_port == src_port && addr_in_2->sin_addr.s_addr == src_ip){
					return *connection;
		}
	}

	struct connection_TCP * null_connection =  new connection_TCP();
	return *null_connection;
}

bool TCPAssignment::accept_now(Sock * listen_to_accept, UUID syscallUUID){
	bool returned = false;
	std::vector<server_TCP>::iterator check_tcp;
	for(check_tcp = listen_to_accept->sock_is_server->accepted_list.begin();
				check_tcp != listen_to_accept->sock_is_server->accepted_list.end(); check_tcp++){

				struct connection_TCP * new_connection = new connection_TCP();
				new_connection->client_addr_in = (struct sockaddr_in*)check_tcp->client_addr;
				new_connection->server_addr_in = (struct sockaddr_in*)listen_to_accept->get_sockaddr();
				new_connection->sockfd = check_tcp->sockfd;
				connection_list.push_back(*new_connection);
				std::cout << "[ACCEPT_NOW] new sockfd:"<<new_connection->sockfd<< std::endl;
				std::cout << "[ACCEPT_NOW] server_ip:"<<new_connection->server_addr_in->sin_addr.s_addr<< std::endl;

				returnSystemCall(syscallUUID, new_connection->sockfd);
				listen_to_accept->sock_is_server->accepted_list.erase(check_tcp);
				returned = true;
				break;
	}
	return returned;
}

}

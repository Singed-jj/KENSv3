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
#include <E/E_TimeUtil.hpp>

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
	uint32_t ip;
	struct sockaddr* client_addr;
	struct sockaddr* server_addr;

	switch(param.syscallNumber)
	{
	case SOCKET:
	{
		//this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);

		sockfd = createFileDescriptor(pid);
			// std::cout << "[SOCKET] START!!"<<sockfd<< std::endl;
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
		if(sock->binded == 0) {
			this->fdToSock.erase(*pidfd);
			removeFileDescriptor(pid, sockfd);
			returnSystemCall(syscallUUID, retval);
			break;
		}

		port = ((struct sockaddr_in *)sock->addr)->sin_port;
    ip = ((struct sockaddr_in *)sock->addr)->sin_addr.s_addr;

		/* CLIENT CLOSE START*/

		struct sockaddr_in * opp_addr_in = get_opp_addr(sockfd, (struct sockaddr_in *)sock->addr, &connection_list);



		// if(opp_addr_in) std::cout<< "[CLOSE] opp: "<<opp_addr_in->sin_addr.s_addr<<std::endl;
		// std::cout<< "[CLOSE] myy: "<<ip<<std::endl;
		// if(sock->state) std::cout<< "[CLOSE] state: "<<sock->state<<std::endl;

		if (opp_addr_in && sock->state == ESTB){
			uint32_t src_ip = htonl(ip);
			uint32_t dest_ip = htonl(opp_addr_in->sin_addr.s_addr);
			uint16_t src_port = htons(port);
			uint16_t dest_port = htons(opp_addr_in->sin_port);
			// uint32_t fin_syn_no = htonl(rand() % 10000);
			uint32_t fin_syn_no = htonl(sock->fin_pending_info.myy_sn);
			uint32_t fin_ack_no = 0;
			uint8_t flagfield = 0b000001;

			Packet * FIN_packet = this->allocatePacket(54);
			write_packet(FIN_packet,flagfield,src_ip,dest_ip,src_port,dest_port,fin_syn_no,fin_ack_no);
			this->sendPacket("IPv4",FIN_packet);
			sock->state = FIN_WAIT1;
			sock->syscallblock = syscallUUID;

			struct TCP * new_TCP = new TCP();
			new_TCP->state = FIN_WAIT1;
			new_TCP->opp_addr = (struct sockaddr *)opp_addr_in;
			new_TCP->myy_sn = ntohl(fin_syn_no);
			sock->fin_pending_info = *new_TCP;
		}
				/* CLIENT CLOSE END*/
		else if(opp_addr_in && sock->state == CLOSE_WAIT){

			// std::cout << "[CLOSE] close wait!!"<< std::endl;
			uint32_t src_ip = htonl(ip);
			uint32_t dest_ip = htonl(opp_addr_in->sin_addr.s_addr);
			uint16_t src_port = htons(port);
			uint16_t dest_port = htons(opp_addr_in->sin_port);
			uint32_t fin_syn_no = htonl(sock->fin_pending_info.myy_sn);
			uint32_t fin_ack_no = 0;
			uint8_t flagfield = 0b000001;

			Packet * FIN_packet = this->allocatePacket(54);
			write_packet(FIN_packet,flagfield,src_ip,dest_ip,src_port,dest_port,fin_syn_no,fin_ack_no);
			this->sendPacket("IPv4",FIN_packet);
			sock->state = LAST_ACK;
			sock->fin_pending_info.myy_sn = ntohl(fin_syn_no);
			sock->fin_pending_info.state = LAST_ACK;
			sock->syscallblock = syscallUUID;

			Time time_wait = TimeUtil::makeTime(60*2,TimeUtil::SEC);
			UUID timer_key = addTimer(sock,time_wait);
			sock->timer_key = timer_key;
			// std::cout <<"[close wait]timer key: "<<timer_key<<std::endl;
		}
		else{
			// not completely binded
			// [debug] connection exist check -->
			// before_connection_list delete -->
			// free materials -->
			// return

			struct key * k = (struct key *)malloc(sizeof(key));
			k->port = port;
			k->ip = ip;

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
		}




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
		struct sockaddr_in * client_addr_in;
		server_addr_in->sin_addr.s_addr = ntohl(server_addr_in->sin_addr.s_addr);
		server_addr_in->sin_port = ntohs(server_addr_in->sin_port);
		// std::cout << "[CONNECT] server_ip: "<<server_addr_in->sin_addr.s_addr<< std::endl;


		int addrlen = param.param3_int;
		client_addr = new sockaddr();
		Sock * sock = fdToSock[*pidfd];

					// assert(0);
		if(sock->binded > 0){
			/* Already binded */
			client_addr = sock->addr;
		}
		else{

			// new connection. assign client ip/port.
			uint8_t ip_buffer[4];
			// memcpy(ip_buffer,&server_addr_in->sin_addr.s_addr, sizeof(ip_buffer));
			ip_buffer[0] = server_addr_in->sin_addr.s_addr >> 24;
			ip_buffer[1] = server_addr_in->sin_addr.s_addr >> 16;
			ip_buffer[2] = server_addr_in->sin_addr.s_addr >> 8;
			ip_buffer[3] = server_addr_in->sin_addr.s_addr;

// std::cout << "[CONNECT] ip_buffer : "<<static_cast<uint16_t>(ip_buffer[0])<< std::endl;
// std::cout << "[CONNECT] ip_buffer : "<<static_cast<uint16_t>(ip_buffer[1])<< std::endl;
// std::cout << "[CONNECT] ip_buffer : "<<static_cast<uint16_t>(ip_buffer[2])<< std::endl;
// std::cout << "[CONNECT] ip_buffer : "<<static_cast<uint16_t>(ip_buffer[3])<< std::endl;
// std::cout << "[CONNECT] ip_buffe_size : "<<sizeof(ip_buffer)<< std::endl;


			int interface_index = this->getHost()->getRoutingTable(ip_buffer);
			// std::cout << "[CONNECT] interface_index : "<<interface_index<< std::endl;

			uint8_t dif[4];
			this->getHost()->getIPAddr(dif, interface_index);
			// ((struct sockaddr_in *)client_addr)->sin_addr.s_addr = *ip_buffer;

			memcpy(&((struct sockaddr_in *)client_addr)->sin_addr.s_addr,dif,sizeof(dif));
			client_addr_in = (struct sockaddr_in *)client_addr;
			client_addr_in->sin_addr.s_addr = ntohl(client_addr_in->sin_addr.s_addr);
			// std::cout << "[CONNECT] ip_buffer : "<<static_cast<uint16_t>(dif[0])<< std::endl;
			// std::cout << "[CONNECT] ip_buffer : "<<static_cast<uint16_t>(dif[1])<< std::endl;
			// std::cout << "[CONNECT] ip_buffer : "<<static_cast<uint16_t>(dif[2])<< std::endl;
			// std::cout << "[CONNECT] ip_buffer : "<<static_cast<uint16_t>(dif[3])<< std::endl;
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
			sock->addr = client_addr;
			if(!(this->allPort.insert(std::pair<uint16_t,int>(port,1)).second)){
				++this->allPort[port];
			}
			this->portAndIpTofd.insert(std::pair<struct key,struct sockey>(*key_buf,*pidfd));

		}

		/* STATE does not changed until now.
		   CREATE elements to write in new syn packet */

		// struct sockaddr_in * server_addr_in = (struct sockaddr_in *)server_addr;

		uint32_t src_ip = htonl(client_addr_in->sin_addr.s_addr);
		uint32_t dest_ip = htonl(server_addr_in->sin_addr.s_addr);
		uint16_t src_port = htons(client_addr_in->sin_port);
		uint16_t dest_port = htons(server_addr_in->sin_port);
		uint8_t flagfield = 0b000010;
		uint32_t seq_no = rand() % 10000; // sequence number field
		uint32_t ack_no = 0; // acknowledgment number field

		/* Update sent socket to sent socket list */

	  sock->syscallblock = syscallUUID;
		sock->binded = 1;

		struct TCP * new_TCP;
		new_TCP = new TCP();
		new_TCP->state = SYN_SENT;
		new_TCP->opp_addr = (struct sockaddr *)server_addr_in;
		new_TCP->myy_sn = seq_no;
		sock->sock_is_client->pending_info = *new_TCP;
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


		// std::cout << "[CONNECT] dest_ip: "<<dest_ip<< std::endl;
		// std::cout << "[CONNECT] dest_port: "<<dest_port<< std::endl;
		// std::cout << "[CONNECT] src_ip: "<<src_ip<< std::endl;
		// std::cout << "[CONNECT] src port: "<<src_port<< std::endl;

		write_packet(SYN_packet, flagfield, src_ip, dest_ip, src_port,dest_port,seq_no, ack_no);
		this->sendPacket("IPv4", SYN_packet);

		struct connection_TCP * new_conn = new connection_TCP();
		new_conn->myy_addr_in = client_addr_in;
		new_conn->opp_addr_in = server_addr_in;
		new_conn->sockfd = sock->sockfd;
		new_conn->pidfd = pidfd;

		before_connection_list.push_back(*new_conn);

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
	// std::cout << "[ACCEPT] START!!"<< std::endl;
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		sockfd =  param.param1_int;
		struct sockey * pidfd = new sockey();
		pidfd->pid = pid;
		pidfd->fd = sockfd;

		struct sockaddr_in * client_addr_in = (struct sockaddr_in *)param.param2_ptr;
		client_addr_in->sin_family = AF_INET; // 임시방편.

		bool is_there_listen = false;

		std::vector<Sock>::iterator listen_to_accept;


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
					// std::cout << "[ACCEPT] accept called early!!"<< std::endl;
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

				// std::cout << "[BIND] START!! "<< sockfd<< std::endl;
		server_addr = (struct sockaddr *)param.param2_ptr;

		struct sockaddr_in * server_addr_in = new sockaddr_in();
		server_addr_in->sin_port = ntohs(((struct sockaddr_in *)server_addr)->sin_port);
		server_addr_in->sin_addr.s_addr = ntohl(((struct sockaddr_in *)server_addr)->sin_addr.s_addr);
		server_addr_in->sin_family = ((struct sockaddr_in *)server_addr)->sin_family;
		addrlen = (int *)&param.param3_int;

		// std::cout << "[BIND] server_ip: "<<server_addr_in->sin_addr.s_addr<< std::endl;
		// std::cout << "[BIND] server_port: "<<server_addr_in->sin_port<< std::endl;

		port = server_addr_in->sin_port;
		ip = server_addr_in->sin_addr.s_addr;

		Sock * sock = fdToSock[*pidfd];

		struct key * k = (struct key *)malloc(sizeof(key));
		k->port = port;
		k->ip = ip;

		struct key * buf = (struct key *)malloc(sizeof(key));
		memset(buf, 0, sizeof(key));
		memcpy(buf, &port, sizeof(port));
		// buf[sizeof(u_short)] = htonl(INADDR_ANY);
		buf->ip = INADDR_ANY;

		if( (sock->binded > 0 && ((struct sockaddr_in *)sock->addr)->sin_port != port) || // 이미 binded 되었거나
			 	this->fdToSock.find(*pidfd) == this->fdToSock.end()|| // sock 의 fd 가 this->fdToSock 에 없거나
				this->portAndIpTofd.find(*k) != this->portAndIpTofd.end() || // bind 하려는 ip:port 에 연결된 fd(=>sock) 이 있거나
				this->portAndIpTofd.find(*buf) != this->portAndIpTofd.end() || // bind 하려는 :port 가 0.0.0.0/0:port 에 binded 되어있거나
				(this->allPort.find(port) != this->allPort.end() && ip == INADDR_ANY)){ //port 가 사용중이고, bind 하려는 ip 가 0.0.0.0/0 이거나

									std::cout << "[BIND] here!!! :"<< this->allPort[port] << std::endl;
									std::cout << "[BIND] 0:"<< (sock->binded > 0 && ((struct sockaddr_in *)sock->addr)->sin_port != port)<< std::endl;
									std::cout << "[BIND] 1:"<< (this->fdToSock.find(*pidfd) == this->fdToSock.end())<< std::endl;
									std::cout << "[BIND] 2:"<< (this->portAndIpTofd.find(*k) != this->portAndIpTofd.end() )<< std::endl;
									std::cout << "[BIND] 3:"<< (this->portAndIpTofd.find(*buf) != this->portAndIpTofd.end() )<< std::endl;
									std::cout << "[BIND] 4:"<< (this->allPort.find(port) != this->allPort.end() && ip == htonl(INADDR_ANY))<< std::endl;
			retval = -1;
					// std::cout << syscallUUID << std::endl;
			returnSystemCall(syscallUUID, retval);
			break;
		}

		sock->addr = (struct sockaddr *)server_addr_in;

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
		memcpy(addr_in, fdToSock[*pidfd]->addr, sizeof(struct sockaddr_in));
   // std::cout << "[GETSOCKNAME] addr : "<<addr_in->sin_addr.s_addr<<" port: "<<addr_in->sin_port<< std::endl;
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
		struct sockaddr_in * addr_in = (struct sockaddr_in *) sock->sock_is_client->pending_info.opp_addr;

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


		struct connection_TCP conn = find_connection(dest_ip,src_ip,dest_port,src_port,&connection_list);
		sock = fdToSock[*conn.pidfd];


		// 		std::cout << "[packetArrived] here!!!!"<< std::endl;

		if(ACK && sock->state == FIN_WAIT1){

			if(ack_no == sock->fin_pending_info.myy_sn + 1){
				sock->state = FIN_WAIT2;
				sock->fin_pending_info.state = FIN_WAIT2;



			}
		}

		else if(FIN && (sock->state == FIN_WAIT2 || sock->state == FIN_WAIT1 || sock->state == TIMED_WAIT)){

  		// std::cout << "[packetArrived] FIN got from server"<< std::endl;
			//  std::cout << "[packetArrived] state: "<<sock->state<< std::endl;
			if(sock->state == TIMED_WAIT) this->cancelTimer(sock->timer_key);
			Time time_wait =  TimeUtil::makeTime(60, TimeUtil::SEC);
			uint32_t ack_seq_no = sock->fin_pending_info.myy_sn + 1; // sequence number field
			uint32_t ack_ack_no = seq_no + 1; // acknowledgment number field
			uint8_t flagfield = 0b010000;
			// sock_cmd_obj->sock = sock;
			// sock_cmd_obj->cmd = CLOSE;

			dest_ip = htonl(dest_ip);
			src_ip = htonl(src_ip);
			dest_port = htons(dest_port);
			src_port = htons(src_port);
			ack_seq_no = htonl(ack_seq_no);
			ack_ack_no = htonl(ack_ack_no);

			sock->fin_pending_info.opp_sn = seq_no;

			Packet * ACK_packet = this->allocatePacket(54);
			write_packet(ACK_packet,flagfield,dest_ip,src_ip,dest_port,src_port,ack_seq_no,ack_ack_no);

			UUID timer_key = this->addTimer(sock,time_wait);
			sock->timer_key = timer_key;
			sock->state = TIMED_WAIT;
			sock->fin_pending_info.state = TIMED_WAIT;
			this->sendPacket("IPv4", ACK_packet);
		}

		else if(FIN && sock->state == ESTB){

			uint32_t ack_seq_no = sock->fin_pending_info.myy_sn; // sequence number field
			uint32_t ack_ack_no = seq_no + 1; // acknowledgment number field
			uint8_t flagfield = 0b010000;

			struct sockaddr_in * client_addr_in = new sockaddr_in();
			client_addr_in->sin_family = AF_INET;
			client_addr_in->sin_addr.s_addr = src_ip;
			client_addr_in->sin_port = src_port;

			dest_ip = htonl(dest_ip);
			src_ip = htonl(src_ip);
			dest_port = htons(dest_port);
			src_port = htons(src_port);
			ack_seq_no = htonl(ack_seq_no);
			ack_ack_no = htonl(ack_ack_no);


			struct TCP * new_TCP = new TCP();
			new_TCP->state = CLOSE_WAIT;
			new_TCP->opp_sn = seq_no;
			new_TCP->myy_sn = ntohl(ack_seq_no);
			new_TCP->opp_addr = (struct sockaddr *)client_addr_in;

			Packet * ACK_packet = this->allocatePacket(54);
			write_packet(ACK_packet,flagfield,dest_ip,src_ip,dest_port,src_port,ack_seq_no,ack_ack_no);
			this->sendPacket("IPv4", ACK_packet);
			sock->state = CLOSE_WAIT;
			sock->fin_pending_info = *new_TCP;
		}

		else if(ACK && sock->state == LAST_ACK){
			if(ack_no == sock->fin_pending_info.myy_sn + 1){
				sock->state = CLOSED;

				this->cancelTimer(sock->timer_key);
				close_r(sock);
			}
		}


		this->freePacket(packet);

	}
	else if(is_connected == 1 && FIN){
		// std::cout <<"[packetArrived]fin got ewrwerw: "<<std::endl;
		bef_to_con(dest_ip,src_ip,dest_port,src_port);
		struct connection_TCP conn = find_connection(dest_ip,src_ip,dest_port,src_port,&connection_list);
		sock = fdToSock[*conn.pidfd];

		uint32_t ack_seq_no = sock->fin_pending_info.myy_sn; // sequence number field
		uint32_t ack_ack_no = seq_no + 1; // acknowledgment number field
		uint8_t flagfield = 0b010000;

		struct sockaddr_in * client_addr_in = new sockaddr_in();
		client_addr_in->sin_family = AF_INET;
		client_addr_in->sin_addr.s_addr = src_ip;
		client_addr_in->sin_port = src_port;

		dest_ip = htonl(dest_ip);
		src_ip = htonl(src_ip);
		dest_port = htons(dest_port);
		src_port = htons(src_port);
		ack_seq_no = htonl(ack_seq_no);
		ack_ack_no = htonl(ack_ack_no);


		struct TCP * new_TCP = new TCP();
		new_TCP->state = CLOSE_WAIT;
		new_TCP->opp_sn = seq_no;
		new_TCP->myy_sn = ntohl(ack_seq_no);
		new_TCP->opp_addr = (struct sockaddr *)client_addr_in;

		Packet * ACK_packet = this->allocatePacket(54);
		write_packet(ACK_packet,flagfield,dest_ip,src_ip,dest_port,src_port,ack_seq_no,ack_ack_no);
		this->sendPacket("IPv4", ACK_packet);
		sock->state = CLOSE_WAIT;
		sock->fin_pending_info = *new_TCP;
	}

	if (is_connected == 1 || is_connected == 0){
		// before connected
				// std::cout << "[packetArrived] something wrong" << std::endl;



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
			// std::cout << "[packetArrived] SYNACK" << std::endl;
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

			struct TCP * new_TCP;
			new_TCP = new TCP();
			new_TCP->state = ESTB;
			new_TCP->opp_addr = (struct sockaddr *)server_addr_in;
			new_TCP->opp_sn = seq_no;
			new_TCP->myy_sn = ack_seq_no;
			sock->sock_is_client->pending_info = *new_TCP;
			sock->state = ESTB;
			sock->fin_pending_info = *new_TCP;
			uint8_t header_length = 0x50;

						// std::cout << "[packetArrived] SYNACK here 1" << std::endl;

			dest_ip = htonl(dest_ip);
			src_ip = htonl(src_ip);
			dest_port = htons(dest_port);
			src_port = htons(src_port);
			ack_seq_no = htonl(ack_seq_no);
			ack_ack_no = htonl(ack_ack_no);

			Packet * ACK_packet = this->allocatePacket(54);
			write_packet(ACK_packet, flagfield,dest_ip,src_ip,dest_port,src_port,ack_seq_no,ack_ack_no);


			this->sendPacket("IPv4", ACK_packet);
			// std::cout << "[packetArrived] sent ACK Packet "<< std::endl;
			// std::cout << "[packetArrived] my syn"<< new_TCP->myy_sn<< std::endl;
			// std::cout << "[packetArrived] "<< dest_ip<< std::endl;
			// std::cout << "[packetArrived] "<< dest_port<< std::endl;
			// std::cout << "[packetArrived] "<< src_ip<< std::endl;
			// std::cout << "[packetArrived] "<< src_port<< std::endl;
			returnSystemCall(sock->syscallblock, 0);
			dest_ip = ntohl(dest_ip);
			src_ip = ntohl(src_ip);
			dest_port = ntohs(dest_port);
			src_port = ntohs(src_port);
			bef_to_con(dest_ip,src_ip,dest_port,src_port);
		}

		else if(SYN || ACK){

			// std::cout << "[packetArrived] SYN || ACK" << std::endl;
			bool is_in_pending = false;
			bool is_in_accepted = false;


			std::vector<server_TCP>::iterator check_pending;
			std::vector<server_TCP>::iterator check_accept;


			// std::cout << "[packetArrived] SA 0 " << std::endl;
			for( check_pending = sock->sock_is_server->pending_list.begin(); check_pending!= sock->sock_is_server->pending_list.end(); check_pending++)
			{
				client_addr_in = (struct sockaddr_in *)check_pending->client_addr;
				if(client_addr_in->sin_addr.s_addr == src_ip && client_addr_in->sin_port == src_port){
					is_in_pending = true;
					break;
				}
			}
			// std::cout << "[packetArrived] SA 1 " << std::endl;

			for( check_accept = sock->sock_is_server->accepted_list.begin(); check_accept!= sock->sock_is_server->accepted_list.end(); check_accept++)
			{
				client_addr_in = (struct sockaddr_in *)check_accept->client_addr;
				if(client_addr_in->sin_addr.s_addr == src_ip && client_addr_in->sin_port == src_port){
					is_in_accepted = true;
					break;
				}
			}

			// std::cout << "[packetArrived] SA 2 " << std::endl;

			/* SYN_PACKET FROM CLIENT and TIME TO SEND SYNACK_PACKET TO CLIENT*/
			if( !is_in_pending && !is_in_accepted && SYN){

				if(sock->sock_is_server->backlog <= (int)sock->sock_is_server->pending_list.size()){
					// drop the packet
				}
				else{

														// std::cout << "[packetArrived] SYN " << std::endl;
					client_addr_in = new sockaddr_in();
					client_addr_in->sin_family = AF_INET;
					client_addr_in->sin_addr.s_addr = src_ip;
					client_addr_in->sin_port = src_port;

					server_addr_in = new sockaddr_in();
					server_addr_in->sin_family = AF_INET;
					server_addr_in->sin_addr.s_addr = dest_ip;
					server_addr_in->sin_port = dest_port;

					int new_sockfd = createFileDescriptor(sock->pid);
					Sock * new_sock = new Sock(AF_INET,SOCK_STREAM,IPPROTO_TCP,new_sockfd);
					pidfd = new sockey();
					pidfd->pid = sock->pid;
					pidfd->fd = new_sockfd;
					new_sock->sock_is_server->state = SYN_RCVD;
					new_sock->state = SYN_RCVD;
					new_sock->addr = (struct sockaddr *)server_addr_in;
					new_sock->binded = 1;

					fdToSock.insert(std::pair<struct sockey,Sock* >(*pidfd,new_sock));

					struct key * key_buf = new key();
					key_buf->port = src_port;
					key_buf->ip = src_ip;
					portAndIpTofd.insert(std::pair<struct key,struct sockey>(*key_buf,*pidfd));
					// struct sockaddr_in * server_addr_in = (struct sockaddr_in *)new_sock->get_sockaddr();
					// std::cout << "[packetArrived] SYN 3 new sock addr : " <<server_addr_in->sin_addr.s_addr<<" port : "<<server_addr_in->sin_port << std::endl;


					uint32_t synack_seq_no = rand() % 10000;
					uint32_t synack_ack_no = seq_no + 1;

					struct server_TCP * new_pending = new server_TCP();
					new_pending->state = SYN_RCVD;
					new_pending->client_addr = (struct sockaddr *)client_addr_in;
					new_pending->server_addr = (struct sockaddr *)server_addr_in;
					new_pending->myy_sn = synack_seq_no;
					new_pending->opp_sn = seq_no;
					new_pending->sockfd = new_sockfd;
					sock->sock_is_server->pending_list.push_back(*new_pending);

					struct TCP * fin_pending_info = new TCP();
					fin_pending_info->opp_addr = (struct sockaddr *)client_addr_in;
					fin_pending_info->myy_sn = synack_seq_no + 1;
					fin_pending_info->opp_sn = seq_no;
					fin_pending_info->state = SYN_RCVD;

					new_sock->fin_pending_info = *fin_pending_info;

					struct connection_TCP * new_conn = new connection_TCP();
					new_conn->opp_addr_in = client_addr_in;
					new_conn->myy_addr_in = server_addr_in;
					new_conn->sockfd = new_sockfd;
					new_conn->pidfd = pidfd;
					before_connection_list.push_back(*new_conn);

					Packet* SYNACK_packet = this->allocatePacket(54);
					uint8_t flagfield = 0b010010;

					dest_ip = htonl(dest_ip);
					src_ip = htonl(src_ip);
					dest_port = htons(dest_port);
					src_port = htons(src_port);
					synack_seq_no = htonl(synack_seq_no);
					synack_ack_no = htonl(synack_ack_no);

					write_packet(SYNACK_packet, flagfield, dest_ip, src_ip, dest_port, src_port,
													synack_seq_no, synack_ack_no);

					this->sendPacket("IPv4", SYNACK_packet);
					// std::cout << "[packetArrived] sent SYNACK Packet" << std::endl;
				}
			}

			else if( is_in_pending && !is_in_accepted && ACK){
				/* Third Handshake (ACK segment from client) */
				// std::cout << "In here THird handshake\n";
				if(ack_no == check_pending->myy_sn + 1){

					/* Update Server TCP state */
					check_pending->state = ESTB;

					sock->sock_is_server->accepted_list.push_back(*check_pending);
					sock->sock_is_server->pending_list.erase(check_pending);
					std::vector<UUID>::iterator syscallblock;
					for (syscallblock=accept_waiting_list.begin();syscallblock!=accept_waiting_list.end();syscallblock++){
						accept_now(sock,*syscallblock);
						accept_waiting_list.erase(syscallblock);
						break;
					}
				}
			}
		}
		this->freePacket(packet);
	}
}

void TCPAssignment::timerCallback(void* payload)
{
	/* CLIENT TIMERCALLBACK */
	// std::cout << "[timerCallback]" <<std::endl;
	Sock * sock = (Sock *)payload;
	if(sock->state == LAST_ACK){
		struct sockaddr_in * client_addr_in = get_opp_addr(sock->sockfd, (struct sockaddr_in *)sock->addr, &connection_list);

		uint32_t src_ip = htonl(((struct sockaddr_in *)sock->addr)->sin_addr.s_addr);
		uint32_t dest_ip = htonl(client_addr_in->sin_addr.s_addr);
		uint16_t src_port = htons(((struct sockaddr_in *)sock->addr)->sin_port);
		uint16_t dest_port = htons(client_addr_in->sin_port);
		uint32_t fin_syn_no = htonl(sock->fin_pending_info.myy_sn);
		uint32_t fin_ack_no = 0;
		uint8_t flagfield = 0b000001;

		Packet * FIN_packet = this->allocatePacket(54);
		write_packet(FIN_packet,flagfield,src_ip,dest_ip,src_port,dest_port,fin_syn_no,fin_ack_no);
		this->sendPacket("IPv4",FIN_packet);

		sock->fin_pending_info.myy_sn = ntohl(fin_syn_no);
		sock->fin_pending_info.state = LAST_ACK;

		Time time_wait =  TimeUtil::makeTime(60, TimeUtil::SEC);
		UUID timer_key = this->addTimer(sock,time_wait);
		sock->timer_key = timer_key;

	}
	else if(sock->state == TIMED_WAIT){
		close_r((Sock *)payload);
	}



}

int TCPAssignment::get_connection_no(uint32_t src_ip, uint32_t dest_ip, uint16_t src_port, uint16_t dest_port){
	std::vector<connection_TCP>::iterator connection;
	// std::cout << "[is_there_connectiond] here"<< std::endl;
	for( connection = connection_list.begin(); connection!= connection_list.end(); connection++)
	{
		struct sockaddr_in * addr_in_1 = connection->myy_addr_in;
		struct sockaddr_in * addr_in_2 = connection->opp_addr_in;

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
		struct sockaddr_in * addr_in_1 = connection->myy_addr_in;
		struct sockaddr_in * addr_in_2 = connection->opp_addr_in;

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


struct connection_TCP TCPAssignment::find_connection(uint32_t src_ip, uint32_t dest_ip, uint16_t src_port, uint16_t dest_port, std::vector<connection_TCP> * befOrConlist ){
	std::vector<connection_TCP>::iterator connection;
	std::vector<connection_TCP> list = *befOrConlist;
	// std::cout << "[find_connection] here"<< std::endl;
	for( connection = list.begin(); connection!= list.end(); connection++)
	{
		struct sockaddr_in * addr_in_1 = connection->myy_addr_in;
		struct sockaddr_in * addr_in_2 = connection->opp_addr_in;

		if(addr_in_1->sin_port == src_port && addr_in_1->sin_addr.s_addr == src_ip &&
				addr_in_2->sin_port == dest_port && addr_in_2->sin_addr.s_addr == dest_ip){
					return *connection;
		}

		else if(addr_in_1->sin_port == dest_port && addr_in_1->sin_addr.s_addr == dest_ip &&
				addr_in_2->sin_port == src_port && addr_in_2->sin_addr.s_addr == src_ip){
					return *connection;
		}
	}

	return *(new connection_TCP());
}



void TCPAssignment::bef_to_con(uint32_t src_ip, uint32_t dest_ip, uint16_t src_port, uint16_t dest_port){
	std::vector<connection_TCP>::iterator connection;
	for( connection = before_connection_list.begin(); connection!= before_connection_list.end(); connection++)
	{
		struct sockaddr_in * addr_in_1 = connection->myy_addr_in;
		struct sockaddr_in * addr_in_2 = connection->opp_addr_in;


		if(addr_in_1->sin_port == src_port && addr_in_1->sin_addr.s_addr == src_ip &&
				addr_in_2->sin_port == dest_port && addr_in_2->sin_addr.s_addr == dest_ip){
					connection_list.push_back(*connection);
					before_connection_list.erase(connection);
					return;
		}
		else if(addr_in_1->sin_port == dest_port && addr_in_1->sin_addr.s_addr == dest_ip &&
				addr_in_2->sin_port == src_port && addr_in_2->sin_addr.s_addr == src_ip){
					connection_list.push_back(*connection);
					before_connection_list.erase(connection);
					return;

		}
	}
}

void TCPAssignment::delete_con(uint32_t src_ip, uint32_t dest_ip, uint16_t src_port, uint16_t dest_port){
	std::vector<connection_TCP>::iterator connection;
	for( connection = connection_list.begin(); connection!= connection_list.end(); connection++)
	{
		struct sockaddr_in * addr_in_1 = connection->myy_addr_in;
		struct sockaddr_in * addr_in_2 = connection->opp_addr_in;

		if(addr_in_1->sin_port == src_port && addr_in_1->sin_addr.s_addr == src_ip &&
				addr_in_2->sin_port == dest_port && addr_in_2->sin_addr.s_addr == dest_ip){
					connection_list.erase(connection);
					return;
		}
		else if(addr_in_1->sin_port == dest_port && addr_in_1->sin_addr.s_addr == dest_ip &&
				addr_in_2->sin_port == src_port && addr_in_2->sin_addr.s_addr == src_ip){
					connection_list.erase(connection);
					return;

		}
	}
}

bool TCPAssignment::accept_now(Sock * listen_to_accept, UUID syscallUUID){

	bool returned = false;
	std::vector<server_TCP>::iterator check_tcp;
	for(check_tcp = listen_to_accept->sock_is_server->accepted_list.begin();
				check_tcp != listen_to_accept->sock_is_server->accepted_list.end(); check_tcp++){

				struct sockaddr_in * client_addr_in = (struct sockaddr_in*)check_tcp->client_addr;
				struct sockaddr_in * server_addr_in = (struct sockaddr_in*)check_tcp->server_addr;
				bef_to_con(server_addr_in->sin_addr.s_addr,client_addr_in->sin_addr.s_addr,
											server_addr_in->sin_port, client_addr_in->sin_port);
				struct key * key_buf = new key();
				key_buf->ip = client_addr_in->sin_addr.s_addr;
				key_buf->port = client_addr_in->sin_port;

        (fdToSock[portAndIpTofd[*key_buf]])->state = ESTB;

				returnSystemCall(syscallUUID, check_tcp->sockfd);
				listen_to_accept->sock_is_server->accepted_list.erase(check_tcp);
				returned = true;
				break;
	}
	return returned;
}


struct sockaddr_in * TCPAssignment::get_opp_addr(int fd, sockaddr_in * client_addr_in, std::vector<connection_TCP> * befOrConlist){
  std::vector<connection_TCP>::iterator connection;
  std::vector<connection_TCP> list = *befOrConlist;
  // std::cout << "[find_connection] here"<< std::endl;
  for( connection = list.begin(); connection!= list.end(); connection++)
  {
    struct sockaddr_in * addr_in = connection->myy_addr_in;

	  // std::cout << "[get_opp_addr] conn->ip:"<<addr_in->sin_addr.s_addr<<"conn->port:"<<addr_in->sin_port<< std::endl;
	  // std::cout << "[get_opp_addr] input->ip:"<<client_addr_in->sin_addr.s_addr<<"input->port:"<<client_addr_in->sin_port<< std::endl;
    if(addr_in->sin_port == client_addr_in->sin_port &&
				addr_in->sin_addr.s_addr == client_addr_in->sin_addr.s_addr &&
        fd == connection->sockfd){
          return connection->opp_addr_in;
    }
  }
	return NULL;
}

// struct sockaddr_in * TCPAssignment::get_client_addr(int fd, sockaddr_in * server_addr_in, std::vector<connection_TCP> * befOrConlist){
//   std::vector<connection_TCP>::iterator connection;
//   std::vector<connection_TCP> list = *befOrConlist;
//   // std::cout << "[find_connection] here"<< std::endl;
//   for( connection = list.begin(); connection!= list.end(); connection++)
//   {
//     struct sockaddr_in * addr_in = connection->myy_addr_in;
//     if(addr_in->sin_port == server_addr_in->sin_port &&
// 				addr_in->sin_addr.s_addr == server_addr_in->sin_addr.s_addr &&
//         fd == connection->sockfd){
//           return connection->opp_addr_in;
//     }
//   }
// 	return NULL;
// }

void TCPAssignment::write_packet(Packet * pck, uint8_t flagfield, uint32_t src_ip, uint32_t dest_ip,
										uint16_t src_port, uint16_t dest_port,
										uint32_t seq_no, uint32_t ack_no){

	uint8_t header_length = 0x50;
	uint16_t window_size = htons(0xc800);
	uint8_t tcp_header_buffer[20];

// std::cout << "[write_packet] src_ip: "<<src_ip<<" src port: "<<src_port<< std::endl;
	pck->writeData(14+12, &src_ip, 4);
	pck->writeData(14+16, &dest_ip, 4);
	pck->writeData(14+20, &src_port, 2);
	pck->writeData(14+22, &dest_port, 2);
	pck->writeData(14+24, &seq_no, 4);
	pck->writeData(14+28, &ack_no, 4);
	pck->writeData(14+28+4, &header_length, 1);
	pck->writeData(14+28+4+1, &flagfield, 1);
	pck->writeData(14+33+1, &window_size, 2);
	pck->readData(14+20, tcp_header_buffer,20 );

	uint16_t checksum = NetworkUtil::tcp_sum(src_ip,dest_ip,tcp_header_buffer,20);
	checksum = ~checksum;
	if(checksum == 0xFFFF) checksum = 0;
	checksum = htons(checksum);
	pck->writeData(14+ 32+1+1+2, (uint8_t*)&checksum, 2);

}

void TCPAssignment::close_r(Sock * sc){
	Sock * sock = sc;
	uint32_t src_ip = ((struct sockaddr_in *)sock->addr)->sin_addr.s_addr;
	uint16_t src_port = ((struct sockaddr_in *)sock->addr)->sin_port;
	uint32_t dest_ip = ((struct sockaddr_in *)sock->fin_pending_info.opp_addr)->sin_addr.s_addr;
	uint16_t dest_port = ((struct sockaddr_in *)sock->fin_pending_info.opp_addr)->sin_port;
	struct sockey * pidfd = new sockey();
	pidfd->pid = sock->pid;
	pidfd->fd = sock->sockfd;


	struct key * k = (struct key *)malloc(sizeof(key));
	k->port = src_port;
	k->ip = src_ip;

	if(this->allPort.find(src_port) == this->allPort.end()){
		// port not binded
	}
	else {
		if(this->allPort[src_port] == 1) this->allPort.erase(src_port);
		else this->allPort[src_port]--;
		this->portAndIpTofd.erase(*k);
	}
	returnSystemCall(sock->syscallblock, 0);

	delete_con(src_ip,dest_ip,src_port,dest_port);
	// free(&find_connection(src_ip,dest_ip,src_port,dest_port));
	// std::cout<<"closing fd: "<<sock->sockfd<<std::endl;
	removeFileDescriptor(sock->pid, sock->sockfd);
	this->fdToSock.erase(*pidfd);
	sock->~Sock();
}


//END DECLARATION
}

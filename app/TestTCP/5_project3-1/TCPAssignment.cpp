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
#include <unistd.h>
#include <iostream>       // std::cout, std::endl
#include <thread>         // std::this_thread::sleep_for
#include <chrono>

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
			uint32_t fin_syn_no = htonl(sock->fin_pending_info->myy_sn);
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
			sock->fin_pending_info = new_TCP;
		}
				/* CLIENT CLOSE END*/
		else if(opp_addr_in && sock->state == CLOSE_WAIT){

			// std::cout << "[CLOSE] close wait!!"<< std::endl;
			uint32_t src_ip = htonl(ip);
			uint32_t dest_ip = htonl(opp_addr_in->sin_addr.s_addr);
			uint16_t src_port = htons(port);
			uint16_t dest_port = htons(opp_addr_in->sin_port);
			uint32_t fin_syn_no = htonl(sock->fin_pending_info->myy_sn);
			uint32_t fin_ack_no = 0;
			uint8_t flagfield = 0b000001;

			Packet * FIN_packet = this->allocatePacket(54);
			write_packet(FIN_packet,flagfield,src_ip,dest_ip,src_port,dest_port,fin_syn_no,fin_ack_no);
			this->sendPacket("IPv4",FIN_packet);
			sock->state = LAST_ACK;
			sock->fin_pending_info->myy_sn = ntohl(fin_syn_no);
			sock->fin_pending_info->state = LAST_ACK;
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
	case READ:{


		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);

		int offset = 0;
		sockfd = param.param1_int;
		void * target_buffer = param.param2_ptr;
		int read_bytes = param.param3_int;

		struct sockey * pidfd = new sockey();
		pidfd->pid = pid;
		pidfd->fd = sockfd;
		Sock * sock = fdToSock[*pidfd];

		sock->erase_time+=1;
		if (read_bytes != 67){
					// std::cout<<"[READ] bjangawfijawofjoawjfojwaeofjwe read_bytes: "<<read_bytes<<std::endl;
		}
		offset = read_from_pending(sock, target_buffer, read_bytes);
		if (offset == read_bytes){
			returnSystemCall(syscallUUID, offset);
		}
		else{
			struct pending_read * new_pr = new pending_read();
			new_pr->syscallblock = syscallUUID;
			new_pr->target_buffer = target_buffer;
			new_pr->read_bytes = read_bytes;
			sock->reader->blocked_read_list.push_back(*new_pr);
		}

		break;
	}
	case WRITE:
	{
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);

		sockfd = param.param1_int;
		void * source_buffer = param.param2_ptr;
		int write_bytes = param.param3_int;
		struct sockey * pidfd = new sockey();
		pidfd->pid = pid;
		pidfd->fd = sockfd;
		Sock * sock = fdToSock[*pidfd];
		int split_write = (write_bytes-1)/512 + 1;
		if (write_bytes == 0){
			std::cout<<"[WRITE] syscall called!! write_bytes is zero "<<std::endl;
			returnSystemCall(syscallUUID, 0);
			break;
		}
		// std::cout<<"[WRITE] syscall called!! write_bytes: "<<write_bytes<<std::endl;

		// writer_window has memory left.
		// 1. check blocked_write_list first
		// 2. <loop start> do write for prefer ones
		// 3. <loop insid> check writer_window
		// 4. <loop end  > if write done for all blocked_write and current_write or writer_window full


		if (sock->writer->writer_window - write_bytes < 0)
				// || sock->writer->writer_window - blocked_write->write_bytes < 0)
		{
			// block write syscall
			std::cout<<"[WRITE] syscall blocked!!"<<std::endl;
			struct pending_write * new_pw = new pending_write();
			new_pw->syscallblock = syscallUUID;
			new_pw->source_buffer = source_buffer;
			new_pw->write_bytes = write_bytes;
			sock->writer->blocked_write_list.push_back(*new_pw);
			break;
		}

		int offset = 0;
		while(write_bytes > 0){
			int tmp_write_bytes = std::min(write_bytes,512);

			Packet * pck = this->allocatePacket(54 + tmp_write_bytes);

			struct sockaddr_in * opp_addr = get_opp_addr(sockfd, ((struct sockaddr_in *)sock->addr), &connection_list);
			uint32_t src_ip = ((struct sockaddr_in *)sock->addr)->sin_addr.s_addr;
			uint16_t src_port = ((struct sockaddr_in *)sock->addr)->sin_port;
			uint32_t dest_ip = opp_addr->sin_addr.s_addr;
			uint16_t dest_port = opp_addr->sin_port;
			uint8_t flagfield = 0b010000;
			uint32_t seq_no = sock->fin_pending_info->myy_sn;
			uint32_t ack_no = sock->fin_pending_info->opp_sn+1;

			dest_ip = htonl(dest_ip);
			src_ip = htonl(src_ip);
			dest_port = htons(dest_port);
			src_port = htons(src_port);
			seq_no = htonl(seq_no);
			ack_no = htonl(ack_no);
			write_packet(pck,flagfield, src_ip, dest_ip, src_port, dest_port,seq_no,ack_no,tmp_write_bytes,offset,source_buffer);

			sock->writer->writer_window -= tmp_write_bytes;
			struct sent_pck * ppck = new sent_pck();
			// std::cout<<"[WRITE] ppck addr: "<<ppck<<std::endl;
			ppck->pck = pck;
			sock->writer->not_sent_list.push_back(*ppck);
			sock->fin_pending_info->myy_sn += tmp_write_bytes;

			// sock->writer->writer_window -= write_bytes;

			write_bytes -= 512;
			offset += tmp_write_bytes;
		}

		// for (int i=10; i>0; --i) {
	 	// 	std::cout << i << std::endl;
	 	// 	std::this_thread::sleep_for (std::chrono::seconds(1));
 		// }
			// send packet
		std::vector<sent_pck>::iterator not_sent_pck;
		not_sent_pck = sock->writer->not_sent_list.begin();
		while(not_sent_pck!=sock->writer->not_sent_list.end())
		{
			int tmp_write_bytes = not_sent_pck->pck->getSize()-54;
			if(sock->writer->recv_window > tmp_write_bytes){
		// std::cout<<"[WRITE] baam1 sent_sock_addr: "<<not_sent_pck<<std::endl;
				sock->writer->ACK_yet_list.push_back(*not_sent_pck);
				sock->writer->writer_window += tmp_write_bytes;
				sock->writer->recv_window -= write_bytes;
				this->sendPacket("IPv4",not_sent_pck->pck);
				sock->writer->not_sent_list.erase(not_sent_pck);
				continue;
			}
			break;
		}

		returnSystemCall(syscallUUID, offset);
		break;
	}
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
	uint8_t tcp_header_buffer[packet->getSize() - 34];
	uint16_t checksum;
	uint32_t seq_no; // sequence number field
	uint32_t ack_no; // acknowledgment number field
	uint16_t opp_size;


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
	packet->readData(14+33+1, &opp_size, 2);

	uint8_t ACK, SYN, FIN, RST; // flag bits
	ACK = flagfield & 0b010000;
	SYN = flagfield & 0b000010;
	FIN = flagfield & 0b000001;
	RST = flagfield & 0b000100;

  /* CHECK checksum */

	// std::cout<< "[packetArrived]] : CHECK CHECKSUM"<<std::endl;
	// std::cout<< "[packetArrived]] SIZE OF PACKET"<< packet->getSize() <<std::endl;
	packet->readData(14+20, tcp_header_buffer, packet->getSize() - 34);
	packet->readData(14+ 32+1+1+2, &checksum, 2);
	tcp_header_buffer[16] = 0;
	tcp_header_buffer[17] = 0;
	uint16_t verify_chk = NetworkUtil::tcp_sum(src_ip,dest_ip,tcp_header_buffer,packet->getSize()-34);
	verify_chk = ~verify_chk;
	if(verify_chk == 0xFFFF) verify_chk = 0;
	verify_chk = htons(verify_chk);
	if (verify_chk != checksum){
		this->freePacket(packet);
		return;
	}
	// std::cout<< "verify_chk : "<< verify_chk <<std::endl;
	// std::cout<< "checksum : "<< checksum <<std::endl;
	assert(verify_chk == checksum);  //FOR DEBUG
	// IF CHECKSUM WRONG JUST DROP Packet

	src_ip = ntohl(src_ip);
	dest_ip = ntohl(dest_ip);
	src_port = ntohs(src_port);
	dest_port = ntohs(dest_port);
	seq_no = ntohl(seq_no);
	ack_no = ntohl(ack_no);
	opp_size = ntohs(opp_size);

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

			if(ack_no == sock->fin_pending_info->myy_sn + 1){
				sock->state = FIN_WAIT2;
				sock->fin_pending_info->state = FIN_WAIT2;



			}
		}

		else if(FIN && (sock->state == FIN_WAIT2 || sock->state == FIN_WAIT1 || sock->state == TIMED_WAIT)){

  		// std::cout << "[packetArrived] FIN got from server"<< std::endl;
			//  std::cout << "[packetArrived] state: "<<sock->state<< std::endl;
			if(sock->state == TIMED_WAIT) this->cancelTimer(sock->timer_key);
			Time time_wait =  TimeUtil::makeTime(60, TimeUtil::SEC);
			uint32_t ack_seq_no = sock->fin_pending_info->myy_sn + 1; // sequence number field
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

			sock->fin_pending_info->opp_sn = seq_no;

			Packet * ACK_packet = this->allocatePacket(54);
			write_packet(ACK_packet,flagfield,dest_ip,src_ip,dest_port,src_port,ack_seq_no,ack_ack_no);

			UUID timer_key = this->addTimer(sock,time_wait);
			sock->timer_key = timer_key;
			sock->state = TIMED_WAIT;
			sock->fin_pending_info->state = TIMED_WAIT;
			this->sendPacket("IPv4", ACK_packet);
		}

		else if(FIN && sock->state == ESTB){

			uint32_t ack_seq_no = sock->fin_pending_info->myy_sn; // sequence number field
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


			if(sock->reader->blocked_read_list.size() >0){
				//EOF
				std::vector<pending_read>::iterator blocked_read;
				std::vector<ack_sent_pck>::iterator waiting_pck;
				blocked_read = sock->reader->blocked_read_list.begin();
				int offset = 0;
				for (waiting_pck = sock->reader->pending_list.begin();
							waiting_pck != sock->reader->pending_list.end();
							waiting_pck ++)
				{

					std::cout<< waiting_pck->pck->getSize()-54<<std::endl;
					waiting_pck->pck->readData(54+waiting_pck->offset, blocked_read->target_buffer + offset,
																			waiting_pck->pck->getSize()-(54+waiting_pck->offset));
					offset+=(waiting_pck->pck->getSize()-(54+waiting_pck->offset));
				}
				returnSystemCall(blocked_read->syscallblock, offset);
			}





			struct TCP * new_TCP = new TCP();
			new_TCP->state = CLOSE_WAIT;
			new_TCP->opp_sn = seq_no;
			new_TCP->myy_sn = ntohl(ack_seq_no);
			new_TCP->opp_addr = (struct sockaddr *)client_addr_in;

			Packet * ACK_packet = this->allocatePacket(54);
			write_packet(ACK_packet,flagfield,dest_ip,src_ip,dest_port,src_port,ack_seq_no,ack_ack_no);
			this->sendPacket("IPv4", ACK_packet);
			sock->state = CLOSE_WAIT;
			sock->fin_pending_info = new_TCP;
		}

		else if(ACK && sock->state == LAST_ACK){
			if(ack_no == sock->fin_pending_info->myy_sn + 1){
				sock->state = CLOSED;

				this->cancelTimer(sock->timer_key);
				close_r(sock);
			}
		}

		else if(ACK && sock->state == ESTB){
			// std::cout<<"[packetArrived] DATA TRANSFER"<<std::endl;
			// std::cout<<"[packetArrived] pck size:"<<packet->getSize()<<std::endl;
			if(packet->getSize()>54){
				// ??read
									// std::cout<<"[packetArrived] DATA RECEIVED"<<std::endl;

				// 0.0 pending_list traverse and find is there duplicate packet
				// 0.1 if not push_back
				// 0.2 send ack packet for received packet
				// 1.1 reader->recv_window Update
				// 1.1 reader->arrived_seq Update
				// 2.0 if there is blocked read syscall then do read to application.
				bool duplicate = false;
				std::vector<ack_sent_pck>::iterator waiting_pck;
				for (waiting_pck= sock->reader->pending_list.begin();
						 waiting_pck!=sock->reader->pending_list.end();
					 	 waiting_pck++)
				{
					uint32_t tmp_seq_no;
					waiting_pck->pck->readData(14+24, &tmp_seq_no, 4);
					tmp_seq_no = ntohl(tmp_seq_no);
					if(tmp_seq_no == seq_no){
						duplicate = true;
						break;
					}
				}
				if(!duplicate){
					struct ack_sent_pck * waiting_pck = new ack_sent_pck();
					waiting_pck->pck = packet;
					waiting_pck->offset = 0;
					sock->reader->pending_list.push_back(*waiting_pck);
					sock->reader->recv_window -= (packet->getSize()-54);
					update_arrived_seq(sock);

					sock->debug_input+=(packet->getSize()-54);
					// std::cout<<"[packetArrived] total_size: "<<sock->debug_input<<std::endl;
						// std::cout<<"[packetArrived] arrived_seq: "<<sock->reader->arrived_seq<<std::endl;
				}
				else{
										std::cout<<"[packetArrived] duplicated!!! packet_seq: "<<seq_no<<std::endl;

				}

				Packet * ack_packet = this->allocatePacket(54);
				sock->fin_pending_info->opp_sn = seq_no;
				sock->fin_pending_info->myy_sn = ack_no;
				uint8_t flagfield = 0b010000;
				int ack_seq_no = ack_no;
				int ack_ack_no = sock->reader->arrived_seq;
				ack_seq_no = htonl(ack_seq_no);
				ack_ack_no = htonl(ack_ack_no);
				dest_ip = htonl(dest_ip);
				src_ip = htonl(src_ip);
				dest_port = htons(dest_port);
				src_port = htons(src_port);

				write_packet(ack_packet,flagfield, dest_ip, src_ip, dest_port, src_port,ack_seq_no,ack_ack_no,0,0,NULL,htons(sock->reader->recv_window));
				this->sendPacket("IPv4", ack_packet);

				std::vector<pending_read>::iterator blocked_read;
				blocked_read = sock->reader->blocked_read_list.begin();
				while (blocked_read != sock->reader->blocked_read_list.end()){
										// std::cout<<"[packetArrived] THERE WAS BLOCKED"<<std::endl;
					int offset;
					offset = read_from_pending(sock, blocked_read->target_buffer, blocked_read->read_bytes);
					if (blocked_read->read_bytes != offset) {
					// if (offset == 0) {
						if(offset == -1) returnSystemCall(blocked_read->syscallblock, offset);
						// std::cout<<"[packetArrived] he tried..but.."<<std::endl;
						// std::cout<<"[packetArrived] he tried.."<<blocked_read->read_bytes<<std::endl;
						// std::cout<<"[packetArrived] but.."<<offset<<std::endl;
						break;
					}

					returnSystemCall(blocked_read->syscallblock, offset);
					sock->reader->blocked_read_list.erase(blocked_read);
				}

				return; // for no freePacket.
			}
			// data transfer
			// 0. check recv_packet->ack_no == sent_packet->pck->seq_no + (sizeof sent_packet)-54
			// -->if yes then make "sent_packet->timer_key" stop and pop sent_pck from writer->ACK_yet_list
			// 1. do send write_packet while checking {opp_size > write_packet_size}
			// 2.
			else{
				std::vector<sent_pck>::iterator ack_yet_pck;
				for (ack_yet_pck = sock->writer->ACK_yet_list.begin();
						 ack_yet_pck != sock->writer->ACK_yet_list.end();
						 ack_yet_pck++)
				{
					// std::cout<<"[packetArrived] ack find"<<std::endl;

					uint32_t sent_pck_seq_no;
					uint32_t sent_pck_ack_no;
					uint16_t recv_window;
					ack_yet_pck->pck->readData(14+24, &sent_pck_seq_no, 4);
					ack_yet_pck->pck->readData(14+28, &sent_pck_ack_no, 4);
					ack_yet_pck->pck->readData(14+33+1, &recv_window, 2);

					sock->writer->recv_window = recv_window;

					if (sent_pck_seq_no == ack_no && sent_pck_ack_no == seq_no){
						// packet successfully received from receiver
						sock->writer->ACK_yet_list.erase(ack_yet_pck);
						break;

					}
					else{
						// ack from duplicate packet
						// PASS
						// NO PROBLEM
					}
				}

				// std::cout<<"[packetArrived] DATA TRANSFER 2"<<std::endl;

				std::vector<pending_write>::iterator blocked_write;
				for (blocked_write = sock->writer->blocked_write_list.begin();
						 blocked_write != sock->writer->blocked_write_list.end();
						 blocked_write++)
				{
							// std::cout<<"[packetArrived] DATA TRANSFER 3"<<std::endl;
					if (sock->writer->writer_window - blocked_write->write_bytes < 0){
						break;
					}

					Packet * pck = this->allocatePacket(54 + blocked_write->write_bytes);

					// struct sockaddr_in * opp_addr = get_opp_addr(fd, ((struct sockaddr_in *)sock->addr), connection_list);
					// uint32_t src_ip = ((struct sockaddr_in *)sock->addr)->sin_addr.s_addr;
					// uint16_t src_port = ((struct sockaddr_in *)sock->addr)->sin_port;
					// uint32_t dest_ip = opp_addr->sin_addr.s_addr;
					// uint16_t dest_port = opp_addr->sin_port;
					uint8_t flagfield = 0b010000;
					uint32_t seq_no = sock->fin_pending_info->myy_sn;
					uint32_t ack_no = sock->fin_pending_info->opp_sn;

					dest_ip = htonl(dest_ip);
					src_ip = htonl(src_ip);
					dest_port = htons(dest_port);
					src_port = htons(src_port);
					seq_no = htonl(seq_no);
					ack_no = htonl(ack_no);

					write_packet(pck,flagfield, dest_ip, src_ip, dest_port, src_port,seq_no,ack_no,blocked_write->write_bytes,0,blocked_write->source_buffer);

					sock->writer->writer_window -= blocked_write->write_bytes;
					struct sent_pck * ppck = new sent_pck();
					ppck->pck = pck;
					sock->writer->writer_window -= blocked_write->write_bytes;

					// std::cout<<"[packetArrived] DATA TRANSFER returnSystemCall"<<std::endl;
					returnSystemCall(blocked_write->syscallblock, blocked_write->write_bytes);

					if(sock->writer->recv_window > blocked_write->write_bytes){
						// send packet
						sock->writer->ACK_yet_list.push_back(*ppck);
						// sock->writer->not_sent_list.erase(ppck);
						sock->writer->writer_window += blocked_write->write_bytes;
						sock->writer->recv_window -= blocked_write->write_bytes;
						sock->fin_pending_info->myy_sn += blocked_write->write_bytes;
						this->sendPacket("IPv4",ppck->pck);
					}
					else{
											std::cout<<"[packetArrived] DATA TRANSFER ???"<<std::endl;
						sock->writer->not_sent_list.push_back(*ppck);
					}


				}

			}

						// std::cout<<"[packetArrived] DATA TRANSFER 3"<<std::endl;
		}


		this->freePacket(packet);

	}
	else if(is_connected == 1 && FIN){
		// std::cout <<"[packetArrived]fin got ewrwerw: "<<std::endl;
		bef_to_con(dest_ip,src_ip,dest_port,src_port);
		struct connection_TCP conn = find_connection(dest_ip,src_ip,dest_port,src_port,&connection_list);
		sock = fdToSock[*conn.pidfd];

		uint32_t ack_seq_no = sock->fin_pending_info->myy_sn; // sequence number field
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
		sock->fin_pending_info = new_TCP;
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
			sock->fin_pending_info = new_TCP;
			sock->writer->recv_window = opp_size;
			sock->reader->arrived_seq = ack_ack_no;
									// std::cout << "[packetArrived] SYNACK>> recv_window: "<<opp_size << std::endl;
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
					new_sock->writer->recv_window = opp_size;
					new_sock->reader->arrived_seq = seq_no+1;

					// std::cout << "[packetArrived] SYN>> recv_window: "<<opp_size << std::endl;

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

					new_sock->fin_pending_info = fin_pending_info;

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
				if(ack_no == check_pending->myy_sn + 1){

					/* Update Server TCP state */
					check_pending->state = ESTB;

					sock->sock_is_server->accepted_list.push_back(*check_pending);
					sock->sock_is_server->pending_list.erase(check_pending);
					sock->fin_pending_info->opp_sn = seq_no;
					sock->fin_pending_info->myy_sn = check_pending->myy_sn;

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
		uint32_t fin_syn_no = htonl(sock->fin_pending_info->myy_sn);
		uint32_t fin_ack_no = 0;
		uint8_t flagfield = 0b000001;

		Packet * FIN_packet = this->allocatePacket(54);
		write_packet(FIN_packet,flagfield,src_ip,dest_ip,src_port,dest_port,fin_syn_no,fin_ack_no);
		this->sendPacket("IPv4",FIN_packet);

		sock->fin_pending_info->myy_sn = ntohl(fin_syn_no);
		sock->fin_pending_info->state = LAST_ACK;

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


void TCPAssignment::write_packet(Packet * pck, uint8_t flagfield, uint32_t src_ip, uint32_t dest_ip,
										uint16_t src_port, uint16_t dest_port,
										uint32_t seq_no, uint32_t ack_no, int size, int offset, void * data,
										uint16_t window_size){

	uint8_t header_length = 0x50;
	uint8_t tcp_header_buffer[20+size];

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
	pck->writeData(54, data+offset, size);
	pck->readData(14+20, tcp_header_buffer,20+size);

	uint16_t checksum = NetworkUtil::tcp_sum(src_ip,dest_ip,tcp_header_buffer,20+size);
	checksum = ~checksum;
	if(checksum == 0xFFFF) checksum = 0;
	checksum = htons(checksum);
	pck->writeData(14+ 32+1+1+2, &checksum, 2);

}

void TCPAssignment::close_r(Sock * sc){
	Sock * sock = sc;
	uint32_t src_ip = ((struct sockaddr_in *)sock->addr)->sin_addr.s_addr;
	uint16_t src_port = ((struct sockaddr_in *)sock->addr)->sin_port;
	uint32_t dest_ip = ((struct sockaddr_in *)sock->fin_pending_info->opp_addr)->sin_addr.s_addr;
	uint16_t dest_port = ((struct sockaddr_in *)sock->fin_pending_info->opp_addr)->sin_port;
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

bool comp_object (const ack_sent_pck &a, const ack_sent_pck &b) {
  uint32_t a_sn, b_sn;
  a.pck->readData(14+24,&a_sn,4);
  b.pck->readData(14+24,&b_sn,4);
  a_sn = ntohl(a_sn);
  b_sn = ntohl(b_sn);
	if (a_sn > 0xf0000000 && b_sn < 0x000000f00){
		//overflow
		return true;
	}
	else if(b_sn > 0xf0000000 && a_sn < 0x00000f00){
		return false;
	}
  return a_sn < b_sn;
};

void TCPAssignment::update_arrived_seq(Sock * sock){
	std::sort(sock->reader->pending_list.begin(),sock->reader->pending_list.end(),comp_object);
	std::vector<ack_sent_pck>::iterator waiting_pck;

	// if(sock->reader->arrived_seq == 32 || sock->reader->arrived_seq == 85 ||
	// 	 sock->reader->arrived_seq == 138 || sock->reader->arrived_seq == 4294967275 ||
	// 	 sock->reader->arrived_seq == 4294967222 || sock->reader->arrived_seq == 63880){
	// 	for (waiting_pck = sock->reader->pending_list.begin();
	// 			 waiting_pck !=sock->reader->pending_list.end();
	// 		 	 waiting_pck++)
	// 	{
	//
	// 		uint32_t debug_seq_no;
	// 		waiting_pck->pck->readData(14+24,&debug_seq_no,4);
	// 		debug_seq_no = ntohl(debug_seq_no);
	// 		// std::cout<< "[debug] seq_no: "<< debug_seq_no<<std::endl;
	// 		// std::cout<< "[debug] offset: "<< waiting_pck->offset<<std::endl;
	// 		// std::cout<< "[debug] real_read: "<< sock->debug<<std::endl;
	// 		// std::cout<< "[debug] read_call: "<< sock->erase_time<<std::endl;
	// 		// std::cout<< "[debug] blocked_reads: "<< sock->reader->blocked_read_list.size()<<std::endl;
	//
	// 	}
	// }


	for (waiting_pck = sock->reader->pending_list.begin();
			 waiting_pck !=sock->reader->pending_list.end();
		 	 waiting_pck++)
	{



		uint32_t seq_no;
		waiting_pck->pck->readData(14+24,&seq_no,4);
		seq_no = ntohl(seq_no);
		// uint32_t chk1 = 0xffffffff;
		// uint32_t chk2 = 0xffffffff;
		uint32_t chk1_bool = sock->reader->arrived_seq>>(32*8-1);
		uint32_t chk2_bool = seq_no>>(32*8-1);

		// std::cout<<sock->reader->arrived_seq<<std::endl;
		// std::cout<<chk1_bool<<std::endl;
		// std::cout<<seq_no<<std::endl;
		// std::cout<<chk2_bool<<std::endl;

		if ((chk1_bool&&chk2_bool)|| !(chk1_bool||chk2_bool)){
			// no overflow
			if(sock->reader->arrived_seq < seq_no ) break;
			else if (sock->reader->arrived_seq > seq_no) continue;
			sock->reader->arrived_seq += waiting_pck->pck->getSize()-54;
		}
		else{
			//there was overflow

			if(sock->reader->arrived_seq > seq_no &&chk1_bool) break;
			else if(sock->reader->arrived_seq < seq_no &&chk2_bool) continue;
			sock->reader->arrived_seq += waiting_pck->pck->getSize()-54;
		}

	}
	// std::cout<< "[update_arrived_seq] arrived_seq: "<<sock->reader->arrived_seq<<std::endl;
}

int TCPAssignment::read_from_pending(Sock * sock, void * target_buffer, int read_bytes){

	int offset = 0;
	// update_arrived_seq(sock);
	std::vector<ack_sent_pck>::iterator waiting_pck;
	waiting_pck =sock->reader->pending_list.begin();
	if(waiting_pck!=sock->reader->pending_list.end()){
		uint32_t seq_no;
		waiting_pck->pck->readData(14+24,&seq_no,4);
		seq_no = ntohl(seq_no);
		if(sock->reader->arrived_seq - (seq_no+ waiting_pck->offset) >= read_bytes)
				// || sock->reader->arrived_seq == 61393 || sock->reader->arrived_seq == 63933)
		{


			while(waiting_pck!=sock->reader->pending_list.end()){


				if(read_bytes == 0) break; // read done.
				// std::cout<<"[read_from_pending] 54+offset: "<<54+waiting_pck->offset<<std::endl;
				// std::cout<<"[read_from_pending] pck_size: "<<(int)waiting_pck->pck->getSize()<<std::endl;


				int tmp_read_bytes = std::min((int)waiting_pck->pck->getSize()-(54+waiting_pck->offset),read_bytes);
				// if(tmp_read_bytes == 30 && sock->reader->arrived_seq == 63933) return -1;
				// std::cout<<"[read_from_pending] 1: "<<(int)waiting_pck->pck->getSize()-(54+waiting_pck->offset)<<std::endl;
				// std::cout<<"[read_from_pending] 2: "<<read_bytes<<std::endl;
				// if(sock->debug_input < 10000){

					// std::cout<<"[read_from_pending] trb: "<<tmp_read_bytes<<std::endl;
					// std::cout<<"[read_from_pending] rb: "<<read_bytes<<std::endl;
					// std::cout<<"[read_from_pending] arrived_seq: "<<sock->reader->arrived_seq<<std::endl;
					// std::cout<<"[read_from_pending] seq_no: "<<seq_no<<std::endl;
					// std::cout<<"[read_from_pending] w_pck_offset: "<<waiting_pck->offset<<std::endl;

				// }
				// std::cout<<"[read_from_pending] rb : "<<read_bytes<<std::endl;

				waiting_pck->pck->readData(54+waiting_pck->offset, target_buffer + offset, tmp_read_bytes);

				// if(tmp_read_bytes == read_bytes && tmp_read_bytes == waiting_pck->pck->getSize()-(54+waiting_pck->offset)){
				// 	this->freePacket(waiting_pck->pck);
				// 	sock->reader->pending_list.erase(waiting_pck);
				// }
				if(tmp_read_bytes == (int)waiting_pck->pck->getSize()-(54+waiting_pck->offset)){
					// data transferred to application.
					// free packet needs.
					this->freePacket(waiting_pck->pck);
					sock->reader->pending_list.erase(waiting_pck);
					// sock->erase_time += 1;
				}
				else if(tmp_read_bytes == read_bytes){
					waiting_pck->offset += read_bytes;
				}
				else {
				std::cout<<"[read_from_pending] something wrong! "<<std::endl;
					waiting_pck++;
				}
				// break;
				sock->reader->recv_window += tmp_read_bytes;
				read_bytes -= tmp_read_bytes;
				offset += tmp_read_bytes;
			}
			sock->debug += 1;
			// std::cout<<"[read_from_pending] debug: "<<sock->debug<<std::endl;
			// std::cout<<"[read_from_pending] erase: "<<sock->erase_time<<std::endl;
			// std::cout<<"[read_from_pending] pending_size: "<<sock->reader->pending_list.size()<<std::endl;
			if(sock->reader->pending_list.size()==0){
				// "backoff"
			}
		}

	}
	return offset;
}
//END DECLARATION
}

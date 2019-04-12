/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include "undecided.hpp"

#include <E/E_TimerModule.hpp>



namespace E
{



class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	//std::unordered_map<char[14], int> portAndIpTofd;

private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();

	std::unordered_map<key, sockey, keyHasher> portAndIpTofd;
	// std::unordered_map<key, int, keyHasher> listenPortAndIpTofd;
	std::unordered_map<sockey, class Sock*, sockeyHasher> fdToSock;

	std::unordered_map<uint16_t,int> allPort;

	/* Project 2-1 */
	std::vector<Sock> syn_sent_sock;
	std::vector<Sock> listening_sock;
	std::vector<connection_TCP> connection_list;
	std::vector<connection_TCP> before_connection_list;
	std::vector<UUID> accept_waiting_list;

protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
	virtual int get_connection_no(uint32_t src_ip, uint32_t dest_ip, uint16_t src_port, uint16_t dest_port) final;
	virtual struct connection_TCP find_connection(uint32_t src_ip, uint32_t dest_ip, uint16_t src_port, uint16_t dest_port, std::vector<connection_TCP> * befOrConlist) final;
	virtual bool accept_now(Sock * listen_to_accept, UUID syscallUUID) final;
	virtual void bef_to_con(uint32_t src_ip, uint32_t dest_ip, uint16_t src_port, uint16_t dest_port) final;
	virtual void delete_con(uint32_t src_ip, uint32_t dest_ip, uint16_t src_port, uint16_t dest_port) final;
	virtual struct sockaddr_in * get_opp_addr(int fd, sockaddr_in * client_addr_in, std::vector<connection_TCP> * befOrConlist) final;
	// virtual struct sockaddr_in * get_client_addr(int fd, sockaddr_in * server_addr_in, std::vector<connection_TCP> * befOrConlist) final;


	virtual void write_packet(Packet * pck, uint8_t flagfield, uint32_t src_ip, uint32_t dest_ip,
											uint16_t src_port, uint16_t dest_port,
											uint32_t seq_no, uint32_t ack_no) final;
	virtual void close_r(Sock * sc) final;

};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};




}



#endif /* E_TCPASSIGNMENT_HPP_ */

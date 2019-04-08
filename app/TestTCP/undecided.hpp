
#ifndef _SOCKET
#define _SOCKET


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
// #include "undecided.hpp"

#include <E/E_TimerModule.hpp>
// #include <tuple>

namespace E{

  struct key{
    uint16_t port;
  	uint32_t ip;

  	bool operator==(const key &other) const{
  		return (port == other.port
  		&& ip == other.ip);
  	}
  };

  struct keyHasher
  {
    std::size_t operator () (const key &key) const
    {

  		using std::size_t;
  		using std::hash;
  		// using std::string;
  		return (hash<uint16_t>()(key.port) ^ (hash<uint32_t>()(key.ip) << 1));
    }
  };

  struct sockey{
    int pid;
    int fd;

    bool operator==(const sockey &other) const{
      return (pid == other.pid
      && fd == other.fd);
    }
  };

  struct sockeyHasher
  {
    std::size_t operator () (const sockey &key) const
    {

      using std::size_t;
      using std::hash;
      // using std::string;
      return (hash<int>()(key.pid) ^ (hash<int>()(key.fd) << 1));
    }
  };

  enum State{
    CLOSED,
    SYN_SENT,
    ESTABLISHED,
    SYN_LISTEN,
    SYN_RCVD,
  };

/**********************************************************************
*                                                                     *
*                           DS FOR SERVER                             *
*                                                                     *
**********************************************************************/

  struct server_TCP {
  	enum State state;
  	struct sockaddr * client_addr; // socket address of tcp client
  	// struct sockaddr * server_addr; // socket address of tcp client
    int sockfd;
    UUID syscallblock;
  	uint32_t server_sn;
  	uint32_t client_sn;
  };

  /**********************************************************************
  *                                                                     *
  *                           DS FOR CLIENT                            *
  *                                                                     *
  **********************************************************************/

  struct client_TCP {
  	enum State state;
  	struct sockaddr* server_addr; // socket address of tcp server
  	uint32_t server_sn;
  	uint32_t client_sn;
  };


  struct connection_TCP {
     int sockfd;
     struct sockaddr_in * client_addr_in;
     struct sockaddr_in * server_addr_in;
  };

  class Sock{
  	//SystemCallParameter param;
  public:
  	int domain;
  	int type;
  	int protocol;
  	int binded; // 0 : not binded, 1 : binded
    int sockfd;
  	int pid;

  private:
  	struct sockaddr * addr;



  public:
    UUID syscallblock; // syscallUUID to return syscall when accept done
    // enum State state;
    // struct sockaddr * listen_addr;

  public:
  	Sock(int domain, int type, int protocol, int sockfd);
  	virtual ~Sock();
    virtual void set_sockaddr(struct sockaddr * sockaddr, int addrlen);
    virtual struct sockaddr * get_sockaddr(void);

    class Server_sock{

    public:
      std::vector<server_TCP> pending_list; // list of pending connections (only SYN_RCVD state is available here)
      std::vector<server_TCP> accepted_list; // list of connections to be accepted (only ESTABLISHED state is available here)
      int backlog; //
      // int pid; // pid for new socket for new client when accept done
      enum State state;
      Server_sock(Sock * sock);
      virtual ~Server_sock();
    };

    class Client_sock{

    public:
      struct client_TCP pending_info; // TCP state, server address of pending connection, client & server isn
      Client_sock(Sock * sock);
      virtual ~Client_sock();
    };

    Server_sock * sock_is_server;
    Client_sock * sock_is_client;
  };




}

#endif /* _SOCKET */

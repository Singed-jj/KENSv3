
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
    ESTB,
    SYN_LISTEN,
    SYN_RCVD,
    FIN_WAIT1,
    FIN_WAIT2,
    TIMED_WAIT,
    CLOSE_WAIT,
    LAST_ACK

  };

/**********************************************************************
*                                                                     *
*                           DS FOR SERVER                             *
*                                                                     *
**********************************************************************/

  struct server_TCP {
  	enum State state;
  	struct sockaddr * client_addr; // socket address of tcp client
  	struct sockaddr * server_addr; // socket address of tcp client
    int sockfd;
    UUID syscallblock;
  	uint32_t myy_sn;
  	uint32_t opp_sn;
  };

  /**********************************************************************
  *                                                                     *
  *                           DS FOR CLIENT                             *
  *                                                                     *
  **********************************************************************/

  struct TCP {
  	enum State state;
  	struct sockaddr* opp_addr; // socket address of tcp server
  	uint32_t myy_sn;
  	uint32_t opp_sn;
  };


  struct connection_TCP {
     int sockfd;
     struct sockey * pidfd;
     struct sockaddr_in * myy_addr_in;
     struct sockaddr_in * opp_addr_in;
  };

  /**********************************************************************
  *                                                                     *
  *                      DS FOR SYS_CALL READ/WRITE                     *
  *                                                                     *
  **********************************************************************/

  struct ack_sent_pck {
    Packet * pck;
    int offset;
  };



  struct pending_read {
    UUID syscallblock;
    void * target_buffer;
    uint16_t read_bytes;
  };
  struct sent_pck {
    Packet * pck;
    UUID timer_key;
  };

  struct pending_write {
    UUID syscallblock;
    void * source_buffer;
    uint16_t write_bytes;
  };

  struct data_reader {
    uint32_t arrived_seq; //last read pointer
    uint32_t recv_window; // receiver window(buffer) left
    std::vector<ack_sent_pck> pending_list;
    std::vector<pending_read> blocked_read_list;
  };

  struct data_writer {
    uint32_t recv_window;
    uint32_t writer_window;
    // uint32_t cur_sn;
    std::vector<sent_pck> not_sent_list; // if it get ACK from receiver, remove pcks(which is in front of that ACK pck and also itself) from sent_pck
    std::vector<sent_pck> ACK_yet_list;
    std::vector<pending_write> blocked_write_list;
  };

  class Sock{

  public:
  	int domain;
  	int type;
  	int protocol;
  	int binded; // 0 : not binded, 1 : binded
    int sockfd;
  	int pid;
  	struct sockaddr * addr;
    UUID syscallblock; // syscallUUID to return syscall when accept done
    UUID timer_key;
    enum State state;
    struct TCP * fin_pending_info;
    struct data_writer * writer;
    struct data_reader * reader;
    /**************
    * DEBUG START *
    **************/
    int debug;
    int erase_time;
    int debug_input;
    /************
    * DEBUG END *
    ************/
    class Server_sock{

    public:
      std::vector<server_TCP> pending_list; // list of pending connections (only SYN_RCVD state is available here)
      std::vector<server_TCP> accepted_list; // list of connections to be accepted (only ESTABLISHED state is available here)
      struct TCP pending_info;
      int backlog;
      enum State state;
      Server_sock(Sock * sock);
      virtual ~Server_sock();
    };

    class Client_sock{

    public:
      struct TCP pending_info; // TCP state, server address of pending connection, client & server isn
      Client_sock(Sock * sock);
      virtual ~Client_sock();
    };


  public:
  	Sock(int domain, int type, int protocol, int sockfd);
  	virtual ~Sock();
    Server_sock * sock_is_server;
    Client_sock * sock_is_client;
  };




}

#endif /* _SOCKET */

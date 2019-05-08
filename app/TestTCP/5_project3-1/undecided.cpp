#include "undecided.hpp"


namespace E{

#define WINDOW_SIZE 51200

Sock::Server_sock::Server_sock(Sock * sock){}
Sock::Client_sock::Client_sock(Sock * sock){}
Sock::Server_sock::~Server_sock(){}
Sock::Client_sock::~Client_sock(){}



Sock::Sock(int domain, int type, int protocol, int sockfd){
  this->domain = domain;
  this->type = type;
  this->protocol = protocol;
  this->binded = 0;
  this->sockfd = sockfd;
  // this->addr = (struct sockaddr *)malloc(sizeof(sockaddr));
  this->addr = new sockaddr();
  this->writer = new data_writer();
  this->reader = new data_reader();

  this->fin_pending_info = new TCP();
  this->writer->writer_window = WINDOW_SIZE;
  this->writer->recv_window = WINDOW_SIZE;
  this->reader->recv_window = WINDOW_SIZE;
  this->sock_is_server = new Server_sock(this);
  this->sock_is_client = new Client_sock(this);
  this->sock_is_client->pending_info.state = CLOSED;
  this->debug = 0;
  this->erase_time = 0;
  this->debug_input =0;
  // this->sock_is_server->pid = 0;
  // memset(this->addr, 0, sizeof(sockaddr));
}

Sock::~Sock(){
  // delete this->addr;
  // this->sip_dip.clear();
  // Server_sock::~Server_sock();
  // Client_sock::~Client_sock();
}




}

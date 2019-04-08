#include "undecided.hpp"


namespace E{


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
  this->sock_is_server = new Server_sock(this);
  this->sock_is_client = new Client_sock(this);
  this->sock_is_client->pending_info.state = CLOSED;
  // this->sock_is_server->pid = 0;
  // memset(this->addr, 0, sizeof(sockaddr));
}

Sock::~Sock(){
  // delete this->addr;
  // this->sip_dip.clear();
}

void Sock::set_sockaddr(struct sockaddr * sockaddr, int addrlen){
  memcpy(this->addr, sockaddr, addrlen);
  // this.addr = sockaddr;
}
struct sockaddr * Sock::get_sockaddr(void){
  return this->addr;
}


}

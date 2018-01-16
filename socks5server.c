/*
** ChatServer.cpp - a practise on select()
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>

#define PORT "3456"
#define STDIN 0

static void sig_child(int signo);
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }
    else
        return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

int deal_connection(int sockfd){
    printf("begin dealing a connection!!!\r\n");
    int serverfd,fd_max;
    fd_set master;
    fd_set read_fds;
    struct sockaddr_in remoteaddr;
    char buf[1024];
    char port[10];
    int nbytes;
    int i,j,rv;
    struct addrinfo hints,*res;
    int methods;
    memset(&hints,0,sizeof hints);
    hints.ai_family=AF_UNSPEC;
    hints.ai_socktype=SOCK_STREAM;
    if((rv=recv(sockfd,buf,sizeof buf,0))<0){
        fprintf(stderr,"recv error\r\n");
        close(sockfd);
        return -1;
    }
    if(rv<3){
        fprintf(stderr,"recv error\r\n");
        close(sockfd);
        return -1;
    }
    if(buf[0]!=5){
        fprintf(stderr,"socks type error!\r\n");
        close(sockfd);
        return -1;
    }
    if(buf[1]<0){
        fprintf(stderr,"selective type low\r\n");
        close(sockfd);
        return -1;
    }
    if(buf[2]>=0){
        if(send(sockfd,"\x05\x00",2,0)<0){
            perror("send error");
            close(sockfd);
            return -1;
        }
    }
    else{
        perror("message error");
        close(sockfd);
        return -1;
    }
    if((rv=recv(sockfd,buf,sizeof buf,0))<0){
        perror("recv error");
    }
   if(buf[0]!=5){
        fprintf(stderr,"socks type error!\r\n");
        close(sockfd);
        return -1;
    }
    switch(buf[1]){
        case 1:{
            if(buf[2]!=0){
                fprintf(stderr,"socket error\r\n");
                close(sockfd);
                return -1;
            }
            break;
        }
        case 2:
        case 3:
        default:{
            fprintf(stderr,"not supported yet\r\n");
            close(sockfd);
            return -1;
        }
    } 
    switch(buf[3]){
        case 1:{
            memcpy(&(remoteaddr.sin_addr.s_addr),buf+4,4);
            memcpy(&(remoteaddr.sin_port),buf+8,2);
            sprintf(port,"%d",ntohs(remoteaddr.sin_port));
            getaddrinfo(inet_ntoa(remoteaddr.sin_addr),port,&hints,&res);
            sprintf(buf,"\x05\x00\x01\x00%s%s",remoteaddr.sin_addr.s_addr,remoteaddr.sin_port);
            if(send(sockfd,buf,10,0)<0){
               perror("send address response error");
               close(sockfd);
               return;
            } 
            break;
        }
        case 3:
        case 4:
        default:{
            fprintf(stderr,"not supported yet\r\n");
            close(sockfd);
            return;
        }
    }
    serverfd=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
    if(serverfd<0){
        perror("Socket creation failed");
        close(sockfd);
        return -1;
    }
    memset(buf,0,sizeof buf);
    if(connect(serverfd,res->ai_addr,res->ai_addrlen)==-1){
        perror("connect real server error");
        close(sockfd);
        return -1;
    }
    FD_ZERO(&master);
        FD_ZERO(&read_fds);
        FD_SET(sockfd,&master);
        FD_SET(serverfd,&master);
        fd_max=serverfd>sockfd?serverfd:sockfd;
        printf("established listenning!!!\r\n");
       for(;;){
           read_fds=master;
           if(select(fd_max+1,&read_fds,NULL,NULL,NULL)==-1){
               perror("select error!!!");
               break;
            }
            if(FD_ISSET(sockfd,&read_fds)){
                if((nbytes=recv(sockfd,buf,sizeof buf,0))==-1){
                    close(sockfd);
                    close(serverfd);
                    perror("closed a transaction");
                    break;
                }
                else if(nbytes==0){
                    printf("client exited\r\n");
                    close(sockfd);
                    close(serverfd);
                    break;
                }
                else{
                    printf("%s\r\n",buf);
                    if(send(serverfd,buf,nbytes,0)==-1){
                        perror("closed transaction");
                        close(sockfd);
                        close(serverfd);
                        break;
                    }
                }
            }
            if(FD_ISSET(serverfd,&read_fds)){
                if((nbytes=recv(serverfd,buf,sizeof buf,0))==-1){
                    close(sockfd);
                    close(serverfd);
                    perror("closed transaction");
                    break;
                }
                else if(nbytes==0){
                    printf("server exited\r\n");
                    close(sockfd);
                    close(serverfd);
                    break;
                }
                else{
                    if(send(sockfd,buf,nbytes,0)==-1){
                        perror("closed transaction");
                        close(sockfd);
                        close(serverfd);
                        break;
                    }
                }
            }
       }
}

int main(void)
{
    pid_t pid;
    int listener;
    int newfd;
    struct sockaddr_storage remoteaddr;
    socklen_t addrlen;
    char buf[256];
    char mess[256];
    int nbytes;
    char remoteIP[INET6_ADDRSTRLEN];

    int yes = 1;
    int i, j, rv;
    struct addrinfo hints, *ai, *p;
    signal(SIGCHLD,sig_child);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    if ((rv = getaddrinfo(NULL, PORT, &hints, &ai)) != 0)
    {
        fprintf(stderr, "selectserver:%s\n", gai_strerror(rv));
        exit(1);
    }

    for (p = ai; p != NULL; p = p->ai_next)
    {
        listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listener < 0)
        {
            continue;
        }
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
        if (bind(listener, p->ai_addr, p->ai_addrlen) < 0)
        {
            close(listener);
            continue;
        }
        break;
    }
    if (p == NULL)
    {
        fprintf(stderr, "selectserver: failed to bind\n");
        exit(2);
    }
    freeaddrinfo(ai);
    if (listen(listener, 10) == -1)
    {
        perror("listen");
        exit(3);
    }
    for(;;){
        newfd = accept(listener, (struct sockaddr *)&remoteaddr, &addrlen);
        if (newfd == -1)
            {
                perror("accept");
                continue;
            
            }
        pid=fork();
        if(pid==0)break;

    }
    if(pid==0){
        deal_connection(newfd);
    }
     return 0;
}

static void sig_child(int signo)
{
    pid_t pid;
    int stat;
    //处理僵尸进程
    while ((pid = waitpid(-1, &stat, WNOHANG)) >0)
    printf("child %d terminated.\n", pid);
}
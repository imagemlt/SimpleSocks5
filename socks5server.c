/*
** socks5server.c - A simple socks5 server
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

#define PORT "1080"
#define STDIN 0

static void sig_child(int signo);
char username[255];
char password[255];
int encrypt;
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
    int serverfd,fd_max;
    fd_set master;
    fd_set read_fds;
    struct hostent* realip;
    struct sockaddr_in remoteaddr;
    char buf[1024];
    char port[10];
    int nbytes;
    int i,j,rv;
    struct addrinfo hints,*res,*p;
    int methods;
    printf("begin dealing a connection!!!\r\n");
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
	j=encrypt?2:0;
	for(i=0;i<buf[1];i++){
		if(buf[2+i]==j){
		break;
		}
	}
    if(i==buf[1]){
        if(send(sockfd,"\x05\xff",2,0)<0){
            perror("send error");
            close(sockfd);
            return -1;
        }
	close(sockfd);
	return -1;
    }
	if(encrypt){
		if(send(sockfd,"\x05\x02",2,0)<0){
			perror("send encrypt error");
			close(sockfd);
			return -1;
		}
		if((rv=recv(sockfd,buf,sizeof buf,0))<=0){
			perror("recv error");
			close(sockfd);
			return -1;
		}
		if(buf[0]!=1){
			printf("version error\r\n");
			printf("data recived:%d%d\r\n",buf[0],buf[1]);
			close(sockfd);
			return -1;
		}
		char* name=(char*)malloc((sizeof(char)) * (buf[1]+1));
		memset(name,0,buf[1]+1);
		strncpy(name,buf+2,buf[1]);
		char* pass=(char*)malloc((sizeof(char))* (buf[buf[1]+2]+1));
		memset(pass,0,(buf[buf[1]+2]+1));
		strncpy(pass,buf+3+buf[1],buf[buf[1]+2]);
		printf("%s,%s\r\n",name,pass);
		if(strcmp(username,name)||strcmp(password,pass)){
			printf("encrypt error\r\n");
			if(send(sockfd,"\x01\x01",2,0)<0){
				perror("send error");
				close(sockfd);
				return -1;
			}
			close(sockfd);
			return -1;
		}
		printf("encrypt success!!!\r\n");
		free(name);
		free(pass);
		if(send(sockfd,"\x01\x00",2,0)<0){
       		 	perror("send error");
        		close(sockfd);
        		return -1;
        	}

	}
	else{
	if(send(sockfd,"\x05\x00",2,0)<0){
	perror("send error");
	close(sockfd);
	return -1;
	}
	}
	
    if((rv=recv(sockfd,buf,sizeof buf,0))<=0){
        perror("recv error");
	close(sockfd);
	return -1;
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
            sprintf(buf,"\x05\x00\x00\x01%s%s",remoteaddr.sin_addr.s_addr,remoteaddr.sin_port);
            break;
        }
        case 3:{
            char* addr=(char*)malloc(sizeof(char)*(buf[4]+1));
            memset(addr,0,sizeof(char)*(buf[4]+1));
            memcpy(addr,buf+5,buf[4]);
            memcpy(&(remoteaddr.sin_port),buf+5+buf[4],2);
            sprintf(port,"%d",ntohs(remoteaddr.sin_port));
            if((rv=getaddrinfo(addr,port,&hints,&res))!=0){
                fprintf("resolve host %s error:%s\r\n",addr,gai_strerror(rv));
                send(sockfd,"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00",10,0);
	            close(sockfd);
		        return -1;
            }
            for(p=res;p!=NULL;p=p->ai_next){
                void* addr;
                char* ipver;
                if(p->ai_family==AF_INET){
                    break;
                }
            }
            if(p==NULL){
                fprintf("resolve host %s error:no usable ipv4 address\r\n",addr);
                send(sockfd,"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00",10,0);
	            close(sockfd);
		        return -1;
            }
            //memset(buf,0,sizeof buf);
            sprintf(buf,"\x05\x00\x00\x00%s%s",((struct sockaddr_in*)p)->sin_addr.s_addr,((struct sockaddr_in*)p)->sin_port);
	buf[3]=1;
            for(i=0;i<10;i++)printf("%02x  ",buf[i]);
            printf("\r\n");
            res=p;
	break;
	}
        case 4:
        default:{
            fprintf(stderr,"not supported yet\r\n");
            close(sockfd);
            return -1;
        }
    }
    serverfd=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
    if(serverfd<0){
        perror("Socket creation failed");
        if(send(sockfd,buf,10,0)<0){
               perror("send address response error");
               close(sockfd);
               return -1;
        } 
        close(sockfd);
        return -1;
    }
    if(connect(serverfd,res->ai_addr,res->ai_addrlen)==-1){
        perror("connect real server error");
         sprintf(buf,"\x05\x05\x00\x01%s%s",remoteaddr.sin_addr.s_addr,remoteaddr.sin_port);
        if(send(sockfd,buf,10,0)<0){
               perror("send address response error");
               close(sockfd);
               return -1;
        } 
        close(sockfd);
        close(sockfd);
        return -1;
    }
	printf("connect to server success!!!\r\n");

	//sprintf(buf,"\x05\x00\x00\x01%s%s",remoteaddr.sin_addr.s_addr,remoteaddr.sin_port);
    if(send(sockfd,buf,10,0)<0){
               perror("send address response error");
               close(sockfd);
               return -1;
      } 
	for(i=0;i<10;i++)printf("%02x ",buf[i]);
	printf("\r\n");
    FD_ZERO(&master);
        FD_ZERO(&read_fds);
        FD_SET(sockfd,&master);
        FD_SET(serverfd,&master);
        fd_max=serverfd>sockfd?serverfd:sockfd;
        printf("established listenning!!!\r\n");
       for(;;){
           memset(buf,0,sizeof buf);
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
                    printf("client requested:\r\n%s\r\n",buf);
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
                    printf("server responsed:\r\n%s\r\n",buf);
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

int main(int argc,char* argv[])
{
    pid_t pid;
    int listener;
    int newfd;
    struct sockaddr_storage remoteaddr;
    socklen_t addrlen;
    char buf[256];
    char mess[256];
    char port[10];
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
    memset(port,0,sizeof port);
    memset(username,0,sizeof username);
    memset(password,0,sizeof password);
    if(argc>1)strncpy(port,argv[1],sizeof port -1);
    else strncpy(port,PORT,sizeof port -1);
    if(argc>=4){
		strncpy(username,argv[2],sizeof username -1);
		strncpy(password,argv[3],sizeof password -1);
		encrypt=1;
	}
	else encrypt=0;
    if ((rv = getaddrinfo(NULL, port, &hints, &ai)) != 0)
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




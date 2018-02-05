/*
** socks5server.c - A simple socks5 server
*/
#include "socks5server.h"

#define PORT "1080"
#define STDIN 0

static void sig_child(int signo);
char username[255];
char password[255];
int encrypt;

int deal_connection(int sockfd){
    int serverfd,fd_max;
    fd_set master;
    fd_set read_fds;
    struct sockaddr_in remoteaddr;
    char buf[1024];
    char port[10];
    int nbytes;
    int i,j,rv,yes;
    METHOD_SELECT_REQUEST m_request;
    METHOD_SELECT_RESPONSE m_response;
    AUTH_REQUEST auth_request;
    AUTH_RESPONSE auth_response;
    SOCKS5_REQUEST socks5_request;
    SOCKS5_RESONSE socks5_response;
    struct addrinfo hints,*res,*p;
    yes=1;
    printf("begin dealing a connection!!!\r\n");
    memset(&hints,0,sizeof hints);
    memset(&m_request,0,sizeof m_request);
    memset(&m_response,0,sizeof m_response);
    memset(&auth_request,0,sizeof auth_request);
    memset(&auth_response,0,sizeof auth_response);
    memset(&socks5_request,0,sizeof socks5_request);
    memset(&socks5_response,0,sizeof socks5_response);
    printf("memset cleared\r\n");
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
    memcpy(&m_request,buf,sizeof m_request);
    if(m_request.VER!=5){
        fprintf(stderr,"socks type error!\r\n");
        close(sockfd);
        return -1;
    }
    if(m_request.NMETHODS<0){
        fprintf(stderr,"selective type low\r\n");
        close(sockfd);
        return -1;
    }
	j=encrypt?2:0;
	for(i=0;i<m_request.NMETHODS;i++){
		if(m_request.METHODS[i]==j){
		break;
		}
	}
    if(i==m_request.NMETHODS){
       
        m_response.VER=5;
        m_response.METHOD='\xff';
        if(send(sockfd,&m_response,2,0)<0){
            perror("send error");
            close(sockfd);
            return -1;
        }
	close(sockfd);
	return -1;
}
	if(encrypt){
        m_response.VER=5;
        m_response.METHOD=2;
		if(send(sockfd,&m_response,2,0)<0){
			perror("send encrypt error");
			close(sockfd);
			return -1;
		}
		if((rv=recv(sockfd,buf,sizeof buf,0))<=0){
			perror("recv error");
			close(sockfd);
			return -1;
        }
        memcpy(&auth_request,buf,sizeof auth_request);
		if(auth_request.VER!=1){
			printf("version error\r\n");
			printf("data recived:%d%d\r\n",buf[0],buf[1]);
			close(sockfd);
			return -1;
		}
		char* name=(char*)malloc((sizeof(char)) * (auth_request.ULEN+1));
		memset(name,0,auth_request.ULEN+1);
		strncpy(name,auth_request.UNAME,auth_request.ULEN);
		char* pass=(char*)malloc((sizeof(char))* (auth_request.UNAME[auth_request.ULEN]+1));
		memset(pass,0,(auth_request.UNAME[auth_request.ULEN]+1));
		strncpy(pass,buf+3+buf[1],auth_request.UNAME[auth_request.ULEN]);
        printf("%s,%s\r\n",name,pass);
		if(strcmp(username,name)||strcmp(password,pass)){
            printf("encrypt error\r\n");
            auth_response.VER=1;
            auth_response.STATUS=1;
			if(send(sockfd,&auth_response,2,0)<0){
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
        auth_response.VER=1;
        auth_response.STATUS=0;
		if(send(sockfd,&auth_response,2,0)<0){
       		 	perror("send error");
        		close(sockfd);
        		return -1;
        	}

	}
	else{
        m_response.VER=5;
        m_response.METHOD=0;
	if(send(sockfd,&m_response,2,0)<0){
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
    memcpy(&socks5_request,buf,sizeof socks5_request);
   if(socks5_request.VER!=5){
        fprintf(stderr,"socks type error!\r\n");
        close(sockfd);
        return -1;
    }
    switch(socks5_request.CMD){
        case 1:{
            if(socks5_request.RSV!=0){
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
    socks5_response.VER=5;
    switch(socks5_request.ATYP){
        case 1:{
            memcpy(&(remoteaddr.sin_addr.s_addr),socks5_request.DST,4);
            memcpy(&(remoteaddr.sin_port),socks5_request.DST+4,2);
            sprintf(port,"%d",ntohs(remoteaddr.sin_port));
            getaddrinfo(inet_ntoa(remoteaddr.sin_addr),port,&hints,&res);
            socks5_response.REP=0;
            socks5_response.ATYP=1;
            memcpy(socks5_response.BND,&(remoteaddr.sin_addr.s_addr),4);
            memcpy(socks5_response.BND+4,&(remoteaddr.sin_port),2);
            //sprintf(socks5_response.BND,"%s%s",remoteaddr.sin_addr.s_addr,remoteaddr.sin_port);
            break;
        }
        case 3:{
            char* addr=(char*)malloc(sizeof(char)*(socks5_request.DST[0]+1));
            memset(addr,0,sizeof(char)*(socks5_request.DST[0]+1));
            memcpy(addr,socks5_request.DST+1,socks5_request.DST[0]);
            memcpy(&(remoteaddr.sin_port),socks5_request.DST+1+socks5_request.DST[0],2);
            sprintf(port,"%d",ntohs(remoteaddr.sin_port));
            if((rv=getaddrinfo(addr,port,&hints,&res))!=0){
                fprintf("resolve host %s error:%s\r\n",addr,gai_strerror(rv));
                socks5_response.REP=4;
                socks5_response.ATYP=1;
                send(sockfd,&socks5_response,10,0);
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
                socks5_response.ATYP=1;
                socks5_response.REP=4;
                send(sockfd,&socks5_response,10,0);
	            close(sockfd);
		        return -1;
            }
            //memset(buf,0,sizeof buf);
            socks5_response.REP=0;
            socks5_response.ATYP=1;
            memcpy(socks5_response.BND,&(((struct sockaddr_in*)p)->sin_addr.s_addr),4);
            memcpy(socks5_response.BND+4,&(((struct sockaddr_in*)p)->sin_port),2);
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
        socks5_response.ATYP=1;
        socks5_response.REP=4;
        if(send(sockfd,&socks5_response,10,0)<0){
               perror("send address response error");
               close(sockfd);
               return -1;
        } 
        close(sockfd);
        return -1;
    }
     setsockopt(serverfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    if(connect(serverfd,res->ai_addr,res->ai_addrlen)==-1){
        perror("connect real server error");
        socks5_response.REP=5;
        socks5_response.ATYP=1;
         sprintf(socks5_response.BND,"%s%s",remoteaddr.sin_addr.s_addr,remoteaddr.sin_port);
        if(send(sockfd,&socks5_response,10,0)<0){
               perror("send address response error");
               close(sockfd);
               return -1;
        } 
        close(sockfd);
        close(sockfd);
        return -1;
    }
	printf("connect to server success!!!\r\n");
    if(send(sockfd,&socks5_response,10,0)<0){
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
                    perror("client closed  transaction");
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
                        perror("client closed transaction");
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
                    perror("server closed transaction");
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
                        perror("server closed transaction");
                        close(sockfd);
                        close(serverfd);
                        break;
                    }
                }
            }
       }
	//close(sockfd);
	//close(serverfd);
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
	close(newfd);

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




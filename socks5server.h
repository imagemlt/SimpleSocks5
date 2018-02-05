#ifndef SOCKS5_H
#define SOCKS5_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>


typedef struct _method_select_request
{
	char VER;
	char NMETHODS;
	char METHODS[255];
} METHOD_SELECT_REQUEST;

typedef struct _method_select_response
{
	char VER;
	char METHOD;
} METHOD_SELECT_RESPONSE;


typedef struct _auth_request
{
	char VER;
	char ULEN;
	char UNAME[255];
	char PLEN;
	char PASSWD[255];
} AUTH_REQUEST;

typedef struct _auth_response
{
	char VER;
	char STATUS;
} AUTH_RESPONSE;

typedef struct _socks5_request
{
	char VER;
	char CMD;
	char RSV;
	char ATYP;
	char DST[22];
} SOCKS5_REQUEST;

typedef struct _socks5_response
{
	char VER;
	char REP;
	char RSV;
	char ATYP;
	char BND[22];
} SOCKS5_RESONSE;

#endif

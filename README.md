# RedTeamC2

A Control and Command server that operates over the port 443 using the HTTPS protocol. The communications take place by a server on the backend using a custom dashboard to send commands to specified agents. Those commands are then handles by 1 of 10 setup relay servers, which are responsible for forwarding the commands to the desried agents. This setup guarentees security by encrypting all traffic using self-signed certificates and SHA-256 encryption (fernats library). The "c2-setup-ansible" folder contains the most up to date code along with the necessary ansible structure to deploy everything.

NOTE: code files are located in c2-setup-ansible/files

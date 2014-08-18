pam_ipset
=========

A pam module to mimic networking style dynamic ACLs on Linux using ipsets

This is useful on Bastion hosts (yes, they still exist;)). When a Bastion host has a leg on separate unroutable networks, it generally has to do NAT, preventing the downstream device from performing proper ACLing based on group memberships.
This PAM module will insert the source IP of the logged in user into an ipset, allowing iptables to allow/deny the traffic for specific groups.

This is still a PoC, and removal from the ipset is not done on logout.

To compile: cc -fPIC -DPIC -shared -rdynamic -o pam_ipset.so pam_ipset.c 

To install: cp pam_ipset.so /lib64/security

To use: create a file /etc/security/pam_ipset.conf which holds the group membership mappings to the ipset mappings

e.g.:
`#` This is a comment
`#` Put all source IPs of users in group alpha into ipset beta:
alpha beta

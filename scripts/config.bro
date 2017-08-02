module OddServices;

# Adding a standard port for a service
# Each Non_Standard_Port rule has a corresponding set of
# standard ports. If a non-standard port is common in your environment
# you can define that here.
# redef standard_ssh_ports += { 2222/tcp };

# More advanced exceptions can make use of the monitored hook.

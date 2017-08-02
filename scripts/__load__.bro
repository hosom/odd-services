@load ./main.bro
@load ./non-standard-ssh.bro
@load ./non-standard-ftp.bro

# Configuration must be performed last to ensure that redefs work properly
@load ./config.bro
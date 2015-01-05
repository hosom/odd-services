module OddServices;

export {
	
	redef enum Notice::Type += {
		Non_Standard_SSH
	};

}

const standard_ssh_ports: set[port] = { 22/tcp } &redef;

event ssh_client_version(c: connection, version: string)
	{
	if ( c$id$resp_p !in standard_ssh_ports && hook OddServices::monitored(c) )
		{
		NOTICE([$note=Non_Standard_SSH,
				$msg=fmt("%s connected to non-standard SSH server port %s on %s",
						c$id$orig_h, c$id$resp_p, c$id$resp_h),
				$src=c$id$orig_h,
				$conn=c,
				$identifier=cat(c$id$orig_h)]);
		}
	}
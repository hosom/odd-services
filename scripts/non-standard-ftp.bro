module OddServices;

export {
	
	redef enum Notice::Type += {
		## Notice identifying that FTP has occurred on a non-standard
		## TCP port. 
		Non_Standard_FTP_Port
	};

	## Standard TCP ports to consider 'default'
	const standard_ftp_ports: set[port] = { 21/tcp } &redef;
}

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
	{
	if ( c$id$resp_p !in standard_ftp_ports && hook OddServices::monitored(c) )
		{
		NOTICE([$note=Non_Standard_FTP_Port,
				$msg=fmt("%s connected to non-standard FTP server port %s on %s",
						c$id$orig_h, c$id$resp_p, c$id$resp_h),
				$src=c$id$orig_h,
				$conn=c,
				$identifier=cat(c$id$orig_h)]);
		}
	}
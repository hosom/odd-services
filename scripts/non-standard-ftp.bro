module OddServices;

export {
	
	redef enum Notice::Type += {
		Non_Standard_FTP
	};

}

const standard_ftp_ports: set[port] = { 21/tcp } &redef;

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
	{
	if ( c$id$resp_p !in standard_ftp_ports && hook OddServices::monitored(c) )
		{
		NOTICE([$note=Non_Standard_FTP,
				$msg=fmt("%s connected to non-standard FTP server port %s on %s",
						c$id$orig_h, c$id$resp_p, c$id$resp_h),
				$src=c$id$orig_h,
				$conn=c,
				$identifier=cat(c$id$orig_h)]);
		}
	}
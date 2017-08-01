module OddServices;

export {
	## Hook to allow for detailed control over notices.
	global monitored: hook(c: connection);
}
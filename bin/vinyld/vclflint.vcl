# VCL to add coverage to vclflint.sh, ideally this should use all of VRT

vcl 4.1;

backend localhost {
	.host = "localhost";
}

import debug;

sub vcl_init {
	if (false) {}
}

sub vcl_synth {
	set resp.body += "foo";
	set resp.body = :AFFE:;
	set resp.body += :COOL:;
}

sub func {
	set req.http.foo = req_top.http.foo;
	set req.http."0foo" = req0.http.foo;
}

sub vcl_recv {
	debug.call(func);
}

sub vcl_backend_refresh {
	set beresp.http.foo = obj_stale.http.foo;
}

sub vcl_hit {
	set req.http.foo = obj.http.foo;
}

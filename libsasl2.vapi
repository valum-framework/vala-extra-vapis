[CCode (cheader_filename = "sasl/sasl.h")]
namespace SASL {

	[CCode (cprefix = "SASL_")]
	public enum Result {
		CONTINUE,
		OK,
		FAIL,
		NOMEM,
		BUFOVER,
		NOMECH,
		BADPROT,
		NOTDONE,
		BADPARAM,
		TRYAGAIN,
		BADMAC,
		NOTINIT,

		INTERACT,
		BADSERV,
		WRONGMECH,

		BADAUTH,
		NOAUTHZ,
		TOOWEAK,
		ENCRYPT,
		TRANS,

		EXPIRED,
		DISABLED,
		NOUSER,
		BADVERS,
		NOVERIFY,

		PWLOCK,
		NOCHANGE,
		WEAKPASS,
		NOUSERPASS,
		NEED_OLD_PASSWD,

		CONSTRAINT_VIOLAT,

		BADBINDING,
		CONFIGERR,

		MECHNAMEMAX
	}

	[Flags]
	public enum ServerFlags {
		SUCCESS_DATA,
		NEED_PROXY,
		NEED_HTTP
	}

	[Flags]
	[CCode (cprefix = "SASL_SEC_")]
	public enum SecurityFlags {
		NOPLAINTEXT,
		NOACTIVE,
		NODICTIONARY,
		FORWARD_SECRECY,
		NOANONYMOUS,
		PASS_CREDENTIALS,
		MUTUAL_AUTH,
		MAXIMUM
	}

	public struct SecurityProperties {
		min_ssf;
		max_ssf;
		maxbufsize;
		SecurityFlags security_flags;
		[CCode (array_null = true)]
		string[] property_names;
		[CCode (array_null = true)]
		string[] property_values;
	}

	[CCode (cprefix = "SASL_CB_")]
	public enum CallbackType {
		LIST_END,
		GETOPT,
		LOG,
		GETPATH,
		VERIFYFILE,
		GETCONFPATH,
		USER,
		AUTHNAME,
		LANGUAGE,
		CNONCE,
		PASS,
		ECHOPROMPT,
		NOECHOPROMPT,
		GETREALM,
		PROXY_POLICY,
		SERVER_USERDB_CHECKPASS,
		SERVER_USERDB_SETPASS,
		CANON_USER
	}

	[CCode (cname = "sasl_callback_t")]
	public delegate Callback (SASL.CallbackType id, void* proc);

	public delegate SASL.Result GetOptCallback (string plugin_name, string option, out string result);

	public enum LogLevel {
		NONE,
		ERR,
		FAIL,
		WARN,
		NOTE,
		DEBUG,
		TRACE,
		PASS
	}

	public delegate SASL.Result LogCallback (SASL.LogLevel, string message);

	public delegate SASL.Result GetPathCallback (out string path);

	[CCode (cprefix = "SASL_VRFY_")]
	public enum VerifyType {
		PLUGIN,
		CONF,
		PASSWD,
		OTHER
	}

	public delegate SASL.Result VerifyFileCallback (string file, VerifyType type);

	public delegate SASL.Result GetConfPathCallback (out string path);

	public delegate SASL.Result GetSimpleCallback (SASL.CallbackType id, out string result);

	public delegate SASL.Result GetSecretCallback (SASL.CallbackType id, out SASL.Secret);

	public delegate SASL.Result ChalPrompt (SASL.CallbackType id, string challenge, string prompt, string defresult, out string result);

	public delegate SASL.Result GetRealm (SASL.CallbackType id, [CCode (array_null = true)]string[] availrealms, out string result);

	public delegate SASL.Result AuthorizeCallback ();
	public delegate SASL.Result ServerUserDBCheckPass
	public delegate SASL.Result ServerUserDBSetPass
	public delegate SASL.Result CanonUserCallback ();

	public int set_path (int path_type, string path);

	[Deprecated (replacement = "version_info")]
	public void version ()
	public void version_info ()
	public void done ();
	public void server_done ();
	public void client_done ();

	[Compact]
	[CCode (cname = "", has_type_id = false)]
	public class Connection {
		public void dispose () ;
		public string errdetail ();
		public void set_error ();
		public SASL.Result getprop ();
		public SASL.Result auxprop_store ();
		public SASL.Result encode ();
		public SASL.Result encodev ();
		public SASL.Result decode ();
	}
}

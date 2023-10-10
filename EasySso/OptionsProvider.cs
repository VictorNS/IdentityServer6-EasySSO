using Duende.IdentityServer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using System.Text;

namespace IdentityServerHost.EasySso;

public class OptionsProvider : IOptionsMonitor<Options>
{
	const string STATE_COOKIE_NAME = "EasySSOState";
	const string DEFAULT_INSTANCE_NAME = "EasySSO";
	object SyncRoot { get; set; } = new object();
	readonly IServerConfiguration _env;
	readonly IDataProtectionProvider _dp;

	public OptionsProvider(IServerConfiguration env, IDataProtectionProvider dp)
	{
		_env = env;
		_dp = dp;
	}

	private Options option = null;
	public Options CurrentValue
	{
		get
		{
			if (option == null)
			{
				lock (SyncRoot)
				{
					option = new Options
					{
						DataProtectionProvider = _dp,
						SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme,
						CallbackPath = new PathString(Constants.ExternalCallbackUrl),
						StateCookie = new CookieBuilder()
						{
							Name = STATE_COOKIE_NAME,
							SecurePolicy = CookieSecurePolicy.SameAsRequest,
							SameSite = SameSiteMode.Lax,
							IsEssential = true
						}
					};

					var stateDataProtector = option.DataProtectionProvider.CreateProtector(
						typeof(Handler).FullName,
						DEFAULT_INSTANCE_NAME);
					option.StateDataFormat = new SecureDataFormat<AuthenticationProperties>(new PropertiesSerializer(), stateDataProtector);

					var stringDataProtector = option.DataProtectionProvider.CreateProtector(
						typeof(Handler).FullName!,
						typeof(string).FullName!,
						DEFAULT_INSTANCE_NAME);
					option.StringDataFormat = new SecureDataFormat<string>(new RemoteAuthenticationOptionsStringSerializer(), stringDataProtector);

					var handler = _env.IsLocalEnvironment
						? new HttpClientHandler()
						{
							ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => true
						}
						: option.BackchannelHttpHandler ?? new HttpClientHandler();

					option.Backchannel = new HttpClient(handler)
					{
						Timeout = option.BackchannelTimeout,
						MaxResponseContentBufferSize = 1024 * 1024 * 10 // 10 MB,
					};
				}
			}

			return option;
		}
	}

	public Options Get(string name)
	{
		return CurrentValue;
	}

	public IDisposable OnChange(Action<Options, string> listener)
	{
		return null;
	}

	private sealed class RemoteAuthenticationOptionsStringSerializer : IDataSerializer<string>
	{
		public string Deserialize(byte[] data)
		{
			return Encoding.UTF8.GetString(data);
		}

		public byte[] Serialize(string model)
		{
			return Encoding.UTF8.GetBytes(model);
		}
	}
}

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace IdentityServerHost.EasySso;

public static class AuthenticationBuilderExtension
{
	internal static AuthenticationBuilder AddEasySSO(this AuthenticationBuilder builder)
	{
		builder.Services.AddSingleton(new IServerConfiguration { IsLocalEnvironment = true }); // for testing on localhost
		builder.Services.AddSingleton(new IProviderConfigurationService());
		builder.Services.AddSingleton<IOptionsMonitor<Options>, OptionsProvider>();
		return builder.AddRemoteScheme<Options, Handler>(Constants.Scheme, Constants.Scheme, null);
	}
}

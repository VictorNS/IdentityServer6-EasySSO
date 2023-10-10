namespace IdentityServerHost.EasySso;

/// <summary>
/// It should be your storage with an interface and other modern features.
/// </summary>
public class IProviderConfigurationService
{
	/// <summary>
	/// No parameters, but it can be returnURL or any other your specific variables.
	/// Or maybe you just want to read some settings file.
	/// </summary>
	/// <returns></returns>
	public ProviderConfiguration GetEasySsoProviderConfiguration()
	{
		// hardcoded example for standard local EasySSO configuration
		return new ProviderConfiguration
		{
			Authority = "http://localhost/EasyConnect/REST",
			ClientId = "IdentityServer6-EasySSO",
			IdentityProvider = "RESTIdentityProvider",
			UserName = "sp-app",
			Password = "password",
			SupportEmail = "support@support.com"
		};
	}
}

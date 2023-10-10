namespace IdentityServerHost.EasySso;

public class ProviderConfiguration
{
	public string Authority { get; set; }
	public string ClientId { get; set; }
	public string IdentityProvider { get; set; }
	public string UserName { get; set; }
	public string Password { get; set; }
	/// <summary>
	/// It's just an example how you can store extra parameters specific for the provider.
	/// </summary>
	public string SupportEmail { get; set; }
}

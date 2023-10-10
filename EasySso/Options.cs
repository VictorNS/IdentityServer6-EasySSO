using Microsoft.AspNetCore.Authentication;

namespace IdentityServerHost.EasySso;

public class Options : RemoteAuthenticationOptions
{
	/// <summary>
	/// Gets or sets the type used to secure data handled by the handler.
	/// </summary>
	public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; } = default!;
	/// <summary>
	/// Gets or sets the type used to secure strings used by the handler.
	/// </summary>
	public ISecureDataFormat<string> StringDataFormat { get; set; } = default!;
	/// <summary>
	/// Determines the settings used to create the nonce cookie before the
	/// cookie gets added to the response.
	/// </summary>
	public CookieBuilder StateCookie { get; set; }
}

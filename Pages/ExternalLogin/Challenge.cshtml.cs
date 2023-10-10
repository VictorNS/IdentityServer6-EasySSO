using Duende.IdentityServer.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace IdentityServerHost.Pages.ExternalLogin;

[AllowAnonymous]
[SecurityHeaders]
public class Challenge : PageModel
{
    private readonly IIdentityServerInteractionService _interactionService;
    private readonly EasySso.IProviderConfigurationService _easySsoProviderConfigurationService;

	public Challenge(IIdentityServerInteractionService interactionService, EasySso.IProviderConfigurationService easySsoProviderConfigurationService)
	{
		_interactionService = interactionService;
		_easySsoProviderConfigurationService = easySsoProviderConfigurationService;
	}

	public IActionResult OnGet(string scheme, string returnUrl)
    {
        if (string.IsNullOrEmpty(returnUrl)) returnUrl = "~/";

        // validate returnUrl - either it is a valid OIDC URL or back to a local page
        if (Url.IsLocalUrl(returnUrl) == false && _interactionService.IsValidReturnUrl(returnUrl) == false)
        {
            // user might have clicked on a malicious link - should be logged
            throw new Exception("invalid return URL");
        }

		AuthenticationProperties props;


		if (scheme == EasySso.Constants.Scheme)
		{
			var providerConfiguration = _easySsoProviderConfigurationService.GetEasySsoProviderConfiguration();

			props = new AuthenticationProperties
			{
				RedirectUri = Url.Page("/externallogin/callback"),
				Items =
				{
					{ "returnUrl", returnUrl },
					{ "Authority", providerConfiguration.Authority },
					{ "IdentityProvider", providerConfiguration.IdentityProvider },
					{ "ClientId", providerConfiguration.ClientId },
					{ "UserName", providerConfiguration.UserName },
					{ "Password", providerConfiguration.Password },
					{ "SupportEmail", providerConfiguration.SupportEmail }
				}
			};

		}
		else
		{
			props = new AuthenticationProperties
			{
				RedirectUri = Url.Page("/externallogin/callback"),
				Items =
				{
					{ "returnUrl", returnUrl },
					{ "scheme", scheme },
				}
			};
		}

		// start challenge and roundtrip the return URL and scheme 
		return Challenge(props, scheme);
    }
}
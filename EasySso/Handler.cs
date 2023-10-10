using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using System.Web;

namespace IdentityServerHost.EasySso;

public class Handler : RemoteAuthenticationHandler<Options>
{
	#region const
	const string KEY_APPLICATION_NAME = "#ApplicationName";
	const string KEY_PARTNER_PROVIDER_NAME = "#PartnerProviderName";
	const string KEY_PARTNER_PROVIDER_TYPE = "#PartnerProviderType";
	const string KEY_TARGET_URL = "#TargetUrl";
	const string KEY_USER_NAME = "#UserName";
	const string KEY_ID = "#ID";
	const string KEY_ERROR_MESSAGE = "#ErrorMessage";
	const string KEY_EMAIL_ADDRESS = "EmailAddress";
	const string PARTNER_PROVIDER_TYPE = "IdentityProvider";
	const string URL_SSO_REQUEST = "SSORequest/Default.aspx";
	const string URL_ATTRIBUTES = "AttributeQuery/Default.aspx";
	const string URL_INTEGRATION_TOKEN = "IntegrationToken/Default.aspx?ID=";
	#endregion const

	ProviderConfiguration _providerConfiguration;

	public Handler(IOptionsMonitor<Options> options, ILoggerFactory loggerFactory, UrlEncoder encoder, ISystemClock clock)
		: base(options, loggerFactory, encoder, clock) { }

	protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
	{
		try
		{
			var id = Request.Query["Id"];

			if (string.IsNullOrWhiteSpace(id))
			{
				await LogIncomingRequest("Request.Query[Id] (Session ID) is empty");
				throw new Exception("Request.Query[Id] (Session ID) is empty");
			}

			Logger.LogInformation("Request.Query[Id] (Session ID): {Id}", id);

			var protectedAuthenticationProperties = Request.Cookies[Options.StateCookie.Name];
			var properties = Options.StateDataFormat.Unprotect(protectedAuthenticationProperties);
			var cookieOptions = Options.StateCookie.Build(Context, Clock.UtcNow);
			Response.Cookies.Delete(Options.StateCookie.Name, cookieOptions);

			if (properties is null || !BuildEasySsoProviderConfiguration(properties))
				throw new Exception("AuthenticationProperties is missed in cookies");

			var userNameResult = await GetUserName(id);
			if (!userNameResult.IsSuccess)
			{
				return HandleRequestResult.Fail(userNameResult.Error);
			}

			var userName = userNameResult.Result;
			var identity = new ClaimsIdentity(new[]
			{
				new Claim(ClaimTypes.NameIdentifier, userName, ClaimsIssuer),
			}, ClaimsIssuer);

			if (IsValidEmail(userName))
			{
				identity.AddClaim(new Claim(ClaimTypes.Email, userName, ClaimsIssuer));
			}
			else
			{
				var userEmailResult = await GetUserEmail(userName);
				if (userEmailResult.IsSuccess && IsValidEmail(userEmailResult.Result))
				{
					identity.AddClaim(new Claim(ClaimTypes.Email, userEmailResult.Result, ClaimsIssuer));
				}
			}

			var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), properties, Scheme.Name);

			return HandleRequestResult.Success(ticket);
		}
		catch (Exception ex)
		{
			Logger.LogError(ex, "EasySSO HandleRemoteAuthenticateAsync");
			return HandleRequestResult.Fail(ex.Message);
		}
	}

	protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
	{
		try
		{
			if (string.IsNullOrEmpty(properties.RedirectUri))
				throw new Exception("RedirectUri is expected");

			if (!BuildEasySsoProviderConfiguration(properties))
				throw new Exception("Invalid EasySSO provider configuration");

			var idResult = await GetLoginSessionID();
			if (!idResult.IsSuccess)
				throw new Exception(idResult.Error);

			var cookieOptions = Options.StateCookie.Build(Context, Clock.UtcNow);
			Response.Cookies.Append(Options.StateCookie.Name, Options.StateDataFormat.Protect(properties), cookieOptions);

			Context.Response.Redirect(GetSsoLoginUrl(_providerConfiguration.Authority, idResult.Result));
		}
		catch (Exception ex)
		{
			Logger.LogError(ex, "EasySSO HandleChallengeAsync");
			throw;
		}
	}

	#region private methods

	async Task<DataRequestResult> GetUserName(string integrationToken)
	{
		var message = BuildMessage(HttpMethod.Get, GetIntegrationTokenUrl(integrationToken));
		var result = await SendRequest(message);

		if (result.IsSuccess)
		{
			if (result.TryGetValue(KEY_USER_NAME, out var value))
			{
				return DataRequestResult.Success(value);
			}

			Logger.LogError(@"EasySSO IntegrationToken response does not contain UserName
Result:
{Result}", result.Result);
			return DataRequestResult.Fail("EasySSO IntegrationToken response does not contain UserName");
		}

		return DataRequestResult.Fail("EasySSO IntegrationToken response error");
	}

	async Task<DataRequestResult> GetLoginSessionID()
	{
		var requestContent = new Dictionary<string, string>
		{
			{ KEY_APPLICATION_NAME, _providerConfiguration.ClientId },
			{ KEY_PARTNER_PROVIDER_NAME, _providerConfiguration.IdentityProvider },
			{ KEY_PARTNER_PROVIDER_TYPE, PARTNER_PROVIDER_TYPE },
			{ KEY_TARGET_URL, BuildRedirectUri(Options.CallbackPath) },
		};

		var message = BuildMessage(HttpMethod.Post, URL_SSO_REQUEST, requestContent);
		var result = await SendRequest(message);

		if (result.IsSuccess)
		{
			if (result.TryGetValue(KEY_ID, out var value))
			{
				return DataRequestResult.Success(value);
			}

			Logger.LogError(@"EasySSO SSORequest response does not contain ID
Result:
{Result}", result.Result);
			return DataRequestResult.Fail("EasySSO SSORequest response does not contain ID");
		}

		return DataRequestResult.Fail("EasySSO SSORequest response error");
	}

	async Task<DataRequestResult> GetUserEmail(string userName)
	{
		var requestContent = new Dictionary<string, string>
		{
			{ KEY_APPLICATION_NAME, _providerConfiguration.ClientId },
			{ KEY_PARTNER_PROVIDER_NAME, _providerConfiguration.IdentityProvider },
			{ KEY_PARTNER_PROVIDER_TYPE, PARTNER_PROVIDER_TYPE },
			{ KEY_USER_NAME, userName },
			{ KEY_EMAIL_ADDRESS, "" },
		};

		var message = BuildMessage(HttpMethod.Post, URL_ATTRIBUTES, requestContent);
		var result = await SendRequest(message);

		if (result.IsSuccess)
		{
			if (result.TryGetValue(KEY_EMAIL_ADDRESS, out var value))
			{
				return DataRequestResult.Success(value);
			}

			Logger.LogError(@"EasySSO AttributeQuery response does not contain ID
Result:
{Result}", result.Result);
			return DataRequestResult.Fail("EasySSO AttributeQuery response does not contain ID");
		}

		return DataRequestResult.Fail("EasySSO AttributeQuery response error");
	}

	static string GetIntegrationTokenUrl(string id) => URL_INTEGRATION_TOKEN + id;

	static string GetSsoLoginUrl(string authorityUrl, string id) => $"{authorityUrl}/?ID={id}";

	HttpRequestMessage BuildMessage(HttpMethod method, string url, Dictionary<string, string> requestContent = null)
	{
		var uri = new Uri($"{_providerConfiguration.Authority}/{url}");
		var content = requestContent is null
			? null
			: new StringContent(DictionaryToEasySsoFormat(requestContent), Encoding.UTF8, "text/plain");
		var authorizationHeader = string.Format(
			"Basic {0}",
			Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Format("{0}:{1}", _providerConfiguration.UserName, _providerConfiguration.Password))));

		return new HttpRequestMessage()
		{
			Method = method,
			RequestUri = uri,
			Content = content,
			Headers = { { "Authorization", authorizationHeader } }
		};
	}

	async Task<HttpRequestResult> SendRequest(HttpRequestMessage message)
	{
		var response = await Options.Backchannel.SendAsync(message, Context.RequestAborted);

		if (!response.IsSuccessStatusCode)
		{
			string contentWithError;

			try
			{
				contentWithError = await response.Content.ReadAsStringAsync();
			}
			catch
			{
				try
				{
					contentWithError = response.ToString();
				}
				catch
				{
					contentWithError = string.Empty;
				}
			}

			Logger.LogError(@"Sending request to EasySSO Server
Message:
{Message}
Content:
{Content}
Response:
{Response}", message, await GetHttpMessageContent(message), contentWithError);
			return HttpRequestResult.Fail();
		}

		var content = await response.Content.ReadAsStringAsync();
		Logger.LogInformation(@"Sending request to EasySSO Server
Message:
{Message}
Content:
{Content}
Response:
{Response}", message, await GetHttpMessageContent(message), content);

		var result = EasySsoFormatToDictionary(content);

		if (TryGetEasySsoError(result, out var error))
		{
			Logger.LogError(@"Sending request to EasySSO Server
Message:
{Message}
Content:
{Content}
Error:
{Error}", message, await GetHttpMessageContent(message), error);
			return HttpRequestResult.Fail();
		}

		return HttpRequestResult.Success(result);
	}

	bool BuildEasySsoProviderConfiguration(AuthenticationProperties properties)
	{
		_providerConfiguration = new ProviderConfiguration();

		bool trySet(string propName, Action<string> setProp)
		{
			if (!properties.Items.TryGetValue(propName, out string value))
				return false;

			setProp(value);
			return true;
		}

		if (!trySet("Authority", v => _providerConfiguration.Authority = v))
			return false;
		if (!trySet("IdentityProvider", v => _providerConfiguration.IdentityProvider = v))
			return false;
		if (!trySet("ClientId", v => _providerConfiguration.ClientId = v))
			return false;
		if (!trySet("UserName", v => _providerConfiguration.UserName = v))
			return false;
		if (!trySet("Password", v => _providerConfiguration.Password = v))
			return false;
		if (!trySet("SupportEmail", v => _providerConfiguration.SupportEmail = v))
			return false;

		return true;
	}

	async Task LogIncomingRequest(string requestName)
	{
		string requestUrl;
		try
		{
			requestUrl = Request.Scheme + Uri.SchemeDelimiter + Request.Host.Host + Request.PathBase + Request.Path + Request.QueryString;
		}
		catch (Exception ex)
		{
			Logger.LogError(ex, "Get URL error");
			requestUrl = "Error, see log";
		}

		string requestBody;
		try
		{
			using var reader = new StreamReader(Request.Body, Encoding.UTF8);
			requestBody = await reader.ReadToEndAsync();
		}
		catch (Exception ex)
		{
			Logger.LogError(ex, "Get body error");
			requestBody = "Error, see log";
		}

		string requestHeaders;
		try
		{
			requestHeaders = string.Join(",", Request.Headers.Select(x => "{" + x.Key + "=" + string.Join(",", x.Value.Select(v => v ?? "<null>")) + "}"));
		}
		catch (Exception ex)
		{
			Logger.LogError(ex, "Get headers error");
			requestHeaders = "Error, see log";
		}

		Logger.LogError(@"{requestName}
requestUrl:
{requestUrl}

requestBody:
{requestBody}

requestHeaders:
{requestHeaders}", requestName, requestUrl, requestBody, requestHeaders);
	}

	static bool IsValidEmail(string userEmail)
	{
		if (string.IsNullOrWhiteSpace(userEmail))
			return false;

		return Regex.IsMatch(userEmail, "^[^@]+@{1}[^@\\.]+\\.[^@\\.]+[^@]*$");
	}

	static string DictionaryToEasySsoFormat(Dictionary<string, string> requestContent)
	{
		var content = requestContent.ToDictionary(x => x.Key, x => new List<string> { x.Value });
		var stringBuilder = new StringBuilder();

		foreach (string key in content.Keys)
		{
			foreach (string value in content[key])
			{
				if (stringBuilder.Length > 0)
				{
					stringBuilder.Append("\r\n");
				}

				stringBuilder.AppendFormat("{0}={1}", key, value);
			}
		}

		return HttpUtility.HtmlEncode(stringBuilder.ToString());
	}

	static Dictionary<string, IList<string>> EasySsoFormatToDictionary(string message)
	{
		message = HttpUtility.HtmlDecode(message);

		var content = new Dictionary<string, IList<string>>();

		foreach (string line in message.Split('\n'))
		{
			int index = line.IndexOf('=');

			if (index < 0)
			{
				continue;
			}

			string key = line[..index].Trim();

			if (string.IsNullOrEmpty(key))
			{
				continue;
			}

			string value = null;

			if (index + 1 < line.Length)
			{
				value = line[(index + 1)..].Trim();
			}

			if (!content.ContainsKey(key))
			{
				content[key] = new List<string>();
			}

			content[key].Add(value);
		}

		return content;
	}

	static bool TryGetEasySsoError(IDictionary<string, IList<string>> keys, out string error)
	{
		if (keys.TryGetValue(KEY_ERROR_MESSAGE, out var errors))
		{
			error = errors[0];
			return true;
		}

		error = string.Empty;
		return false;
	}

	static async Task<string> GetHttpMessageContent(HttpRequestMessage message)
	{
		if (message.Content is StringContent c)
		{
			return await c.ReadAsStringAsync();
		}
		return "NULL";
	}

	#endregion private methods

	#region private classes
	private class HttpRequestResult
	{
		public Dictionary<string, IList<string>> Result { get; private set; }
		public bool IsSuccess { get; private set; }

		public static HttpRequestResult Fail()
		{
			return new HttpRequestResult();
		}

		public static HttpRequestResult Success(Dictionary<string, IList<string>> result)
		{
			return new HttpRequestResult(result);
		}

		private HttpRequestResult()
		{
			Result = new();
			IsSuccess = false;
		}

		private HttpRequestResult(Dictionary<string, IList<string>> result)
		{
			Result = result;
			IsSuccess = true;
		}

		public bool TryGetValue(string key, out string value)
		{
			if (Result.TryGetValue(key, out var values))
			{
				if (values.Count > 0)
				{
					value = values[0];
					return true;
				}
			}

			value = string.Empty;
			return false;
		}
	}

	private class DataRequestResult
	{
		public string Error { get; private set; }
		public bool IsSuccess { get; private set; }
		public string Result { get; private set; }

		public static DataRequestResult Fail(string error)
		{
			return new DataRequestResult(error, false);
		}

		public static DataRequestResult Success(string result)
		{
			return new DataRequestResult(result);
		}

		private DataRequestResult(string result)
		{
			IsSuccess = true;
			Result = result;
		}

		private DataRequestResult(string error, bool isSuccess)
		{
			Error = error;
			IsSuccess = isSuccess;
		}
	}
	#endregion private classes
}

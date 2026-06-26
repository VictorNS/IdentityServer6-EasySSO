# IdentityServer6-EasySSO

IdentityServer6-EasySSO is a .NET 6 sample host that combines Duende IdentityServer, ASP.NET Core Identity, SQL Server persistence, and a custom EasySSO external authentication handler. It is intended as a practical starting point for experimenting with OpenID Connect/OAuth 2.0 flows and integrating an EasySSO provider into an IdentityServer login experience.

The project is based on the Duende IdentityServer ASP.NET Identity host style and adds an `EasySSO` remote authentication scheme alongside OpenID Connect providers such as Google, Azure AD, and the Duende demo IdentityServer.

## Features

- Duende IdentityServer 6.1 configured for OpenID Connect and OAuth 2.0.
- ASP.NET Core Identity user store backed by Entity Framework Core and SQL Server.
- Razor Pages UI for login, logout, consent, device authorization, CIBA consent, diagnostics, grants, and redirects.
- In-memory IdentityServer clients, identity resources, API resources, and API scopes for demos and local development.
- Custom `EasySSO` remote authentication handler with server-side state protection.
- External login flow that creates or links local ASP.NET Identity users from external provider claims.
- Serilog console logging with detailed request logging during development.
- Automatic EF Core migration execution at application startup.

## Technology Stack

- .NET 6 / ASP.NET Core 6
- Duende IdentityServer 6.1.2
- ASP.NET Core Identity
- Entity Framework Core 6 with SQL Server
- Razor Pages
- Serilog
- Bootstrap and jQuery assets under `wwwroot`

## Project Structure

```text
.
├── Configuration/              # In-memory IdentityServer clients, resources, and scopes
├── Data/                       # ASP.NET Identity DbContext and EF Core migrations
├── EasySso/                    # Custom EasySSO authentication scheme implementation
├── Models/                     # ApplicationUser model
├── Pages/                      # Razor Pages UI for IdentityServer interactions
├── Properties/launchSettings.json
├── appsettings.json            # SQL Server connection string
├── HostingExtensions.cs        # Service registration, pipeline, database migration
├── IdentityServerExtensions.cs # IdentityServer registration
└── Program.cs                  # Application entry point
```

## Prerequisites

- [.NET 6 SDK](https://dotnet.microsoft.com/download/dotnet/6.0)
- SQL Server, SQL Server Express, or LocalDB-compatible SQL Server instance
- A Duende IdentityServer license if your usage requires one. Duende IdentityServer is a commercial product; review Duende's licensing terms for your scenario.
- Optional: an EasySSO server or local EasyConnect REST endpoint if you want to exercise the custom EasySSO provider.

## Quick Start

1. Clone the repository.

	```bash
	git clone https://github.com/<your-org>/IdentityServer6-EasySSO.git
	cd IdentityServer6-EasySSO
	```

2. Restore packages.

	```bash
	dotnet restore IdentityServer6-EasySSO.sln
	```

3. Configure the database connection string in `appsettings.json`.

	The default value is:

	```json
	{
	  "ConnectionStrings": {
		 "DefaultConnection": "Server=(local);Database=IdentityServer6-EasySSO;Trusted_Connection=True;MultipleActiveResultSets=true;Encrypt=false"
	  }
	}
	```

	Change `Server=(local)` if your SQL Server instance uses another name, for example `(localdb)\\MSSQLLocalDB`, `.\\SQLEXPRESS`, or a remote SQL Server host.

4. Run the application.

	```bash
	dotnet run --project Host.AspNetIdentity.csproj
	```

5. Open the host.

	```text
	https://localhost:5001/Account/Login
	```

	The default launch profile starts the app on `https://localhost:5001` and opens the login page.

On startup, the app calls `Database.Migrate()`, so the included EF Core migrations are applied automatically to the configured SQL Server database.

## IdentityServer Configuration

IdentityServer is configured in `IdentityServerExtensions.cs` with in-memory resources and clients:

- `Configuration/Resources.cs` defines standard identity resources, a custom `custom.profile` identity resource, API scopes, and API resources.
- `Configuration/Clients.cs` combines console/native clients and web clients.
- `Configuration/ClientsConsole.cs` contains sample clients for client credentials, reference tokens, resource owner password, PKCE, device flow, CIBA, mTLS, JWT assertions, and resource indicators.
- `Configuration/ClientsWeb.cs` contains JavaScript and MVC sample clients using authorization code or hybrid flows.

Useful development endpoints include:

```text
https://localhost:5001/.well-known/openid-configuration
https://localhost:5001/connect/token
https://localhost:5001/connect/authorize
https://localhost:5001/connect/userinfo
```

Example client credentials token request:

```bash
curl -k -X POST https://localhost:5001/connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=client" \
  -d "client_secret=secret" \
  -d "grant_type=client_credentials" \
  -d "scope=resource1.scope1"
```

## EasySSO Integration

The custom EasySSO integration lives in the `EasySso` folder and is registered from `HostingExtensions.cs` via:

```csharp
builder.Services.AddAuthentication()
	 // other providers
	 .AddEasySSO();
```

The scheme name is `EasySSO`, and the callback path is:

```text
/signin-easysso
```

The flow works as follows:

1. A user selects the EasySSO external provider from the login UI.
2. `Pages/ExternalLogin/Challenge.cshtml.cs` loads the EasySSO provider settings.
3. The handler calls EasySSO `SSORequest/Default.aspx` to create a login session.
4. The user is redirected to the EasySSO login URL with the returned session ID.
5. EasySSO redirects back to `/signin-easysso?Id=<integration-token>`.
6. The handler calls `IntegrationToken/Default.aspx` and, when needed, `AttributeQuery/Default.aspx` to resolve user information.
7. The external login callback creates or links an ASP.NET Identity user and signs the user in locally.

The sample provider settings are currently hardcoded in `EasySso/IProviderConfigurationService.cs`:

```csharp
return new ProviderConfiguration
{
	 Authority = "http://localhost/EasyConnect/REST",
	 ClientId = "IdentityServer6-EasySSO",
	 IdentityProvider = "RESTIdentityProvider",
	 UserName = "sp-app",
	 Password = "password",
	 SupportEmail = "support@support.com"
};
```

For a real deployment, replace this sample class with configuration-backed or database-backed storage, protect credentials with your platform's secret management tooling, and disable local certificate validation behavior.

## External Identity Providers

The host registers these external providers in `HostingExtensions.cs`:

- Google OpenID Connect
- Duende demo IdentityServer
- Azure AD
- EasySSO

The Google and Azure AD client IDs in this sample are development/demo values. Replace them with your own registered applications before using this host outside local testing.

## Database and Migrations

The app uses `ApplicationDbContext`, which inherits from `IdentityDbContext<ApplicationUser>`. Existing migrations are stored under `Data/Migrations`.

Common EF Core commands:

```bash
dotnet ef migrations add <MigrationName>
dotnet ef database update
```

Because the application runs migrations at startup, `dotnet ef database update` is optional for normal local development if the configured database is reachable by the app.

## Development Notes

- The app uses `UseDeveloperExceptionPage()` and verbose Serilog logging, so it is currently configured for development scenarios.
- Razor runtime compilation is enabled to make page changes visible during development.
- IdentityServer clients and resources are stored in memory. Move them to configuration or a database for dynamic administration.
- The custom EasySSO options provider accepts self-signed certificates when `IsLocalEnvironment` is `true`.
- The sample contains demo secrets such as `secret` and `password`; replace all sample credentials before real use.

## Production Checklist

Before adapting this project for production, review at least the following items:

- Configure a valid Duende IdentityServer license if required.
- Move client secrets, EasySSO credentials, signing keys, and connection strings out of source control.
- Replace hardcoded external provider registrations with environment-specific configuration.
- Use HTTPS with trusted certificates for the host and EasySSO backchannel.
- Disable development exception pages and local certificate bypass behavior.
- Review cookie, SameSite, CORS, redirect URI, and logout URI settings for your deployment domains.
- Add persistent signing credentials and key rotation.
- Add health checks, structured logging sinks, monitoring, and backup/restore procedures.
- Decide whether IdentityServer clients/resources should stay in memory or move to a persisted operational/configuration store.

## Useful Commands

```bash
# Restore dependencies
dotnet restore IdentityServer6-EasySSO.sln

# Build the project
dotnet build IdentityServer6-EasySSO.sln

# Run the host
dotnet run --project Host.AspNetIdentity.csproj

# Add a new EF Core migration
dotnet ef migrations add <MigrationName>

# Apply migrations manually
dotnet ef database update
```

## License

This repository is released under the Unlicense. See `LICENSE` for details.

Third-party dependencies, including Duende IdentityServer, are governed by their own licenses.

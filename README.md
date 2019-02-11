# AspNetCore.Security.Auth0

Asp Net Core Jwt Bearer Token Security package for integration with Auth0.

## Info
| | |
| --- | --- |
| **NuGet** | [![NuGet Badge](https://buildstats.info/nuget/AspNetCore.Security.Auth0)](https://www.nuget.org/packages/AspNetCore.Security.Auth0) |

## Auth0 settings
You need two applications :
1. **Single Page Application**:  used to authenticate the user in a SPA
2. **Machine to Machine**: used by this project to read users + profile (AppData)

See the [wiki : HowTo](https://github.com/StefH/AspNetCore.Security.Auth0/wiki/HowTo) for more details.

## C# Project changes

### appsettings.json
``` json
"Auth0Options": {
    "JwtAuthority": "https://abc.eu.auth0.com/",
    "JwtAudience": "https://my-test-api",
    "Policies": [ "read:data" ],

    "Audience": "https://abc.eu.auth0.com/api/v2/",
    "ClientId": "<replace>",
    "ClientSecret": "<replace>",
    "Domain": "https://abc.eu.auth0.com/"
}
```

### Startup.cs

##### ConfigureServices()
``` c#
public void ConfigureServices(IServiceCollection services)
{
    // Configure MVC AuthorizeFilter
    services.AddMvc(config =>
    {
        var policy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .Build();
        config.Filters.Add(new AuthorizeFilter(policy));
    }).SetCompatibilityVersion(CompatibilityVersion.Version_2_1);

    // other services ...

    // Add Auth0
    services.AddAuth0(options =>
    {
        var section = Configuration.GetSection("Auth0Options");

        options.JwtAuthority = section["JwtAuthority"]; // Something like https://abc.eu.auth0.com/
        options.JwtAudience = section["JwtAudience"]; // The API Identfier

        options.Audience = section["Audience"]; // Something like https://abc.eu.auth0.com/api/v2/
        options.ClientId = section["ClientId"]; // The Client ID from the Machine 2 Machine
        options.ClientSecret = section["ClientSecret"]; // The Client Secret from the Machine 2 Machine
        options.Domain = section["Domain"]; // Something like https://abc.eu.auth0.com/
        options.Policies = section.GetSection("Policies").Get<List<string>>(); The policies, like "read:data" and "write:data"
    });
}
```

##### Configure()

``` c#
public void Configure(...)
{
    // Add the authentication middleware to the middleware pipeline
    app.UseAuthentication();

    app.UseMvc();
}
```

##### Controllers

Update your controllers to add *Authorize* and use the correct *policy*:

``` c#
namespace Sample.Frontend.Controllers
{
    [Authorize("read:data")]
    [ApiController]
    public class DataQueryController : ControllerBase
    {
        // more code ...
    }
}
```
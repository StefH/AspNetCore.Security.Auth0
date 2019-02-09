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

        options.JwtAuthority = section["JwtAuthority"];
        options.JwtAudience = section["JwtAudience"];

        options.Audience = section["Audience"];
        options.ClientId = section["ClientId"];
        options.ClientSecret = section["ClientSecret"];
        options.Domain = section["Domain"];
        options.Policies = section.GetSection("Policies").Get<List<string>>();
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
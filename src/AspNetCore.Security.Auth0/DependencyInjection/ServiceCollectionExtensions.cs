using AspNetCore.Security.Auth0.Authorization;
using AspNetCore.Security.Auth0.Implementations;
using AspNetCore.Security.Auth0.Interfaces.Internal;
using AspNetCore.Security.Auth0.Options;
using AspNetCore.Security.Auth0.Validation;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using System;
using Microsoft.Extensions.Configuration;

// ReSharper disable once CheckNamespace
namespace Microsoft.Extensions.DependencyInjection
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddAuth0([NotNull] this IServiceCollection services, [NotNull] IConfiguration config)
        {
            Guard.NotNull(services, nameof(services));
            Guard.NotNull(config, nameof(config));

            services.Configure<Auth0Options>(config);
            return services;
        }

        public static IServiceCollection AddAuth0([NotNull] this IServiceCollection services, [NotNull] Action<Auth0Options> configureAuth0Options)
        {
            Guard.NotNull(services, nameof(services));
            Guard.NotNull(configureAuth0Options, nameof(configureAuth0Options));

            var auth0Options = new Auth0Options();
            configureAuth0Options(auth0Options);

            services.Configure(configureAuth0Options);

            services.AddOptions();

            services.AddServices();

            services.AddJwtBearerAuthentication(auth0Options);

            services.AddAuthorization(options =>
            {
                foreach (string policy in auth0Options.Policies)
                {
                    options.AddPolicy(policy, auth0Options.Domain);
                }
            });

            return services;
        }

        private static void AddServices(this IServiceCollection services)
        {
            // https://www.stevejgordon.co.uk/introduction-to-httpclientfactory-aspnetcore
            services.AddHttpClient();

            // register the scope authorization handler
            services.AddSingleton<IAuthorizationHandler, HasScopeHandler>();

            // register the IAuth0ClientFactory
            services.AddSingleton<IAuth0ClientFactory, Auth0ClientFactory>();

            // register the IAuth0UserService
            services.AddSingleton<IAuth0UserService, Auth0UserService>();
        }

        private static void AddJwtBearerAuthentication(this IServiceCollection services, Auth0Options auth0Options)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;

            }).AddJwtBearer(options =>
            {
                options.Authority = auth0Options.JwtAuthority;
                options.Audience = auth0Options.JwtAudience;
            });
        }

        private static void AddPolicy(this AuthorizationOptions options, string policyName, string domain)
        {
            options.AddPolicy(policyName, policy => policy.Requirements.Add(new HasScopeRequirement(policyName, domain)));
        }
    }
}
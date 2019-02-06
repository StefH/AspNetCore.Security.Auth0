using AspNetCore.Security.Auth0.Interfaces.Internal;
using AspNetCore.Security.Auth0.Models;
using AspNetCore.Security.Auth0.Options;
using AspNetCore.Security.Auth0.Validation;
using JetBrains.Annotations;
using Microsoft.Extensions.Options;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace AspNetCore.Security.Auth0.Implementations
{
    internal class Auth0UserService : IAuth0UserService
    {
        private readonly IAuth0ClientFactory _factory;
        private readonly Auth0Options _options;

        public Auth0UserService([NotNull] IAuth0ClientFactory factory, [NotNull] IOptions<Auth0Options> options)
        {
            Guard.NotNull(factory, nameof(factory));
            Guard.NotNull(options, nameof(options));

            _factory = factory;
            _options = options.Value;
        }

        public async Task<User> GetUserAsync(string userId)
        {
            var tokenClient = _factory.CreateClient<IAuth0TokenApi>();
            tokenClient.Domain = _options.Domain;

            // Get a Access Token (as Machine 2 Machine application)
            var request = new Auth0AccessTokenRequest
            {
                ClientId = _options.ClientId,
                ClientSecret = _options.ClientSecret,
                Audience = _options.Audience
            };
            var token = await tokenClient.GetTokenAsync(request);

            // Call the management api (as Machine 2 Machine application) to retrieve a user
            var userClient = _factory.CreateClient<IAuth0UserApi>();
            userClient.Endpoint = $"{_options.Domain}api/v2/";
            userClient.Authorization = new AuthenticationHeaderValue(token.TokenType, token.AccessToken);

            return await userClient.GetAsync(userId);
        }
    }
}
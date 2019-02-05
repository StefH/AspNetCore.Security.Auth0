using System.Threading.Tasks;
using AspNetCore.Security.Auth0.Models;
using RestEase;

namespace AspNetCore.Security.Auth0.Interfaces.Internal
{
    /// <summary>
    /// This interface describes the Auth0 Token API and is used by RestEase to create a Rest Client.
    /// </summary>
    internal interface IAuth0TokenApi : IAuth0Api
    {
        /// <summary>
        /// Get access-token.
        /// </summary>
        /// <param name="request">The request</param>
        /// <returns>Token</returns>
        [Post("{domain}oauth/token")]
        Task<Auth0AccessToken> GetTokenAsync([Body] Auth0AccessTokenRequest request);
    }
}
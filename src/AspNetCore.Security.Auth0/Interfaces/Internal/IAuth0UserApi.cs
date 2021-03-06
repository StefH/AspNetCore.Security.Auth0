using AspNetCore.Security.Auth0.Models;
using RestEase;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace AspNetCore.Security.Auth0.Interfaces.Internal
{
    /// <summary>
    /// This interface describes the Auth0 User API and is used by RestEase to create a Rest Client.
    /// </summary>
    internal interface IAuth0UserApi : IAuth0Api
    {
        /// <summary>
        /// The Auth0 domain (host).
        /// </summary>
        [Path("domain", UrlEncode = false)]
        string Endpoint { get; set; }

        /// <summary>
        /// Gets or sets the Authorization Header (bearer).
        /// </summary>
        [Header("Authorization")]
        AuthenticationHeaderValue Authorization { get; set; }

        /// <summary>
        /// Get a User.
        /// </summary>
        /// <param name="userId">The user id</param>
        /// <returns>A <see cref="User"/></returns>
        [Get("{domain}users/{userId}")]
        Task<User> GetAsync([Path] string userId);
    }
}

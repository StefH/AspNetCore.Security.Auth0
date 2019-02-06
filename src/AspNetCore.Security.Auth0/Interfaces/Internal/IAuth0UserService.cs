using AspNetCore.Security.Auth0.Models;
using JetBrains.Annotations;
using System.Threading.Tasks;

namespace AspNetCore.Security.Auth0.Interfaces.Internal
{
    internal interface IAuth0UserService
    {
        Task<User> GetUserAsync([NotNull] string userId);
    }
}
using AspNetCore.Security.Auth0.Interfaces.Internal;
using AspNetCore.Security.Auth0.Models;
using AspNetCore.Security.Auth0.Options;
using AspNetCore.Security.Auth0.Validation;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AspNetCore.Security.Auth0.Authorization
{
    /// <summary>
    /// This requirement checks if the scope claim issued by your Auth0 tenant is present.
    /// If the scope claim exists, the requirement checks if the scope claim contains the requested scope.
    /// 
    /// Based on <see cref="!:https://github.com/auth0-samples/auth0-aspnetcore-webapi-samples/blob/master/Quickstart/01-Authorization/HasScopeHandler.cs">HasScopeHandler.cs</see>.
    /// </summary>
    /// <seealso cref="AuthorizationHandler{HasScopeRequirement}" />
    internal class HasScopeHandler : AuthorizationHandler<HasScopeRequirement>
    {
        private static string NameIdentifierClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";
        private static string ScopeType = "scope";

        private readonly IAuth0ClientFactory _factory;
        private readonly Auth0Options _options;
        private readonly ILogger<HasScopeHandler> _logger;

        public HasScopeHandler([NotNull] IAuth0ClientFactory factory, [NotNull] IOptions<Auth0Options> options, [NotNull]  ILogger<HasScopeHandler> logger)
        {
            Guard.NotNull(factory, nameof(factory));
            Guard.NotNull(options, nameof(options));
            Guard.NotNull(logger, nameof(logger));

            _factory = factory;
            _logger = logger;
            _options = options.Value;
        }

        /// <summary>
        /// Makes a decision if authorization is allowed based on a specific requirement.
        /// </summary>
        /// <param name="context">The authorization context.</param>
        /// <param name="requirement">The requirement to evaluate.</param>
        /// <returns>Task</returns>
        protected override async Task HandleRequirementAsync([NotNull] AuthorizationHandlerContext context, [NotNull] HasScopeRequirement requirement)
        {
            Guard.NotNull(context, nameof(context));
            Guard.NotNull(requirement, nameof(requirement));

            if (!UserHasRequiredScopeRequirement(context, requirement))
            {
                _logger.LogWarning("User '{IdentityName}' does not have the required scope '{scope}'.", context.User.Identity.Name, string.Join(",", requirement.Scope));
                return;
            }

            var nameIdentifierClaim = GetNameIdentifierClaim(context);
            if (nameIdentifierClaim == null)
            {
                _logger.LogWarning("User '{IdentityName}' does not have the required NameIdentifierClaimType.", context.User.Identity.Name);
                return;
            }

            var user = await GetUserAsync(nameIdentifierClaim.Value);
            if (user?.AppMetadata == null)
            {
                _logger.LogWarning("User with userid '{UserId}' does not have any AppMetadata defined.", nameIdentifierClaim.Value);
                return;
            }

            AddUserIdentityToContext(context, requirement, user);
        }

        /// <summary>
        /// Check if the user has the correct scope requirement claim.
        /// </summary>
        private bool UserHasRequiredScopeRequirement(AuthorizationHandlerContext context, HasScopeRequirement requirement)
        {
            // Check if the user has the 'scope' claim.
            if (!context.User.HasClaim(c => c.Type == ScopeType && c.Issuer == requirement.Issuer))
            {
                return false;
            }

            // Split the scopes string into an array
            string[] scopes = context.User.FindFirst(c => c.Type == ScopeType && c.Issuer == requirement.Issuer).Value.Split(' ');

            // Check if the scope array contains the required scope
            return scopes.Any(s => s == requirement.Scope);
        }

        /// <summary>
        /// Get the 'NameIdentifier' claim for the user.
        /// </summary>
        private Claim GetNameIdentifierClaim(AuthorizationHandlerContext context)
        {
            // Claim "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" has the value (user-id `auth0|5b02c858dc67155d2b5f7fdc`)
            return context.User.Claims.FirstOrDefault(c => c.Type == NameIdentifierClaimType);
        }

        private async Task<User> GetUserAsync(string userId)
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

            // Call the management api to retrieve a user
            var userClient = _factory.CreateClient<IAuth0UserApi>();
            userClient.Domain = $"{_options.Domain}api/v2/";
            userClient.Authorization = new AuthenticationHeaderValue(token.TokenType, token.AccessToken);

            return await userClient.GetAsync(userId);
        }

        /// <summary>
        /// Adds the user identity to the context and mark the specified requirement as being successfully evaluated.
        /// </summary>
        private void AddUserIdentityToContext(AuthorizationHandlerContext context, HasScopeRequirement requirement, User user)
        {
            var identity = new Auth0ClaimsIdentity(context.User.Claims, user.FullName, user.AppMetadata);
            context.User.AddIdentity(identity);

            context.Succeed(requirement);
        }
    }
}
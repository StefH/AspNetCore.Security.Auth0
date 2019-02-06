using AspNetCore.Security.Auth0.Interfaces.Internal;
using AspNetCore.Security.Auth0.Models;
using AspNetCore.Security.Auth0.Validation;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Logging;
using System.Linq;
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

        private readonly IAuth0UserService _userService;
        private readonly ILogger<HasScopeHandler> _logger;

        public HasScopeHandler([NotNull] IAuth0UserService userService, [NotNull]  ILogger<HasScopeHandler> logger)
        {
            Guard.NotNull(userService, nameof(userService));
            Guard.NotNull(logger, nameof(logger));

            _userService = userService;
            _logger = logger;
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

            var user = await _userService.GetUserAsync(nameIdentifierClaim.Value);
            if (user?.AppMetadata == null)
            {
                _logger.LogWarning("User '{IdentityName}' with userid '{UserId}' does not have any AppMetadata defined.", context.User.Identity.Name, nameIdentifierClaim.Value);
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
            // Claim "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier" has the value (user-id `auth0|5b02c820dc67155d2b5f7fdc`)
            return context.User.Claims.FirstOrDefault(c => c.Type == NameIdentifierClaimType);
        }

        /// <summary>
        /// Adds the Auth0ClaimsIdentity to the context and mark the specified requirement as being successfully evaluated.
        /// </summary>
        private void AddUserIdentityToContext(AuthorizationHandlerContext context, HasScopeRequirement requirement, User user)
        {
            var identity = new Auth0ClaimsIdentity(context.User.Claims, user.FullName, user.AppMetadata);
            context.User.AddIdentity(identity);

            context.Succeed(requirement);
        }
    }
}
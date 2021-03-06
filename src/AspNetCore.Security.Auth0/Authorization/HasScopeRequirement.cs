﻿using AspNetCore.Security.Auth0.Validation;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authorization;

namespace AspNetCore.Security.Auth0.Authorization
{
    /// <summary>
    /// Create a new authorization requirement called HasScopeRequirement.
    /// </summary>
    /// <seealso cref="IAuthorizationRequirement" />
    internal class HasScopeRequirement : IAuthorizationRequirement
    {
        [PublicAPI]
        public string Issuer { get; }

        [PublicAPI]
        public string Scope { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="HasScopeRequirement"/> class.
        /// </summary>
        /// <param name="scope">The scope.</param>
        /// <param name="issuer">The issuer.</param>
        public HasScopeRequirement([NotNull] string scope, [NotNull] string issuer)
        {
            Guard.NotNull(scope, nameof(scope));
            Guard.NotNull(issuer, nameof(issuer));

            Scope = scope;
            Issuer = issuer;
        }
    }
}

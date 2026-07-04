using SecurityPatterns.Application.Models;

namespace SecurityPatterns.Application.Interfaces;

/// <summary>
/// Application-level contract for authentication operations.
/// Decouples use-case logic from infrastructure implementations.
/// </summary>
public interface IAuthService
{
    /// <summary>
    /// Authenticates a user with username/password and returns a JWT token.
    /// </summary>
    /// <param name="request">The login credentials.</param>
    /// <returns>A token response if authentication succeeds; null if credentials are invalid.</returns>
    TokenResponse? Authenticate(LoginRequest request);

    /// <summary>
    /// Returns the authenticated user's profile extracted from the current context.
    /// </summary>
    /// <param name="claims">The claims extracted from the validated JWT token.</param>
    ProfileResponse GetProfile(IDictionary<string, string> claims);
}

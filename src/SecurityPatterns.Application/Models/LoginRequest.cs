namespace SecurityPatterns.Application.Models;

/// <summary>
/// Represents an incoming login request containing user credentials.
/// </summary>
public sealed record LoginRequest
{
    /// <summary>
    /// The username for authentication.
    /// </summary>
    public required string Username { get; init; }

    /// <summary>
    /// The password for authentication.
    /// </summary>
    public required string Password { get; init; }
}

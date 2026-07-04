namespace SecurityPatterns.Core.Abstractions;

/// <summary>
/// Defines the contract for a component that produces authentication tokens.
/// </summary/// <remarks>
/// <para>
/// This interface encapsulates the token-issuance responsibility as a standalone concern,
/// enabling implementations to be swapped without affecting consuming code (Open/Closed Principle).
/// </para>
/// <para>
/// Typical implementations include JWT signers, opaque-token generators backed by
/// a secure random source, or hardware-backed attestation issuers.
/// </para>
/// <para>
/// Security considerations:
/// <list type="bullet">
///   <item>Implementations MUST use a cryptographically secure random number generator for token identifiers.</item>
///   <item>The <paramref name="lifetime"/> parameter MUST be clamped to a policy-defined maximum
///         to prevent issuance of excessively long-lived tokens.</item>
///   <item>Returned <see cref="TokenResult"/> instances MUST NOT be cached or reused;
///         each call MUST produce a fresh token.</item>
/// </list>
/// </para>
/// </remarks>
public interface ITokenIssuer
{
    /// <summary>
    /// Generates a new authentication token for the specified subject.
    /// </summary>
    /// <param name="subjectId">
    /// The immutable, unique identifier of the principal (e.g., user ID, service account ID).
    /// This value becomes the authoritative subject claim inside the token and MUST NOT be
    /// spoofable or guessable.
    /// </param>
    /// <param name="username">
    /// A human-readable display name or username associated with the subject.
    /// This value is included for convenience and MUST NOT be used as an authorization key.
    /// </param>
    /// <param name="claims">
    /// A collection of additional key-value claims to embed in the token (e.g., roles, scopes).
    /// Implementations MUST validate claim values against a whitelist to prevent
    /// injection of privileged claims by untrusted callers.
    /// </param>
    /// <param name="lifetime">
    /// The intended validity duration of the token. Implementations SHOULD enforce
    /// an upper-bound policy and reject excessively long lifetimes to reduce the
    /// window of opportunity for token theft.
    /// </param>
    /// <returns>
    /// A <see cref="TokenResult"/> containing the serialized token, its unique identifier,
    /// and the absolute UTC expiration timestamp.
    /// </returns>
    TokenResult GenerateToken(
        string subjectId,
        string username,
        IDictionary<string, string> claims,
        TimeSpan lifetime);
}

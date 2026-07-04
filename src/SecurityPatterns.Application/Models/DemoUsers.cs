namespace SecurityPatterns.Application.Models;

/// <summary>
/// Hardcoded demo user store for thesis demonstration purposes.
/// In production, this would be replaced by a database-backed user repository.
/// </summary>
public static class DemoUsers
{
    private static readonly Dictionary<string, DemoUser> Users = new(StringComparer.OrdinalIgnoreCase)
    {
        ["moein"] = new(
            SubjectId: "usr-001",
            Username: "moein",
            PasswordHash: "Password123!",
            Role: "Admin",
            Scope: "thesis:read thesis:write"),

        ["admin"] = new(
            SubjectId: "usr-002",
            Username: "admin",
            PasswordHash: "Admin456!",
            Role: "SuperAdmin",
            Scope: "thesis:read thesis:write admin:full-access"),
    };

    /// <summary>
    /// Validates credentials and returns the matching user, or null if not found.
    /// </summary>
    public static DemoUser? Validate(string username, string password)
    {
        if (Users.TryGetValue(username, out DemoUser? user) && user.PasswordHash == password)
        {
            return user;
        }

        return null;
    }

    public sealed record DemoUser(
        string SubjectId,
        string Username,
        string PasswordHash,
        string Role,
        string Scope);
}

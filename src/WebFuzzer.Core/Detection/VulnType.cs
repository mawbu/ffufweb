namespace WebFuzzer.Core.Detection;

/// <summary>
/// Loại lỗ hổng được phát hiện.
/// </summary>
public enum VulnType
{
    None,
    SQLi,
    SQLi_TimeBased,
    SQLi_Boolean,
    XSS,
    PathTraversal,
    InfoDisclosure,
    AuthBypass,
    ServerError,
    SSRF,
    CommandInjection,
    IDOR,
    IDOR_KeyBased,    // Privilege Escalation (role, isAdmin)
    IDOR_ValueBased   // Classic IDOR (email, specific resource data)
}

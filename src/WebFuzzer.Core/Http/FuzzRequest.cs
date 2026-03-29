using WebFuzzer.Core.Models;

namespace WebFuzzer.Core.Http;

/// <summary>
/// Model đại diện cho một HTTP request fuzz đã được build sẵn.
/// </summary>
public class FuzzRequest
{
    /// <summary>HTTP method.</summary>
    public string Method { get; set; } = "GET";

    /// <summary>URL đầy đủ sau khi thay FUZZ.</summary>
    public string Url { get; set; } = string.Empty;

    /// <summary>Payload (từ wordlist) đã được inject vào URL/Body.</summary>
    public string Payload { get; set; } = string.Empty;

    /// <summary>Headers của request.</summary>
    public Dictionary<string, string> Headers { get; set; } = new();

    /// <summary>Body của request (POST/PUT).</summary>
    public string? Body { get; set; }

    /// <summary>Tạo FuzzRequest từ FuzzOptions và payload cụ thể.</summary>
    public static FuzzRequest Build(FuzzOptions options, string payload)
    {
        var req = new FuzzRequest
        {
            Method  = options.Method.ToUpperInvariant(),
            Url     = options.Url.Replace("FUZZ", Uri.EscapeDataString(payload)),
            Payload = payload,
            Body    = options.Data?.Replace("FUZZ", payload)
        };

        // Parse custom headers
        foreach (var header in options.Headers ?? [])
        {
            var idx = header.IndexOf(':');
            if (idx > 0)
            {
                var name  = header[..idx].Trim();
                var value = header[(idx + 1)..].Trim().Replace("FUZZ", payload);
                req.Headers[name] = value;
            }
        }

        // Cookie
        if (!string.IsNullOrWhiteSpace(options.Cookie))
            req.Headers["Cookie"] = options.Cookie;

        return req;
    }
}

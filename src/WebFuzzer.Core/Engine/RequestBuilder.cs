using WebFuzzer.Core.Models;

namespace WebFuzzer.Core.Engine;

public static class RequestBuilder
{
    public static HttpRequestMessage Build(FuzzOptions options, string word)
    {
        // Thay thế tất cả instances của FUZZ keyword
        var url = options.Url.Replace("FUZZ", Uri.EscapeDataString(word));
        
        var request = new HttpRequestMessage(
            new HttpMethod(options.Method),
            url
        );

        // Add custom headers
        foreach (var header in options.Headers ?? [])
        {
            var parts = header.Split(':', 2);
            if (parts.Length == 2)
            {
                var headerName = parts[0].Trim();
                var headerValue = parts[1].Trim().Replace("FUZZ", word);
                request.Headers.TryAddWithoutValidation(headerName, headerValue);
            }
        }

        // Add cookies
        if (!string.IsNullOrEmpty(options.Cookie))
            request.Headers.TryAddWithoutValidation("Cookie", options.Cookie);

        // Add POST body
        if (!string.IsNullOrEmpty(options.Data))
        {
            var body = options.Data.Replace("FUZZ", word);
            request.Content = new StringContent(body, System.Text.Encoding.UTF8,
                options.ContentType ?? "application/x-www-form-urlencoded");
        }

        return request;
    }
}
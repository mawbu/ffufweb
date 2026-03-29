using WebFuzzer.Core.Models;

namespace WebFuzzer.Core.Http;

public class FuzzHttpClientFactory
{
    private readonly FuzzOptions _options;

    public FuzzHttpClientFactory(FuzzOptions options) => _options = options;

    public HttpClient Create()
    {
        var handler = new SocketsHttpHandler
        {
            // Connection pooling
            MaxConnectionsPerServer = _options.Threads + 10,
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            PooledConnectionIdleTimeout = TimeSpan.FromSeconds(30),
            
            // Không follow redirect tự động (để filter được)
            AllowAutoRedirect = _options.FollowRedirects,
            
            // Bỏ qua SSL errors (fuzzing thường dùng self-signed cert)
            SslOptions = new System.Net.Security.SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (_, _, _, _) => true
            }
        };

        // Proxy support
        if (!string.IsNullOrEmpty(_options.Proxy))
        {
            handler.Proxy = new System.Net.WebProxy(_options.Proxy);
            handler.UseProxy = true;
        }

        return new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(_options.TimeoutSeconds)
        };
    }
}
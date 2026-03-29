using WebFuzzer.Core.Http;
using WebFuzzer.Core.Models;
using Xunit;

namespace WebFuzzer.Tests;

public class FuzzRequestTests
{
    [Fact]
    public void Build_ReplacesFuzzInUrl()
    {
        var options = new FuzzOptions
        {
            Url    = "https://example.com/FUZZ",
            Method = "GET"
        };
        var req = FuzzRequest.Build(options, "admin");

        Assert.Contains("admin", req.Url);
        Assert.DoesNotContain("FUZZ", req.Url);
        Assert.Equal("admin", req.Payload);
    }

    [Fact]
    public void Build_ReplacesFuzzInBody()
    {
        var options = new FuzzOptions
        {
            Url    = "https://example.com/login",
            Method = "POST",
            Data   = "username=FUZZ&password=secret"
        };
        var req = FuzzRequest.Build(options, "admin");

        Assert.Equal("username=admin&password=secret", req.Body);
    }

    [Fact]
    public void Build_ParsesCustomHeaders()
    {
        var options = new FuzzOptions
        {
            Url     = "https://example.com/FUZZ",
            Headers = ["X-Custom: hello", "Authorization: Bearer token123"]
        };
        var req = FuzzRequest.Build(options, "test");

        Assert.True(req.Headers.ContainsKey("X-Custom"));
        Assert.Equal("hello", req.Headers["X-Custom"]);
        Assert.True(req.Headers.ContainsKey("Authorization"));
    }

    [Fact]
    public void Build_SetsCookieHeader()
    {
        var options = new FuzzOptions
        {
            Url    = "https://example.com/FUZZ",
            Cookie = "session=abc123"
        };
        var req = FuzzRequest.Build(options, "test");

        Assert.True(req.Headers.ContainsKey("Cookie"));
        Assert.Equal("session=abc123", req.Headers["Cookie"]);
    }

    [Fact]
    public void Build_UppercasesMethod()
    {
        var options = new FuzzOptions
        {
            Url    = "https://example.com/FUZZ",
            Method = "post"
        };
        var req = FuzzRequest.Build(options, "test");

        Assert.Equal("POST", req.Method);
    }
}

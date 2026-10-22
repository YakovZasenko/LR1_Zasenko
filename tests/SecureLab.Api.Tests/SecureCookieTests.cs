using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace SecureLab.Api.Tests;

public sealed class SecureCookieTests(SecureLabApiFactory factory, ITestOutputHelper output)
    : IClassFixture<SecureLabApiFactory>
{
    [Fact]
    public async Task SecureCookie_IsSentBackOnlyOverHttps()
    {
        var password = Environment.GetEnvironmentVariable("SeedUsers__Password")
            ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

        using var host = factory.WithWebHostBuilder(b => b.ConfigureTestServices(s =>
            s.PostConfigure<CookieAuthenticationOptions>(IdentityConstants.ApplicationScheme,
                o => o.Cookie.SecurePolicy = CookieSecurePolicy.Always)));

        using var https = host.CreateClient(new WebApplicationFactoryClientOptions
            { BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true });
        using var http = host.CreateClient(new WebApplicationFactoryClientOptions
            { BaseAddress = new Uri("http://localhost"), AllowAutoRedirect = false, HandleCookies = true });

        var creds = new { userName = "alice", password };

        using var loginHttps = await https.PostAsJsonAsync("/api/auth/login", creds);
        using var meHttps = await https.GetAsync("/api/me");
        using var loginHttp = await http.PostAsJsonAsync("/api/auth/login", creds);
        using var meHttp = await http.GetAsync("/api/me");

        output.WriteLine($"HTTPS client: login={(int)loginHttps.StatusCode}, next request /api/me={(int)meHttps.StatusCode}");
        output.WriteLine($"HTTP  client: login={(int)loginHttp.StatusCode}, next request /api/me={(int)meHttp.StatusCode}");
        output.WriteLine("Set-Cookie attrs (https): " + CookieAttrs(loginHttps));
        output.WriteLine("Set-Cookie attrs (http):  " + CookieAttrs(loginHttp));

        Assert.Equal(HttpStatusCode.NoContent, loginHttps.StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, loginHttp.StatusCode);
        Assert.Equal(HttpStatusCode.OK, meHttps.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, meHttp.StatusCode);
    }

    private static string CookieAttrs(HttpResponseMessage r) =>
        r.Headers.TryGetValues("Set-Cookie", out var v)
            ? string.Join(" | ", v.Select(c => string.Join("; ",
                c.Split(';').Skip(1).Select(p => p.Trim()))))
            : "(no Set-Cookie)";
}

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using SecureLab.Api.Data;

namespace SecureLab.Api.Tests;

public sealed class IncidentEndpointTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task GetList_ReturnsOnlyAllowedSeededIncidentsForAlice()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);

        var response = await client.GetFromJsonAsync<List<IncidentListItemDto>>("/api/incidents");

        Assert.NotNull(response);
        Assert.Contains(response, item => item.Id == DbSeeder.AliceIncidentId);
        Assert.DoesNotContain(response, item => item.Id == DbSeeder.BobIncidentId);
    }

    [Fact]
    public async Task GetDetails_ForUnknownId_ReturnsProblemDetails404()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);

        using var response = await client.GetAsync($"/api/incidents/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task GetDetails_DoesNotExposeInternalOwnerFields()
    {
        using var client = await factory.LoginAsync("alice", StudyPassword);

        using var response = await client.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync();
        using var document = await JsonDocument.ParseAsync(stream);

        Assert.False(document.RootElement.TryGetProperty("ownerUserId", out _));
        Assert.False(document.RootElement.TryGetProperty("passwordHash", out _));
    }

    [Fact]
    public void ClientScript_DoesNotUseDangerousInnerHtmlSink()
    {
        var scriptPath = Path.Combine(GetRepositoryRoot(), "src", "SecureLab.Api", "Client", "app.js");
        var script = File.ReadAllText(scriptPath);

        Assert.DoesNotContain("innerHTML", script, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BrowserLabScript_UsesSafeDomRendering_AndPreservesSeededCommentMarker()
    {
        var browserLabScriptPath = Path.Combine(
            GetRepositoryRoot(),
            "src", "SecureLab.Api", "Client", "browser-lab.js");
        var script = await File.ReadAllTextAsync(browserLabScriptPath);

        Assert.DoesNotContain("innerHTML", script, StringComparison.Ordinal);
        Assert.Contains("textContent", script, StringComparison.Ordinal);

        using var client = await factory.LoginAsync("alice", StudyPassword);
        using var response = await client.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var payload = await response.Content.ReadAsStringAsync();
        Assert.Contains("data-lab05-marker", payload, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CorsPolicy_AllowsConfiguredProbeOrigin_AndOmitsHeadersForDisallowedOrigin()
    {
        using var client = factory.CreateClient();

        using var allowedRequest = new HttpRequestMessage(HttpMethod.Get, "/health");
        allowedRequest.Headers.Add("Origin", "http://localhost:4173");
        using var allowedResponse = await client.SendAsync(allowedRequest);

        Assert.Equal(HttpStatusCode.OK, allowedResponse.StatusCode);
        Assert.True(allowedResponse.Headers.TryGetValues("Access-Control-Allow-Origin", out var origins));
        Assert.Contains("http://localhost:4173", origins);
        Assert.True(allowedResponse.Headers.TryGetValues("Access-Control-Allow-Credentials", out var creds));
        Assert.Contains("true", creds);

        using var disallowedRequest = new HttpRequestMessage(HttpMethod.Get, "/health");
        disallowedRequest.Headers.Add("Origin", "http://localhost:4174");
        using var disallowedResponse = await client.SendAsync(disallowedRequest);

        Assert.Equal(HttpStatusCode.OK, disallowedResponse.StatusCode);
        Assert.False(disallowedResponse.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task BrowserHeaders_AreAppliedToClientDocument()
    {
        using var client = factory.CreateClient();
        using var response = await client.GetAsync("/browser-lab.html");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.TryGetValues("Content-Security-Policy", out var cspValues));
        var csp = Assert.Single(cspValues);
        Assert.Contains("default-src 'self'", csp, StringComparison.Ordinal);
        Assert.Contains("frame-ancestors 'none'", csp, StringComparison.Ordinal);

        Assert.True(response.Headers.TryGetValues("X-Content-Type-Options", out var nosniff));
        Assert.Contains("nosniff", nosniff);

        Assert.True(response.Headers.TryGetValues("Referrer-Policy", out var referrer));
        Assert.Contains("no-referrer", referrer);
    }

    private static string GetRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "SecureLab.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName
            ?? throw new InvalidOperationException("Repository root with SecureLab.sln was not found.");
    }

    private sealed record IncidentListItemDto(
        Guid Id,
        string Title,
        string Severity,
        string Status,
        DateTimeOffset OccurredAtUtc,
        DateTimeOffset CreatedAtUtc);
}

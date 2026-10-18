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

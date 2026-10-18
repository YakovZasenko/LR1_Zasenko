using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

public sealed class Lab04AuthorizationTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string StudyPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    [Fact]
    public async Task A01_AnonymousRequest_ToProtectedDetails_Returns401WithoutRedirect()
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        using var response = await client.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task A02_Owner_CanReadAndUpdateOwnIncident()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var readResponse = await alice.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.Equal(HttpStatusCode.OK, readResponse.StatusCode);

        var createdId = await CreateTempIncidentAsync(alice, "Initial Alice Title");
        try
        {
            using var updateResponse = await alice.PutAsJsonAsync($"/api/incidents/{createdId}", new
            {
                title = "Updated By Owner Alice",
                description = "Updated description with valid length for test.",
                severity = "Medium"
            });

            Assert.Equal(HttpStatusCode.NoContent, updateResponse.StatusCode);

            var updated = await alice.GetFromJsonAsync<JsonObject>($"/api/incidents/{createdId}");
            Assert.Equal("Updated By Owner Alice", updated!["title"]!.GetValue<string>());
            Assert.Equal("Medium", updated["severity"]!.GetValue<string>());
        }
        finally
        {
            await CleanupIncidentAsync(createdId);
        }
    }

    [Fact]
    public async Task A03_NonOwner_CannotReadBobIncident_Returns404()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var response = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("Невідома спроба входу", body);
        Assert.DoesNotContain("Боб Мельник", body);
    }

    [Fact]
    public async Task A03R_Analyst_CanReadAliceIncidentForAnalysis_ButCannotMutateContent()
    {
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var readResponse = await morgan.GetAsync($"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.Equal(HttpStatusCode.OK, readResponse.StatusCode);

        var before = await alice.GetFromJsonAsync<JsonObject>($"/api/incidents/{DbSeeder.AliceIncidentId}");

        using var updateResponse = await morgan.PutAsJsonAsync($"/api/incidents/{DbSeeder.AliceIncidentId}", new
        {
            title = "Analyst Unauthorized Edit",
            description = "Analyst should not be able to edit incident content.",
            severity = "High"
        });

        Assert.Equal(HttpStatusCode.NotFound, updateResponse.StatusCode);

        var after = await alice.GetFromJsonAsync<JsonObject>($"/api/incidents/{DbSeeder.AliceIncidentId}");
        Assert.Equal(before!["title"]!.GetValue<string>(), after!["title"]!.GetValue<string>());
    }

    [Fact]
    public async Task A04_NonOwner_UpdateAndDeleteBobIncident_AreDenied_AndDoNotChangeState()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var bob = await factory.LoginAsync("bob", StudyPassword);

        var before = await bob.GetFromJsonAsync<JsonObject>($"/api/incidents/{DbSeeder.BobIncidentId}");

        using var updateResponse = await alice.PutAsJsonAsync($"/api/incidents/{DbSeeder.BobIncidentId}", new
        {
            title = "Forged Title By Alice",
            description = "Alice trying to overwrite Bob incident description.",
            severity = "Low"
        });
        Assert.Equal(HttpStatusCode.NotFound, updateResponse.StatusCode);

        using var deleteResponse = await alice.DeleteAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        Assert.Equal(HttpStatusCode.NotFound, deleteResponse.StatusCode);

        var after = await bob.GetFromJsonAsync<JsonObject>($"/api/incidents/{DbSeeder.BobIncidentId}");
        Assert.NotNull(after);
        Assert.Equal(before!["title"]!.GetValue<string>(), after!["title"]!.GetValue<string>());
        Assert.Equal(before["description"]!.GetValue<string>(), after["description"]!.GetValue<string>());
        Assert.Equal(before["severity"]!.GetValue<string>(), after["severity"]!.GetValue<string>());
    }

    [Fact]
    public async Task A05_List_AsAlice_ReturnsOnlyOwnIncidents_AndExcludesBobResources()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        var list = await alice.GetFromJsonAsync<JsonArray>("/api/incidents");

        Assert.NotNull(list);
        var ids = list!.Select(node => node!["id"]!.GetValue<Guid>()).ToList();

        Assert.Contains(DbSeeder.AliceIncidentId, ids);
        Assert.DoesNotContain(DbSeeder.BobIncidentId, ids);
        Assert.DoesNotContain(Guid.Parse("20000000-0000-0000-0000-000000000004"), ids);
    }

    [Fact]
    public async Task A06_A09_Reporter_CannotPerformPrivilegedTriage_Returns403WithTraceId_AndStatusUnchanged()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        var createdId = await CreateTempIncidentAsync(alice, "Incident For Denied Triage");

        try
        {
            using var triageResponse = await alice.PostAsync($"/api/incidents/{createdId}/triage", content: null);

            Assert.Equal(HttpStatusCode.Forbidden, triageResponse.StatusCode);
            var problem = await triageResponse.Content.ReadFromJsonAsync<JsonObject>();
            Assert.NotNull(problem);
            Assert.True(problem!.ContainsKey("traceId"));
            Assert.False(string.IsNullOrWhiteSpace(problem["traceId"]!.GetValue<string>()));

            var after = await alice.GetFromJsonAsync<JsonObject>($"/api/incidents/{createdId}");
            Assert.Equal("New", after!["status"]!.GetValue<string>());
        }
        finally
        {
            await CleanupIncidentAsync(createdId);
        }
    }

    [Fact]
    public async Task A07_Analyst_CanPerformPermittedTriageTransition_FromNewToTriaged()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);

        var createdId = await CreateTempIncidentAsync(alice, "Incident For Analyst Triage");

        try
        {
            using var triageResponse = await morgan.PostAsync($"/api/incidents/{createdId}/triage", content: null);
            Assert.Equal(HttpStatusCode.NoContent, triageResponse.StatusCode);

            var after = await alice.GetFromJsonAsync<JsonObject>($"/api/incidents/{createdId}");
            Assert.Equal("Triaged", after!["status"]!.GetValue<string>());

            using var repeatResponse = await morgan.PostAsync($"/api/incidents/{createdId}/triage", content: null);
            Assert.Equal(HttpStatusCode.Conflict, repeatResponse.StatusCode);
        }
        finally
        {
            await CleanupIncidentAsync(createdId);
        }
    }

    [Fact]
    public async Task A08a_RegularUpdate_IgnoresForgedOwnerRoleAndStatusFields()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        var createdId = await CreateTempIncidentAsync(alice, "Incident For Overposting Check");

        try
        {
            using var response = await alice.PutAsJsonAsync($"/api/incidents/{createdId}", new
            {
                title = "Legitimately Updated Title",
                description = "Legitimate description update while attempting overposting.",
                severity = "High",
                ownerUserId = DbSeeder.BobId,
                status = "Triaged",
                role = "Analyst"
            });

            Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

            await using var scope = factory.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            var entity = await db.Incidents.AsNoTracking().SingleAsync(i => i.Id == createdId);

            Assert.Equal("Legitimately Updated Title", entity.Title);
            Assert.Equal(DbSeeder.AliceId, entity.OwnerUserId);
            Assert.Equal(IncidentStatus.New, entity.Status);
        }
        finally
        {
            await CleanupIncidentAsync(createdId);
        }
    }

    [Fact]
    public async Task A10_ForeignAndUnknownIncident_ReturnIndistinguishable404ProblemDetails()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);

        using var foreignResponse = await alice.GetAsync($"/api/incidents/{DbSeeder.BobIncidentId}");
        using var unknownResponse = await alice.GetAsync($"/api/incidents/{Guid.NewGuid()}");

        Assert.Equal(HttpStatusCode.NotFound, foreignResponse.StatusCode);
        Assert.Equal(unknownResponse.StatusCode, foreignResponse.StatusCode);
        Assert.Equal(
            unknownResponse.Content.Headers.ContentType?.ToString(),
            foreignResponse.Content.Headers.ContentType?.ToString());

        var foreignBody = await foreignResponse.Content.ReadFromJsonAsync<JsonObject>();
        var unknownBody = await unknownResponse.Content.ReadFromJsonAsync<JsonObject>();

        foreignBody!.Remove("traceId");
        foreignBody.Remove("requestId");
        unknownBody!.Remove("traceId");
        unknownBody.Remove("requestId");

        Assert.True(JsonNode.DeepEquals(unknownBody, foreignBody));
    }

    [Fact]
    public async Task A12_ChildCommentEndpoint_DeniesForeignAndInternalCommentsForReporter_AndAllowsAnalyst()
    {
        using var alice = await factory.LoginAsync("alice", StudyPassword);
        using var morgan = await factory.LoginAsync("morgan", StudyPassword);

        // 1. Alice (Reporter) cannot read comment on Bob's incident
        using var foreignCommentResponse = await alice.GetAsync($"/api/incident-comments/{DbSeeder.BobCommentId}");
        Assert.Equal(HttpStatusCode.NotFound, foreignCommentResponse.StatusCode);

        // 2. Alice (Reporter) cannot read internal comment even on her own incident
        using var internalAsAliceResponse = await alice.GetAsync($"/api/incident-comments/{DbSeeder.InternalCommentId}");
        Assert.Equal(HttpStatusCode.NotFound, internalAsAliceResponse.StatusCode);

        // 3. Alice's incident details projection does not expose internal comment to Reporter
        var aliceDetails = await alice.GetFromJsonAsync<JsonObject>($"/api/incidents/{DbSeeder.AliceIncidentId}");
        var aliceCommentIds = aliceDetails!["comments"]!.AsArray()
            .Select(c => c!["id"]!.GetValue<Guid>())
            .ToList();
        Assert.DoesNotContain(DbSeeder.InternalCommentId, aliceCommentIds);

        // 4. Morgan (Analyst) can read internal comment both directly and in details
        using var internalAsMorganResponse = await morgan.GetAsync($"/api/incident-comments/{DbSeeder.InternalCommentId}");
        Assert.Equal(HttpStatusCode.OK, internalAsMorganResponse.StatusCode);
    }

    private static async Task<Guid> CreateTempIncidentAsync(HttpClient client, string title)
    {
        using var response = await client.PostAsJsonAsync("/api/incidents", new
        {
            title,
            description = "Synthetic incident created for authorization test.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-5)
        });
        response.EnsureSuccessStatusCode();

        var created = await response.Content.ReadFromJsonAsync<JsonObject>();
        return created!["id"]!.GetValue<Guid>();
    }

    private async Task CleanupIncidentAsync(Guid id)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();

        await db.IncidentStatusHistory.Where(h => h.IncidentId == id).ExecuteDeleteAsync();
        await db.IncidentComments.Where(c => c.IncidentId == id).ExecuteDeleteAsync();
        await db.Incidents.Where(i => i.Id == id).ExecuteDeleteAsync();
    }
}

using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

public sealed class Lab02RegressionTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    // T-02: Автоматичний тест відхилення некоректного DTO (порожній title, числове severity "7", дата в майбутньому)
    [Fact]
    public async Task Post_WithInvalidDto_Returns400ValidationProblemWithoutInternalDetails()
    {
        var body = new
        {
            title = "   ",
            description = "Навчальний опис інциденту.",
            severity = "7",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(30)
        };

        using var response = await _client.PostAsJsonAsync("/api/incidents", body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        var errors = document.RootElement.GetProperty("errors");

        Assert.True(errors.TryGetProperty("title", out _));
        Assert.True(errors.TryGetProperty("severity", out _));
        Assert.True(errors.TryGetProperty("occurredAtUtc", out _));
        Assert.DoesNotContain("Exception", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SELECT", json, StringComparison.OrdinalIgnoreCase);
    }

    // T-09: Автоматичний тест межі cross-field правила (39 символів -> 400, 40 символів -> 201)
    [Fact]
    public async Task Post_HighSeverityCrossFieldBoundary_Rejects39CharsAndAccepts40Chars()
    {
        var title39 = $"T09-39-{Guid.NewGuid():N}";
        var title40 = $"T09-40-{Guid.NewGuid():N}";

        try
        {
            var body39 = new
            {
                title = title39,
                description = "  " + new string('x', 39) + "  ",
                severity = "High",
                occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-5)
            };

            using var response39 = await _client.PostAsJsonAsync("/api/incidents", body39);
            Assert.Equal(HttpStatusCode.BadRequest, response39.StatusCode);

            var json39 = await response39.Content.ReadAsStringAsync();
            using var doc39 = JsonDocument.Parse(json39);
            var errors = doc39.RootElement.GetProperty("errors");
            Assert.True(errors.TryGetProperty("description", out _));

            var body40 = new
            {
                title = title40,
                description = "  " + new string('x', 40) + "  ",
                severity = "High",
                occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-5)
            };

            using var response40 = await _client.PostAsJsonAsync("/api/incidents", body40);
            Assert.Equal(HttpStatusCode.Created, response40.StatusCode);
        }
        finally
        {
            await using var scope = factory.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            await db.Incidents
                .Where(item => item.Title == title39 || item.Title == title40)
                .ExecuteDeleteAsync();
        }
    }

    // T-03: Автоматичний тест предметного конфлікту (повторний активний title повертає 409 Conflict)
    [Fact]
    public async Task Post_WithDuplicateActiveTitle_Returns409ConflictProblemDetails()
    {
        var title = $"Regression-{Guid.NewGuid():N}";
        var body = new
        {
            title = $"  {title}  ",
            description = "Перший інцидент для перевірки конфлікту заголовка.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
        };

        try
        {
            using var firstResponse = await _client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Created, firstResponse.StatusCode);

            using var secondResponse = await _client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Conflict, secondResponse.StatusCode);
            Assert.Equal("application/problem+json", secondResponse.Content.Headers.ContentType?.MediaType);

            var json = await secondResponse.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(json);
            Assert.Equal(409, document.RootElement.GetProperty("status").GetInt32());
            Assert.DoesNotContain("Exception", json, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            await using var scope = factory.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            await db.Incidents
                .Where(item => item.Title == title)
                .ExecuteDeleteAsync();
        }
    }

    // S-02 та T-04: Retest SQLi та позитивна регресія (USB + легітимний апостроф)
    [Fact]
    public async Task Search_AfterFix_BlocksSqliAndSupportsLiteralSubstringAndApostrophe()
    {
        // S-02: Контрольний SQLi-ввід повертає порожній список
        var sqliQuery = "/api/incidents/search?q=" + Uri.EscapeDataString("zz-no-match' OR TRUE -- ");
        var sqliResults = await _client.GetFromJsonAsync<List<IncidentSearchResultResponse>>(sqliQuery);
        Assert.NotNull(sqliResults);
        Assert.Empty(sqliResults);

        // T-04: Звичайний пошук USB знаходить рівно один запис ...0005
        var usbResults = await _client.GetFromJsonAsync<List<IncidentSearchResultResponse>>(
            "/api/incidents/search?q=USB");
        Assert.NotNull(usbResults);
        var usbItem = Assert.Single(usbResults);
        Assert.Equal(Guid.Parse("20000000-0000-0000-0000-000000000005"), usbItem.Id);

        // T-04: Пошук з апострофом O'Brien повертає 200 OK та запис ...0004
        var apostropheQuery = "/api/incidents/search?q=" + Uri.EscapeDataString("O'Brien");
        var apostropheResults = await _client.GetFromJsonAsync<List<IncidentSearchResultResponse>>(apostropheQuery);
        Assert.NotNull(apostropheResults);
        var apostropheItem = Assert.Single(apostropheResults);
        Assert.Equal(Guid.Parse("20000000-0000-0000-0000-000000000004"), apostropheItem.Id);

        // Перевірка буквального пошуку % (екранування wildcard)
        var percentResults = await _client.GetFromJsonAsync<List<IncidentSearchResultResponse>>(
            "/api/incidents/search?q=%25");
        Assert.NotNull(percentResults);
        Assert.Empty(percentResults);
    }

    // T-05: Невідомий sortBy повертає 400 із ключем sortBy
    [Fact]
    public async Task Search_WithUnknownSortBy_Returns400WithSortByKey()
    {
        using var response = await _client.GetAsync("/api/incidents/search?sortBy=price");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        var errors = document.RootElement.GetProperty("errors");
        Assert.True(errors.TryGetProperty("sortBy", out _));
    }
}
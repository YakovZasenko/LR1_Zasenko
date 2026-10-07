using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

public static class Lab02Endpoints
{
    private static string EscapeLike(string value) =>
        value
            .Replace("\\", "\\\\")
            .Replace("%", "\\%")
            .Replace("_", "\\_");

    public static void MapLab02Endpoints(this WebApplication app)
    {
        // Безпечний параметризований пошук з для сортування
        app.MapGet("/api/incidents/search", async (
            string? q,
            string? sortBy,
            SecureLabDbContext db,
            CancellationToken ct) =>
        {
            var pattern = "%" + EscapeLike(q ?? "") + "%";

            var found = db.Incidents
                .AsNoTracking()
                .Where(incident =>
                    EF.Functions.ILike(incident.Title, pattern, "\\") ||
                    EF.Functions.ILike(incident.Description, pattern, "\\"));

            // Allowlist для sortBy з канонічними рангами за контрактом 2-A
            IQueryable<Incident>? ordered = sortBy switch
            {
                null or "" or "createdAtUtc" => found
                    .OrderByDescending(incident => incident.CreatedAtUtc)
                    .ThenBy(incident => incident.Id),

                "severity" => found
                    .OrderBy(incident =>
                        incident.Severity == IncidentSeverity.Critical ? 0 :
                        incident.Severity == IncidentSeverity.High ? 1 :
                        incident.Severity == IncidentSeverity.Medium ? 2 : 3)
                    .ThenBy(incident => incident.Id),

                "status" => found
                    .OrderBy(incident =>
                        incident.Status == IncidentStatus.New ? 0 :
                        incident.Status == IncidentStatus.Triaged ? 1 :
                        incident.Status == IncidentStatus.InProgress ? 2 :
                        incident.Status == IncidentStatus.Resolved ? 3 : 4)
                    .ThenBy(incident => incident.Id),

                _ => null
            };

            if (ordered is null)
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["sortBy"] = ["Допустимі значення sortBy: createdAtUtc, severity, status."]
                });
            }

            var items = await ordered
                .Take(50)
                .Select(incident => new IncidentSearchResultResponse(
                    incident.Id,
                    incident.Title,
                    incident.Description,
                    incident.Severity.ToString(),
                    incident.Status.ToString(),
                    incident.CreatedAtUtc))
                .ToListAsync(ct);

            return Results.Ok(items);
        });

        // Виправлений обробник POST /api/incidents (Контракт 2-A добрий рівень)
        app.MapPost("/api/incidents", async (
            CreateIncidentRequest request,
            SecureLabDbContext db,
            CancellationToken ct) =>
        {
            var now = DateTimeOffset.UtcNow;
            var errors = new Dictionary<string, string[]>();

            // перевірка title: required та довжина до Trim <= 160
            if (string.IsNullOrWhiteSpace(request.Title))
            {
                errors["title"] = ["Заголовок інциденту є обов'язковим."];
            }
            else if (request.Title.Length > 160)
            {
                errors["title"] = ["Заголовок інциденту не може перевищувати 160 символів."];
            }

            // перевірка description: required та довжина до Trim <= 4000
            if (string.IsNullOrWhiteSpace(request.Description))
            {
                errors["description"] = ["Опис інциденту є обов'язковим."];
            }
            else if (request.Description.Length > 4000)
            {
                errors["description"] = ["Опис інциденту не може перевищувати 4000 символів."];
            }

            // Перевірка severity: TryParse (без урахування регістру), Enum.IsDefined (блокує "7")
            var severityIsValid = Enum.TryParse<IncidentSeverity>(
                request.Severity,
                ignoreCase: true,
                out var severity) && Enum.IsDefined(severity);

            if (!severityIsValid)
            {
                errors["severity"] = ["Допустимі значення: Low, Medium, High, Critical."];
            }

            if (request.OccurredAtUtc is null)
            {
                errors["occurredAtUtc"] = ["Час виникнення інциденту є обов'язковим."];
            }
            else if (request.OccurredAtUtc.Value > now.AddMinutes(5))
            {
                errors["occurredAtUtc"] = ["Час виникнення не може випереджати поточний UTC-час сервера більш ніж на 5 хвилин."];
            }

            var title = request.Title?.Trim() ?? "";
            var description = request.Description?.Trim() ?? "";

            // Якщо severity High або Critical, description після Trim() має містити щонайменше 40 символів
            if (severityIsValid
                && (severity == IncidentSeverity.High || severity == IncidentSeverity.Critical)
                && !errors.ContainsKey("description")
                && description.Length < 40)
            {
                errors["description"] = ["Для рівня High або Critical опис після обрізання пробілів має містити щонайменше 40 символів."];
            }

            if (errors.Count > 0)
            {
                return Results.ValidationProblem(errors);
            }

            var hasActiveDuplicate = await db.Incidents.AnyAsync(
                incident => incident.Title == title && incident.Status != IncidentStatus.Closed,
                ct);

            if (hasActiveDuplicate)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status409Conflict,
                    title: "Конфлікт створення інциденту",
                    detail: "Активний інцидент із таким заголовком уже існує.");
            }

            var occurredAtUtc = request.OccurredAtUtc!.Value.ToUniversalTime();

            var incident = new Incident
            {
                Id = Guid.NewGuid(),
                Title = title,
                Description = description,
                Severity = severity,
                Status = IncidentStatus.New,
                OwnerUserId = DbSeeder.AliceId,
                OccurredAtUtc = occurredAtUtc,
                CreatedAtUtc = now,
                UpdatedAtUtc = now
            };

            db.Incidents.Add(incident);
            await db.SaveChangesAsync(ct);

            // Формування Response DTO
            var response = new CreatedIncidentResponse(
                incident.Id,
                incident.Title,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc);

            return Results.Created($"/api/incidents/{incident.Id}", response);
        });
    }
}

public sealed record CreateIncidentRequest(
    string? Title,
    string? Description,
    string? Severity,
    DateTimeOffset? OccurredAtUtc);

public sealed record CreatedIncidentResponse(
    Guid Id,
    string Title,
    string Severity,
    string Status,
    DateTimeOffset OccurredAtUtc,
    DateTimeOffset CreatedAtUtc);

public sealed record IncidentSearchResultResponse(
    Guid Id,
    string Title,
    string Description,
    string Severity,
    string Status,
    DateTimeOffset CreatedAtUtc);
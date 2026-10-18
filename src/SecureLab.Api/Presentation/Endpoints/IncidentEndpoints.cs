using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Presentation.Contracts;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Presentation.Endpoints;

public static class IncidentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents")
            .RequireAuthorization();

        group.MapGet("/", GetListAsync);
        group.MapGet("/severity-summary", GetSeveritySummaryAsync);
        group.MapGet("/{id:guid}", GetDetailsAsync);
        group.MapPut("/{id:guid}", UpdateAsync);
        group.MapDelete("/{id:guid}", DeleteAsync);
        group.MapPost("/{id:guid}/triage", TriageAsync);

        endpoints.MapGet("/api/incident-comments/{id:guid}", GetCommentAsync)
            .WithTags("Incidents")
            .RequireAuthorization();

        return endpoints;
    }

    private static async Task<IResult> GetListAsync(
        string? status,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        IncidentStatus? parsedStatus = null;
        if (!string.IsNullOrWhiteSpace(status))
        {
            if (!Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var value))
            {
                return Results.Problem(
                    title: "Некоректний фільтр статусу",
                    detail: $"Статус '{status}' не підтримується.",
                    statusCode: StatusCodes.Status400BadRequest);
            }

            parsedStatus = value;
        }

        if (!TryGetUserContext(httpContext, out var ownerId, out var isAnalyst))
        {
            return Results.Challenge();
        }

        var items = await queries.GetListAsync(parsedStatus, ownerId, isAnalyst, cancellationToken);
        return Results.Ok(items);
    }

    private static async Task<IResult> GetSeveritySummaryAsync(
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        if (!TryGetUserContext(httpContext, out var ownerId, out var isAnalyst))
        {
            return Results.Challenge();
        }

        var summary = await queries.GetSeveritySummaryAsync(ownerId, isAnalyst, cancellationToken);
        return Results.Ok(summary);
    }

    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        if (!TryGetUserContext(httpContext, out var ownerId, out var isAnalyst))
        {
            return Results.Challenge();
        }

        var incident = await queries.GetDetailsAsync(id, ownerId, isAnalyst, cancellationToken);
        return incident is null
            ? IncidentNotFound()
            : Results.Ok(incident);
    }

    private static async Task<IResult> UpdateAsync(
        Guid id,
        UpdateIncidentRequest request,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);

        if (incident is null)
        {
            return IncidentNotFound();
        }

        var decision = await authorizationService.AuthorizeAsync(
            httpContext.User,
            incident,
            IncidentOperations.Update);

        if (!decision.Succeeded)
        {
            return IncidentNotFound();
        }

        var title = request.Title?.Trim() ?? string.Empty;
        var description = request.Description?.Trim() ?? string.Empty;
        if (title.Length is < 5 or > 120 || description.Length is < 10 or > 2000)
        {
            return Results.Problem(
                title: "Некоректні дані оновлення",
                statusCode: StatusCodes.Status400BadRequest);
        }

        if (!string.IsNullOrWhiteSpace(request.Severity))
        {
            if (!Enum.TryParse<IncidentSeverity>(request.Severity.Trim(), ignoreCase: true, out var severity)
                || !Enum.IsDefined(severity))
            {
                return Results.Problem(
                    title: "Некоректний рівень критичності",
                    statusCode: StatusCodes.Status400BadRequest);
            }

            incident.Severity = severity;
        }

        incident.Title = title;
        incident.Description = description;
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;

        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> DeleteAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);

        if (incident is null)
        {
            return IncidentNotFound();
        }

        var decision = await authorizationService.AuthorizeAsync(
            httpContext.User,
            incident,
            IncidentOperations.Delete);

        if (!decision.Succeeded)
        {
            return IncidentNotFound();
        }

        dbContext.Incidents.Remove(incident);
        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> TriageAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext dbContext,
        ILogger<Program> logger,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);

        if (incident is null)
        {
            return IncidentNotFound();
        }

        var decision = await authorizationService.AuthorizeAsync(
            httpContext.User,
            incident,
            IncidentOperations.Triage);

        if (!decision.Succeeded)
        {
            var traceId = Activity.Current?.Id ?? httpContext.TraceIdentifier;
            logger.LogWarning(
                "authorization.denied subject={SubjectId} action={Action} resource={ResourceId} result={Result} occurredAtUtc={OccurredAtUtc:O} traceId={TraceId}",
                httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier),
                "incident.triage",
                incident.Id,
                "denied",
                DateTimeOffset.UtcNow,
                traceId);

            return Results.Problem(
                title: "Forbidden",
                statusCode: StatusCodes.Status403Forbidden);
        }

        if (incident.Status != IncidentStatus.New)
        {
            return Results.Problem(
                title: "Перехід стану дозволено лише зі статусу New",
                statusCode: StatusCodes.Status409Conflict);
        }

        incident.Status = IncidentStatus.Triaged;
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    private static async Task<IResult> GetCommentAsync(
        Guid id,
        HttpContext httpContext,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        if (!TryGetUserContext(httpContext, out var ownerId, out var isAnalyst))
        {
            return Results.Challenge();
        }

        var comment = await dbContext.IncidentComments
            .AsNoTracking()
            .Where(c => c.Id == id
                && (isAnalyst || c.Incident.OwnerUserId == ownerId)
                && (isAnalyst || !c.IsInternal))
            .Select(c => new IncidentCommentResponse(
                c.Id,
                c.Author.DisplayName,
                c.Text,
                c.CreatedAtUtc))
            .SingleOrDefaultAsync(cancellationToken);

        return comment is null
            ? IncidentNotFound()
            : Results.Ok(comment);
    }

    private static bool TryGetUserContext(HttpContext httpContext, out Guid userId, out bool isAnalyst)
    {
        var userIdValue = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        isAnalyst = httpContext.User.IsInRole(DbSeeder.AnalystRole);
        return Guid.TryParse(userIdValue, out userId);
    }

    private static IResult IncidentNotFound() => Results.Problem(
        title: "Інцидент не знайдено",
        statusCode: StatusCodes.Status404NotFound);
}

public sealed record UpdateIncidentRequest(
    string? Title,
    string? Description,
    string? Severity);



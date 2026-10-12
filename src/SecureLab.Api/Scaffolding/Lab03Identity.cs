using System.Net.Mail;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {
        // ---------- REGISTER ----------
        app.MapPost("/api/auth/register", async (RegistrationInput input, UserManager<ApplicationUser> users) =>
        {
            var errors = ValidateRegistration(input);
            if (errors.Count > 0) return Results.ValidationProblem(errors);

            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                UserName = input.UserName!.Trim(),
                Email = input.Email!.Trim(),
                DisplayName = input.DisplayName!.Trim()
            };
            var result = await users.CreateAsync(user, input.Password!);
            if (!result.Succeeded)
            {
                var codes = result.Errors.Select(error => error.Code).ToArray();
                if (codes.Any(code => code is "DuplicateUserName" or "DuplicateEmail"))
                    return Results.Conflict(new { message = "Account already exists" });
                return Results.BadRequest(new { message = "Registration failed", codes });
            }
            var role = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
            if (!role.Succeeded) throw new InvalidOperationException("Default role assignment failed.");
            return Results.Created("/api/me", new RegisterResponse(user.Id, user.UserName!, user.DisplayName));
        });

        // ---------- LOGIN ----------
        app.MapPost("/api/auth/login", async (
            LoginInput input,
            SignInManager<ApplicationUser> signIn,
            HttpContext context,
            ILogger<Program> logger) =>
        {
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrEmpty(input.Password))
            {
                LogAuthEvent(logger, "login", "failure", context);
                return Results.Unauthorized();
            }
            var result = await signIn.PasswordSignInAsync(input.UserName, input.Password, false, false);
            LogAuthEvent(logger, "login", result.Succeeded ? "success" : "failure", context);
            return result.Succeeded ? Results.NoContent() : Results.Unauthorized();
        }).RequireRateLimiting("login");

        // ---------- LOGOUT ----------
        app.MapPost("/api/auth/logout", async (
            SignInManager<ApplicationUser> signIn,
            HttpContext context,
            ILogger<Program> logger) =>
        {
            await signIn.SignOutAsync();
            LogAuthEvent(logger, "logout", "success", context);
            return Results.NoContent();
        });

        app.MapGet("/api/me", GetCurrentUser).RequireAuthorization();

        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }

    private static IResult GetCurrentUser(HttpContext httpContext)
    {
        var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userId, out var verifiedUserId))
        {
            return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);
        }

        var userName = httpContext.User.FindFirst(ClaimTypes.Name)?.Value ?? string.Empty;
        var role = httpContext.User.FindFirst(ClaimTypes.Role)?.Value ?? string.Empty;
        return Results.Ok(new MeResponse(verifiedUserId, userName, role));
    }

    private static void LogAuthEvent(ILogger logger, string eventType, string result, HttpContext context) =>
        logger.LogInformation("Auth event {EventType}: result {Result}, trace {TraceId}",
            eventType, result, context.TraceIdentifier);

    private static Dictionary<string, string[]> ValidateRegistration(RegistrationInput input)
    {
        var errors = new Dictionary<string, string[]>();

        var userName = input.UserName?.Trim();
        if (string.IsNullOrEmpty(userName))
            errors["userName"] = ["Ім'я користувача є обов'язковим."];
        else if (userName.Length is < 3 or > 50)
            errors["userName"] = ["Довжина імені користувача — від 3 до 50 символів."];
        else if (!userName.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '@' or '+'))
            errors["userName"] = ["Дозволені лише латинські літери, цифри та символи - . _ @ +"];

        var email = input.Email?.Trim();
        if (string.IsNullOrEmpty(email))
            errors["email"] = ["Email є обов'язковим."];
        else if (email.Length > 256 || !MailAddress.TryCreate(email, out var parsed) || parsed.Address != email)
            errors["email"] = ["Email має некоректний формат або задовгий (макс. 256)."];

        var displayName = input.DisplayName?.Trim();
        if (string.IsNullOrEmpty(displayName))
            errors["displayName"] = ["Відображуване ім'я є обов'язковим."];
        else if (displayName.Length > 120)
            errors["displayName"] = ["Відображуване ім'я не може перевищувати 120 символів."];

        if (string.IsNullOrEmpty(input.Password))
            errors["password"] = ["Пароль є обов'язковим."];
        else if (input.Password.Length > 128)
            errors["password"] = ["Пароль не може перевищувати 128 символів."];

        return errors;
    }
}

public sealed record RegistrationInput(string? UserName, string? Email, string? DisplayName, string? Password);
public sealed record LoginInput(string? UserName, string? Password);
public sealed record RegisterResponse(Guid Id, string UserName, string DisplayName);
public sealed record MeResponse(Guid UserId, string UserName, string Role);

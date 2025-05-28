namespace HotelReservationSystem.Middleware;

public class ApplicationInsightsTelemetryMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ApplicationInsightsTelemetryMiddleware> _logger;

    public ApplicationInsightsTelemetryMiddleware(
        RequestDelegate next,
        ILogger<ApplicationInsightsTelemetryMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled exception");
            throw;
        }
    }
}

public static class ApplicationInsightsTelemetryMiddlewareExtensions
{
    public static IApplicationBuilder UseApplicationInsightsTelemetry(
        this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<ApplicationInsightsTelemetryMiddleware>();
    }
}
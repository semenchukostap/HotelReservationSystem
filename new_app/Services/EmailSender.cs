using Microsoft.AspNetCore.Identity.UI.Services;

namespace HotelReservationSystem.Services
{
    public class EmailSender : IEmailSender
    {
        private readonly ILogger<EmailSender> _logger;

        public EmailSender(ILogger<EmailSender> logger)
        {
            _logger = logger;
        }

        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            // Implementation would go here - similar to the EmailService in the legacy app
            _logger.LogInformation($"Email: {email}, Subject: {subject}");
            return Task.CompletedTask;
        }
    }
}
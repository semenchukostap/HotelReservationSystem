namespace HotelReservationSystem.Services
{
    public interface ISmsSender
    {
        Task SendSmsAsync(string number, string message);
    }

    public class SmsSender : ISmsSender
    {
        public Task SendSmsAsync(string number, string message)
        {
            // Implementation would go here
            return Task.CompletedTask;
        }
    }
}
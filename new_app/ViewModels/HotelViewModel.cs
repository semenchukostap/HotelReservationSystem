using new_app.Models;

namespace new_app.ViewModels
{
    public class HotelViewModel
    {
        public Hotel? Hotel { get; set; }
        public IEnumerable<Country> Countries { get; set; } = new List<Country>();
    }
}
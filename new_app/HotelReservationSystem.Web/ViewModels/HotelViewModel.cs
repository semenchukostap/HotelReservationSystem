using HotelReservationSystem.Core.Models;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace HotelReservationSystem.Web.ViewModels
{
    public class HotelViewModel
    {
        public Hotel? Hotel { get; set; }
        public IEnumerable<Country>? Countries { get; set; }
        public IEnumerable<SelectListItem>? CountryOptions => Countries?.Select(c => new SelectListItem
        {
            Value = c.Id.ToString(),
            Text = c.Name
        });
    }
}
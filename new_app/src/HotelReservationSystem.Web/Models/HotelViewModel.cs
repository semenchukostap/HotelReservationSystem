using HotelReservationSystem.Core.DTOs;
using System.Collections.Generic;

namespace HotelReservationSystem.Web.Models;

public class HotelViewModel
{
    public HotelDto Hotel { get; set; } = new HotelDto();
    public IEnumerable<CountryDto> Countries { get; set; } = new List<CountryDto>();
}
using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Data
{
    public class AutoMapperProfile : Profile
    {
        public AutoMapperProfile()
        {
            // Define all mappings here
            CreateMap<Hotel, HotelDto>()
                .ForMember(dto => dto.Country, opt => opt.MapFrom(h => h.Country != null ? h.Country.Name : string.Empty));
            
            CreateMap<HotelDto, Hotel>();
            
            CreateMap<Country, CountryDto>();
            CreateMap<CountryDto, Country>();
        }
    }
}
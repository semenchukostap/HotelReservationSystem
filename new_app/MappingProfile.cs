using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            // Domain to DTO
            CreateMap<Hotel, HotelDto>()
                .ForMember(dto => dto.CountryName, opt => opt.MapFrom(h => h.Country != null ? h.Country.Name : string.Empty));
            
            CreateMap<Country, CountryDto>();
            
            // DTO to Domain
            CreateMap<HotelDto, Hotel>();
            CreateMap<CountryDto, Country>();
            CreateMap<NewOrderDto, Order>();
        }
    }
}
using AutoMapper;
using HotelReservationSystem.Core.DTOs;
using HotelReservationSystem.Core.Models;

namespace HotelReservationSystem.Core.Data;

public class MappingProfile : Profile
{
    public MappingProfile()
    {
        // Define mappings between domain entities and DTOs
        CreateMap<Country, CountryDto>();
        
        CreateMap<Hotel, HotelDto>()
            .ForMember(dto => dto.Country, opt => opt.MapFrom(h => h.Country!.Name));
        CreateMap<HotelDto, Hotel>();

        CreateMap<NewOrderDto, Order>();
    }
}
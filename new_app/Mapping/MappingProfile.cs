using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Mapping
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            // Domain to DTO
            CreateMap<Hotel, HotelDto>()
                .ForMember(dto => dto.CountryName, opt => opt.MapFrom(h => h.Country.Name));

            CreateMap<Country, CountryDto>();

            // DTO to Domain
            CreateMap<HotelDto, Hotel>()
                .ForMember(h => h.Country, opt => opt.Ignore());

            CreateMap<CountryDto, Country>();
            
            CreateMap<NewOrderDto, Order>()
                .ForMember(o => o.Customer, opt => opt.Ignore())
                .ForMember(o => o.Hotel, opt => opt.Ignore())
                .ForMember(o => o.DateOrdered, opt => opt.Ignore())
                .ForMember(o => o.NumberOfDays, opt => opt.Ignore())
                .ForMember(o => o.FullPrice, opt => opt.Ignore());
        }
    }
}
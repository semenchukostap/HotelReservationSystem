using AutoMapper;
using new_app.DTOs;
using new_app.Models;

namespace new_app.MappingProfiles
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            // Domain to DTO
            CreateMap<Country, CountryDto>();
            CreateMap<Hotel, HotelDto>();
            
            // DTO to Domain
            CreateMap<CountryDto, Country>();
            CreateMap<HotelDto, Hotel>();
            
            // Order mappings
            CreateMap<NewOrderDto, Order>()
                .ForMember(o => o.DateOrdered, opt => opt.MapFrom(src => DateTime.Now))
                .ForMember(o => o.Id, opt => opt.Ignore())
                .ForMember(o => o.Customer, opt => opt.Ignore())
                .ForMember(o => o.Hotel, opt => opt.Ignore())
                .ForMember(o => o.NumberOfDays, opt => opt.Ignore())
                .ForMember(o => o.FullPrice, opt => opt.Ignore());
        }
    }
}
using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Helpers
{
    /// <summary>
    /// Defines AutoMapper profiles for mapping between entities and DTOs
    /// </summary>
    public class MappingProfiles : Profile
    {
        public MappingProfiles()
        {
            // Hotel mappings
            CreateMap<Hotel, HotelDto>();
            CreateMap<HotelDto, Hotel>();

            // Country mappings
            CreateMap<Country, CountryDto>();
            CreateMap<CountryDto, Country>();

            // Customer mappings
            CreateMap<Customer, CustomerDto>();
            CreateMap<CustomerDto, Customer>();

            // Order mappings
            CreateMap<Order, OrderDto>();
            CreateMap<OrderDto, Order>();
            
            // NewOrder DTO mapping
            CreateMap<NewOrderDto, Order>()
                .ForMember(dest => dest.Id, opt => opt.Ignore())
                .ForMember(dest => dest.Customer, opt => opt.Ignore())
                .ForMember(dest => dest.Hotel, opt => opt.Ignore())
                .ForMember(dest => dest.DateOrdered, opt => opt.MapFrom(src => DateTime.Now))
                .ForMember(dest => dest.NumberOfDays, opt => opt.MapFrom(src => 
                    (int)(src.EndDate - src.StartDate).TotalDays))
                .ForMember(dest => dest.FullPrice, opt => opt.Ignore());

            // ApplicationUser mappings if needed
            CreateMap<ApplicationUser, ApplicationUserDto>();
            CreateMap<ApplicationUserDto, ApplicationUser>()
                .ForMember(dest => dest.PasswordHash, opt => opt.Ignore())
                .ForMember(dest => dest.SecurityStamp, opt => opt.Ignore());
        }
    }
}
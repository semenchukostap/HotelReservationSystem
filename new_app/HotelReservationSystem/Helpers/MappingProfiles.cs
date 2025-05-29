using AutoMapper;
using HotelReservationSystem.DTOs;
using HotelReservationSystem.Models;
using System;

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
            CreateMap<Hotel, HotelDto>().ReverseMap();

            // Country mappings
            CreateMap<Country, CountryDto>().ReverseMap();

            // Customer mappings
            CreateMap<Customer, CustomerDto>().ReverseMap();

            // Order mappings
            CreateMap<Order, OrderDto>().ReverseMap();
            
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
                .ForMember(dest => dest.SecurityStamp, opt => opt.Ignore())
                .ForMember(dest => dest.ConcurrencyStamp, opt => opt.Ignore())
                .ForMember(dest => dest.NormalizedEmail, opt => opt.Ignore())
                .ForMember(dest => dest.NormalizedUserName, opt => opt.Ignore());
        }
    }
}

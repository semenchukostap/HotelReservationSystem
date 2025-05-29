# Hotel Reservation System (.NET 8)

This is a migrated version of the Hotel Reservation System application from .NET Framework 4.5.2 to .NET 8.

## Getting Started

1. Ensure you have .NET 8 SDK installed
2. Clone the repository
3. Update the connection string in `appsettings.json`
4. Run the application:
   ```
   cd HotelReservationSystem.Web
   dotnet run
   ```
5. Navigate to `https://localhost:5001` in your browser

## Features

- Hotel Management
- Customer Management
- Reservation System
- User Authentication and Authorization
- Admin Dashboard

## Technology Stack

- .NET 8
- ASP.NET Core MVC
- Entity Framework Core 8
- ASP.NET Core Identity
- Bootstrap 5
- jQuery
- DataTables
- AutoMapper

## Database Migration

If you need to recreate the database:

```
cd HotelReservationSystem.Data
dotnet ef migrations add InitialCreate --startup-project ../HotelReservationSystem.Web/
dotnet ef database update --startup-project ../HotelReservationSystem.Web/
```
# Hotel Reservation System (.NET 8)

This folder contains the migrated Hotel Reservation System application, converted from .NET Framework 4.5.2/ASP.NET MVC 5 to .NET 8/ASP.NET Core MVC.

## Configuration Structure

The application uses a structured configuration approach following .NET best practices. Configuration is primarily stored in `appsettings.json` with environment-specific overrides in `appsettings.{Environment}.json`.

### Connection Strings

Database connections are configured in the ConnectionStrings section:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\MSSQLLocalDB;Database=HotelReservation;Trusted_Connection=True;MultipleActiveResultSets=true",
    "LoggingConnection": "Server=(localdb)\\MSSQLLocalDB;Database=HotelReservationLogs;Trusted_Connection=True"
  }
}
```

### Logging Configuration

Application logging is configured using the built-in .NET logging providers:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning",
      "Microsoft.Hosting.Lifetime": "Information"
    },
    "File": {
      "Path": "logs/hotel-app.log",
      "FileSizeLimitBytes": 10485760,
      "RetainedFileCountLimit": 10
    },
    "Console": {
      "LogLevel": {
        "Default": "Information"
      }
    }
  }
}
```

### Application Insights

Azure Application Insights integration is configured as follows:

```json
{
  "ApplicationInsights": {
    "ConnectionString": "InstrumentationKey=your-key-here;IngestionEndpoint=https://region.in.applicationinsights.azure.com/",
    "EnableAdaptiveSampling": true,
    "EnablePerformanceCounterCollectionModule": true,
    "EnableQuickPulseMetricStream": true
  }
}
```

### Authentication Providers

The system supports multiple authentication providers:

```json
{
  "Authentication": {
    "Google": {
      "ClientId": "your-client-id",
      "ClientSecret": "your-client-secret"
    },
    "Microsoft": {
      "ClientId": "your-client-id",
      "ClientSecret": "your-client-secret",
      "TenantId": "your-tenant-id"
    },
    "Facebook": {
      "AppId": "your-app-id",
      "AppSecret": "your-app-secret"
    },
    "JwtBearer": {
      "Authority": "https://your-authority.com",
      "Audience": "api://your-audience",
      "RequireHttpsMetadata": true
    }
  }
}
```

### Identity Settings

ASP.NET Core Identity is configured with the following settings:

```json
{
  "Identity": {
    "Password": {
      "RequireDigit": true,
      "RequiredLength": 8,
      "RequireLowercase": true,
      "RequireNonAlphanumeric": true,
      "RequireUppercase": true
    },
    "Lockout": {
      "DefaultLockoutTimeSpan": "00:15:00",
      "MaxFailedAccessAttempts": 5,
      "AllowedForNewUsers": true
    },
    "User": {
      "RequireUniqueEmail": true,
      "AllowedUserNameCharacters": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+"
    },
    "SignIn": {
      "RequireConfirmedAccount": true,
      "RequireConfirmedEmail": true,
      "RequireConfirmedPhoneNumber": false
    }
  }
}
```

### Admin User Configuration

The initial system administrator account can be configured during application startup:

```json
{
  "AdminUser": {
    "Username": "admin@hotel.com",
    "Email": "admin@hotel.com",
    "Password": "Admin_Password_123",
    "FirstName": "System",
    "LastName": "Administrator",
    "CreateIfNotExists": true
  }
}
```
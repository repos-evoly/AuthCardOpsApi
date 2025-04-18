using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using AuthCardOpsApi.Data.Context;
using AuthCardOpsApi.Core.Dtos;
using AuthCardOpsApi.Validators;
using FluentValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Microsoft.Extensions.DependencyInjection;
using AuthCardOpsApi.Core.Filters;
using AuthCardOpsApi.Core.Repositories;
using Microsoft.AspNetCore.Builder;
using AuthCardOpsApi.Core.Abstractions;
using Microsoft.Extensions.Hosting;
using AuthCardOpsApi.Data.Seeding;

namespace AuthCardOpsApi.Core.Startup
{
  public static class DependencyInjectionSetup
  {
    public static WebApplicationBuilder RegisterServices(this WebApplicationBuilder builder)
    {
      var issuer = builder.Configuration["Jwt:Issuer"] ?? throw new ArgumentNullException("Jwt:Issuer is missing in configuration.");
      var audience = builder.Configuration["Jwt:Audience"] ?? throw new ArgumentNullException("Jwt:Audience is missing in configuration.");
      var jwtKey = builder.Configuration["Jwt:Key"] ?? throw new ArgumentNullException("Jwt:Key is missing in configuration.");

      builder.Services.RegisterCors();
      builder.Services.RegisterSwagger();
      builder.Services.RegisterAuths(issuer, audience, jwtKey);
      if (builder.Environment.IsDevelopment())
      {
        builder.Services.AddDbContext<AuthCardOpsApiDbContext>(opt => opt.UseSqlServer(builder.Configuration["ConnectionStrings:DevConnection"]));
      }
      else if (builder.Environment.IsStaging())
      {
        builder.Services.AddDbContext<AuthCardOpsApiDbContext>(opt => opt.UseSqlServer(builder.Configuration["ConnectionStrings:StagingConnection"]));
      }
      else
      {
        builder.Services.AddDbContext<AuthCardOpsApiDbContext>(opt =>
        {
          opt.UseSqlServer(builder.Configuration["ConnectionStrings:ProdConnection"]);
        });
      }
      builder.Services.AddHttpContextAccessor();
      builder.Services.AddTransient<DataSeeder>();
      builder.Services.AddAutoMapper(typeof(MappingConfig));
      builder.Services.Configure<JsonOptions>(options =>
      {
        options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
        options.SerializerOptions.WriteIndented = true;
        options.SerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
        options.SerializerOptions.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.CamelCase));
      });

      builder.Services.RegisterValidators();
      builder.Services.RegisterRepos();
      return builder;
    }

    public static IServiceCollection RegisterCors(this IServiceCollection cors)
    {
      cors.AddCors(options =>
            {
              options.AddPolicy("AllowSpecificOrigins",
                    builder =>
                    {
                      builder.WithOrigins("http://localhost:3000",
                                          "http://localhost:3010",
                                          "http://10.3.3.11:3010",
                                          "http://localhost:5000",
                                          "http://10.1.1.205:3010")
                             .AllowAnyHeader()
                             .AllowAnyMethod()
                             .AllowCredentials();
                    });
            });
      return cors;
    }

    public static IServiceCollection RegisterAuths(this IServiceCollection auth, string issuer, string audience, string jwtKey)
    {
      auth.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
      .AddCookie(options =>
      {
        options.Cookie.Name = "AuthToken";
      })
      .AddJwtBearer(options =>
            {
              options.RequireHttpsMetadata = false;
              options.SaveToken = true;
              options.TokenValidationParameters = new TokenValidationParameters()
              {
                ValidateActor = true,
                ValidateAudience = true,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true,
                ValidIssuer = issuer,
                ValidAudience = audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
              };
              options.Events = new JwtBearerEvents
              {
                OnMessageReceived = context =>
                {
                  if (context.Request.Cookies.ContainsKey("AuthToken"))
                  {
                    context.Token = context.Request.Cookies["AuthToken"];
                  }
                  return Task.CompletedTask;
                },
                // The below should be uncommented in case the above "ValidateLifetime = true"
                // OnAuthenticationFailed = context =>
                // {
                //   if (context.Exception is SecurityTokenExpiredException)
                //   {
                //     // Handle token expiration
                //     context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                //     context.Response.ContentType = "application/json";
                //     context.Response.WriteAsync(JsonSerializer.Serialize(new Error
                //     {
                //       StatusCode = StatusCodes.Status401Unauthorized,
                //       Message = "Expired token. Please logout and then login."
                //     })).Wait(); // Use .Wait() to write the response immediately
                //     return Task.CompletedTask;
                //   }
                //   return Task.CompletedTask;
                // }
              };
            });
      // Define the set or roles in policies
      auth.AddAuthorization(a =>
      {
        a.AddPolicy("requireAuthUser", b => b
              .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
              .RequireAuthenticatedUser());
        a.AddPolicy("AdmMak", b => b.RequireRole("SuperAdmin", "Admin", "Maker"));
        a.AddPolicy("AdmChk", b => b.RequireRole("SuperAdmin", "Admin", "Checker", "GeneralChecker"));
        a.AddPolicy("AdmMakChk", b => b.RequireRole("SuperAdmin", "Admin", "Maker", "Checker", "GeneralChecker"));
        a.AddPolicy("AdmViwChk", b => b.RequireRole("SuperAdmin", "Admin", "Viewer", "Checker", "GeneralChecker"));
      });
      return auth;
    }

    public static IServiceCollection RegisterValidators(this IServiceCollection validators)
    {



      return validators;
    }

    public static IServiceCollection RegisterRepos(this IServiceCollection services)
    {
      services.AddEndpointsApiExplorer();
      services.AddScoped(typeof(IRepository<>), typeof(Repository<>));
      services.AddScoped<IQrCodeRepository, QrCodeRepository>();
      services.AddTransient<IUnitOfWork, UnitOfWork>();

      return services;
    }


    public static IServiceCollection RegisterSwagger(this IServiceCollection services)
    {
      services.AddSwaggerGen(options =>
          {
            options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
              Scheme = "Bearer",
              BearerFormat = "JWT",
              In = ParameterLocation.Header,
              Name = "Authorization",
              Description = "Bearer Authentication with JWT Token",
              Type = SecuritySchemeType.Http
            });
            options.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
              {
                new OpenApiSecurityScheme
                {
                  Reference = new OpenApiReference
                  {
                    Id = "Bearer",
                    Type = ReferenceType.SecurityScheme
                  }
                },
                new List<string>()
              }
            });
            options.OperationFilter<FileUploadOperationFilter>();
          });

      return services;
    }
  }
}
using AutoMapper;
using AuthApi.Data.Models;
using AuthApi.Core.Dtos;

namespace AuthApi
{
  public class MappingConfig : Profile
  {
    public MappingConfig()
        {
            

            // Role Mappings
            CreateMap<Role, RoleDto>().ReverseMap();
            CreateMap<Role, EditRoleDto>().ReverseMap();

            // User Mappings
            CreateMap<User, UserDto>().ReverseMap();
            CreateMap<User, EditUserDto>().ReverseMap();
        }
   

    private static void MapNullableFloats(Customer source, CustomerDto destination)
    {
      var floatProperties = typeof(CustomerDto).GetProperties()
          .Where(p => p.PropertyType == typeof(float?) && p.GetSetMethod() != null);

      foreach (var property in floatProperties)
      {
        var sourceProperty = source.GetType().GetProperty(property.Name);
        if (sourceProperty != null)
        {
          var sourceValue = (float?)sourceProperty.GetValue(source);
          property.SetValue(destination, sourceValue ?? 0f);
        }
      }
    }
  }
}
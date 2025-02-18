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
   

   
  }
}
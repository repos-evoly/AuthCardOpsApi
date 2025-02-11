using AuthApi.Core.Dtos;
using AuthApi.Data.Models;
using Microsoft.AspNetCore.Http;

namespace AuthApi.Core.Abstractions
{
  public interface IMigrationRepository
  {
    public string GetRawData();
    public string CleanData();
    public Task<string> MigrateCustomers();
    public string MigrateCustomerRelatedData();
  }
}

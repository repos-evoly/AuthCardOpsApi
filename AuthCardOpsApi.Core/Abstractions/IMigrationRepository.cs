using AuthCardOpsApi.Core.Dtos;
using AuthCardOpsApi.Data.Models;
using Microsoft.AspNetCore.Http;

namespace AuthCardOpsApi.Core.Abstractions
{
  public interface IMigrationRepository
  {
    public string GetRawData();
    public string CleanData();
    public Task<string> MigrateCustomers();
    public string MigrateCustomerRelatedData();
  }
}

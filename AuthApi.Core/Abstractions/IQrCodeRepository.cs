using System.Threading.Tasks;

namespace AuthApi.Core.Abstractions
{
    public interface IQrCodeRepository
    {
        Task<string> GenerateAndSaveQrCodeAsync(string email, string secretKey);
        Task<byte[]> GetQrCodeAsync(string fileName);
        Task<bool> DeleteQrCodeAsync(string fileName);
    }
}

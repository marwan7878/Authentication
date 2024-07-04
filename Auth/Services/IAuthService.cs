using Auth.Models;

namespace Auth.Services
{
    public interface IAuthService
    {
        Task<Authentication> RegisterAsync(Register model);
    }
}

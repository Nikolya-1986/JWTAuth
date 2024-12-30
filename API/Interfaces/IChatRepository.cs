using API.Dtos;

namespace API.Interfaces
{
    public interface IChatRepository
    {
        Task<IEnumerable<ChatMessage>> GetMessagesForUser(string userId);
        Task AddMessage(ChatMessage message);
        Task SaveChangesAsync();   
    }
}
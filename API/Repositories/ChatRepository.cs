using Microsoft.EntityFrameworkCore;
using API.Interfaces;
using API.Data;
using API.Dtos;

namespace Repositories
{
    public class ChatRepository : IChatRepository
    {
        private readonly AppDbContext _context;

        public ChatRepository(AppDbContext context)
        {
            _context = context;
        }

        public async Task<IEnumerable<ChatMessage>> GetMessagesForUser(string userId)
        {
            return await _context.ChatMessages
                .Where(m => m.ReceiverId == userId || m.SenderId == userId)
                .ToListAsync();
        }

        public async Task AddMessage(ChatMessage message)
        {
            await _context.ChatMessages.AddAsync(message);
        }

        public async Task SaveChangesAsync()
        {
            await _context.SaveChangesAsync();
        }
    }
}
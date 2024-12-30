using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using API.Models;
using API.Dtos;

namespace API.Data
{
    public class AppDbContext:IdentityDbContext<AppUser>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options): base(options)
        {

        }    
        public DbSet<ChatMessage> ChatMessages { get; set; }
        // public DbSet<User> Users { get; set; }
    }
}
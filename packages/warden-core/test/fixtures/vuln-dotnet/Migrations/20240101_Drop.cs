using Microsoft.EntityFrameworkCore.Migrations;
public partial class Drop : Migration {
    protected override void Up(MigrationBuilder migrationBuilder) {
        migrationBuilder.DropColumn(name: "Phone", table: "Users");
        migrationBuilder.DropTable(name: "LegacySessions");
    }
}

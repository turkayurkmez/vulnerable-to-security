using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace VulnerableIssuerAPI.Migrations
{
    /// <inheritdoc />
    public partial class state_machine : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "FailureReason",
                table: "Transactions",
                newName: "UpdatedAt");

            migrationBuilder.RenameColumn(
                name: "CVV",
                table: "Cards",
                newName: "HoldBalance");

            migrationBuilder.AlterColumn<int>(
                name: "Status",
                table: "Transactions",
                type: "INTEGER",
                nullable: false,
                oldClrType: typeof(string),
                oldType: "TEXT");

            migrationBuilder.AddColumn<string>(
                name: "DeclineReason",
                table: "Transactions",
                type: "TEXT",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "DeclineReason",
                table: "Transactions");

            migrationBuilder.RenameColumn(
                name: "UpdatedAt",
                table: "Transactions",
                newName: "FailureReason");

            migrationBuilder.RenameColumn(
                name: "HoldBalance",
                table: "Cards",
                newName: "CVV");

            migrationBuilder.AlterColumn<string>(
                name: "Status",
                table: "Transactions",
                type: "TEXT",
                nullable: false,
                oldClrType: typeof(int),
                oldType: "INTEGER");
        }
    }
}

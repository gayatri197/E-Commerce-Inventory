import java.sql.*;
import java.util.Scanner;

public class ProductDAO {

    public static void addProduct() throws Exception {
        Scanner sc = new Scanner(System.in);
        System.out.print("Name: "); String name = sc.nextLine();
        System.out.print("Description: "); String desc = sc.nextLine();
        System.out.print("Price: "); double price = sc.nextDouble();
        System.out.print("Stock: "); int stock = sc.nextInt();
        System.out.print("Category ID: "); int categoryId = sc.nextInt();

        Connection con = DBConnection.getConnection();
        String sql = "INSERT INTO products(name, description, price, stock, category_id) VALUES (?, ?, ?, ?, ?)";
        PreparedStatement stmt = con.prepareStatement(sql);
        stmt.setString(1, name);
        stmt.setString(2, desc);
        stmt.setDouble(3, price);
        stmt.setInt(4, stock);
        stmt.setInt(5, categoryId);
        stmt.executeUpdate();
        System.out.println("Product added!");
    }

    public static void viewProducts() throws Exception {
        Connection con = DBConnection.getConnection();
        Statement stmt = con.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM products");

        while (rs.next()) {
            System.out.println("ID: " + rs.getInt("product_id") +
                    " | Name: " + rs.getString("name") +
                    " | Price: " + rs.getDouble("price") +
                    " | Stock: " + rs.getInt("stock"));
        }
    }

    public static void deleteProduct() throws Exception {
        Scanner sc = new Scanner(System.in);
        System.out.print("Enter Product ID to delete: ");
        int id = sc.nextInt();
        Connection con = DBConnection.getConnection();
        PreparedStatement stmt = con.prepareStatement("DELETE FROM products WHERE product_id = ?");
        stmt.setInt(1, id);
        int rows = stmt.executeUpdate();
        System.out.println(rows > 0 ? "Deleted!" : "Product not found.");
    }

    public static void updateProduct() throws Exception {
        Scanner sc = new Scanner(System.in);
        System.out.print("Enter Product ID to update: ");
        int id = sc.nextInt(); sc.nextLine();
        System.out.print("New Name: "); String name = sc.nextLine();
        System.out.print("New Description: "); String desc = sc.nextLine();
        System.out.print("New Price: "); double price = sc.nextDouble();
        System.out.print("New Stock: "); int stock = sc.nextInt();

        Connection con = DBConnection.getConnection();
        String sql = "UPDATE products SET name=?, description=?, price=?, stock=? WHERE product_id=?";
        PreparedStatement stmt = con.prepareStatement(sql);
        stmt.setString(1, name);
        stmt.setString(2, desc);
        stmt.setDouble(3, price);
        stmt.setInt(4, stock);
        stmt.setInt(5, id);
        stmt.executeUpdate();
        System.out.println("Product updated!");
    }
}

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        int choice = -1;
        while (choice != 0) {
            System.out.println("\n=== E-Commerce Product Management ===");
            System.out.println("1. View Products");
            System.out.println("2. Add Product");
            System.out.println("3. Update Product");
            System.out.println("4. Delete Product");
            System.out.println("0. Exit");
            System.out.print("Choose: ");
            choice = sc.nextInt();

            try {
                switch (choice) {
                    case 1: ProductDAO.viewProducts(); break;
                    case 2: ProductDAO.addProduct(); break;
                    case 3: ProductDAO.updateProduct(); break;
                    case 4: ProductDAO.deleteProduct(); break;
                    case 0: System.out.println("Goodbye!"); break;
                    default: System.out.println("Invalid option.");
                }
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        }
        sc.close();
    }
}

public class Product {
    public int id;
    public String name;
    public String description;
    public double price;
    public int stock;
    public int categoryId;

    public Product(int id, String name, String desc, double price, int stock, int catId) {

        this.id = id;
        this.name = name;
        this.description = desc;
        this.price = price;
        this.stock = stock;
        this.categoryId = catId;
    }
}

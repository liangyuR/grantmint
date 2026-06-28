package dev.hg.grantmint.server.admin;

import dev.hg.grantmint.server.domain.Product;
import dev.hg.grantmint.server.repo.ProductRepository;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Admin CRUD operations for {@link Product}. Every mutation is audited by the caller (controller).
 */
@Service
public class ProductAdminService {

    private final ProductRepository productRepo;

    public ProductAdminService(ProductRepository productRepo) {
        this.productRepo = productRepo;
    }

    @Transactional
    public Product create(String slug, String name, String description) {
        if (productRepo.existsBySlug(slug)) {
            throw new IllegalArgumentException("Slug already in use: " + slug);
        }
        Product product = new Product();
        product.setSlug(slug);
        product.setName(name);
        product.setDescription(description);
        return productRepo.save(product);
    }

    @Transactional(readOnly = true)
    public List<Product> list() {
        return productRepo.findAll();
    }

    @Transactional(readOnly = true)
    public Product get(UUID productId) {
        return productRepo
                .findById(productId)
                .orElseThrow(() -> new NoSuchElementException("Product not found: " + productId));
    }

    @Transactional
    public Product update(UUID productId, String name, String description) {
        Product product = get(productId);
        product.setName(name);
        product.setDescription(description);
        return productRepo.save(product);
    }

    @Transactional
    public void delete(UUID productId) {
        Product product = get(productId);
        productRepo.delete(product);
    }
}

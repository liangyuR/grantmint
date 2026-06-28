package dev.hg.grantmint.server.api;

import dev.hg.grantmint.server.admin.ProductAdminService;
import dev.hg.grantmint.server.audit.AuditActorType;
import dev.hg.grantmint.server.audit.AuditService;
import dev.hg.grantmint.server.domain.Product;
import dev.hg.grantmint.server.security.AdminPrincipal;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Admin CRUD for products. Protected by the admin session chain (ROLE_ADMIN). Slug is immutable
 * after creation; PUT only updates name and description. Every mutation is audited.
 */
@RestController
@RequestMapping("/admin/products")
@Tag(name = "Products (admin)", description = "Admin CRUD for products.")
@SecurityRequirement(name = OpenApiConfig.ADMIN_SESSION)
public class ProductAdminController {

    private final ProductAdminService products;
    private final AuditService audit;

    public ProductAdminController(ProductAdminService products, AuditService audit) {
        this.products = products;
        this.audit = audit;
    }

    @PostMapping
    @Operation(summary = "Create a product")
    ResponseEntity<ProductView> create(
            @RequestBody CreateProductRequest request,
            @AuthenticationPrincipal AdminPrincipal admin,
            HttpServletRequest httpRequest) {
        Product product = products.create(request.slug(), request.name(), request.description());
        audit.record(
                admin.username(),
                AuditActorType.ADMIN,
                "product.created",
                "product",
                product.getId().toString(),
                Map.of("slug", product.getSlug()),
                httpRequest.getRemoteAddr());
        return ResponseEntity.status(HttpStatus.CREATED).body(ProductView.of(product));
    }

    @GetMapping
    @Operation(summary = "List all products")
    List<ProductView> list() {
        return products.list().stream().map(ProductView::of).toList();
    }

    @GetMapping("/{productId}")
    @Operation(summary = "Get a product by id")
    ProductView get(@PathVariable UUID productId) {
        return ProductView.of(products.get(productId));
    }

    @PutMapping("/{productId}")
    @Operation(summary = "Update a product", description = "Updates name and description; the slug is immutable.")
    ProductView update(
            @PathVariable UUID productId,
            @RequestBody UpdateProductRequest request,
            @AuthenticationPrincipal AdminPrincipal admin,
            HttpServletRequest httpRequest) {
        Product product = products.update(productId, request.name(), request.description());
        audit.record(
                admin.username(),
                AuditActorType.ADMIN,
                "product.updated",
                "product",
                product.getId().toString(),
                Map.of(),
                httpRequest.getRemoteAddr());
        return ProductView.of(product);
    }

    @DeleteMapping("/{productId}")
    @Operation(summary = "Delete a product")
    ResponseEntity<Void> delete(
            @PathVariable UUID productId,
            @AuthenticationPrincipal AdminPrincipal admin,
            HttpServletRequest httpRequest) {
        products.delete(productId);
        audit.record(
                admin.username(),
                AuditActorType.ADMIN,
                "product.deleted",
                "product",
                productId.toString(),
                Map.of(),
                httpRequest.getRemoteAddr());
        return ResponseEntity.noContent().build();
    }

    /** @param slug URL-safe lowercase identifier; immutable after creation */
    public record CreateProductRequest(String slug, String name, String description) {}

    /** Slug is immutable and must not be included; name and description are updatable. */
    public record UpdateProductRequest(String name, String description) {}

    public record ProductView(
            UUID id, String slug, String name, String description, OffsetDateTime createdAt, OffsetDateTime updatedAt) {

        static ProductView of(Product p) {
            return new ProductView(
                    p.getId(), p.getSlug(), p.getName(), p.getDescription(), p.getCreatedAt(), p.getUpdatedAt());
        }
    }
}

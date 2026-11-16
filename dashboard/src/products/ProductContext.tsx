import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { api, ApiError } from '../api/client';
import type { Product } from '../api/types';

interface ProductContextValue {
  products: Product[];
  product: Product | null;
  loading: boolean;
  error: string | null;
  selectProduct: (id: string) => void;
  refreshProducts: () => Promise<void>;
}

const ProductContext = createContext<ProductContextValue | null>(null);

export function ProductProvider({ children }: { children: ReactNode }) {
  const [products, setProducts] = useState<Product[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const generation = useRef(0);

  const refreshProducts = useCallback(async () => {
    const request = ++generation.current;
    setLoading(true);
    setError(null);
    try {
      const data = await api.get<Product[]>('/admin/products');
      if (request !== generation.current) return;
      setProducts(data);
      setSelectedId((current) => data.some((p) => p.id === current) ? current : data[0]?.id ?? '');
    } catch (err) {
      if (request === generation.current) {
        setError(err instanceof ApiError ? err.message : '加载应用失败。');
      }
    } finally {
      if (request === generation.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshProducts();
    return () => { generation.current += 1; };
  }, [refreshProducts]);

  return (
    <ProductContext.Provider value={{
      products,
      product: products.find((p) => p.id === selectedId) ?? null,
      loading,
      error,
      selectProduct: setSelectedId,
      refreshProducts,
    }}>
      {children}
    </ProductContext.Provider>
  );
}

export function useProducts() {
  const value = useContext(ProductContext);
  if (!value) throw new Error('ProductProvider is required');
  return value;
}

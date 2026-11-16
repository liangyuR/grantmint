import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useProducts } from '../products/ProductContext';
import type { FormEvent } from 'react';
import { api, ApiError } from '../api/client';
import type { Product } from '../api/types';
import Alert from '../components/Alert';
import ConfirmDialog from '../components/ConfirmDialog';
import FormField, { buttonClasses, inputClasses, secondaryButtonClasses } from '../components/FormField';

interface ProductFormState {
  slug: string;
  name: string;
  description: string;
}

const EMPTY_FORM: ProductFormState = { slug: '', name: '', description: '' };

export default function ProductsPage() {
  const { products, loading, refreshProducts, selectProduct } = useProducts();
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<ProductFormState>(EMPTY_FORM);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [saving, setSaving] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<Product | null>(null);
  const [deleting, setDeleting] = useState(false);

  function startCreate() {
    setEditingId(null);
    setForm(EMPTY_FORM);
    setShowCreateForm(true);
  }

  function startEdit(product: Product) {
    setEditingId(product.id);
    setForm({ slug: product.slug, name: product.name, description: product.description ?? '' });
    setShowCreateForm(true);
  }

  function cancelForm() {
    setShowCreateForm(false);
    setEditingId(null);
    setForm(EMPTY_FORM);
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaving(true);
    setError(null);
    setMessage(null);
    try {
      if (editingId) {
        await api.put(`/admin/products/${editingId}`, {
          name: form.name,
          description: form.description || null,
        });
        setMessage(`Updated product "${form.name}".`);
      } else {
        await api.post('/admin/products', {
          slug: form.slug,
          name: form.name,
          description: form.description || null,
        });
        setMessage(`Created product "${form.name}".`);
      }
      cancelForm();
      await refreshProducts();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Save failed.');
    } finally {
      setSaving(false);
    }
  }

  async function confirmDelete() {
    if (!pendingDelete) return;
    setDeleting(true);
    setError(null);
    try {
      await api.delete(`/admin/products/${pendingDelete.id}`);
      setMessage(`Deleted product "${pendingDelete.name}".`);
      setPendingDelete(null);
      await refreshProducts();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Delete failed.');
    } finally {
      setDeleting(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-white">Products</h1>
        <button type="button" className={buttonClasses} onClick={startCreate}>
          New product
        </button>
      </div>

      {error && <Alert kind="error">{error}</Alert>}
      {message && <Alert kind="success">{message}</Alert>}

      {showCreateForm && (
        <form
          onSubmit={(e) => void handleSubmit(e)}
          className="grid gap-4 rounded-lg border border-gray-800 bg-gray-900 p-4 sm:grid-cols-3"
        >
          <FormField id="product-slug" label="Slug">
            <input
              id="product-slug"
              className={inputClasses}
              value={form.slug}
              disabled={editingId !== null}
              required
              minLength={3}
              maxLength={64}
              pattern="[a-z0-9][a-z0-9-]{1,62}[a-z0-9]"
              title="3–64 lowercase letters, digits or hyphens; start and end with a letter or digit"
              onChange={(e) => setForm({ ...form, slug: e.target.value })}
              placeholder="acme-notes"
            />
          </FormField>
          <FormField id="product-name" label="Name">
            <input
              id="product-name"
              className={inputClasses}
              value={form.name}
              required
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="Acme Notes"
            />
          </FormField>
          <FormField id="product-description" label="Description">
            <input
              id="product-description"
              className={inputClasses}
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
              placeholder="Optional"
            />
          </FormField>
          <div className="sm:col-span-3 flex gap-2">
            <button type="submit" disabled={saving} className={buttonClasses}>
              {saving ? 'Saving…' : editingId ? 'Save changes' : 'Create product'}
            </button>
            <button type="button" className={secondaryButtonClasses} onClick={cancelForm}>
              Cancel
            </button>
          </div>
        </form>
      )}

      <div className="overflow-x-auto rounded-lg border border-gray-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-gray-900 text-xs uppercase tracking-wider text-gray-400">
            <tr>
              <th scope="col" className="px-4 py-2">Slug</th>
              <th scope="col" className="px-4 py-2">Name</th>
              <th scope="col" className="px-4 py-2">Description</th>
              <th scope="col" className="px-4 py-2">
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {loading && (
              <tr>
                <td colSpan={4} className="px-4 py-6 text-center text-gray-500">
                  Loading…
                </td>
              </tr>
            )}
            {!loading && products.length === 0 && (
              <tr>
                <td colSpan={4} className="px-4 py-6 text-center text-gray-500">
                  No products yet.
                </td>
              </tr>
            )}
            {products?.map((product) => (
              <tr key={product.id} className="hover:bg-gray-900/60">
                <td className="px-4 py-2 font-mono text-gray-300">{product.slug}</td>
                <td className="px-4 py-2 text-gray-100"><Link className="text-indigo-300 underline" to={`/products/${product.id}`} onClick={() => selectProduct(product.id)}>{product.name}</Link></td>
                <td className="px-4 py-2 text-gray-400">{product.description || '—'}</td>
                <td className="px-4 py-2 text-right">
                  <div className="flex justify-end gap-2">
                    <button
                      type="button"
                      className={secondaryButtonClasses}
                      onClick={() => startEdit(product)}
                      aria-label={`Edit ${product.name}`}
                    >
                      Edit
                    </button>
                    <button
                      type="button"
                      className="rounded-md border border-red-900 px-3 py-1.5 text-sm font-medium text-red-300 hover:bg-red-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500"
                      onClick={() => setPendingDelete(product)}
                      aria-label={`Delete ${product.name}`}
                    >
                      Delete
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {pendingDelete && (
        <ConfirmDialog
          title={`Delete product "${pendingDelete.name}"?`}
          description="Products with licenses cannot be deleted. Deleting an unused product also deletes its policies and registered keys. This cannot be undone."
          confirmLabel="Delete"
          danger
          busy={deleting}
          onCancel={() => setPendingDelete(null)}
          onConfirm={() => void confirmDelete()}
        />
      )}
    </div>
  );
}

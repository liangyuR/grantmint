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
        setMessage(`已更新应用“${form.name}”。`);
      } else {
        await api.post('/admin/products', {
          slug: form.slug,
          name: form.name,
          description: form.description || null,
        });
        setMessage(`已创建应用“${form.name}”。`);
      }
      cancelForm();
      await refreshProducts();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : '保存失败。');
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
      setMessage(`已删除应用“${pendingDelete.name}”。`);
      setPendingDelete(null);
      await refreshProducts();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : '删除失败。');
    } finally {
      setDeleting(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-white">应用管理</h1>
        <button type="button" className={buttonClasses} onClick={startCreate}>
          新建应用
        </button>
      </div>

      {error && <Alert kind="error">{error}</Alert>}
      {message && <Alert kind="success">{message}</Alert>}

      {showCreateForm && (
        <form
          onSubmit={(e) => void handleSubmit(e)}
          className="grid gap-4 rounded-lg border border-gray-800 bg-gray-900 p-4 sm:grid-cols-3"
        >
          <FormField id="product-slug" label="应用标识">
            <input
              id="product-slug"
              className={inputClasses}
              value={form.slug}
              disabled={editingId !== null}
              required
              minLength={3}
              maxLength={64}
              pattern="[a-z0-9][a-z0-9-]{1,62}[a-z0-9]"
              title="3～64 位小写字母、数字或连字符；首尾为字母或数字"
              onChange={(e) => setForm({ ...form, slug: e.target.value })}
              placeholder="acme-notes"
            />
          </FormField>
          <FormField id="product-name" label="名称">
            <input
              id="product-name"
              className={inputClasses}
              value={form.name}
              required
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="Acme Notes"
            />
          </FormField>
          <FormField id="product-description" label="说明">
            <input
              id="product-description"
              className={inputClasses}
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
              placeholder="可选"
            />
          </FormField>
          <div className="sm:col-span-3 flex gap-2">
            <button type="submit" disabled={saving} className={buttonClasses}>
              {saving ? '保存中…' : editingId ? '保存修改' : '创建应用'}
            </button>
            <button type="button" className={secondaryButtonClasses} onClick={cancelForm}>
              取消
            </button>
          </div>
        </form>
      )}

      <div className="overflow-x-auto rounded-lg border border-gray-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-gray-900 text-xs uppercase tracking-wider text-gray-400">
            <tr>
              <th scope="col" className="px-4 py-2">应用标识</th>
              <th scope="col" className="px-4 py-2">名称</th>
              <th scope="col" className="px-4 py-2">说明</th>
              <th scope="col" className="px-4 py-2">
                <span className="sr-only">操作</span>
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {loading && (
              <tr>
                <td colSpan={4} className="px-4 py-6 text-center text-gray-500">
                  正在加载…
                </td>
              </tr>
            )}
            {!loading && products.length === 0 && (
              <tr>
                <td colSpan={4} className="px-4 py-6 text-center text-gray-500">
                  尚未创建应用。
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
                      aria-label={`编辑 ${product.name}`}
                    >
                      编辑
                    </button>
                    <button
                      type="button"
                      className="rounded-md border border-red-900 px-3 py-1.5 text-sm font-medium text-red-300 hover:bg-red-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500"
                      onClick={() => setPendingDelete(product)}
                      aria-label={`删除 ${product.name}`}
                    >
                      删除
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
          title={`删除应用“${pendingDelete.name}”？`}
          description="已有授权的应用不能删除。删除其他应用会同时删除其策略、注册密钥和 API 密钥，此操作不可撤销。"
          confirmLabel="删除"
          danger
          busy={deleting}
          onCancel={() => setPendingDelete(null)}
          onConfirm={() => void confirmDelete()}
        />
      )}
    </div>
  );
}

import { Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider } from './auth/AuthContext'
import ProtectedRoute from './components/ProtectedRoute'
import Shell from './components/Shell'
import LoginPage from './pages/LoginPage'
import ProductsPage from './pages/ProductsPage'
import ProductDetailPage from './pages/ProductDetailPage'
import LicensesPage from './pages/LicensesPage'
import LicenseDetailDrawer from './pages/LicenseDetailDrawer'
import AuditPage from './pages/AuditPage'

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route element={<ProtectedRoute />}>
          <Route element={<Shell />}>
            <Route index element={<Navigate to="/products" replace />} />
            <Route path="products" element={<ProductsPage />} />
            <Route path="products/:productId" element={<ProductDetailPage />} />
            <Route path="licenses" element={<LicensesPage />}>
              <Route path=":licenseId" element={<LicenseDetailDrawer />} />
            </Route>
            <Route path="audit" element={<AuditPage />} />
            <Route path="*" element={<Navigate to="/products" replace />} />
          </Route>
        </Route>
      </Routes>
    </AuthProvider>
  )
}

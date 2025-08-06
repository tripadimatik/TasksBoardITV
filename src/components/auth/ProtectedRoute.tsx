import { useAuth } from "../../contexts/AuthContext";
import { Navigate, useLocation } from "react-router-dom";

interface ProtectedRouteProps {
  children: React.ReactNode;
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
  const { user, loading } = useAuth();
  const location = useLocation();

  // Показываем загрузку, пока проверяем аутентификацию
  if (loading) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-4">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        <p className="text-gray-600">Загрузка данных...</p>
      </div>
    );
  }

  // Если пользователь не аутентифицирован, перенаправляем на страницу входа
  if (!user) {
    console.log('User not authenticated, redirecting to /auth');
    // Редиректим на страницу входа, сохраняя путь, откуда пришли
    // Используем более строгое перенаправление с replace: true
    return <Navigate to="/auth" state={{ from: location }} replace={true} />;
  }

  // Если пользователь аутентифицирован, показываем защищенный контент
  return <>{children}</>;
};
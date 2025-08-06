import { useLocation, useNavigate } from "react-router-dom";
import { useEffect } from "react";
import { useAuth } from "@/contexts/AuthContext";

const NotFound = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user } = useAuth();

  useEffect(() => {
    console.error(
      "404 Error: User attempted to access non-existent route:",
      location.pathname
    );
    
    // Автоматически перенаправляем на соответствующую страницу через 3 секунды
    const timer = setTimeout(() => {
      if (user) {
        // Если пользователь аутентифицирован, перенаправляем на главную страницу
        navigate('/', { replace: true });
      } else {
        // Если пользователь не аутентифицирован, перенаправляем на страницу авторизации
        navigate('/auth', { replace: true });
      }
    }, 3000);
    
    return () => clearTimeout(timer);
  }, [location.pathname, navigate, user]);

  const handleRedirect = () => {
    if (user) {
      navigate('/', { replace: true });
    } else {
      navigate('/auth', { replace: true });
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <div className="text-center">
        <h1 className="text-4xl font-bold mb-4">404</h1>
        <p className="text-xl text-gray-600 mb-4">Страница не найдена</p>
        <button 
          onClick={handleRedirect}
          className="text-blue-500 hover:text-blue-700 underline"
        >
          {user ? 'Вернуться на главную' : 'Перейти на страницу входа'}
        </button>
      </div>
    </div>
  );
};

export default NotFound;

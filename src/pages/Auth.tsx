import { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { LoginForm } from "@/components/auth/LoginForm";
import { RegisterForm } from "@/components/auth/RegisterForm";
import { useAuth } from "@/contexts/AuthContext";
import { useToast } from "@/hooks/use-toast";

export const Auth = () => {
  const [isLogin, setIsLogin] = useState(true);
  const navigate = useNavigate();
  const location = useLocation();
  const { user, loading } = useAuth();
  const { toast } = useToast();

  useEffect(() => {
    // Проверяем, аутентифицирован ли пользователь
    if (user) {
      console.log('User is authenticated, redirecting from Auth page');
      const from = location.state?.from?.pathname || "/";
      navigate(from, { replace: true });
    } else {
      console.log('User is not authenticated, staying on Auth page');
    }
  }, [user, navigate, location.state]);

  // Показываем индикатор загрузки, пока проверяем состояние аутентификации
  if (loading) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-4">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        <p className="text-gray-600">Проверка аутентификации...</p>
      </div>
    );
  }
  
  // Если пользователь аутентифицирован, показываем индикатор перенаправления
  if (user) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-4">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        <p className="text-gray-600">Перенаправление...</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100 px-3 sm:px-4 py-4">
      <Card className="w-full max-w-sm sm:max-w-md mx-auto">
        <CardHeader className="text-center p-4 sm:p-6">
          <CardTitle className="text-xl sm:text-2xl font-bold">
            {isLogin ? 'Вход в систему' : 'Регистрация'}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 sm:space-y-4 p-4 sm:p-6">
          {isLogin ? (
            <LoginForm
              onLogin={() => {
                const from = location.state?.from?.pathname || "/";
                navigate(from, { replace: true });
              }}
              onRegister={() => setIsLogin(false)}
            />
          ) : (
            <RegisterForm
              onRegister={() => {
                setIsLogin(true);
                toast({
                  title: "Успешно!",
                  description: "Регистрация завершена. Теперь вы можете войти в систему.",
                });
              }}
              onBackToLogin={() => setIsLogin(true)}
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
};
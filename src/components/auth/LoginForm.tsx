import React, { useState } from 'react';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ArrowRight } from 'lucide-react';
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/contexts/AuthContext";
import { 
  validateEmail, 
  sanitizeInput, 
  detectSuspiciousPatterns, 
  logSuspiciousActivity 
} from "@/lib/security";

interface LoginFormProps {
  onLogin: (userData: { email: string }) => void;
  onRegister: () => void;
}

export const LoginForm: React.FC<LoginFormProps> = ({ onLogin, onRegister }) => {
  const { toast } = useToast();
  const { signIn } = useAuth();
  const [loading, setLoading] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Базовая проверка заполненности полей
    if (!email || !password) {
      toast({
        title: "Ошибка",
        description: "Заполните все поля",
        variant: "destructive"
      });
      return;
    }

    // Валидация email
    if (!validateEmail(email)) {
      toast({
        title: "Ошибка",
        description: "Некорректный email адрес",
        variant: "destructive"
      });
      return;
    }

    // Базовая проверка пароля
    if (password.length < 1) {
      toast({
        title: "Ошибка",
        description: "Пароль не может быть пустым",
        variant: "destructive"
      });
      return;
    }

    // Проверка на подозрительные паттерны
    if (detectSuspiciousPatterns(email)) {
      logSuspiciousActivity('Попытка входа с подозрительным email', { email });
      toast({
        title: "Ошибка",
        description: "Обнаружены недопустимые символы в email",
        variant: "destructive"
      });
      return;
    }

    setLoading(true);
    try {
      // Санитизация email перед отправкой
      const sanitizedEmail = sanitizeInput(email.toLowerCase().trim(), 254);
      
      await signIn(sanitizedEmail, password);
      onLogin({ email: sanitizedEmail });
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      let displayMessage = "Произошла ошибка при входе";
      
      if (errorMessage?.includes('credential') || errorMessage?.includes('password')) {
        displayMessage = "Неверный email или пароль";
      } else if (errorMessage?.includes('requests') || errorMessage?.includes('попыток')) {
        displayMessage = "Слишком много попыток входа. Попробуйте позже";
      } else if (errorMessage?.includes('недопустимые символы')) {
        displayMessage = errorMessage;
      }
      
      toast({
        title: "Ошибка входа",
        description: displayMessage,
        variant: "destructive"
      });
    }
    setLoading(false);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-3 sm:space-y-4 animate-fade-in">
      <div className="space-y-1.5 sm:space-y-2">
        <Label htmlFor="email" className="text-sm font-medium">Email</Label>
        <Input
          id="email"
          type="email"
          value={email}
          onChange={(e) => {
            // Базовая санитизация при вводе email
            const sanitizedValue = e.target.value.replace(/[<>"'&]/g, '').slice(0, 254);
            setEmail(sanitizedValue);
          }}
          placeholder="Введите ваш email"
          className="h-11 sm:h-10 text-base sm:text-sm transition-all duration-200"
          required
        />
      </div>
      
      <div className="space-y-1.5 sm:space-y-2">
        <Label htmlFor="password" className="text-sm font-medium">Пароль</Label>
        <Input
          id="password"
          type="password"
          value={password}
          onChange={(e) => {
            // Ограничиваем длину пароля при вводе
            const value = e.target.value.slice(0, 128);
            setPassword(value);
          }}
          placeholder="Введите ваш пароль"
          className="h-11 sm:h-10 text-base sm:text-sm transition-all duration-200"
          required
        />
      </div>
      
      <Button type="submit" className="w-full h-11 sm:h-10 text-base sm:text-sm font-medium transition-all duration-200 hover:shadow-lg transform hover:-translate-y-0.5" disabled={loading}>
        {loading ? 'Вход...' : 'Войти'}
        <ArrowRight className="ml-2 h-4 w-4" />
      </Button>
      
      <div className="text-center pt-2">
        <Button
          type="button"
          variant="link"
          onClick={onRegister}
          className="text-sm h-auto p-0 font-normal"
        >
          Нет аккаунта? Зарегистрироваться
        </Button>
      </div>
    </form>
  );
};

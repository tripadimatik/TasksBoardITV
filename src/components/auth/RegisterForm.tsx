import React, { useState } from 'react';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ArrowLeft } from 'lucide-react';
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/contexts/AuthContext";
import { 
  validateEmail, 
  validatePassword, 
  validateName, 
  sanitizeInput, 
  detectSuspiciousPatterns, 
  logSuspiciousActivity 
} from "@/lib/security";

interface UserData {
  email: string;
  firstName: string;
  lastName: string;
  patronymic: string;
  role: string;
}

interface RegisterFormProps {
  onRegister: (userData: UserData) => void;
  onBackToLogin: () => void;
}

export const RegisterForm: React.FC<RegisterFormProps> = ({ onRegister, onBackToLogin }) => {
  const { toast } = useToast();
  const { signUp } = useAuth();
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    lastName: '',
    firstName: '',
    patronymic: '',
    email: '',
    password: '',
    confirmPassword: ''
  });

  const handleChange = (field: string, value: string) => {
    // Базовая санитизация при вводе
    let sanitizedValue = value;
    
    // Удаляем потенциально опасные символы при вводе
    if (field === 'email') {
      sanitizedValue = value.replace(/[<>"'&]/g, '').slice(0, 254);
    } else if (['firstName', 'lastName', 'patronymic'].includes(field)) {
      sanitizedValue = value.replace(/[<>"'&]/g, '').slice(0, 50);
    }
    
    setFormData(prev => ({ ...prev, [field]: sanitizedValue }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Валидация email
    if (!validateEmail(formData.email)) {
      toast({
        title: "Ошибка",
        description: "Некорректный email адрес",
        variant: "destructive"
      });
      return;
    }

    // Валидация пароля
    const passwordValidation = validatePassword(formData.password);
    if (!passwordValidation.isValid) {
      toast({
        title: "Ошибка",
        description: passwordValidation.error || "Некорректный пароль",
        variant: "destructive"
      });
      return;
    }

    // Проверка совпадения паролей
    if (formData.password !== formData.confirmPassword) {
      toast({
        title: "Ошибка",
        description: "Пароли не совпадают",
        variant: "destructive"
      });
      return;
    }

    // Валидация имени
    const firstNameValidation = validateName(formData.firstName);
    if (!firstNameValidation.isValid) {
      toast({
        title: "Ошибка",
        description: firstNameValidation.error || "Некорректное имя",
        variant: "destructive"
      });
      return;
    }

    // Валидация фамилии
    const lastNameValidation = validateName(formData.lastName);
    if (!lastNameValidation.isValid) {
      toast({
        title: "Ошибка",
        description: lastNameValidation.error || "Некорректная фамилия",
        variant: "destructive"
      });
      return;
    }

    // Валидация отчества (если указано)
    if (formData.patronymic.trim()) {
      const patronymicValidation = validateName(formData.patronymic);
      if (!patronymicValidation.isValid) {
        toast({
          title: "Ошибка",
          description: patronymicValidation.error || "Некорректное отчество",
          variant: "destructive"
        });
        return;
      }
    }

    // Проверка на подозрительные паттерны
    const fieldsToCheck = [
      { value: formData.email, name: 'email' },
      { value: formData.firstName, name: 'имя' },
      { value: formData.lastName, name: 'фамилия' },
      { value: formData.patronymic, name: 'отчество' }
    ];

    for (const field of fieldsToCheck) {
      if (field.value && detectSuspiciousPatterns(field.value)) {
        logSuspiciousActivity(`Подозрительные символы в поле ${field.name}`, { field: field.name, value: field.value });
        toast({
          title: "Ошибка",
          description: `Обнаружены недопустимые символы в поле "${field.name}"`,
          variant: "destructive"
        });
        return;
      }
    }

    setLoading(true);
    try {
      // Санитизация данных перед отправкой
      const sanitizedData = {
        email: sanitizeInput(formData.email.toLowerCase().trim(), 254),
        firstName: sanitizeInput(formData.firstName.trim(), 50),
        lastName: sanitizeInput(formData.lastName.trim(), 50),
        patronymic: formData.patronymic.trim() ? sanitizeInput(formData.patronymic.trim(), 50) : '',
        role: "USER"
      };

      await signUp(sanitizedData.email, formData.password, sanitizedData);

      onRegister(sanitizedData);

      toast({
        title: "Успешно!",
        description: "Регистрация завершена. Вы можете войти в систему.",
      });
    } catch (error: unknown) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      let displayMessage = "Произошла ошибка при регистрации";
      
      // Проверяем конкретные сообщения об ошибках от сервера
      if (errorMessage?.includes('Пароль должен содержать') || 
          errorMessage?.includes('Пароль слишком') ||
          errorMessage?.includes('строчные буквы') ||
          errorMessage?.includes('заглавные буквы') ||
          errorMessage?.includes('цифры') ||
          errorMessage?.includes('специальные символы') ||
          errorMessage?.includes('слишком простой')) {
        displayMessage = errorMessage; // Показываем точное сообщение о требованиях к паролю
      } else if (errorMessage?.includes('email') || errorMessage?.includes('Email')) {
        displayMessage = "Этот email уже используется";
      } else if (errorMessage?.includes('недопустимые символы') || errorMessage?.includes('содержит недопустимые')) {
        displayMessage = errorMessage;
      } else if (errorMessage && errorMessage !== 'Unknown error' && !errorMessage?.includes('HTTP error! status: 400')) {
        // Показываем любое другое конкретное сообщение от сервера, кроме общих HTTP ошибок
        displayMessage = errorMessage;
      }
      
      toast({
        title: "Ошибка регистрации",
        description: displayMessage,
        variant: "destructive"
      });
    }
    setLoading(false);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-3 sm:space-y-4 animate-fade-in">
      <Button
        type="button"
        variant="ghost"
        onClick={onBackToLogin}
        className="mb-3 sm:mb-4 p-0 h-auto font-normal text-sm flex items-center min-h-[44px] sm:min-h-auto"
      >
        <ArrowLeft className="mr-2 h-4 w-4" />
        Назад к входу
      </Button>
      
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4">
        <div className="space-y-1.5 sm:space-y-2">
          <Label htmlFor="lastName" className="text-sm font-medium">Фамилия</Label>
          <Input
            id="lastName"
            value={formData.lastName}
            onChange={(e) => setFormData({...formData, lastName: e.target.value})}
            placeholder="Иванов"
            className="h-11 sm:h-10 text-base sm:text-sm transition-all duration-200"
            required
          />
        </div>
        <div className="space-y-1.5 sm:space-y-2">
          <Label htmlFor="firstName" className="text-sm font-medium">Имя</Label>
          <Input
            id="firstName"
            value={formData.firstName}
            onChange={(e) => setFormData({...formData, firstName: e.target.value})}
            placeholder="Иван"
            className="h-11 sm:h-10 text-base sm:text-sm"
            required
          />
        </div>
      </div>
      
      <div className="space-y-1.5 sm:space-y-2">
        <Label htmlFor="patronymic" className="text-sm font-medium">Отчество (необязательно)</Label>
        <Input
          id="patronymic"
          value={formData.patronymic}
          onChange={(e) => setFormData({...formData, patronymic: e.target.value})}
          placeholder="Иванович"
          className="h-11 sm:h-10 text-base sm:text-sm"
        />
      </div>
      
      <div className="space-y-1.5 sm:space-y-2">
        <Label htmlFor="email" className="text-sm font-medium">Email</Label>
        <Input
          id="email"
          type="email"
          value={formData.email}
          onChange={(e) => setFormData({...formData, email: e.target.value})}
          placeholder="ivan@example.com"
          className="h-11 sm:h-10 text-base sm:text-sm"
          required
        />
      </div>
      
      <div className="space-y-1.5 sm:space-y-2">
        <Label htmlFor="password" className="text-sm font-medium">Пароль</Label>
        <Input
          id="password"
          type="password"
          value={formData.password}
          onChange={(e) => setFormData({...formData, password: e.target.value})}
          placeholder="••••••••"
          className="h-11 sm:h-10 text-base sm:text-sm"
          required
        />
      </div>
      
      <div className="space-y-1.5 sm:space-y-2">
        <Label htmlFor="confirmPassword" className="text-sm font-medium">Подтвердите пароль</Label>
        <Input
          id="confirmPassword"
          type="password"
          value={formData.confirmPassword}
          onChange={(e) => setFormData({...formData, confirmPassword: e.target.value})}
          placeholder="••••••••"
          className="h-11 sm:h-10 text-base sm:text-sm"
          required
        />
      </div>
      
      <Button type="submit" className="w-full h-11 sm:h-10 text-base sm:text-sm font-medium transition-all duration-200 hover:shadow-lg transform hover:-translate-y-0.5" disabled={loading}>
        {loading ? 'Регистрация...' : 'Зарегистрироваться'}
      </Button>
    </form>
  );
};


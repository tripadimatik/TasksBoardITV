import React, { createContext, useEffect, useState } from "react";
import { apiClient, User, AuthResponse } from "../lib/api";
import { useToast } from "@/hooks/use-toast";
import { UserRole } from "@/lib/types";

interface UserData {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  patronymic?: string;
  role: UserRole;
  displayName: string;
  createdAt: string;
  updatedAt: string;
}

interface AuthContextType {
  user: UserData | null;
  loading: boolean;
  signIn: (email: string, password: string) => Promise<void>;
  signUp: (email: string, password: string, userData: {
    firstName: string;
    lastName: string;
    patronymic?: string;
    role?: string;
  }) => Promise<void>;
  logout: () => Promise<void>;
  refreshUserData: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  loading: true,
  signIn: async () => {},
  signUp: async () => {},
  logout: async () => {},
  refreshUserData: async () => {},
});

const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  console.log('AuthProvider initializing...');
  const [user, setUser] = useState<UserData | null>(null);
  const [loading, setLoading] = useState(true);
  const { toast } = useToast();

  const setUserFromApiData = (userData: User) => {
    setUser({
      id: userData.id,
      email: userData.email,
      firstName: userData.firstName,
      lastName: userData.lastName,
      patronymic: userData.patronymic,
      role: userData.role,
      displayName: `${userData.firstName} ${userData.lastName}`,
      createdAt: userData.createdAt,
      updatedAt: userData.updatedAt
    });
  };

  const refreshUserData = async () => {
    try {
      const userData = await apiClient.getCurrentUser();
      setUserFromApiData(userData);
    } catch (error) {
      console.error("Error fetching user data:", error);
      toast({
        title: "Ошибка",
        description: "Не удалось загрузить данные пользователя. Попробуйте перезагрузить страницу.",
        variant: "destructive"
      });
      // Если токен недействителен, очищаем его
      apiClient.removeAuthToken();
      setUser(null);
    }
  };

  const signIn = async (email: string, password: string) => {
    try {
      const response: AuthResponse = await apiClient.login(email, password);
      apiClient.setAuthToken(response.token);
      setUserFromApiData(response.user);
    } catch (error) {
      console.error("Login error:", error);
      throw error;
    }
  };

  const signUp = async (email: string, password: string, userData: {
    firstName: string;
    lastName: string;
    patronymic?: string;
    role?: string;
  }) => {
    try {
      const response: AuthResponse = await apiClient.register({
        email,
        password,
        firstName: userData.firstName,
        lastName: userData.lastName,
        patronymic: userData.patronymic,
        role: userData.role || 'USER'
      });
      
      apiClient.setAuthToken(response.token);
      setUserFromApiData(response.user);
    } catch (error) {
      console.error("Registration error:", error);
      throw error;
    }
  };

  const logout = async () => {
    apiClient.removeAuthToken();
    setUser(null);
    
    // Перенаправляем на страницу авторизации
    const currentPath = window.location.pathname;
    if (currentPath !== '/auth') {
      window.location.href = '/auth';
    }
  };

  useEffect(() => {
    const initAuth = async () => {
      console.log('AuthContext: Starting authentication initialization...');
      try {
        const token = apiClient.getAuthToken();
        console.log('AuthContext: Token found:', !!token);
        
        if (token) {
          try {
            console.log('AuthContext: Fetching user data...');
            const userData = await apiClient.getCurrentUser();
            console.log('AuthContext: User data received:', userData);
            setUserFromApiData(userData);
          } catch (error) {
            console.error('AuthContext: Error fetching user data:', error);
            apiClient.removeAuthToken();
            setUser(null);
            
            // Перенаправляем на страницу авторизации если токен недействителен
            const currentPath = window.location.pathname;
            console.log('AuthContext: Redirecting to auth, current path:', currentPath);
            if (currentPath !== '/auth') {
              window.location.href = '/auth';
            }
          }
        } else {
          // Нет токена, пользователь не аутентифицирован
          console.log('AuthContext: No token found, user not authenticated');
          setUser(null);
          
          // Проверяем, находимся ли мы на защищенном маршруте
          const currentPath = window.location.pathname;
          console.log('AuthContext: Current path:', currentPath);
          if (currentPath !== '/auth') {
            console.log('AuthContext: Redirecting to auth page');
            window.location.href = '/auth';
          }
        }
      } catch (error) {
        console.error('AuthContext: Critical error during initialization:', error);
      } finally {
        console.log('AuthContext: Setting loading to false');
        setLoading(false);
      }
    };

    initAuth();
  }, []);

  return (
    <AuthContext.Provider 
      value={{
        user,
        loading,
        signIn,
        signUp,
        logout,
        refreshUserData
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export { AuthContext };
export default AuthProvider;
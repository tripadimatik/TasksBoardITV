// Re-export для обратной совместимости
export { default as AuthProvider, AuthContext } from './AuthProvider';
export { useAuth } from '../hooks/use-auth';

// Также экспортируем как именованный экспорт для совместимости
export { default as AuthContextProvider } from './AuthProvider';
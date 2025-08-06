import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { UserCircle, Mail, User, X, Shield, UserCog, Briefcase, CheckCircle2, Loader2 } from 'lucide-react';
import { apiClient } from '../../lib/api';
import { useAuth } from '../../contexts/AuthContext';
import { useToast } from '@/hooks/use-toast';
import { useIsMobile } from '@/hooks/use-mobile';

import { UserRole } from '@/lib/types';

interface UserProfileProps {
  user: {
    id: string;
    email: string;
    firstName: string;
    lastName: string;
    patronymic?: string;
    role: UserRole;
  };
  onClose: () => void;
  onUpdate?: () => void;
}

export const UserProfile: React.FC<UserProfileProps> = ({ user, onClose, onUpdate }) => {
  const isMobile = useIsMobile();
  const { user: currentUser, refreshUserData } = useAuth();
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);

  const getRoleDisplay = (role: string) => {
    switch (role) {
      case 'BOSS':
        return 'Руководитель';
      case 'ADMIN':
        return 'Администратор';
      case 'USER':
        return 'Исполнитель';
      default:
        return 'Пользователь';
    }
  };

  const getRoleVariant = (role: string) => {
    return role === 'USER' ? 'secondary' : 'default';
  };

  const getNextRole = (currentRole: string) => {
    switch (currentRole) {
      case 'USER':
        return 'BOSS';
      case 'BOSS':
      case 'ADMIN':
        return 'USER';
      default:
        return 'USER';
    }
  };

  const handleRoleChange = async () => {
    if (!currentUser) {
      toast({
        title: "Ошибка",
        description: "Вы не авторизованы",
        variant: "destructive"
      });
      return;
    }

    // Проверяем права текущего пользователя
    try {
      if (currentUser.role !== 'ADMIN' && currentUser.role !== 'BOSS') {
        toast({
          title: "Ошибка",
          description: "У вас нет прав для изменения роли пользователя",
          variant: "destructive"
        });
        return;
      }

      setLoading(true);
      const newRole = getNextRole(user.role);
      
      // Обновляем роль пользователя через API
      await apiClient.updateUser(user.id, { role: newRole });
      
      toast({
        title: "Успешно",
        description: `Роль пользователя изменена на ${getRoleDisplay(newRole)}`,
      });

      // Обновляем данные текущего пользователя, если меняем свою роль
      if (user.id === currentUser.id) {
        await refreshUserData();
      }
      
      // Вызываем колбэк обновления, если он предоставлен
      if (onUpdate) {
        onUpdate();
      }
    } catch (error: unknown) {
      console.error("Error updating role:", error);
      const errorMessage = error instanceof Error ? error.message : "Не удалось изменить роль пользователя";
      toast({
        title: "Ошибка",
        description: errorMessage,
        variant: "destructive"
      });
    } finally {
      setLoading(false);
    }
  };

  const fullName = `${user.lastName} ${user.firstName}${user.patronymic ? ' ' + user.patronymic : ''}`;

  // Проверяем, является ли текущий пользователь админом или боссом
  const canChangeRole = currentUser && 
    (currentUser.role === 'ADMIN' || currentUser.role === 'BOSS') && 
    currentUser.id !== user.id;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-2 sm:p-4 z-50">
      <Card className="w-[95vw] max-w-md sm:max-w-lg bg-white shadow-xl max-h-[90vh] overflow-y-auto">
        <CardHeader className="relative px-3 sm:px-6 pt-3 sm:pt-6 pb-2 sm:pb-6">
          <Button
            variant="ghost"
            size="sm"
            onClick={onClose}
            className="absolute right-2 top-2 h-8 w-8 p-0 hover:bg-gray-100"
          >
            <X className="h-4 w-4" />
          </Button>
          <div className="flex items-center gap-2 sm:gap-3">
            <div className="bg-blue-100 p-2 sm:p-3 rounded-full flex-shrink-0">
              <UserCircle className="h-6 w-6 sm:h-8 sm:w-8 text-blue-600" />
            </div>
            <div className="min-w-0 flex-1">
              <CardTitle className="text-lg sm:text-xl font-semibold text-gray-900 truncate">
                Профиль пользователя
              </CardTitle>
              <CardDescription className="text-sm sm:text-base text-gray-600">
                Информация о пользователе
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4 sm:space-y-6 px-3 sm:px-6 pb-3 sm:pb-6">
          {/* Основная информация */}
          <div className="space-y-3 sm:space-y-4">
            <div className="flex items-center gap-2 sm:gap-3 p-2 sm:p-3 bg-gray-50 rounded-lg">
              <div className="bg-blue-100 p-1.5 sm:p-2 rounded-full flex-shrink-0">
                <User className="h-3 w-3 sm:h-4 sm:w-4 text-blue-600" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs sm:text-sm font-medium text-gray-700">Полное имя</p>
                <p className="text-sm sm:text-base font-semibold text-gray-900 truncate">
                  {user.lastName} {user.firstName} {user.patronymic || ''}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 sm:gap-3 p-2 sm:p-3 bg-gray-50 rounded-lg">
              <div className="bg-green-100 p-1.5 sm:p-2 rounded-full flex-shrink-0">
                <Mail className="h-3 w-3 sm:h-4 sm:w-4 text-green-600" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs sm:text-sm font-medium text-gray-700">Email</p>
                <p className="text-sm sm:text-base font-semibold text-gray-900 break-all">
                  {user.email}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 sm:gap-3 p-2 sm:p-3 bg-gray-50 rounded-lg">
              <div className="bg-purple-100 p-1.5 sm:p-2 rounded-full flex-shrink-0">
                <Shield className="h-3 w-3 sm:h-4 sm:w-4 text-purple-600" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs sm:text-sm font-medium text-gray-700">Роль</p>
                <div className="flex items-center gap-1.5 sm:gap-2">
                  <Badge variant={getRoleVariant(user.role)} className="text-xs sm:text-sm px-2 py-1">
                    {getRoleDisplay(user.role)}
                  </Badge>
                  {user.role === 'BOSS' && <Briefcase className="h-3 w-3 sm:h-4 sm:w-4 text-amber-600" />}
                  {user.role === 'ADMIN' && <UserCog className="h-3 w-3 sm:h-4 sm:w-4 text-blue-600" />}
                </div>
              </div>
            </div>
          </div>
          {/* Управление ролью (только для админов и боссов) */}
          {currentUser && (currentUser.role === 'ADMIN' || currentUser.role === 'BOSS') && currentUser.id !== user.id && (
            <div className="border-t pt-3 sm:pt-4">
              <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 sm:p-4">
                <div className="flex items-center gap-1.5 sm:gap-2 mb-2 sm:mb-3">
                  <UserCog className="h-4 w-4 sm:h-5 sm:w-5 text-amber-600" />
                  <h3 className="font-semibold text-amber-800 text-sm sm:text-base">Управление ролью</h3>
                </div>
                <p className="text-xs sm:text-sm text-amber-700 mb-3 sm:mb-4">
                  Текущая роль: <strong>{getRoleDisplay(user.role)}</strong>
                </p>
                <Button
                  onClick={handleRoleChange}
                  disabled={loading}
                  className="w-full bg-amber-600 hover:bg-amber-700 text-white h-10 sm:h-9 text-sm sm:text-base"
                >
                  {loading ? (
                    <>
                      <Loader2 className="h-3 w-3 sm:h-4 sm:w-4 mr-2 animate-spin" />
                      Изменение...
                    </>
                  ) : (
                    <>
                      <CheckCircle2 className="h-3 w-3 sm:h-4 sm:w-4 mr-2" />
                      Изменить на {getRoleDisplay(getNextRole(user.role))}
                    </>
                  )}
                </Button>
              </div>
            </div>
          )}
          {/* Кнопка закрытия */}
          <div className="flex justify-end pt-3 sm:pt-4 border-t">
            <Button
              onClick={onClose}
              variant="outline"
              className="px-4 sm:px-6 h-10 sm:h-9 text-sm sm:text-base w-full sm:w-auto"
            >
              Закрыть
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

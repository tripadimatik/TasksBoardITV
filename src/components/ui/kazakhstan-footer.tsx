import React from 'react';

interface KazakhstanFooterProps {
  className?: string;
}

export const KazakhstanFooter: React.FC<KazakhstanFooterProps> = ({ 
  className = "" 
}) => {
  return (
    <footer className={`bg-sky-50 border-t border-sky-100 ${className}`}>
      {/* Национальный орнамент */}
      <div className="w-full h-2 bg-sky-600 relative overflow-hidden">
        <div className="absolute inset-0 w-full h-full opacity-30">
          <div className="flex h-full items-center justify-center space-x-2">
            <div className="w-2 h-1 bg-white rounded-full"></div>
            <div className="w-1 h-1 bg-white rounded-full"></div>
            <div className="w-2 h-1 bg-white rounded-full"></div>
            <div className="w-1 h-1 bg-white rounded-full"></div>
            <div className="w-2 h-1 bg-white rounded-full"></div>
          </div>
        </div>
      </div>
      
      {/* Основное содержимое футера */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
        <div className="flex flex-col sm:flex-row justify-between items-center space-y-2 sm:space-y-0">
          <div className="flex items-center space-x-2 text-sm text-gray-600">
            <span className="font-medium text-sky-700">Система управления задачами</span>
            <span className="hidden sm:inline">•</span>
            <span className="text-amber-600 font-medium">Республика Казахстан</span>
          </div>
          
          <div className="flex items-center space-x-4 text-xs text-gray-500">
            <span>© 2025 Государственная платформа</span>
            <div className="flex items-center space-x-1">
              <div className="w-3 h-2 bg-sky-500 rounded-sm"></div>
              <div className="w-2 h-2 bg-amber-400 rounded-full"></div>
              <div className="w-3 h-2 bg-sky-500 rounded-sm"></div>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default KazakhstanFooter;
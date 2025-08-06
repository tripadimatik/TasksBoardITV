import React from 'react';

interface KazakhstanFlagProps {
  className?: string;
  showOrnament?: boolean;
}

export const KazakhstanFlag: React.FC<KazakhstanFlagProps> = ({ 
  className = "h-6 w-10", 
  showOrnament = false 
}) => {
  return (
    <svg 
      className={className} 
      viewBox="0 0 100 50" 
      xmlns="http://www.w3.org/2000/svg"
      role="img"
      aria-label="Флаг Республики Казахстан"
    >
      {/* Основной фон флага */}
      <rect width="100" height="50" fill="#00AFCA" />
      
      {/* Орнамент слева (если включен) */}
      {showOrnament && (
        <g fill="#FFCD00">
          <rect x="2" y="8" width="1" height="6" />
          <rect x="4" y="6" width="1" height="10" />
          <rect x="6" y="8" width="1" height="6" />
          <rect x="2" y="20" width="1" height="6" />
          <rect x="4" y="18" width="1" height="10" />
          <rect x="6" y="20" width="1" height="6" />
          <rect x="2" y="32" width="1" height="6" />
          <rect x="4" y="30" width="1" height="10" />
          <rect x="6" y="32" width="1" height="6" />
        </g>
      )}
      
      {/* Солнце */}
      <g fill="#FFCD00">
        {/* Лучи солнца */}
        <path d="M50 10 L51 15 L49 15 Z" />
        <path d="M50 35 L51 40 L49 40 Z" />
        <path d="M35 25 L40 26 L40 24 Z" />
        <path d="M60 24 L65 25 L60 26 Z" />
        <path d="M42 15 L45 18 L43 20 Z" />
        <path d="M55 30 L57 32 L55 35 Z" />
        <path d="M58 15 L55 18 L57 20 Z" />
        <path d="M42 35 L45 32 L43 30 Z" />
        
        {/* Основной круг солнца */}
        <circle cx="50" cy="25" r="8" />
        
        {/* Орел в центре солнца */}
        <g fill="#00AFCA">
          <path d="M46 22 Q50 20 54 22 Q52 25 50 26 Q48 25 46 22" />
          <path d="M48 26 Q50 28 52 26 Q51 27 50 28 Q49 27 48 26" />
        </g>
      </g>
    </svg>
  );
};

export default KazakhstanFlag;
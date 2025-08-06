import { createRoot } from 'react-dom/client'
import App from './App.tsx'
import './index.css'

// Логирование для отладки на мобильных устройствах
console.log('Main.tsx loaded - starting app initialization');
console.log('User agent:', navigator.userAgent);
console.log('Window location:', window.location.href);
console.log('Screen size:', window.screen.width + 'x' + window.screen.height);

try {
  const rootElement = document.getElementById("root");
  console.log('Root element found:', !!rootElement);
  
  if (!rootElement) {
    console.error('Root element not found!');
    throw new Error('Root element not found');
  }
  
  console.log('Creating React root...');
  const root = createRoot(rootElement);
  
  console.log('Rendering app...');
  root.render(<App />);
  
  console.log('App rendered successfully');
} catch (error) {
  console.error('Error during app initialization:', error);
  // Показываем ошибку на экране для мобильной отладки
  document.body.innerHTML = `
    <div style="padding: 20px; font-family: Arial, sans-serif; color: red;">
      <h2>App Initialization Error</h2>
      <p><strong>Error:</strong> ${error.message}</p>
      <p><strong>Stack:</strong> ${error.stack}</p>
      <p><strong>User Agent:</strong> ${navigator.userAgent}</p>
      <p><strong>Location:</strong> ${window.location.href}</p>
    </div>
  `;
}

import './setup';

import { apis, events } from '@affine/electron-api';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

import { App } from './app';

async function main() {
  const handleMaximized = (maximized: boolean | undefined) => {
    document.documentElement.dataset.maximized = String(maximized);
  };
  const handleFullscreen = (fullscreen: boolean | undefined) => {
    document.documentElement.dataset.fullscreen = String(fullscreen);
  };
  const handleActive = (active: boolean | undefined) => {
    document.documentElement.dataset.active = String(active);
  };

  apis?.ui.isMaximized().then(handleMaximized).catch(console.error);
  apis?.ui.isFullScreen().then(handleFullscreen).catch(console.error);
  events?.ui.onMaximized(handleMaximized);
  events?.ui.onFullScreen(handleFullscreen);
  events?.ui.onTabShellViewActiveChange(handleActive);

  mountApp();
}

function mountApp() {
  const root = document.getElementById('app');
  if (!root) {
    throw new Error('Root element not found');
  }
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>
  );
}

main().catch(console.error);

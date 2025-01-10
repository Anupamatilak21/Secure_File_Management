const { app, BrowserWindow } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: true
    }
  });

  // Load your HTML page (front-end of your app)
  mainWindow.loadURL('http://localhost:5000'); // This points to your Flask app

  // Open DevTools (optional)
  mainWindow.webContents.openDevTools();

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  // Start the Flask server
  const flaskApp = spawn('python', ['app.py']); // Replace with the path to your Flask app if needed

  flaskApp.stdout.on('data', (data) => {
    console.log(`stdout: ${data}`);
  });

  flaskApp.stderr.on('data', (data) => {
    console.error(`stderr: ${data}`);
  });

  flaskApp.on('close', (code) => {
    console.log(`Flask app exited with code ${code}`);
  });

  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

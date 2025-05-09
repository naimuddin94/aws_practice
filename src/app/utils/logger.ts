import fs from 'fs';
import path from 'path';

const logsDir = path.join(__dirname, "../../../", 'logs');

// Create logs directory if not exists
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir);
}

const getTimestamp = () => {
  return new Date().toLocaleString(); // e.g. "4/18/2025, 2:35:10 PM"
};

// ✅ Log success message to success.txt
const logSuccess = (message: string) => {
  const logLine = `[SUCCESS] ${getTimestamp()} - ${message}\n`;
  fs.appendFileSync(path.join(logsDir, 'success.txt'), logLine, 'utf8');
};

// ❌ Log error message to error.txt (with optional stack)
const logError = (message: string, error?: unknown) => {
  let details = '';

  if (error instanceof Error) {
    details = `\nMessage: ${error.message}\nStack: ${error.stack}`;
  } else if (typeof error === 'string') {
    details = `\n${error}`;
  } else if (typeof error === 'object' && error !== null) {
    details = `\n${JSON.stringify(error, null, 2)}`;
  }

  const logLine = `[ERROR] ${getTimestamp()} - ${message}${details}\n\n`;
  fs.appendFileSync(path.join(logsDir, 'error.txt'), logLine, 'utf8');
};


// ℹ️ Optional info log to success.txt
const logInfo = (message: string) => {
  const logLine = `[INFO] ${getTimestamp()} - ${message}\n`;
  fs.appendFileSync(path.join(logsDir, 'success.txt'), logLine, 'utf8');
};

export const Logger = {
  success: logSuccess,
  error: logError,
  info: logInfo,
};

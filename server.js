import express from 'express';
import cors from 'cors';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import multer from 'multer';
import litterRoutes from './routes/litter.js';
import authRoutes from './routes/auth.js';
import authorityRoutes from './routes/authorityRoutes.js';
import errorHandler from './middleware/errorHandler.js';
import multerErrorHandler from './middleware/multerErrorHandler.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());

// JSON for non-multipart requests
app.use(express.json());
app.use(express.static(join(__dirname, 'public')));

// Multer for image uploads (memory storage for demo)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    files: 5,
    fileSize: 5 * 1024 * 1024 // 5MB each
  }
});

// Attach upload middleware for report submissions
const reportUploadMiddleware = (req, res, next) => {
  if (req.method === 'POST' && req.path === '/report') {
    return upload.array('images', 5)(req, res, next);
  }
  next();
};

app.use('/api/litter', reportUploadMiddleware, litterRoutes);
app.use('/api/v1/litter', reportUploadMiddleware, litterRoutes);

// Auth & Lookup Routes
app.use('/api/v1/auth', authRoutes);

// Authority Portal & RBAC Routes
app.use('/api/v1/authority', authorityRoutes);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'Server is running', timestamp: new Date().toISOString() });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Multer-specific error handling must run before the generic handler
app.use(multerErrorHandler);

// Error handling middleware
app.use(errorHandler);

// Start server
app.listen(PORT, () => {
  console.log(`🌍 CleanRoute Server running on http://localhost:${PORT}`);
  console.log(`📍 API endpoint: http://localhost:${PORT}/api/v1/litter`);
  console.log(`🔐 Citizen Auth API: http://localhost:${PORT}/api/v1/auth`);
  console.log(`🏛️ Authority Portal API: http://localhost:${PORT}/api/v1/authority`);
  console.log(`💚 Ready to accept verified litter reports`);
});

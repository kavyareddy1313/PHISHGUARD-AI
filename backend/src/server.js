/**
 * FishGuard AI - Backend Server Entrypoint
 * Express API + WebSocket (Socket.IO) real-time security alerts
 */

const http = require('http');
const express = require('express');
const cors = require('cors');
const { Server } = require('socket.io');

const EmailService = require('./services/EmailService');
const createApiRouter = require('./routes/api');

const app = express();
const server = http.createServer(app);

// Enable CORS
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Socket.IO configuration
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

// Initialize Email Threat Intelligence Service
const emailService = new EmailService(io);

// Mount REST API
app.use('/api', createApiRouter(emailService));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'FishGuard AI Backend API',
    version: '1.0.0'
  });
});

io.on('connection', (socket) => {
  console.log(`[FishGuard-WS] Client connected: ${socket.id}`);
  socket.emit('connected', { message: 'FishGuard AI SOC Real-time Telemetry Connected' });

  socket.on('disconnect', () => {
    console.log(`[FishGuard-WS] Client disconnected: ${socket.id}`);
  });
});

const PORT = process.env.PORT || 5001;
server.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`🛡️  FishGuard AI Backend listening on port ${PORT}`);
  console.log(`📡 WebSocket server initialized`);
  console.log(`====================================================`);
});

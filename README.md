# CleanRoute 🌍♻️

A modern, crowd-sourced litter reporting platform empowering communities to identify problem areas and coordinate cleanup efforts.

## 📋 Project Overview

CleanRoute is a full-stack web application that allows users to:
- Report litter locations with detailed descriptions
- View a map of reported litter hotspots
- Track community cleanup efforts
- Connect with other environmental advocates

## 🏗️ Architecture

```
CleanRoute/
├── public/                 # Frontend assets
│   ├── index.html         # Main HTML file
│   ├── main.css           # Stylesheet
│   └── script.js          # Frontend JavaScript
├── routes/                # API routes
│   └── litter.js          # Litter report endpoints
├── controllers/           # Business logic
│   └── litterController.js # Report operations
├── middleware/            # Express middleware
│   └── errorHandler.js    # Global error handling
├── server.js              # Express server setup
├── package.json           # Dependencies
├── .env.example           # Environment variables template
└── README.md              # Documentation
```

## 🚀 Getting Started

### Prerequisites

- Node.js 18.0.0 or higher
- npm or yarn package manager

### Installation

1. **Clone and enter the project directory:**
   ```bash
   cd CleanRoute
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Create environment file:**
   ```bash
   cp .env.example .env
   ```

4. **Start the server:**
   ```bash
   npm start
   ```

   Or for development with auto-reload:
   ```bash
   npm run dev
   ```

5. **Access the application:**
   - Open your browser and navigate to `http://localhost:3000`

## 📚 API Endpoints

### Litter Reports

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/litter/report` | Submit a new litter report |
| GET | `/api/litter/reports` | Get all reports (with filters) |
| GET | `/api/litter/reports/:id` | Get specific report |
| PUT | `/api/litter/reports/:id` | Update report |
| DELETE | `/api/litter/reports/:id` | Delete report |
| GET | `/api/litter/stats` | Get statistics |

### Health Check

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Server health status |

## 📝 API Request Examples

### Submit a Litter Report

```bash
curl -X POST http://localhost:3000/api/litter/report \
  -H "Content-Type: application/json" \
  -d '{
    "description": "Plastic bags and bottles scattered near the park entrance",
    "latitude": 40.7128,
    "longitude": -74.0060,
    "category": "plastic"
  }'
```

### Get All Reports

```bash
curl http://localhost:3000/api/litter/reports
```

### Filter by Category

```bash
curl http://localhost:3000/api/litter/reports?category=plastic&limit=10&offset=0
```

## 🎨 Design Philosophy

- **Modern & Clean**: Minimalist design with focus on usability
- **Responsive**: Fully mobile-optimized interface
- **Accessible**: WCAG compliant accessibility standards
- **Performance**: Fast load times and smooth interactions
- **Maintainable**: Well-organized code with clear separation of concerns

## 🔧 Technology Stack

- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Backend**: Node.js, Express.js
- **Architecture**: REST API
- **Package Manager**: npm

## ⚙️ Configuration

### Environment Variables

Create a `.env` file based on `.env.example`:

```env
NODE_ENV=development
PORT=3000
LOG_LEVEL=debug
```

## 🧪 Testing the API

### Using cURL

```bash
# Get server health
curl http://localhost:3000/api/health

# Get all reports
curl http://localhost:3000/api/litter/reports

# Get statistics
curl http://localhost:3000/api/litter/stats
```

### Using JavaScript Fetch

```javascript
// Submit a report
fetch('/api/litter/report', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    description: 'Litter found',
    latitude: 40.7128,
    longitude: -74.0060,
    category: 'plastic'
  })
})
.then(response => response.json())
.then(data => console.log(data));
```

## 📱 Frontend Features

- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Form Validation**: Client-side and server-side validation
- **Real-time Feedback**: User feedback messages for actions
- **Statistics Dashboard**: View community impact metrics
- **Smooth Navigation**: Easy access to all platform features

## 🔐 Best Practices Implemented

✅ **Security**
- CORS configuration
- Input validation
- Error handling
- Environment variables for sensitive data

✅ **Code Quality**
- ES6 modules
- Clear function documentation
- Separation of concerns
- Consistent naming conventions

✅ **Performance**
- Efficient CSS selectors
- Minimal DOM manipulation
- Lazy loading ready
- Optimized asset delivery

✅ **Accessibility**
- Semantic HTML
- Proper form labels
- Keyboard navigation
- ARIA attributes ready

✅ **Scalability**
- Modular route structure
- Controller layer for business logic
- Middleware for cross-cutting concerns
- Ready for database integration

## 🚧 Future Enhancements

- [ ] Database integration (MongoDB/PostgreSQL)
- [ ] User authentication & authorization
- [ ] Real-time map visualization
- [ ] Photo uploads for reports
- [ ] Email notifications
- [ ] Mobile app (React Native)
- [ ] Advanced analytics dashboard
- [ ] Community leaderboard
- [ ] AI-powered report analysis
- [ ] Integration with local authorities

## 📄 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Contributions are welcome! Please follow the code style and best practices outlined in this project.

## 📞 Support

For issues or questions, please open an issue on the project repository.

---

**Made with 💚 for a cleaner community**
